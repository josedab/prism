//! LLM Gateway middleware for request processing

use crate::error::{PrismError, Result};
use crate::llm::config::*;
use crate::llm::provider::RequestEndpoint;
use crate::llm::router::{CostTracker, LlmRouter, RateLimitResult, TokenRateLimiter};
use crate::middleware::{HttpRequest, HttpResponse, Middleware, Next, ProxyBody, RequestContext};
use async_trait::async_trait;
use bytes::Bytes;
use http::{header, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, warn};

/// LLM Gateway middleware
pub struct LlmGatewayMiddleware {
    config: LlmGatewayConfig,
    router: Arc<LlmRouter>,
    rate_limiter: Option<Arc<TokenRateLimiter>>,
    cost_tracker: Option<Arc<CostTracker>>,
    cache: Option<Arc<PromptCache>>,
}

impl LlmGatewayMiddleware {
    /// Create a new LLM gateway middleware
    pub fn new(config: LlmGatewayConfig) -> Result<Self> {
        let router = Arc::new(LlmRouter::new(&config)?);

        let rate_limiter = config.rate_limiting.as_ref().map(|rl| {
            Arc::new(TokenRateLimiter::new(rl.clone()))
        });

        let cost_tracker = config.cost_tracking.as_ref().map(|ct| {
            Arc::new(CostTracker::new(ct.clone()))
        });

        let cache = config.caching.as_ref().map(|cc| {
            Arc::new(PromptCache::new(cc.clone()))
        });

        Ok(Self {
            config,
            router,
            rate_limiter,
            cost_tracker,
            cache,
        })
    }

    /// Extract rate limit key from request
    fn extract_rate_limit_key(&self, request: &HttpRequest, ctx: &RequestContext) -> String {
        if let Some(rl_config) = &self.config.rate_limiting {
            match rl_config.key_by {
                RateLimitKeyType::Ip => {
                    ctx.client_ip.clone().unwrap_or_else(|| "unknown".to_string())
                }
                RateLimitKeyType::Header => {
                    if let Some(header_name) = &rl_config.key_header {
                        request.headers()
                            .get(header_name)
                            .and_then(|v| v.to_str().ok())
                            .map(String::from)
                            .unwrap_or_else(|| "unknown".to_string())
                    } else {
                        "unknown".to_string()
                    }
                }
                RateLimitKeyType::ApiKey => {
                    request.headers()
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.trim_start_matches("Bearer ").to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                }
                RateLimitKeyType::Global => "global".to_string(),
            }
        } else {
            ctx.client_ip.clone().unwrap_or_else(|| "unknown".to_string())
        }
    }

    /// Check if request is an LLM request
    fn is_llm_request(&self, request: &HttpRequest) -> bool {
        let path = request.uri().path();

        // Check for common LLM API paths
        path.contains("/v1/chat/completions")
            || path.contains("/v1/completions")
            || path.contains("/v1/embeddings")
            || path.contains("/api/chat")
            || path.contains("/api/generate")
    }

    /// Parse LLM request from body
    fn parse_llm_request(&self, body: &[u8]) -> Result<LlmRequest> {
        serde_json::from_slice(body)
            .map_err(|e| PrismError::InvalidRequest(format!("Failed to parse LLM request: {}", e)))
    }

    /// Build error response
    fn error_response(&self, status: StatusCode, message: &str) -> HttpResponse {
        let body = serde_json::json!({
            "error": {
                "message": message,
                "type": "invalid_request_error",
                "code": status.as_u16()
            }
        });

        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap()
    }

    /// Build rate limit response
    fn rate_limit_response(&self, result: &RateLimitResult) -> HttpResponse {
        let (retry_after, message) = match result {
            RateLimitResult::TokenLimitExceeded { retry_after_ms, tokens_available } => {
                (*retry_after_ms, format!("Token limit exceeded. {} tokens available.", tokens_available))
            }
            RateLimitResult::RequestLimitExceeded { retry_after_ms } => {
                (*retry_after_ms, "Request limit exceeded.".to_string())
            }
            RateLimitResult::Allowed => unreachable!(),
        };

        let body = serde_json::json!({
            "error": {
                "message": message,
                "type": "rate_limit_error",
                "code": 429
            }
        });

        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header(header::CONTENT_TYPE, "application/json")
            .header("Retry-After", (retry_after / 1000).max(1).to_string())
            .header("X-RateLimit-Reset-Ms", retry_after.to_string())
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap()
    }
}

#[async_trait]
impl Middleware for LlmGatewayMiddleware {
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        // Check if LLM gateway is enabled
        if !self.config.enabled {
            return next.run(request, ctx).await;
        }

        // Check if this is an LLM request
        if !self.is_llm_request(&request) {
            return next.run(request, ctx).await;
        }

        debug!("Processing LLM request: {}", request.uri().path());

        // Collect the body
        let (parts, body) = request.into_parts();
        let body_bytes = match body {
            ProxyBody::Streaming(incoming) => {
                let collected = incoming.collect().await
                    .map_err(|e| PrismError::InvalidRequest(format!("Failed to read body: {}", e)))?;
                collected.to_bytes()
            }
            ProxyBody::Buffered(full) => {
                let collected = full.collect().await
                    .map_err(|e| PrismError::InvalidRequest(format!("Failed to read body: {}", e)))?;
                collected.to_bytes()
            }
        };

        // Parse the LLM request
        let llm_request = match self.parse_llm_request(&body_bytes) {
            Ok(req) => req,
            Err(e) => {
                warn!("Failed to parse LLM request: {}", e);
                return Ok(self.error_response(StatusCode::BAD_REQUEST, &e.to_string()));
            }
        };

        // Route the request
        let routing = match self.router.route(&llm_request).await {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to route LLM request: {}", e);
                return Ok(self.error_response(StatusCode::BAD_GATEWAY, &e.to_string()));
            }
        };

        // Extract rate limit key
        let request = Request::from_parts(parts.clone(), ProxyBody::buffered(body_bytes.clone()));
        let rate_key = self.extract_rate_limit_key(&request, &ctx);

        // Check rate limits
        if let Some(limiter) = &self.rate_limiter {
            let result = limiter.check(&rate_key, routing.input_tokens as u64);
            if !result.is_allowed() {
                warn!("Rate limit exceeded for key: {}", rate_key);
                return Ok(self.rate_limit_response(&result));
            }
        }

        // Check cache for non-streaming requests
        if !llm_request.stream {
            if let Some(cache) = &self.cache {
                if let Some(cached) = cache.get(&llm_request) {
                    debug!("Cache hit for LLM request");
                    return Ok(cached);
                }
            }
        }

        // Transform request for the provider
        let transformed = match routing.provider.transform_request(llm_request.clone()) {
            Ok(t) => t,
            Err(e) => {
                return Ok(self.error_response(StatusCode::BAD_REQUEST, &e.to_string()));
            }
        };

        // Build provider request
        let endpoint = if transformed.messages.is_empty() {
            RequestEndpoint::Completions
        } else {
            RequestEndpoint::ChatCompletions
        };

        let provider_request = match routing.provider.build_request(&transformed, endpoint) {
            Ok(r) => r,
            Err(e) => {
                return Ok(self.error_response(StatusCode::BAD_GATEWAY, &e.to_string()));
            }
        };

        // Make the request to the provider
        let start = Instant::now();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.config.timeout_secs))
            .build()
            .map_err(|e| PrismError::Internal(format!("Failed to create HTTP client: {}", e)))?;

        let method = provider_request.method().clone();
        let uri = provider_request.uri().to_string();
        let headers = provider_request.headers().clone();
        let body = provider_request.into_body();

        let mut req_builder = client.request(method.clone(), &uri);
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                req_builder = req_builder.header(name.as_str(), v);
            }
        }
        req_builder = req_builder.body(body.to_vec());

        let response = req_builder.send().await
            .map_err(|e| PrismError::Upstream(format!("Request to LLM provider failed: {}", e)))?;

        let status = response.status();
        let response_headers = response.headers().clone();

        // Handle streaming response
        if llm_request.stream && status.is_success() {
            // For streaming, we pass through the response
            let response_body = response.bytes().await
                .map_err(|e| PrismError::Upstream(format!("Failed to read response: {}", e)))?;

            let mut builder = Response::builder().status(status);
            for (name, value) in response_headers.iter() {
                builder = builder.header(name, value);
            }

            return builder
                .body(Full::new(response_body))
                .map_err(|e| PrismError::Internal(format!("Failed to build response: {}", e)));
        }

        // Handle non-streaming response
        let response_body = response.bytes().await
            .map_err(|e| PrismError::Upstream(format!("Failed to read response: {}", e)))?;

        let elapsed = start.elapsed();
        debug!("LLM request completed in {:?}", elapsed);

        // Parse response for token tracking
        let mut output_tokens = 0u32;
        let mut total_cost = 0.0f64;

        if status.is_success() {
            if let Ok(llm_response) = routing.provider.parse_response(&response_body) {
                if let Some(usage) = llm_response.usage {
                    output_tokens = usage.completion_tokens;

                    // Track costs
                    if let Some(tracker) = &self.cost_tracker {
                        if let Some(model_config) = routing.provider.get_model_config(&llm_request.model) {
                            total_cost = tracker.track(
                                &rate_key,
                                usage.prompt_tokens,
                                usage.completion_tokens,
                                model_config.input_cost_per_1k,
                                model_config.output_cost_per_1k,
                            );
                        }
                    }

                    // Record rate limit usage
                    if let Some(limiter) = &self.rate_limiter {
                        limiter.record_usage(&rate_key, usage.total_tokens as u64);
                    }

                    // Record router stats
                    self.router.record_success(
                        usage.prompt_tokens as u64,
                        usage.completion_tokens as u64,
                    );
                }
            }

            // Cache successful response
            if let Some(cache) = &self.cache {
                cache.put_with_body(&llm_request, status, &response_headers, response_body.clone());
            }
        } else {
            self.router.record_failure();
        }

        // Build response
        let mut builder = Response::builder().status(status);

        // Copy relevant headers
        for (name, value) in response_headers.iter() {
            if name != header::TRANSFER_ENCODING && name != header::CONTENT_LENGTH {
                builder = builder.header(name, value);
            }
        }

        // Add cost header if configured
        if let Some(tracker) = &self.cost_tracker {
            if tracker.should_include_header() {
                builder = builder.header(
                    tracker.cost_header(),
                    format!("{:.6}", total_cost),
                );
            }
        }

        // Add token usage headers
        builder = builder
            .header("X-LLM-Input-Tokens", routing.input_tokens.to_string())
            .header("X-LLM-Output-Tokens", output_tokens.to_string())
            .header("X-LLM-Provider", routing.provider_name.as_str())
            .header("X-LLM-Latency-Ms", elapsed.as_millis().to_string());

        builder
            .body(Full::new(response_body))
            .map_err(|e| PrismError::Internal(format!("Failed to build response: {}", e)))
    }

    fn name(&self) -> &'static str {
        "llm_gateway"
    }
}

/// Prompt cache for caching LLM responses
pub struct PromptCache {
    config: PromptCacheConfig,
    entries: RwLock<HashMap<String, CacheEntry>>,
}

impl PromptCache {
    /// Create a new prompt cache
    pub fn new(config: PromptCacheConfig) -> Self {
        Self {
            config,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Generate cache key from request
    fn cache_key(&self, request: &LlmRequest) -> String {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();

        // Include configured key parameters
        for param in &self.config.key_includes {
            match param.as_str() {
                "model" => hasher.update(request.model.as_bytes()),
                "messages" => {
                    let messages_json = serde_json::to_string(&request.messages).unwrap_or_default();
                    hasher.update(messages_json.as_bytes());
                }
                "temperature" => {
                    if let Some(t) = request.temperature {
                        hasher.update(t.to_string().as_bytes());
                    }
                }
                "max_tokens" => {
                    if let Some(m) = request.max_tokens {
                        hasher.update(m.to_string().as_bytes());
                    }
                }
                "prompt" => {
                    if let Some(p) = &request.prompt {
                        hasher.update(p.as_bytes());
                    }
                }
                _ => {}
            }
        }

        hex::encode(hasher.finalize())
    }

    /// Get cached response
    pub fn get(&self, request: &LlmRequest) -> Option<HttpResponse> {
        if !self.config.enabled {
            return None;
        }

        // Skip streaming requests
        if request.stream && self.config.skip_streaming {
            return None;
        }

        let key = self.cache_key(request);
        let entries = self.entries.read();

        if let Some(entry) = entries.get(&key) {
            if entry.is_valid(self.config.ttl_secs) {
                debug!("Cache hit for key: {}", &key[..16]);
                return Some(entry.to_response());
            }
        }

        None
    }

    /// Put response in cache
    /// Note: This method creates a cache entry with the status and headers.
    /// The body must be provided separately for caching to work properly.
    pub fn put_with_body(&self, request: &LlmRequest, status: StatusCode, headers: &http::HeaderMap, body: Bytes) {
        if !self.config.enabled {
            return;
        }

        if request.stream && self.config.skip_streaming {
            return;
        }

        let key = self.cache_key(request);

        let mut header_map = HashMap::new();
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                header_map.insert(name.to_string(), v.to_string());
            }
        }

        let entry = CacheEntry::from_parts(status, header_map, body);

        let mut entries = self.entries.write();

        // Check max entries
        if entries.len() >= self.config.max_entries {
            // Remove oldest entries
            let mut to_remove = Vec::new();
            let cutoff = Instant::now() - Duration::from_secs(self.config.ttl_secs);

            for (k, v) in entries.iter() {
                if v.created < cutoff {
                    to_remove.push(k.clone());
                }
            }

            for k in to_remove {
                entries.remove(&k);
            }
        }

        entries.insert(key, entry);
    }

    /// Clear the cache
    pub fn clear(&self) {
        let mut entries = self.entries.write();
        entries.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let entries = self.entries.read();
        CacheStats {
            entries: entries.len(),
            max_entries: self.config.max_entries,
        }
    }
}

/// Cache entry
struct CacheEntry {
    status: StatusCode,
    headers: HashMap<String, String>,
    body: Bytes,
    created: Instant,
}

impl CacheEntry {
    fn from_parts(status: StatusCode, headers: HashMap<String, String>, body: Bytes) -> Self {
        Self {
            status,
            headers,
            body,
            created: Instant::now(),
        }
    }

    fn is_valid(&self, ttl_secs: u64) -> bool {
        self.created.elapsed() < Duration::from_secs(ttl_secs)
    }

    fn to_response(&self) -> HttpResponse {
        let mut builder = Response::builder().status(self.status);

        for (name, value) in &self.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        builder.header("X-Cache", "HIT")
            .body(Full::new(self.body.clone()))
            .unwrap()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entries: usize,
    pub max_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_generation() {
        let config = PromptCacheConfig {
            enabled: true,
            backend: CacheBackendType::Memory,
            redis_url: None,
            max_entries: 100,
            ttl_secs: 3600,
            semantic_matching: false,
            similarity_threshold: 0.95,
            key_includes: vec!["model".to_string(), "messages".to_string()],
            skip_streaming: true,
        };

        let cache = PromptCache::new(config);

        let request = LlmRequest {
            model: "gpt-4".to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: Some(MessageContent::Text("Hello".to_string())),
                name: None,
                function_call: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            prompt: None,
            max_tokens: None,
            temperature: None,
            top_p: None,
            n: None,
            stream: false,
            stop: None,
            presence_penalty: None,
            frequency_penalty: None,
            user: None,
            functions: None,
            tools: None,
            extra: HashMap::new(),
        };

        let key = cache.cache_key(&request);
        assert!(!key.is_empty());
        assert_eq!(key.len(), 64); // SHA256 hex string
    }
}
