//! LLM Router for multi-provider routing and fallback

use crate::error::{PrismError, Result};
use crate::llm::config::*;
use crate::llm::provider::{create_provider, LlmProvider};
use crate::llm::tokenizer::{TokenCounter, TokenCounterRegistry};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::debug;

/// LLM Router manages multiple providers and handles routing decisions
pub struct LlmRouter {
    /// Provider instances by name
    providers: HashMap<String, Arc<dyn LlmProvider>>,
    /// Provider order for fallback
    fallback_order: Vec<String>,
    /// Default provider name
    default_provider: Option<String>,
    /// Model to provider mapping
    model_providers: RwLock<HashMap<String, String>>,
    /// Fallback configuration
    fallback_config: Option<FallbackConfig>,
    /// Token counter registry
    token_counters: TokenCounterRegistry,
    /// Request statistics
    stats: RouterStats,
    /// Concurrency limiter
    #[allow(dead_code)]
    semaphore: Option<Arc<Semaphore>>,
}

impl LlmRouter {
    /// Create a new LLM router from configuration
    pub fn new(config: &LlmGatewayConfig) -> Result<Self> {
        let mut providers = HashMap::new();
        let mut fallback_order = Vec::new();
        let mut model_providers = HashMap::new();

        // Create providers from config
        for (name, provider_config) in &config.providers {
            if !provider_config.enabled {
                debug!("Skipping disabled provider: {}", name);
                continue;
            }

            let provider = create_provider(name.clone(), provider_config.clone());
            providers.insert(name.clone(), provider.clone());

            // Build model to provider mapping
            for model in &provider_config.models {
                model_providers.insert(model.name.clone(), name.clone());
            }

            // Add to fallback order based on priority
            fallback_order.push(name.clone());
        }

        // Sort fallback order by priority
        if let Some(fallback) = &config.fallback {
            if fallback.enabled && !fallback.providers.is_empty() {
                fallback_order = fallback.providers.clone();
            }
        } else {
            // Sort by priority from config
            fallback_order.sort_by_key(|name| {
                config.providers.get(name)
                    .map(|p| p.priority)
                    .unwrap_or(0)
            });
        }

        // Create semaphore for concurrency limiting
        let semaphore = config.rate_limiting.as_ref().map(|rl| {
            Arc::new(Semaphore::new(rl.requests_per_minute as usize))
        });

        Ok(Self {
            providers,
            fallback_order,
            default_provider: config.default_provider.clone(),
            model_providers: RwLock::new(model_providers),
            fallback_config: config.fallback.clone(),
            token_counters: TokenCounterRegistry::new(),
            stats: RouterStats::default(),
            semaphore,
        })
    }

    /// Route a request to the appropriate provider
    pub async fn route(&self, request: &LlmRequest) -> Result<RoutingDecision> {
        self.stats.requests.fetch_add(1, Ordering::Relaxed);

        // Determine the target provider
        let provider_name = self.select_provider(&request.model)?;
        let provider = self.providers.get(&provider_name)
            .ok_or_else(|| PrismError::Config(format!("Provider not found: {}", provider_name)))?;

        // Get token counter for the model
        let token_counter = self.get_token_counter(provider.as_ref(), &request.model);

        // Estimate input tokens
        let input_tokens = token_counter.count_request_tokens(request);

        Ok(RoutingDecision {
            provider: provider.clone(),
            provider_name,
            input_tokens: input_tokens as u32,
            fallback_providers: self.get_fallback_providers(&request.model),
        })
    }

    /// Select the best provider for a model
    fn select_provider(&self, model: &str) -> Result<String> {
        // Check explicit model mapping
        {
            let mappings = self.model_providers.read();
            if let Some(provider) = mappings.get(model) {
                return Ok(provider.clone());
            }
        }

        // Check if any provider supports this model
        for (name, provider) in &self.providers {
            if provider.supports_model(model) {
                return Ok(name.clone());
            }
        }

        // Fall back to default provider
        if let Some(default) = &self.default_provider {
            return Ok(default.clone());
        }

        // Use first available provider
        self.fallback_order.first()
            .cloned()
            .ok_or_else(|| PrismError::Config("No LLM providers configured".to_string()))
    }

    /// Get fallback providers for a model
    fn get_fallback_providers(&self, model: &str) -> Vec<String> {
        let mut fallbacks = Vec::new();

        if let Some(config) = &self.fallback_config {
            if !config.enabled {
                return fallbacks;
            }

            // Get model mappings if available
            let model_mappings = config.model_mapping.get(model);

            for provider_name in &config.providers {
                if self.providers.contains_key(provider_name) {
                    // Check if there's a model mapping for this provider
                    if let Some(mappings) = model_mappings {
                        if mappings.contains_key(provider_name) {
                            fallbacks.push(provider_name.clone());
                        }
                    } else {
                        fallbacks.push(provider_name.clone());
                    }
                }
            }
        }

        fallbacks
    }

    /// Get token counter for a model
    fn get_token_counter(&self, provider: &dyn LlmProvider, model: &str) -> Arc<dyn TokenCounter> {
        if let Some(model_config) = provider.get_model_config(model) {
            self.token_counters.get(&model_config.tokenizer)
        } else {
            // Default to cl100k_base for unknown models
            self.token_counters.default()
        }
    }

    /// Get a provider by name
    pub fn get_provider(&self, name: &str) -> Option<Arc<dyn LlmProvider>> {
        self.providers.get(name).cloned()
    }

    /// Get all provider names
    pub fn provider_names(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }

    /// Get router statistics
    pub fn stats(&self) -> RouterStatsSnapshot {
        RouterStatsSnapshot {
            total_requests: self.stats.requests.load(Ordering::Relaxed),
            successful_requests: self.stats.successes.load(Ordering::Relaxed),
            failed_requests: self.stats.failures.load(Ordering::Relaxed),
            fallback_requests: self.stats.fallbacks.load(Ordering::Relaxed),
            total_input_tokens: self.stats.input_tokens.load(Ordering::Relaxed),
            total_output_tokens: self.stats.output_tokens.load(Ordering::Relaxed),
        }
    }

    /// Record a successful request
    pub fn record_success(&self, input_tokens: u64, output_tokens: u64) {
        self.stats.successes.fetch_add(1, Ordering::Relaxed);
        self.stats.input_tokens.fetch_add(input_tokens, Ordering::Relaxed);
        self.stats.output_tokens.fetch_add(output_tokens, Ordering::Relaxed);
    }

    /// Record a failed request
    pub fn record_failure(&self) {
        self.stats.failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a fallback
    pub fn record_fallback(&self) {
        self.stats.fallbacks.fetch_add(1, Ordering::Relaxed);
    }
}

/// Routing decision result
pub struct RoutingDecision {
    /// Selected provider
    pub provider: Arc<dyn LlmProvider>,
    /// Provider name
    pub provider_name: String,
    /// Estimated input tokens
    pub input_tokens: u32,
    /// Fallback providers if primary fails
    pub fallback_providers: Vec<String>,
}

/// Router statistics
#[derive(Default)]
struct RouterStats {
    requests: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
    fallbacks: AtomicU64,
    input_tokens: AtomicU64,
    output_tokens: AtomicU64,
}

/// Router statistics snapshot
#[derive(Debug, Clone)]
pub struct RouterStatsSnapshot {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub fallback_requests: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
}

/// Rate limiter for token-based limiting
pub struct TokenRateLimiter {
    config: TokenRateLimitConfig,
    buckets: RwLock<HashMap<String, TokenBucket>>,
}

impl TokenRateLimiter {
    /// Create a new token rate limiter
    pub fn new(config: TokenRateLimitConfig) -> Self {
        Self {
            config,
            buckets: RwLock::new(HashMap::new()),
        }
    }

    /// Check if a request is allowed
    pub fn check(&self, key: &str, tokens: u64) -> RateLimitResult {
        if !self.config.enabled {
            return RateLimitResult::Allowed;
        }

        let mut buckets = self.buckets.write();
        let bucket = buckets.entry(key.to_string()).or_insert_with(|| {
            TokenBucket::new(
                self.config.tokens_per_minute,
                self.config.requests_per_minute,
                self.config.burst_percent,
            )
        });

        bucket.try_consume(tokens)
    }

    /// Record actual token usage after response
    pub fn record_usage(&self, key: &str, tokens: u64) {
        let mut buckets = self.buckets.write();
        if let Some(bucket) = buckets.get_mut(key) {
            bucket.record_actual(tokens);
        }
    }

    /// Clean up expired buckets
    pub fn cleanup(&self) {
        let mut buckets = self.buckets.write();
        let now = Instant::now();
        buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_access) < Duration::from_secs(300)
        });
    }
}

/// Token bucket for rate limiting
struct TokenBucket {
    /// Available tokens
    tokens: f64,
    /// Available requests
    requests: f64,
    /// Max tokens (including burst)
    max_tokens: f64,
    /// Max requests
    max_requests: f64,
    /// Tokens per second refill rate
    token_refill_rate: f64,
    /// Requests per second refill rate
    request_refill_rate: f64,
    /// Last refill time
    last_refill: Instant,
    /// Last access time
    last_access: Instant,
    /// Actual tokens used (for reconciliation)
    actual_used: u64,
}

impl TokenBucket {
    fn new(tokens_per_minute: u64, requests_per_minute: u32, burst_percent: f64) -> Self {
        let burst_multiplier = 1.0 + (burst_percent / 100.0);
        let max_tokens = (tokens_per_minute as f64) * burst_multiplier;
        let max_requests = (requests_per_minute as f64) * burst_multiplier;

        Self {
            tokens: max_tokens,
            requests: max_requests,
            max_tokens,
            max_requests,
            token_refill_rate: tokens_per_minute as f64 / 60.0,
            request_refill_rate: requests_per_minute as f64 / 60.0,
            last_refill: Instant::now(),
            last_access: Instant::now(),
            actual_used: 0,
        }
    }

    fn try_consume(&mut self, tokens: u64) -> RateLimitResult {
        self.refill();
        self.last_access = Instant::now();

        let tokens_f = tokens as f64;

        // Check request limit
        if self.requests < 1.0 {
            return RateLimitResult::RequestLimitExceeded {
                retry_after_ms: (1000.0 / self.request_refill_rate) as u64,
            };
        }

        // Check token limit
        if self.tokens < tokens_f {
            let tokens_needed = tokens_f - self.tokens;
            let wait_ms = (tokens_needed / self.token_refill_rate * 1000.0) as u64;
            return RateLimitResult::TokenLimitExceeded {
                retry_after_ms: wait_ms,
                tokens_available: self.tokens as u64,
            };
        }

        // Consume
        self.tokens -= tokens_f;
        self.requests -= 1.0;

        RateLimitResult::Allowed
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        self.tokens = (self.tokens + elapsed * self.token_refill_rate).min(self.max_tokens);
        self.requests = (self.requests + elapsed * self.request_refill_rate).min(self.max_requests);
        self.last_refill = now;
    }

    fn record_actual(&mut self, tokens: u64) {
        self.actual_used += tokens;
    }
}

/// Rate limit check result
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed,
    /// Token limit exceeded
    TokenLimitExceeded {
        retry_after_ms: u64,
        tokens_available: u64,
    },
    /// Request limit exceeded
    RequestLimitExceeded {
        retry_after_ms: u64,
    },
}

impl RateLimitResult {
    /// Check if the request is allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed)
    }
}

/// Cost tracker for LLM usage
pub struct CostTracker {
    config: CostTrackingConfig,
    costs: RwLock<HashMap<String, CostBucket>>,
    total_cost: AtomicU64,
}

impl CostTracker {
    /// Create a new cost tracker
    pub fn new(config: CostTrackingConfig) -> Self {
        Self {
            config,
            costs: RwLock::new(HashMap::new()),
            total_cost: AtomicU64::new(0),
        }
    }

    /// Track cost for a request
    pub fn track(&self, key: &str, input_tokens: u32, output_tokens: u32, input_cost_per_1k: f64, output_cost_per_1k: f64) -> f64 {
        if !self.config.enabled {
            return 0.0;
        }

        let input_cost = (input_tokens as f64 / 1000.0) * input_cost_per_1k;
        let output_cost = (output_tokens as f64 / 1000.0) * output_cost_per_1k;
        let total = input_cost + output_cost;

        // Store as micro-dollars (millionths) for atomic operations
        let micro_dollars = (total * 1_000_000.0) as u64;
        self.total_cost.fetch_add(micro_dollars, Ordering::Relaxed);

        // Track per-key costs
        let mut costs = self.costs.write();
        let bucket = costs.entry(key.to_string()).or_insert_with(CostBucket::default);
        bucket.add(total, input_tokens, output_tokens);

        total
    }

    /// Get total cost in USD
    pub fn total_cost_usd(&self) -> f64 {
        self.total_cost.load(Ordering::Relaxed) as f64 / 1_000_000.0
    }

    /// Get cost for a specific key
    pub fn get_cost(&self, key: &str) -> Option<CostSnapshot> {
        let costs = self.costs.read();
        costs.get(key).map(|b| CostSnapshot {
            total_cost: b.total_cost,
            input_tokens: b.input_tokens,
            output_tokens: b.output_tokens,
            request_count: b.request_count,
        })
    }

    /// Check if cost header should be included
    pub fn should_include_header(&self) -> bool {
        self.config.include_headers
    }

    /// Get the cost header name
    pub fn cost_header(&self) -> &str {
        &self.config.cost_header
    }
}

/// Cost bucket for tracking
#[derive(Default)]
struct CostBucket {
    total_cost: f64,
    input_tokens: u64,
    output_tokens: u64,
    request_count: u64,
}

impl CostBucket {
    fn add(&mut self, cost: f64, input_tokens: u32, output_tokens: u32) {
        self.total_cost += cost;
        self.input_tokens += input_tokens as u64;
        self.output_tokens += output_tokens as u64;
        self.request_count += 1;
    }
}

/// Cost snapshot for a key
#[derive(Debug, Clone)]
pub struct CostSnapshot {
    pub total_cost: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub request_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(1000, 10, 20.0);

        // Should allow initial request
        let result = bucket.try_consume(100);
        assert!(result.is_allowed());

        // Should still have capacity
        let result = bucket.try_consume(100);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_rate_limit_exceeded() {
        let mut bucket = TokenBucket::new(100, 10, 0.0);

        // Consume all tokens
        let result = bucket.try_consume(100);
        assert!(result.is_allowed());

        // Next request should be limited
        let result = bucket.try_consume(50);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_cost_tracking() {
        let config = CostTrackingConfig {
            enabled: true,
            prometheus_metrics: false,
            include_headers: true,
            cost_header: "X-Cost".to_string(),
            alert_webhook: None,
            alert_threshold: None,
            attribution_key: RateLimitKeyType::Ip,
            attribution_header: None,
        };

        let tracker = CostTracker::new(config);

        // Track some costs
        let cost = tracker.track("user1", 1000, 500, 0.01, 0.03);
        assert!(cost > 0.0);

        // Verify total cost
        assert!(tracker.total_cost_usd() > 0.0);
    }
}
