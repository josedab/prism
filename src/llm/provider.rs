//! LLM Provider implementations for different AI services

use crate::error::{PrismError, Result};
use crate::llm::config::*;
use async_trait::async_trait;
use bytes::Bytes;
use http::{header, Method, Request};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Trait for LLM provider implementations
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Get the provider type
    fn provider_type(&self) -> LlmProviderType;

    /// Get the provider name/ID
    fn name(&self) -> &str;

    /// Build an HTTP request for the given LLM request
    fn build_request(
        &self,
        request: &LlmRequest,
        endpoint: RequestEndpoint,
    ) -> Result<Request<Bytes>>;

    /// Parse the response and extract token usage
    fn parse_response(&self, body: &[u8]) -> Result<LlmResponse>;

    /// Parse a streaming chunk
    fn parse_stream_chunk(&self, chunk: &[u8]) -> Result<Option<StreamChunk>>;

    /// Transform request for this provider (e.g., model name mapping)
    fn transform_request(&self, request: LlmRequest) -> Result<LlmRequest>;

    /// Check if the provider is healthy
    async fn health_check(&self) -> Result<bool>;

    /// Get model configuration
    fn get_model_config(&self, model: &str) -> Option<&ModelConfig>;

    /// Get the base URL
    fn base_url(&self) -> &str;

    /// Check if a model is supported
    fn supports_model(&self, model: &str) -> bool;
}

/// Request endpoint type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestEndpoint {
    /// Chat completions endpoint
    ChatCompletions,
    /// Completions endpoint (legacy)
    Completions,
    /// Embeddings endpoint
    Embeddings,
    /// Models list endpoint
    Models,
}

/// Provider health state
#[derive(Debug)]
pub struct ProviderHealth {
    /// Whether the provider is healthy
    pub healthy: AtomicBool,
    /// Consecutive failure count
    pub failure_count: AtomicU32,
    /// Consecutive success count
    pub success_count: AtomicU32,
    /// Last check time
    pub last_check: RwLock<Option<Instant>>,
    /// Last error message
    pub last_error: RwLock<Option<String>>,
}

impl Default for ProviderHealth {
    fn default() -> Self {
        Self {
            healthy: AtomicBool::new(true),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_check: RwLock::new(None),
            last_error: RwLock::new(None),
        }
    }
}

impl ProviderHealth {
    /// Record a successful health check
    pub fn record_success(&self, healthy_threshold: u32) {
        self.failure_count.store(0, Ordering::SeqCst);
        let count = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;
        if count >= healthy_threshold {
            self.healthy.store(true, Ordering::SeqCst);
        }
    }

    /// Record a failed health check
    pub fn record_failure(&self, unhealthy_threshold: u32, error: String) {
        self.success_count.store(0, Ordering::SeqCst);
        let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
        if count >= unhealthy_threshold {
            self.healthy.store(false, Ordering::SeqCst);
        }
        if let Ok(mut last_error) = self.last_error.try_write() {
            *last_error = Some(error);
        }
    }

    /// Check if healthy
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }
}

/// OpenAI provider implementation
pub struct OpenAIProvider {
    name: String,
    config: LlmProviderConfig,
    models: HashMap<String, ModelConfig>,
    #[allow(dead_code)]
    health: ProviderHealth,
}

impl OpenAIProvider {
    /// Create a new OpenAI provider
    pub fn new(name: String, config: LlmProviderConfig) -> Self {
        let mut models = HashMap::new();
        for model in &config.models {
            models.insert(model.name.clone(), model.clone());
        }

        // Add default OpenAI models if none specified
        if models.is_empty() {
            models.insert(
                "gpt-4".to_string(),
                ModelConfig {
                    name: "gpt-4".to_string(),
                    display_name: Some("GPT-4".to_string()),
                    context_window: 8192,
                    max_output_tokens: 4096,
                    input_cost_per_1k: 0.03,
                    output_cost_per_1k: 0.06,
                    supports_functions: true,
                    supports_vision: false,
                    supports_streaming: true,
                    tokenizer: TokenizerType::Cl100kBase,
                },
            );
            models.insert(
                "gpt-4-turbo".to_string(),
                ModelConfig {
                    name: "gpt-4-turbo".to_string(),
                    display_name: Some("GPT-4 Turbo".to_string()),
                    context_window: 128000,
                    max_output_tokens: 4096,
                    input_cost_per_1k: 0.01,
                    output_cost_per_1k: 0.03,
                    supports_functions: true,
                    supports_vision: true,
                    supports_streaming: true,
                    tokenizer: TokenizerType::Cl100kBase,
                },
            );
            models.insert(
                "gpt-3.5-turbo".to_string(),
                ModelConfig {
                    name: "gpt-3.5-turbo".to_string(),
                    display_name: Some("GPT-3.5 Turbo".to_string()),
                    context_window: 16385,
                    max_output_tokens: 4096,
                    input_cost_per_1k: 0.0005,
                    output_cost_per_1k: 0.0015,
                    supports_functions: true,
                    supports_vision: false,
                    supports_streaming: true,
                    tokenizer: TokenizerType::Cl100kBase,
                },
            );
        }

        Self {
            name,
            config,
            models,
            health: ProviderHealth::default(),
        }
    }

    fn get_api_key(&self) -> Result<String> {
        match &self.config.api_key {
            Some(key) => {
                // Check for environment variable reference
                if key.starts_with("${") && key.ends_with("}") {
                    let var_name = &key[2..key.len() - 1];
                    std::env::var(var_name).map_err(|_| {
                        PrismError::Config(format!(
                            "Environment variable {} not found for OpenAI API key",
                            var_name
                        ))
                    })
                } else {
                    Ok(key.clone())
                }
            }
            None => std::env::var("OPENAI_API_KEY").map_err(|_| {
                PrismError::Config("OpenAI API key not configured".to_string())
            }),
        }
    }
}

#[async_trait]
impl LlmProvider for OpenAIProvider {
    fn provider_type(&self) -> LlmProviderType {
        LlmProviderType::OpenAI
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn build_request(
        &self,
        request: &LlmRequest,
        endpoint: RequestEndpoint,
    ) -> Result<Request<Bytes>> {
        let api_key = self.get_api_key()?;

        let path = match endpoint {
            RequestEndpoint::ChatCompletions => "/v1/chat/completions",
            RequestEndpoint::Completions => "/v1/completions",
            RequestEndpoint::Embeddings => "/v1/embeddings",
            RequestEndpoint::Models => "/v1/models",
        };

        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);

        let body = serde_json::to_vec(request)
            .map_err(|e| PrismError::InvalidRequest(format!("Failed to serialize request: {}", e)))?;

        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {}", api_key));

        // Add organization header if present
        if let Some(org_id) = &self.config.organization_id {
            builder = builder.header("OpenAI-Organization", org_id);
        }

        // Add custom headers
        for (key, value) in &self.config.headers {
            builder = builder.header(key, value);
        }

        builder
            .body(Bytes::from(body))
            .map_err(|e| PrismError::InvalidRequest(format!("Failed to build request: {}", e)))
    }

    fn parse_response(&self, body: &[u8]) -> Result<LlmResponse> {
        serde_json::from_slice(body)
            .map_err(|e| PrismError::Upstream(format!("Failed to parse response: {}", e)))
    }

    fn parse_stream_chunk(&self, chunk: &[u8]) -> Result<Option<StreamChunk>> {
        let chunk_str = std::str::from_utf8(chunk)
            .map_err(|e| PrismError::Upstream(format!("Invalid UTF-8 in stream: {}", e)))?;

        // Handle SSE format: "data: {...}\n\n"
        for line in chunk_str.lines() {
            if line.starts_with("data: ") {
                let data = &line[6..];
                if data == "[DONE]" {
                    return Ok(None);
                }
                let parsed: StreamChunk = serde_json::from_str(data)
                    .map_err(|e| PrismError::Upstream(format!("Failed to parse chunk: {}", e)))?;
                return Ok(Some(parsed));
            }
        }

        Ok(None)
    }

    fn transform_request(&self, mut request: LlmRequest) -> Result<LlmRequest> {
        // Use default model if not specified
        if request.model.is_empty() {
            if let Some(default) = &self.config.default_model {
                request.model = default.clone();
            } else {
                request.model = "gpt-3.5-turbo".to_string();
            }
        }
        Ok(request)
    }

    async fn health_check(&self) -> Result<bool> {
        // For health check, we just verify the API key is valid by listing models
        let api_key = self.get_api_key()?;
        let url = format!("{}/v1/models", self.config.base_url.trim_end_matches('/'));

        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| PrismError::HealthCheck(format!("OpenAI health check failed: {}", e)))?;

        Ok(response.status().is_success())
    }

    fn get_model_config(&self, model: &str) -> Option<&ModelConfig> {
        self.models.get(model)
    }

    fn base_url(&self) -> &str {
        &self.config.base_url
    }

    fn supports_model(&self, model: &str) -> bool {
        self.models.contains_key(model) || model.starts_with("gpt-")
    }
}

/// Anthropic provider implementation
pub struct AnthropicProvider {
    name: String,
    config: LlmProviderConfig,
    models: HashMap<String, ModelConfig>,
    #[allow(dead_code)]
    health: ProviderHealth,
}

impl AnthropicProvider {
    /// Create a new Anthropic provider
    pub fn new(name: String, config: LlmProviderConfig) -> Self {
        let mut models = HashMap::new();
        for model in &config.models {
            models.insert(model.name.clone(), model.clone());
        }

        // Add default Anthropic models if none specified
        if models.is_empty() {
            models.insert(
                "claude-3-opus-20240229".to_string(),
                ModelConfig {
                    name: "claude-3-opus-20240229".to_string(),
                    display_name: Some("Claude 3 Opus".to_string()),
                    context_window: 200000,
                    max_output_tokens: 4096,
                    input_cost_per_1k: 0.015,
                    output_cost_per_1k: 0.075,
                    supports_functions: true,
                    supports_vision: true,
                    supports_streaming: true,
                    tokenizer: TokenizerType::Claude,
                },
            );
            models.insert(
                "claude-3-sonnet-20240229".to_string(),
                ModelConfig {
                    name: "claude-3-sonnet-20240229".to_string(),
                    display_name: Some("Claude 3 Sonnet".to_string()),
                    context_window: 200000,
                    max_output_tokens: 4096,
                    input_cost_per_1k: 0.003,
                    output_cost_per_1k: 0.015,
                    supports_functions: true,
                    supports_vision: true,
                    supports_streaming: true,
                    tokenizer: TokenizerType::Claude,
                },
            );
            models.insert(
                "claude-3-haiku-20240307".to_string(),
                ModelConfig {
                    name: "claude-3-haiku-20240307".to_string(),
                    display_name: Some("Claude 3 Haiku".to_string()),
                    context_window: 200000,
                    max_output_tokens: 4096,
                    input_cost_per_1k: 0.00025,
                    output_cost_per_1k: 0.00125,
                    supports_functions: true,
                    supports_vision: true,
                    supports_streaming: true,
                    tokenizer: TokenizerType::Claude,
                },
            );
        }

        Self {
            name,
            config,
            models,
            health: ProviderHealth::default(),
        }
    }

    fn get_api_key(&self) -> Result<String> {
        match &self.config.api_key {
            Some(key) => {
                if key.starts_with("${") && key.ends_with("}") {
                    let var_name = &key[2..key.len() - 1];
                    std::env::var(var_name).map_err(|_| {
                        PrismError::Config(format!(
                            "Environment variable {} not found for Anthropic API key",
                            var_name
                        ))
                    })
                } else {
                    Ok(key.clone())
                }
            }
            None => std::env::var("ANTHROPIC_API_KEY").map_err(|_| {
                PrismError::Config("Anthropic API key not configured".to_string())
            }),
        }
    }

    /// Convert OpenAI-style request to Anthropic format
    fn convert_to_anthropic_format(&self, request: &LlmRequest) -> Result<serde_json::Value> {
        let mut anthropic_request = serde_json::Map::new();

        anthropic_request.insert("model".to_string(), serde_json::json!(request.model));

        if let Some(max_tokens) = request.max_tokens {
            anthropic_request.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
        } else {
            anthropic_request.insert("max_tokens".to_string(), serde_json::json!(4096));
        }

        // Convert messages
        let mut messages = Vec::new();
        let mut system_message = None;

        for msg in &request.messages {
            if msg.role == "system" {
                if let Some(content) = &msg.content {
                    system_message = Some(match content {
                        MessageContent::Text(t) => t.clone(),
                        MessageContent::Parts(parts) => {
                            parts
                                .iter()
                                .filter_map(|p| match p {
                                    ContentPart::Text { text } => Some(text.clone()),
                                    _ => None,
                                })
                                .collect::<Vec<_>>()
                                .join("\n")
                        }
                    });
                }
            } else {
                let content = msg.content.as_ref().map(|c| match c {
                    MessageContent::Text(t) => serde_json::json!(t),
                    MessageContent::Parts(parts) => {
                        let converted: Vec<serde_json::Value> = parts
                            .iter()
                            .map(|p| match p {
                                ContentPart::Text { text } => {
                                    serde_json::json!({"type": "text", "text": text})
                                }
                                ContentPart::ImageUrl { image_url } => {
                                    serde_json::json!({
                                        "type": "image",
                                        "source": {
                                            "type": "url",
                                            "url": image_url.url
                                        }
                                    })
                                }
                            })
                            .collect();
                        serde_json::json!(converted)
                    }
                });

                messages.push(serde_json::json!({
                    "role": msg.role,
                    "content": content
                }));
            }
        }

        anthropic_request.insert("messages".to_string(), serde_json::json!(messages));

        if let Some(system) = system_message {
            anthropic_request.insert("system".to_string(), serde_json::json!(system));
        }

        if let Some(temp) = request.temperature {
            anthropic_request.insert("temperature".to_string(), serde_json::json!(temp));
        }

        if let Some(top_p) = request.top_p {
            anthropic_request.insert("top_p".to_string(), serde_json::json!(top_p));
        }

        if request.stream {
            anthropic_request.insert("stream".to_string(), serde_json::json!(true));
        }

        if let Some(stop) = &request.stop {
            anthropic_request.insert("stop_sequences".to_string(), serde_json::json!(stop));
        }

        Ok(serde_json::Value::Object(anthropic_request))
    }
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    fn provider_type(&self) -> LlmProviderType {
        LlmProviderType::Anthropic
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn build_request(
        &self,
        request: &LlmRequest,
        endpoint: RequestEndpoint,
    ) -> Result<Request<Bytes>> {
        let api_key = self.get_api_key()?;

        let path = match endpoint {
            RequestEndpoint::ChatCompletions => "/v1/messages",
            RequestEndpoint::Completions => "/v1/complete",
            _ => return Err(PrismError::InvalidRequest("Unsupported endpoint".to_string())),
        };

        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);

        let anthropic_request = self.convert_to_anthropic_format(request)?;
        let body = serde_json::to_vec(&anthropic_request)
            .map_err(|e| PrismError::InvalidRequest(format!("Failed to serialize request: {}", e)))?;

        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-api-key", &api_key)
            .header("anthropic-version", "2023-06-01");

        // Add custom headers
        for (key, value) in &self.config.headers {
            builder = builder.header(key, value);
        }

        builder
            .body(Bytes::from(body))
            .map_err(|e| PrismError::InvalidRequest(format!("Failed to build request: {}", e)))
    }

    fn parse_response(&self, body: &[u8]) -> Result<LlmResponse> {
        // Parse Anthropic response and convert to OpenAI format
        let anthropic_response: serde_json::Value = serde_json::from_slice(body)
            .map_err(|e| PrismError::Upstream(format!("Failed to parse response: {}", e)))?;

        // Convert to OpenAI-compatible format
        let content = anthropic_response
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        if item.get("type")?.as_str()? == "text" {
                            item.get("text")?.as_str().map(String::from)
                        } else {
                            None
                        }
                    })
                    .next()
            })
            .unwrap_or_default();

        let usage = anthropic_response.get("usage").map(|u| TokenUsage {
            prompt_tokens: u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            completion_tokens: u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            total_tokens: 0, // Will be calculated
            cached_tokens: None,
        });

        let mut usage = usage.unwrap_or_default();
        usage.total_tokens = usage.prompt_tokens + usage.completion_tokens;

        Ok(LlmResponse {
            id: anthropic_response
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            object: "chat.completion".to_string(),
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            model: anthropic_response
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            choices: vec![ResponseChoice {
                index: 0,
                message: Some(ChatMessage {
                    role: "assistant".to_string(),
                    content: Some(MessageContent::Text(content)),
                    name: None,
                    function_call: None,
                    tool_calls: None,
                    tool_call_id: None,
                }),
                text: None,
                finish_reason: anthropic_response
                    .get("stop_reason")
                    .and_then(|v| v.as_str())
                    .map(|s| match s {
                        "end_turn" => "stop",
                        "max_tokens" => "length",
                        "stop_sequence" => "stop",
                        _ => s,
                    })
                    .map(String::from),
                logprobs: None,
                delta: None,
            }],
            usage: Some(usage),
            system_fingerprint: None,
        })
    }

    fn parse_stream_chunk(&self, chunk: &[u8]) -> Result<Option<StreamChunk>> {
        let chunk_str = std::str::from_utf8(chunk)
            .map_err(|e| PrismError::Upstream(format!("Invalid UTF-8 in stream: {}", e)))?;

        for line in chunk_str.lines() {
            if line.starts_with("data: ") {
                let data = &line[6..];
                if data == "[DONE]" {
                    return Ok(None);
                }

                let parsed: serde_json::Value = serde_json::from_str(data)
                    .map_err(|e| PrismError::Upstream(format!("Failed to parse chunk: {}", e)))?;

                // Convert Anthropic streaming format to OpenAI format
                let event_type = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("");

                match event_type {
                    "content_block_delta" => {
                        let delta_text = parsed
                            .get("delta")
                            .and_then(|d| d.get("text"))
                            .and_then(|t| t.as_str())
                            .unwrap_or("");

                        return Ok(Some(StreamChunk {
                            id: parsed
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            object: "chat.completion.chunk".to_string(),
                            created: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            model: "claude".to_string(),
                            choices: vec![ResponseChoice {
                                index: 0,
                                message: None,
                                text: None,
                                finish_reason: None,
                                logprobs: None,
                                delta: Some(ChatMessage {
                                    role: "assistant".to_string(),
                                    content: Some(MessageContent::Text(delta_text.to_string())),
                                    name: None,
                                    function_call: None,
                                    tool_calls: None,
                                    tool_call_id: None,
                                }),
                            }],
                        }));
                    }
                    "message_stop" => {
                        return Ok(None);
                    }
                    _ => {}
                }
            }
        }

        Ok(None)
    }

    fn transform_request(&self, mut request: LlmRequest) -> Result<LlmRequest> {
        if request.model.is_empty() {
            if let Some(default) = &self.config.default_model {
                request.model = default.clone();
            } else {
                request.model = "claude-3-sonnet-20240229".to_string();
            }
        }
        Ok(request)
    }

    async fn health_check(&self) -> Result<bool> {
        // Anthropic doesn't have a models endpoint, so we check by making a minimal request
        // In production, you might want to use a dedicated health check endpoint
        Ok(true) // Simplified for now
    }

    fn get_model_config(&self, model: &str) -> Option<&ModelConfig> {
        self.models.get(model)
    }

    fn base_url(&self) -> &str {
        &self.config.base_url
    }

    fn supports_model(&self, model: &str) -> bool {
        self.models.contains_key(model) || model.starts_with("claude")
    }
}

/// Generic OpenAI-compatible provider (for Ollama, vLLM, etc.)
pub struct GenericProvider {
    name: String,
    config: LlmProviderConfig,
    models: HashMap<String, ModelConfig>,
    #[allow(dead_code)]
    health: ProviderHealth,
}

impl GenericProvider {
    /// Create a new generic provider
    pub fn new(name: String, config: LlmProviderConfig) -> Self {
        let mut models = HashMap::new();
        for model in &config.models {
            models.insert(model.name.clone(), model.clone());
        }

        Self {
            name,
            config,
            models,
            health: ProviderHealth::default(),
        }
    }

    fn get_api_key(&self) -> Option<String> {
        match &self.config.api_key {
            Some(key) => {
                if key.starts_with("${") && key.ends_with("}") {
                    let var_name = &key[2..key.len() - 1];
                    std::env::var(var_name).ok()
                } else {
                    Some(key.clone())
                }
            }
            None => None,
        }
    }
}

#[async_trait]
impl LlmProvider for GenericProvider {
    fn provider_type(&self) -> LlmProviderType {
        self.config.provider_type.clone()
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn build_request(
        &self,
        request: &LlmRequest,
        endpoint: RequestEndpoint,
    ) -> Result<Request<Bytes>> {
        let path = match endpoint {
            RequestEndpoint::ChatCompletions => "/v1/chat/completions",
            RequestEndpoint::Completions => "/v1/completions",
            RequestEndpoint::Embeddings => "/v1/embeddings",
            RequestEndpoint::Models => "/v1/models",
        };

        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);

        let body = serde_json::to_vec(request)
            .map_err(|e| PrismError::InvalidRequest(format!("Failed to serialize request: {}", e)))?;

        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header(header::CONTENT_TYPE, "application/json");

        // Add API key if present
        if let Some(api_key) = self.get_api_key() {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", api_key));
        }

        // Add custom headers
        for (key, value) in &self.config.headers {
            builder = builder.header(key, value);
        }

        builder
            .body(Bytes::from(body))
            .map_err(|e| PrismError::InvalidRequest(format!("Failed to build request: {}", e)))
    }

    fn parse_response(&self, body: &[u8]) -> Result<LlmResponse> {
        serde_json::from_slice(body)
            .map_err(|e| PrismError::Upstream(format!("Failed to parse response: {}", e)))
    }

    fn parse_stream_chunk(&self, chunk: &[u8]) -> Result<Option<StreamChunk>> {
        let chunk_str = std::str::from_utf8(chunk)
            .map_err(|e| PrismError::Upstream(format!("Invalid UTF-8 in stream: {}", e)))?;

        for line in chunk_str.lines() {
            if line.starts_with("data: ") {
                let data = &line[6..];
                if data == "[DONE]" {
                    return Ok(None);
                }
                let parsed: StreamChunk = serde_json::from_str(data)
                    .map_err(|e| PrismError::Upstream(format!("Failed to parse chunk: {}", e)))?;
                return Ok(Some(parsed));
            }
        }

        Ok(None)
    }

    fn transform_request(&self, mut request: LlmRequest) -> Result<LlmRequest> {
        if request.model.is_empty() {
            if let Some(default) = &self.config.default_model {
                request.model = default.clone();
            }
        }
        Ok(request)
    }

    async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/v1/models", self.config.base_url.trim_end_matches('/'));

        let client = reqwest::Client::new();
        let mut request = client.get(&url).timeout(Duration::from_secs(10));

        if let Some(api_key) = self.get_api_key() {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request
            .send()
            .await
            .map_err(|e| PrismError::HealthCheck(format!("Health check failed: {}", e)))?;

        Ok(response.status().is_success())
    }

    fn get_model_config(&self, model: &str) -> Option<&ModelConfig> {
        self.models.get(model)
    }

    fn base_url(&self) -> &str {
        &self.config.base_url
    }

    fn supports_model(&self, model: &str) -> bool {
        // Generic providers accept any model
        self.models.is_empty() || self.models.contains_key(model)
    }
}

/// Create a provider from configuration
pub fn create_provider(name: String, config: LlmProviderConfig) -> Arc<dyn LlmProvider> {
    match config.provider_type {
        LlmProviderType::OpenAI | LlmProviderType::AzureOpenAI => {
            Arc::new(OpenAIProvider::new(name, config))
        }
        LlmProviderType::Anthropic => Arc::new(AnthropicProvider::new(name, config)),
        _ => Arc::new(GenericProvider::new(name, config)),
    }
}
