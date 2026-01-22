//! Configuration types for the LLM Gateway

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main LLM Gateway configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmGatewayConfig {
    /// Whether the LLM gateway is enabled
    #[serde(default)]
    pub enabled: bool,

    /// LLM provider configurations
    #[serde(default)]
    pub providers: HashMap<String, LlmProviderConfig>,

    /// Default provider to use when not specified
    pub default_provider: Option<String>,

    /// Token rate limiting configuration
    #[serde(default)]
    pub rate_limiting: Option<TokenRateLimitConfig>,

    /// Prompt caching configuration
    #[serde(default)]
    pub caching: Option<PromptCacheConfig>,

    /// Cost tracking configuration
    #[serde(default)]
    pub cost_tracking: Option<CostTrackingConfig>,

    /// Fallback configuration for multi-model routing
    #[serde(default)]
    pub fallback: Option<FallbackConfig>,

    /// Request timeout for LLM requests
    #[serde(default = "default_llm_timeout")]
    pub timeout_secs: u64,

    /// Maximum retries for failed requests
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Enable streaming response passthrough
    #[serde(default = "default_true")]
    pub streaming_enabled: bool,
}

impl Default for LlmGatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            providers: HashMap::new(),
            default_provider: None,
            rate_limiting: None,
            caching: None,
            cost_tracking: None,
            fallback: None,
            timeout_secs: default_llm_timeout(),
            max_retries: default_max_retries(),
            streaming_enabled: true,
        }
    }
}

fn default_llm_timeout() -> u64 {
    120
}

fn default_max_retries() -> u32 {
    3
}

fn default_true() -> bool {
    true
}

/// Configuration for an LLM provider
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmProviderConfig {
    /// Provider type (openai, anthropic, cohere, ollama, vllm, custom)
    #[serde(rename = "type")]
    pub provider_type: LlmProviderType,

    /// Base URL for the provider API
    pub base_url: String,

    /// API key (can use environment variable with ${VAR_NAME} syntax)
    pub api_key: Option<String>,

    /// Default model to use
    pub default_model: Option<String>,

    /// Available models for this provider
    #[serde(default)]
    pub models: Vec<ModelConfig>,

    /// Organization ID (for OpenAI)
    pub organization_id: Option<String>,

    /// Custom headers to add to requests
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Provider-specific settings
    #[serde(default)]
    pub settings: HashMap<String, serde_json::Value>,

    /// Whether this provider is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Priority for fallback routing (lower = higher priority)
    #[serde(default)]
    pub priority: i32,

    /// Health check configuration
    #[serde(default)]
    pub health_check: Option<LlmHealthCheckConfig>,
}

/// Supported LLM provider types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum LlmProviderType {
    /// OpenAI API (GPT-4, GPT-3.5, etc.)
    OpenAI,
    /// Anthropic API (Claude models)
    Anthropic,
    /// Cohere API
    Cohere,
    /// Local Ollama instance
    Ollama,
    /// vLLM inference server
    Vllm,
    /// Azure OpenAI Service
    AzureOpenAI,
    /// Google Vertex AI / Gemini
    Google,
    /// AWS Bedrock
    Bedrock,
    /// Custom OpenAI-compatible API
    Custom,
}

impl Default for LlmProviderType {
    fn default() -> Self {
        Self::Custom
    }
}

/// Configuration for a specific model
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConfig {
    /// Model name/ID
    pub name: String,

    /// Display name for the model
    pub display_name: Option<String>,

    /// Maximum context window size (tokens)
    #[serde(default = "default_context_window")]
    pub context_window: usize,

    /// Maximum output tokens
    #[serde(default = "default_max_output")]
    pub max_output_tokens: usize,

    /// Cost per 1K input tokens (in USD)
    #[serde(default)]
    pub input_cost_per_1k: f64,

    /// Cost per 1K output tokens (in USD)
    #[serde(default)]
    pub output_cost_per_1k: f64,

    /// Whether the model supports function calling
    #[serde(default)]
    pub supports_functions: bool,

    /// Whether the model supports vision/images
    #[serde(default)]
    pub supports_vision: bool,

    /// Whether the model supports streaming
    #[serde(default = "default_true")]
    pub supports_streaming: bool,

    /// Tokenizer to use for this model
    #[serde(default)]
    pub tokenizer: TokenizerType,
}

fn default_context_window() -> usize {
    4096
}

fn default_max_output() -> usize {
    4096
}

/// Tokenizer types for token counting
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TokenizerType {
    /// OpenAI cl100k_base (GPT-4, GPT-3.5-turbo)
    #[default]
    Cl100kBase,
    /// OpenAI p50k_base (text-davinci-003)
    P50kBase,
    /// Anthropic Claude tokenizer
    Claude,
    /// Simple word-based estimation
    Simple,
    /// Character-based estimation (for unknown models)
    CharBased,
}

/// Token-based rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRateLimitConfig {
    /// Whether token rate limiting is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum tokens per minute per client
    #[serde(default = "default_tokens_per_minute")]
    pub tokens_per_minute: u64,

    /// Maximum requests per minute per client
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,

    /// Key extraction method (ip, header, api_key)
    #[serde(default)]
    pub key_by: RateLimitKeyType,

    /// Header name for key extraction (when key_by is "header")
    pub key_header: Option<String>,

    /// Burst allowance (percentage above limit)
    #[serde(default = "default_burst_percent")]
    pub burst_percent: f64,

    /// Whether to include input tokens in rate limiting
    #[serde(default = "default_true")]
    pub count_input_tokens: bool,

    /// Whether to include output tokens in rate limiting
    #[serde(default = "default_true")]
    pub count_output_tokens: bool,
}

fn default_tokens_per_minute() -> u64 {
    100000
}

fn default_requests_per_minute() -> u32 {
    60
}

fn default_burst_percent() -> f64 {
    20.0
}

/// Rate limit key extraction types
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitKeyType {
    /// Key by client IP address
    #[default]
    Ip,
    /// Key by header value
    Header,
    /// Key by API key
    ApiKey,
    /// Global rate limit (no per-client tracking)
    Global,
}

/// Prompt caching configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptCacheConfig {
    /// Whether prompt caching is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Cache backend type
    #[serde(default)]
    pub backend: CacheBackendType,

    /// Redis URL (for Redis backend)
    pub redis_url: Option<String>,

    /// Maximum cache size (entries)
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: usize,

    /// Default TTL for cached responses (seconds)
    #[serde(default = "default_cache_ttl")]
    pub ttl_secs: u64,

    /// Enable semantic similarity matching for cache hits
    #[serde(default)]
    pub semantic_matching: bool,

    /// Similarity threshold for semantic matching (0.0 - 1.0)
    #[serde(default = "default_similarity_threshold")]
    pub similarity_threshold: f64,

    /// Cache key includes: model, temperature, max_tokens, etc.
    #[serde(default = "default_cache_key_params")]
    pub key_includes: Vec<String>,

    /// Skip caching for streaming requests
    #[serde(default)]
    pub skip_streaming: bool,
}

fn default_cache_max_entries() -> usize {
    10000
}

fn default_cache_ttl() -> u64 {
    3600
}

fn default_similarity_threshold() -> f64 {
    0.95
}

fn default_cache_key_params() -> Vec<String> {
    vec![
        "model".to_string(),
        "messages".to_string(),
        "temperature".to_string(),
        "max_tokens".to_string(),
    ]
}

/// Cache backend types
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CacheBackendType {
    /// In-memory cache
    #[default]
    Memory,
    /// Redis cache
    Redis,
}

/// Cost tracking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostTrackingConfig {
    /// Whether cost tracking is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Export costs to Prometheus metrics
    #[serde(default = "default_true")]
    pub prometheus_metrics: bool,

    /// Include cost in response headers
    #[serde(default)]
    pub include_headers: bool,

    /// Header name for request cost
    #[serde(default = "default_cost_header")]
    pub cost_header: String,

    /// Webhook URL for cost alerts
    pub alert_webhook: Option<String>,

    /// Cost threshold for alerts (USD)
    pub alert_threshold: Option<f64>,

    /// Attribution key (for cost attribution)
    #[serde(default)]
    pub attribution_key: RateLimitKeyType,

    /// Attribution header name
    pub attribution_header: Option<String>,
}

fn default_cost_header() -> String {
    "X-LLM-Request-Cost".to_string()
}

/// Fallback configuration for multi-provider routing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackConfig {
    /// Whether fallback is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Fallback providers in order of preference
    pub providers: Vec<String>,

    /// Retry on these HTTP status codes
    #[serde(default = "default_fallback_status_codes")]
    pub retry_on_status: Vec<u16>,

    /// Retry on timeout
    #[serde(default = "default_true")]
    pub retry_on_timeout: bool,

    /// Retry on connection errors
    #[serde(default = "default_true")]
    pub retry_on_connection_error: bool,

    /// Maximum total retries across all providers
    #[serde(default = "default_max_fallback_retries")]
    pub max_retries: u32,

    /// Model mapping between providers
    #[serde(default)]
    pub model_mapping: HashMap<String, HashMap<String, String>>,
}

fn default_fallback_status_codes() -> Vec<u16> {
    vec![429, 500, 502, 503, 504]
}

fn default_max_fallback_retries() -> u32 {
    5
}

/// Health check configuration for LLM providers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmHealthCheckConfig {
    /// Whether health checks are enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Health check interval (seconds)
    #[serde(default = "default_health_interval")]
    pub interval_secs: u64,

    /// Health check timeout (seconds)
    #[serde(default = "default_health_timeout_secs")]
    pub timeout_secs: u64,

    /// Number of failures before marking unhealthy
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// Number of successes before marking healthy
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,

    /// Use a simple ping request instead of model list
    #[serde(default)]
    pub use_ping: bool,
}

fn default_health_interval() -> u64 {
    30
}

fn default_health_timeout_secs() -> u64 {
    10
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_healthy_threshold() -> u32 {
    2
}

/// LLM request structure (OpenAI-compatible)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmRequest {
    /// Model to use
    pub model: String,

    /// Messages for chat completion
    #[serde(default)]
    pub messages: Vec<ChatMessage>,

    /// Prompt for completion (non-chat)
    pub prompt: Option<String>,

    /// Maximum tokens to generate
    pub max_tokens: Option<u32>,

    /// Temperature for sampling
    pub temperature: Option<f64>,

    /// Top-p nucleus sampling
    pub top_p: Option<f64>,

    /// Number of completions to generate
    pub n: Option<u32>,

    /// Whether to stream the response
    #[serde(default)]
    pub stream: bool,

    /// Stop sequences
    pub stop: Option<Vec<String>>,

    /// Presence penalty
    pub presence_penalty: Option<f64>,

    /// Frequency penalty
    pub frequency_penalty: Option<f64>,

    /// User identifier for abuse tracking
    pub user: Option<String>,

    /// Function definitions
    pub functions: Option<Vec<serde_json::Value>>,

    /// Tool definitions (newer API)
    pub tools: Option<Vec<serde_json::Value>>,

    /// Additional provider-specific parameters
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Chat message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Role (system, user, assistant, function, tool)
    pub role: String,

    /// Message content
    pub content: Option<MessageContent>,

    /// Function name (for function messages)
    pub name: Option<String>,

    /// Function call (for assistant messages)
    pub function_call: Option<serde_json::Value>,

    /// Tool calls (newer API)
    pub tool_calls: Option<Vec<serde_json::Value>>,

    /// Tool call ID (for tool messages)
    pub tool_call_id: Option<String>,
}

/// Message content (can be string or array for vision)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    /// Simple text content
    Text(String),
    /// Array of content parts (for vision)
    Parts(Vec<ContentPart>),
}

/// Content part for multi-modal messages
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentPart {
    /// Text content
    #[serde(rename = "text")]
    Text { text: String },
    /// Image content
    #[serde(rename = "image_url")]
    ImageUrl { image_url: ImageUrl },
}

/// Image URL for vision models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageUrl {
    /// URL or base64 data URI
    pub url: String,
    /// Detail level (low, high, auto)
    pub detail: Option<String>,
}

/// LLM response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    /// Response ID
    pub id: String,

    /// Object type
    pub object: String,

    /// Creation timestamp
    pub created: u64,

    /// Model used
    pub model: String,

    /// Response choices
    pub choices: Vec<ResponseChoice>,

    /// Token usage
    pub usage: Option<TokenUsage>,

    /// System fingerprint
    pub system_fingerprint: Option<String>,
}

/// Response choice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseChoice {
    /// Choice index
    pub index: u32,

    /// Message content
    pub message: Option<ChatMessage>,

    /// Text completion (non-chat)
    pub text: Option<String>,

    /// Finish reason
    pub finish_reason: Option<String>,

    /// Log probabilities
    pub logprobs: Option<serde_json::Value>,

    /// Delta for streaming
    pub delta: Option<ChatMessage>,
}

/// Token usage information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Prompt/input tokens
    pub prompt_tokens: u32,

    /// Completion/output tokens
    pub completion_tokens: u32,

    /// Total tokens
    pub total_tokens: u32,

    /// Cached tokens (if applicable)
    #[serde(default)]
    pub cached_tokens: Option<u32>,
}

impl TokenUsage {
    /// Calculate cost based on model pricing
    pub fn calculate_cost(&self, input_cost_per_1k: f64, output_cost_per_1k: f64) -> f64 {
        let input_cost = (self.prompt_tokens as f64 / 1000.0) * input_cost_per_1k;
        let output_cost = (self.completion_tokens as f64 / 1000.0) * output_cost_per_1k;
        input_cost + output_cost
    }
}

/// Streaming chunk structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunk {
    /// Chunk ID
    pub id: String,

    /// Object type
    pub object: String,

    /// Creation timestamp
    pub created: u64,

    /// Model used
    pub model: String,

    /// Choices
    pub choices: Vec<ResponseChoice>,
}
