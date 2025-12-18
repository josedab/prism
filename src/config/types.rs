//! Configuration type definitions

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Root configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Listener configurations
    pub listeners: Vec<ListenerConfig>,

    /// Upstream backend configurations
    #[serde(default)]
    pub upstreams: HashMap<String, UpstreamConfig>,

    /// Route configurations
    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    /// Observability configuration
    #[serde(default)]
    pub observability: ObservabilityConfig,

    /// Admin API configuration
    #[serde(default)]
    pub admin: Option<AdminConfig>,

    /// Global settings
    #[serde(default)]
    pub global: GlobalConfig,

    // ============================================
    // Next-Gen Features Configuration
    // ============================================
    /// SPIFFE/SPIRE zero-trust identity configuration
    #[serde(default)]
    pub spiffe: Option<SpiffeConfigDef>,

    /// io_uring high-performance I/O configuration (Linux only)
    #[serde(default)]
    pub io_uring: Option<IoUringConfigDef>,

    /// xDS API configuration (Envoy compatibility)
    #[serde(default)]
    pub xds: Option<XdsConfigDef>,

    /// Kubernetes Gateway API configuration
    #[serde(default)]
    pub kubernetes: Option<KubernetesConfigDef>,

    /// Edge compute / WASM functions configuration
    #[serde(default)]
    pub edge: Option<EdgeConfigDef>,

    /// WASM plugin system configuration
    #[serde(default)]
    pub plugins: Option<PluginConfigDef>,

    /// HTTP/3 (QUIC) configuration
    #[serde(default)]
    pub http3: Option<Http3ConfigDef>,

    /// AI anomaly detection configuration
    #[serde(default)]
    pub anomaly_detection: Option<AnomalyConfigDef>,

    /// eBPF observability configuration (Linux only)
    #[serde(default)]
    pub ebpf: Option<EbpfConfigDef>,

    /// GraphQL-aware routing configuration
    #[serde(default)]
    pub graphql: Option<GraphQLConfigDef>,
}

/// Listener configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// Bind address (e.g., "0.0.0.0:443")
    pub address: String,

    /// Protocol type
    #[serde(default)]
    pub protocol: Protocol,

    /// TLS configuration (required for https/http3)
    pub tls: Option<TlsConfig>,

    /// Maximum concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

fn default_max_connections() -> usize {
    10000
}

/// Protocol types supported
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Http,
    Https,
    Http3,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to certificate file (PEM format)
    pub cert: PathBuf,

    /// Path to private key file (PEM format)
    pub key: PathBuf,

    /// ALPN protocols to advertise
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,

    /// Minimum TLS version
    #[serde(default = "default_min_tls_version")]
    pub min_version: String,

    /// Client authentication mode (mTLS)
    #[serde(default)]
    pub client_auth: ClientAuthMode,

    /// Path to CA certificate for verifying client certificates
    pub client_ca: Option<PathBuf>,
}

/// Client authentication mode for mTLS
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMode {
    /// No client authentication required
    #[default]
    None,
    /// Client certificate is optional but verified if provided
    Optional,
    /// Client certificate is required and verified
    Required,
}

fn default_alpn() -> Vec<String> {
    vec!["h2".to_string(), "http/1.1".to_string()]
}

fn default_min_tls_version() -> String {
    "1.2".to_string()
}

/// Upstream backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// List of backend servers
    pub servers: Vec<ServerConfig>,

    /// Health check configuration
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,

    /// Load balancing algorithm
    #[serde(default)]
    pub load_balancing: LoadBalancingAlgorithm,

    /// Connection pool settings
    #[serde(default)]
    pub pool: PoolConfig,

    /// Connect timeout
    #[serde(default = "default_connect_timeout", with = "humantime_serde")]
    pub connect_timeout: Duration,

    /// Request timeout
    #[serde(default = "default_request_timeout", with = "humantime_serde")]
    pub request_timeout: Duration,

    /// Circuit breaker configuration
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Retry policy configuration
    #[serde(default)]
    pub retry: Option<RetryConfig>,
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(30)
}

/// Individual server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Server address (host:port)
    pub address: String,

    /// Weight for weighted load balancing
    #[serde(default = "default_weight")]
    pub weight: u32,

    /// Whether this server is initially enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_weight() -> u32 {
    1
}

fn default_enabled() -> bool {
    true
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// Health check type
    #[serde(default)]
    pub check_type: HealthCheckType,

    /// Path for HTTP health checks
    #[serde(default = "default_health_path")]
    pub path: String,

    /// Expected HTTP status code
    #[serde(default = "default_expected_status")]
    pub expected_status: u16,

    /// Check interval
    #[serde(default = "default_interval", with = "humantime_serde")]
    pub interval: Duration,

    /// Check timeout
    #[serde(default = "default_health_timeout", with = "humantime_serde")]
    pub timeout: Duration,

    /// Number of failures before marking unhealthy
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// Number of successes before marking healthy
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            check_type: HealthCheckType::default(),
            path: default_health_path(),
            expected_status: default_expected_status(),
            interval: default_interval(),
            timeout: default_health_timeout(),
            unhealthy_threshold: default_unhealthy_threshold(),
            healthy_threshold: default_healthy_threshold(),
        }
    }
}

fn default_health_path() -> String {
    "/health".to_string()
}

fn default_expected_status() -> u16 {
    200
}

fn default_interval() -> Duration {
    Duration::from_secs(10)
}

fn default_health_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_healthy_threshold() -> u32 {
    2
}

/// Health check types
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HealthCheckType {
    #[default]
    Http,
    Tcp,
}

/// Load balancing algorithms
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingAlgorithm {
    #[default]
    RoundRobin,
    LeastConnections,
    Random,
    IpHash,
    Weighted,
    ConsistentHash,
}

/// Connection pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolConfig {
    /// Maximum connections per upstream
    #[serde(default = "default_max_connections_per_upstream")]
    pub max_connections: usize,

    /// Minimum idle connections
    #[serde(default = "default_min_idle")]
    pub min_idle: usize,

    /// Maximum connection lifetime
    #[serde(default = "default_max_lifetime", with = "humantime_serde")]
    pub max_lifetime: Duration,

    /// Idle timeout
    #[serde(default = "default_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections_per_upstream(),
            min_idle: default_min_idle(),
            max_lifetime: default_max_lifetime(),
            idle_timeout: default_idle_timeout(),
        }
    }
}

fn default_max_connections_per_upstream() -> usize {
    100
}

fn default_min_idle() -> usize {
    10
}

fn default_max_lifetime() -> Duration {
    Duration::from_secs(3600)
}

fn default_idle_timeout() -> Duration {
    Duration::from_secs(60)
}

/// Route configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Match conditions
    #[serde(rename = "match")]
    pub match_config: MatchConfig,

    /// Target upstream name
    pub upstream: Option<String>,

    /// Static response handler
    pub handler: Option<HandlerConfig>,

    /// Middleware chain
    #[serde(default)]
    pub middlewares: Vec<MiddlewareConfig>,

    /// Path rewrite rules
    pub rewrite: Option<RewriteConfig>,

    /// Priority (lower = higher priority)
    #[serde(default)]
    pub priority: i32,
}

/// Route matching configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchConfig {
    /// Host to match (supports wildcards)
    pub host: Option<String>,

    /// Exact path match
    pub path: Option<String>,

    /// Path prefix match
    pub path_prefix: Option<String>,

    /// Path regex match
    pub path_regex: Option<String>,

    /// Required headers
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// HTTP methods to match
    #[serde(default)]
    pub methods: Vec<String>,
}

/// Static handler configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandlerConfig {
    /// Handler type
    #[serde(rename = "type")]
    pub handler_type: HandlerType,

    /// HTTP status code
    #[serde(default = "default_handler_status")]
    pub status: u16,

    /// Response body
    #[serde(default)]
    pub body: String,

    /// Response headers
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Redirect URL (for redirect type)
    pub redirect_url: Option<String>,
}

fn default_handler_status() -> u16 {
    200
}

/// Handler types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HandlerType {
    Static,
    Redirect,
}

/// Path rewrite configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewriteConfig {
    /// Pattern to match (regex)
    pub pattern: String,

    /// Replacement string
    pub replacement: String,
}

/// Middleware configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MiddlewareConfig {
    /// Rate limiting middleware
    pub rate_limit: Option<RateLimitConfig>,

    /// Authentication middleware
    pub auth: Option<AuthConfig>,

    /// Header manipulation
    pub headers: Option<HeadersConfig>,

    /// Compression middleware
    pub compression: Option<CompressionConfig>,

    /// Timeout override
    pub timeout: Option<TimeoutConfig>,

    /// Circuit breaker
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Retry policy
    pub retry: Option<RetryConfig>,

    /// CORS configuration
    pub cors: Option<CorsConfigDef>,

    /// Chaos engineering / fault injection
    pub chaos: Option<ChaosConfigDef>,

    /// Request hedging
    pub hedging: Option<HedgingConfigDef>,

    /// Adaptive concurrency limits
    pub adaptive_concurrency: Option<AdaptiveConcurrencyConfigDef>,
}

/// CORS configuration for config file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorsConfigDef {
    /// Allowed origins (use "*" for all)
    #[serde(default = "default_cors_origins")]
    pub allowed_origins: Vec<String>,

    /// Allowed HTTP methods
    #[serde(default = "default_cors_methods")]
    pub allowed_methods: Vec<String>,

    /// Allowed headers
    #[serde(default = "default_cors_headers")]
    pub allowed_headers: Vec<String>,

    /// Headers to expose to the client
    #[serde(default)]
    pub expose_headers: Vec<String>,

    /// Whether to allow credentials
    #[serde(default)]
    pub allow_credentials: bool,

    /// Max age for preflight cache (seconds)
    #[serde(default = "default_cors_max_age")]
    pub max_age: Option<u64>,
}

fn default_cors_origins() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_cors_methods() -> Vec<String> {
    vec![
        "GET".to_string(),
        "POST".to_string(),
        "PUT".to_string(),
        "DELETE".to_string(),
        "OPTIONS".to_string(),
    ]
}

fn default_cors_headers() -> Vec<String> {
    vec!["Content-Type".to_string(), "Authorization".to_string()]
}

fn default_cors_max_age() -> Option<u64> {
    Some(86400)
}

/// Chaos engineering configuration for config file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChaosConfigDef {
    /// Whether chaos engineering is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Latency injection configuration
    #[serde(default)]
    pub latency: Option<LatencyConfigDef>,

    /// Error injection configuration
    #[serde(default)]
    pub error: Option<ErrorConfigDef>,

    /// Abort injection configuration
    #[serde(default)]
    pub abort: Option<AbortConfigDef>,

    /// Response corruption configuration
    #[serde(default)]
    pub corruption: Option<CorruptionConfigDef>,

    /// Bandwidth throttling configuration
    #[serde(default)]
    pub throttle: Option<ThrottleConfigDef>,

    /// Target specific paths (empty = all paths)
    #[serde(default)]
    pub target_paths: Vec<String>,

    /// Target specific methods (empty = all methods)
    #[serde(default)]
    pub target_methods: Vec<String>,

    /// Target specific headers (must match all)
    #[serde(default)]
    pub target_headers: HashMap<String, String>,
}

/// Latency injection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LatencyConfigDef {
    /// Percentage of requests to affect (0-100)
    #[serde(default = "default_chaos_percentage")]
    pub percentage: f64,

    /// Fixed latency to add (e.g., "100ms")
    pub fixed: Option<String>,

    /// Minimum random latency (e.g., "10ms")
    pub min: Option<String>,

    /// Maximum random latency (e.g., "500ms")
    pub max: Option<String>,

    /// Distribution type: "uniform", "normal", "exponential", "pareto"
    #[serde(default)]
    pub distribution: String,
}

/// Error injection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorConfigDef {
    /// Percentage of requests to fail (0-100)
    #[serde(default = "default_chaos_percentage")]
    pub percentage: f64,

    /// HTTP status code to return
    #[serde(default = "default_error_status_chaos")]
    pub status: u16,

    /// Error message body
    #[serde(default)]
    pub message: String,

    /// Custom headers to include in error response
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// gRPC status code (for gRPC requests)
    #[serde(default)]
    pub grpc_status: Option<i32>,
}

/// Abort injection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortConfigDef {
    /// Percentage of requests to abort (0-100)
    #[serde(default = "default_chaos_percentage")]
    pub percentage: f64,

    /// When to abort: "before_request", "during_request", "before_response"
    #[serde(default)]
    pub timing: String,
}

/// Response corruption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorruptionConfigDef {
    /// Percentage of responses to corrupt (0-100)
    #[serde(default = "default_chaos_percentage")]
    pub percentage: f64,

    /// Type of corruption: "truncate", "bit_flip", "replace", "duplicate"
    #[serde(default)]
    pub corruption_type: String,

    /// For truncation: percentage of body to keep (0-100)
    #[serde(default = "default_truncate_pct")]
    pub truncate_percentage: f64,

    /// For bit_flip: number of bits to flip
    #[serde(default = "default_bit_flips")]
    pub bit_flips: usize,
}

/// Bandwidth throttling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThrottleConfigDef {
    /// Percentage of requests to throttle (0-100)
    #[serde(default = "default_chaos_percentage")]
    pub percentage: f64,

    /// Bandwidth limit in bytes per second
    #[serde(default = "default_bandwidth_bps")]
    pub bandwidth_bps: u64,
}

fn default_chaos_percentage() -> f64 {
    10.0
}

fn default_error_status_chaos() -> u16 {
    500
}

fn default_truncate_pct() -> f64 {
    50.0
}

fn default_bit_flips() -> usize {
    5
}

fn default_bandwidth_bps() -> u64 {
    1024
}

/// Request hedging configuration for config file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HedgingConfigDef {
    /// Whether hedging is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Delay before sending hedge requests (milliseconds)
    #[serde(default = "default_hedge_delay")]
    pub delay_ms: u64,

    /// Maximum number of hedge requests
    #[serde(default = "default_max_hedges")]
    pub max_hedges: usize,

    /// Maximum percentage of additional requests allowed (budget)
    #[serde(default = "default_hedge_budget_percent")]
    pub budget_percent: f64,

    /// Time window for budget calculation (seconds)
    #[serde(default = "default_budget_window_secs")]
    pub budget_window_secs: u64,

    /// Only hedge safe (idempotent) methods
    #[serde(default = "default_true_val")]
    pub safe_methods_only: bool,

    /// HTTP status codes that indicate success
    #[serde(default = "default_success_codes")]
    pub success_codes: Vec<u16>,

    /// HTTP status codes that should trigger hedging
    #[serde(default = "default_hedgeable_codes")]
    pub hedgeable_codes: Vec<u16>,
}

fn default_hedge_delay() -> u64 {
    100
}

fn default_max_hedges() -> usize {
    2
}

fn default_hedge_budget_percent() -> f64 {
    10.0
}

fn default_budget_window_secs() -> u64 {
    60
}

fn default_true_val() -> bool {
    true
}

fn default_success_codes() -> Vec<u16> {
    vec![200, 201, 202, 204, 301, 302, 304]
}

fn default_hedgeable_codes() -> Vec<u16> {
    vec![408, 429, 500, 502, 503, 504]
}

/// Adaptive concurrency configuration for config file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptiveConcurrencyConfigDef {
    /// Whether adaptive concurrency is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Initial concurrency limit
    #[serde(default = "default_initial_limit")]
    pub initial_limit: usize,

    /// Minimum concurrency limit
    #[serde(default = "default_min_limit")]
    pub min_limit: usize,

    /// Maximum concurrency limit
    #[serde(default = "default_max_limit")]
    pub max_limit: usize,

    /// Algorithm: "gradient", "aimd", "vegas", "fixed"
    #[serde(default)]
    pub algorithm: String,

    /// Smoothing factor for exponential moving average (0.0 - 1.0)
    #[serde(default = "default_smoothing")]
    pub smoothing: f64,

    /// Window size for latency measurements
    #[serde(default = "default_window_size")]
    pub window_size: usize,

    /// Tolerance for latency increase before reducing limit
    #[serde(default = "default_latency_tolerance")]
    pub latency_tolerance: f64,

    /// How often to recalculate limits (milliseconds)
    #[serde(default = "default_adjustment_interval_ms")]
    pub adjustment_interval_ms: u64,

    /// Timeout waiting for a permit (milliseconds)
    #[serde(default = "default_permit_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_initial_limit() -> usize {
    100
}

fn default_min_limit() -> usize {
    10
}

fn default_max_limit() -> usize {
    1000
}

fn default_smoothing() -> f64 {
    0.2
}

fn default_window_size() -> usize {
    100
}

fn default_latency_tolerance() -> f64 {
    1.5
}

fn default_adjustment_interval_ms() -> u64 {
    1000
}

fn default_permit_timeout_ms() -> u64 {
    5000
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Requests per second
    pub requests_per_second: u32,

    /// Burst size
    #[serde(default = "default_burst")]
    pub burst: u32,

    /// Key extractor (ip, header, etc.)
    #[serde(default)]
    pub key_by: RateLimitKey,
}

fn default_burst() -> u32 {
    10
}

/// Rate limit key extraction method
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitKey {
    #[default]
    Ip,
    Header(String),
    Global,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Auth type
    #[serde(rename = "type")]
    pub auth_type: AuthType,

    /// JWKS URL for JWT validation
    pub jwks_url: Option<String>,

    /// Header name for API key auth
    pub header: Option<String>,

    /// Valid API keys
    pub api_keys: Option<Vec<String>>,
}

/// Authentication types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Jwt,
    ApiKey,
    Basic,
}

/// Header manipulation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadersConfig {
    /// Headers to add to request
    #[serde(default)]
    pub request_add: HashMap<String, String>,

    /// Headers to remove from request
    #[serde(default)]
    pub request_remove: Vec<String>,

    /// Headers to add to response
    #[serde(default)]
    pub response_add: HashMap<String, String>,

    /// Headers to remove from response
    #[serde(default)]
    pub response_remove: Vec<String>,
}

/// Compression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionConfig {
    /// Enable gzip compression
    #[serde(default = "default_true")]
    pub gzip: bool,

    /// Enable brotli compression
    #[serde(default)]
    pub brotli: bool,

    /// Minimum size to compress
    #[serde(default = "default_min_compress_size")]
    pub min_size: usize,
}

fn default_true() -> bool {
    true
}

fn default_min_compress_size() -> usize {
    1024
}

/// Timeout configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutConfig {
    /// Connect timeout
    #[serde(default = "default_connect_timeout", with = "humantime_serde")]
    pub connect: Duration,

    /// Read timeout
    #[serde(default = "default_request_timeout", with = "humantime_serde")]
    pub read: Duration,

    /// Write timeout
    #[serde(default = "default_request_timeout", with = "humantime_serde")]
    pub write: Duration,
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to open circuit
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,

    /// Success threshold to close circuit
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,

    /// Half-open timeout
    #[serde(default = "default_half_open_timeout", with = "humantime_serde")]
    pub half_open_timeout: Duration,
}

fn default_failure_threshold() -> u32 {
    5
}

fn default_success_threshold() -> u32 {
    3
}

fn default_half_open_timeout() -> Duration {
    Duration::from_secs(30)
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryConfig {
    /// Maximum retry attempts
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Retry on these status codes
    #[serde(default = "default_retry_on")]
    pub retry_on: Vec<u16>,

    /// Initial retry delay
    #[serde(default = "default_retry_delay", with = "humantime_serde")]
    pub initial_delay: Duration,

    /// Maximum retry delay
    #[serde(default = "default_max_retry_delay", with = "humantime_serde")]
    pub max_delay: Duration,
}

fn default_max_retries() -> u32 {
    3
}

fn default_retry_on() -> Vec<u16> {
    vec![502, 503, 504]
}

fn default_retry_delay() -> Duration {
    Duration::from_millis(100)
}

fn default_max_retry_delay() -> Duration {
    Duration::from_secs(5)
}

/// Observability configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    /// Metrics configuration
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Tracing configuration
    #[serde(default)]
    pub tracing: TracingConfig,

    /// Access log configuration
    #[serde(default)]
    pub access_log: AccessLogConfig,
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Enable metrics endpoint
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Metrics endpoint path
    #[serde(default = "default_metrics_path")]
    pub path: String,

    /// Include per-route metrics
    #[serde(default = "default_true")]
    pub per_route: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_metrics_path(),
            per_route: true,
        }
    }
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

/// Tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TracingConfig {
    /// Enable distributed tracing
    #[serde(default)]
    pub enabled: bool,

    /// Service name for tracing
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Tracing exporter type
    #[serde(default)]
    pub exporter: TracingExporter,

    /// Exporter endpoint (OTLP endpoint)
    #[serde(default = "default_tracing_endpoint")]
    pub endpoint: String,

    /// Sample rate (0.0 - 1.0)
    #[serde(default = "default_sample_rate_f32")]
    pub sample_rate: f32,

    /// Propagate trace context to upstream
    #[serde(default = "default_true")]
    pub propagate: bool,
}

fn default_service_name() -> String {
    "prism".to_string()
}

fn default_tracing_endpoint() -> String {
    "http://localhost:4317".to_string()
}

fn default_sample_rate_f32() -> f32 {
    1.0
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            service_name: default_service_name(),
            exporter: TracingExporter::default(),
            endpoint: default_tracing_endpoint(),
            sample_rate: default_sample_rate_f32(),
            propagate: true,
        }
    }
}

#[allow(dead_code)]
fn default_sample_rate() -> f64 {
    1.0
}

/// Tracing exporter types
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TracingExporter {
    #[default]
    Jaeger,
    Otlp,
    Zipkin,
}

/// Access log configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessLogConfig {
    /// Enable access logging
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Log format
    #[serde(default)]
    pub format: LogFormat,

    /// Log file path (stdout if not specified)
    pub path: Option<PathBuf>,
}

impl Default for AccessLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            format: LogFormat::default(),
            path: None,
        }
    }
}

/// Access log formats
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Json,
    Combined,
    Common,
}

/// Admin API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Admin API bind address
    pub address: String,

    /// Enable authentication
    #[serde(default)]
    pub auth_enabled: bool,

    /// Admin API key
    pub api_key: Option<String>,
}

/// Global settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalConfig {
    /// Worker threads (defaults to CPU count)
    pub worker_threads: Option<usize>,

    /// Maximum request body size
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Graceful shutdown timeout
    #[serde(default = "default_shutdown_timeout", with = "humantime_serde")]
    pub shutdown_timeout: Duration,

    /// Enable HTTP/2 by default
    #[serde(default = "default_true")]
    pub http2: bool,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            worker_threads: None,
            max_body_size: default_max_body_size(),
            shutdown_timeout: default_shutdown_timeout(),
            http2: true,
        }
    }
}

fn default_max_body_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

fn default_shutdown_timeout() -> Duration {
    Duration::from_secs(30)
}

/// Helper module for humantime serde
mod humantime_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = humantime::format_duration(*duration).to_string();
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        humantime::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

// ============================================
// Next-Gen Feature Configuration Types
// ============================================

/// SPIFFE/SPIRE configuration for config file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpiffeConfigDef {
    /// Enable SPIFFE integration
    #[serde(default)]
    pub enabled: bool,

    /// Workload API socket path
    #[serde(default = "default_spiffe_socket")]
    pub workload_api_socket: String,

    /// Trust domain
    #[serde(default = "default_trust_domain")]
    pub trust_domain: String,

    /// Workload path component
    #[serde(default = "default_workload_path")]
    pub workload_path: String,

    /// Enable mTLS with SVID
    #[serde(default = "default_true")]
    pub mtls_enabled: bool,

    /// SVID refresh interval (seconds)
    #[serde(default = "default_svid_refresh")]
    pub refresh_interval_secs: u64,

    /// Allowed trust domains for incoming connections
    #[serde(default)]
    pub allowed_trust_domains: Vec<String>,

    /// Authorization rules
    #[serde(default)]
    pub authorization_rules: Vec<SpiffeAuthRuleDef>,
}

fn default_spiffe_socket() -> String {
    "unix:///tmp/spire-agent/public/api.sock".to_string()
}

fn default_trust_domain() -> String {
    "example.org".to_string()
}

fn default_workload_path() -> String {
    "/prism/proxy".to_string()
}

fn default_svid_refresh() -> u64 {
    300
}

/// SPIFFE authorization rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpiffeAuthRuleDef {
    /// Rule name
    pub name: String,
    /// SPIFFE ID patterns to match
    pub spiffe_ids: Vec<String>,
    /// Paths this rule applies to
    #[serde(default)]
    pub paths: Vec<String>,
    /// HTTP methods
    #[serde(default)]
    pub methods: Vec<String>,
    /// Action: "allow" or "deny"
    #[serde(default = "default_allow")]
    pub action: String,
}

fn default_allow() -> String {
    "allow".to_string()
}

/// io_uring configuration for config file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IoUringConfigDef {
    /// Enable io_uring (Linux 5.1+ only)
    #[serde(default)]
    pub enabled: bool,

    /// Submission queue depth
    #[serde(default = "default_sq_depth")]
    pub sq_depth: u32,

    /// Completion queue depth (0 = 2x sq_depth)
    #[serde(default)]
    pub cq_depth: u32,

    /// Enable kernel polling (SQPOLL)
    #[serde(default)]
    pub kernel_poll: bool,

    /// Enable fixed buffers for zero-copy
    #[serde(default = "default_true")]
    pub fixed_buffers: bool,

    /// Number of fixed buffers
    #[serde(default = "default_num_buffers")]
    pub num_buffers: usize,

    /// Size of each buffer (bytes)
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Enable registered file descriptors
    #[serde(default = "default_true")]
    pub registered_fds: bool,
}

fn default_sq_depth() -> u32 {
    4096
}

fn default_num_buffers() -> usize {
    1024
}

fn default_buffer_size() -> usize {
    4096
}

/// xDS API configuration for config file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XdsConfigDef {
    /// Enable xDS client
    #[serde(default)]
    pub enabled: bool,

    /// xDS server address (e.g., "xds://control-plane:15010")
    pub server_address: Option<String>,

    /// Node ID for this proxy
    #[serde(default = "default_node_id")]
    pub node_id: String,

    /// Cluster name
    #[serde(default = "default_cluster_name")]
    pub cluster: String,

    /// Use ADS (Aggregated Discovery Service)
    #[serde(default = "default_true")]
    pub use_ads: bool,

    /// Initial fetch timeout (seconds)
    #[serde(default = "default_xds_timeout")]
    pub initial_fetch_timeout_secs: u64,

    /// Resource types to subscribe to
    #[serde(default = "default_xds_resources")]
    pub resource_types: Vec<String>,
}

fn default_node_id() -> String {
    "prism-proxy".to_string()
}

fn default_cluster_name() -> String {
    "default".to_string()
}

fn default_xds_timeout() -> u64 {
    15
}

fn default_xds_resources() -> Vec<String> {
    vec![
        "listener".to_string(),
        "route".to_string(),
        "cluster".to_string(),
        "endpoint".to_string(),
    ]
}

/// Kubernetes Gateway API configuration for config file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesConfigDef {
    /// Enable Kubernetes Gateway API controller
    #[serde(default)]
    pub enabled: bool,

    /// Gateway class name to watch
    #[serde(default = "default_gateway_class")]
    pub gateway_class_name: String,

    /// Kubernetes namespace to watch (empty = all namespaces)
    #[serde(default)]
    pub namespace: String,

    /// Controller name
    #[serde(default = "default_controller_name")]
    pub controller_name: String,

    /// Enable leader election for HA
    #[serde(default)]
    pub leader_election: bool,

    /// Status update interval (seconds)
    #[serde(default = "default_status_interval")]
    pub status_update_interval_secs: u64,
}

fn default_gateway_class() -> String {
    "prism".to_string()
}

fn default_controller_name() -> String {
    "prism.io/gateway-controller".to_string()
}

fn default_status_interval() -> u64 {
    30
}

/// Edge compute configuration for config file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfigDef {
    /// Enable edge compute
    #[serde(default)]
    pub enabled: bool,

    /// Maximum concurrent functions
    #[serde(default = "default_max_functions")]
    pub max_concurrent_functions: usize,

    /// Function timeout (milliseconds)
    #[serde(default = "default_function_timeout")]
    pub timeout_ms: u64,

    /// Memory limit per function (bytes)
    #[serde(default = "default_function_memory")]
    pub memory_limit: usize,

    /// CPU time limit per request (milliseconds)
    #[serde(default = "default_cpu_time")]
    pub cpu_time_limit_ms: u64,

    /// Enable KV storage
    #[serde(default)]
    pub kv_enabled: bool,

    /// KV namespace configurations
    #[serde(default)]
    pub kv_namespaces: Vec<KvNamespaceConfigDef>,

    /// Edge function routes
    #[serde(default)]
    pub functions: Vec<EdgeFunctionDef>,
}

fn default_max_functions() -> usize {
    100
}

fn default_function_timeout() -> u64 {
    30000
}

fn default_function_memory() -> usize {
    128 * 1024 * 1024 // 128MB
}

fn default_cpu_time() -> u64 {
    50
}

/// KV namespace configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvNamespaceConfigDef {
    /// Namespace name
    pub name: String,
    /// Maximum entries
    #[serde(default = "default_kv_max_entries")]
    pub max_entries: usize,
    /// Maximum key size (bytes)
    #[serde(default = "default_kv_key_size")]
    pub max_key_size: usize,
    /// Maximum value size (bytes)
    #[serde(default = "default_kv_value_size")]
    pub max_value_size: usize,
}

fn default_kv_max_entries() -> usize {
    10000
}

fn default_kv_key_size() -> usize {
    512
}

fn default_kv_value_size() -> usize {
    25 * 1024 * 1024 // 25MB
}

/// Edge function definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeFunctionDef {
    /// Function name
    pub name: String,
    /// Path to WASM module
    pub wasm_path: PathBuf,
    /// Routes that trigger this function
    pub routes: Vec<String>,
    /// Environment variables
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// WASM plugin configuration for config file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginConfigDef {
    /// Enable plugin system
    #[serde(default)]
    pub enabled: bool,

    /// Plugin directory
    #[serde(default = "default_plugin_dir")]
    pub plugin_dir: PathBuf,

    /// Maximum memory per plugin (bytes)
    #[serde(default = "default_plugin_memory")]
    pub max_memory: usize,

    /// Maximum execution time (milliseconds)
    #[serde(default = "default_plugin_timeout")]
    pub max_execution_time_ms: u64,

    /// Plugins to load
    #[serde(default)]
    pub plugins: Vec<PluginDef>,
}

fn default_plugin_dir() -> PathBuf {
    PathBuf::from("/etc/prism/plugins")
}

fn default_plugin_memory() -> usize {
    64 * 1024 * 1024 // 64MB
}

fn default_plugin_timeout() -> u64 {
    100
}

/// Individual plugin definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginDef {
    /// Plugin name
    pub name: String,
    /// Path to WASM file
    pub path: PathBuf,
    /// Plugin configuration (JSON)
    #[serde(default)]
    pub config: HashMap<String, serde_json::Value>,
    /// Execution phases
    #[serde(default = "default_plugin_phases")]
    pub phases: Vec<String>,
    /// Priority (lower = earlier)
    #[serde(default)]
    pub priority: i32,
}

fn default_plugin_phases() -> Vec<String> {
    vec!["request".to_string(), "response".to_string()]
}

/// HTTP/3 configuration for config file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http3ConfigDef {
    /// Enable HTTP/3
    #[serde(default)]
    pub enabled: bool,

    /// UDP port for QUIC (usually same as HTTPS port)
    pub port: Option<u16>,

    /// Maximum concurrent streams
    #[serde(default = "default_max_streams")]
    pub max_concurrent_streams: u32,

    /// Initial stream window size
    #[serde(default = "default_stream_window")]
    pub initial_stream_window_size: u32,

    /// Initial connection window size
    #[serde(default = "default_conn_window")]
    pub initial_connection_window_size: u32,

    /// Enable 0-RTT
    #[serde(default)]
    pub enable_0rtt: bool,

    /// Max idle timeout (seconds)
    #[serde(default = "default_h3_idle_timeout")]
    pub max_idle_timeout_secs: u64,

    /// Advertise via Alt-Svc header
    #[serde(default = "default_true")]
    pub advertise_alt_svc: bool,
}

fn default_max_streams() -> u32 {
    100
}

fn default_stream_window() -> u32 {
    1024 * 1024 // 1MB
}

fn default_conn_window() -> u32 {
    10 * 1024 * 1024 // 10MB
}

fn default_h3_idle_timeout() -> u64 {
    30
}

/// AI anomaly detection configuration for config file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnomalyConfigDef {
    /// Enable anomaly detection
    #[serde(default)]
    pub enabled: bool,

    /// Z-score threshold for anomaly detection
    #[serde(default = "default_zscore_threshold")]
    pub zscore_threshold: f64,

    /// Minimum samples before detection starts
    #[serde(default = "default_min_samples")]
    pub min_samples: usize,

    /// Rolling window size for statistics
    #[serde(default = "default_rolling_window")]
    pub rolling_window_size: usize,

    /// Alert cooldown period (seconds)
    #[serde(default = "default_alert_cooldown")]
    pub alert_cooldown_secs: u64,

    /// Features to monitor
    #[serde(default)]
    pub features: AnomalyFeaturesDef,

    /// Webhook URL for alerts
    pub webhook_url: Option<String>,
}

fn default_zscore_threshold() -> f64 {
    3.0
}

fn default_min_samples() -> usize {
    100
}

fn default_rolling_window() -> usize {
    1000
}

fn default_alert_cooldown() -> u64 {
    300
}

/// Anomaly detection features configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnomalyFeaturesDef {
    /// Monitor latency anomalies
    #[serde(default = "default_true")]
    pub latency: bool,
    /// Monitor error rate anomalies
    #[serde(default = "default_true")]
    pub error_rate: bool,
    /// Monitor request rate anomalies
    #[serde(default = "default_true")]
    pub request_rate: bool,
    /// Monitor response size anomalies
    #[serde(default)]
    pub response_size: bool,
    /// Enable bot detection
    #[serde(default = "default_true")]
    pub user_agent: bool,
    /// Monitor geographic distribution
    #[serde(default)]
    pub geo_distribution: bool,
}

/// eBPF observability configuration for config file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EbpfConfigDef {
    /// Enable eBPF (Linux 4.9+ only, requires CAP_BPF)
    #[serde(default)]
    pub enabled: bool,

    /// Track TCP connection states
    #[serde(default = "default_true")]
    pub track_tcp_states: bool,

    /// Collect socket-level metrics
    #[serde(default = "default_true")]
    pub socket_metrics: bool,

    /// Track per-connection latency
    #[serde(default = "default_true")]
    pub connection_latency: bool,

    /// Enable flow tracking
    #[serde(default)]
    pub flow_tracking: bool,

    /// Histogram buckets for latency (microseconds)
    #[serde(default = "default_latency_buckets")]
    pub latency_buckets: Vec<u64>,
}

fn default_latency_buckets() -> Vec<u64> {
    vec![10, 50, 100, 250, 500, 1000, 2500, 5000, 10000]
}

/// GraphQL configuration for config file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphQLConfigDef {
    /// Enable GraphQL-aware routing
    #[serde(default)]
    pub enabled: bool,

    /// GraphQL endpoint path
    #[serde(default = "default_graphql_path")]
    pub path: String,

    /// Maximum query depth
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,

    /// Maximum query complexity
    #[serde(default = "default_max_complexity")]
    pub max_complexity: usize,

    /// Block introspection queries
    #[serde(default)]
    pub block_introspection: bool,

    /// Operation-specific routing
    #[serde(default)]
    pub operation_routing: Vec<GraphQLOperationRouteDef>,

    /// Cache query results
    #[serde(default)]
    pub cache_enabled: bool,

    /// Cache TTL (seconds)
    #[serde(default = "default_graphql_cache_ttl")]
    pub cache_ttl_secs: u64,
}

fn default_graphql_path() -> String {
    "/graphql".to_string()
}

fn default_max_depth() -> usize {
    10
}

fn default_max_complexity() -> usize {
    1000
}

fn default_graphql_cache_ttl() -> u64 {
    60
}

/// GraphQL operation routing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphQLOperationRouteDef {
    /// Operation name pattern (supports wildcards)
    pub operation: String,
    /// Operation type: "query", "mutation", "subscription"
    #[serde(default)]
    pub operation_type: Option<String>,
    /// Target upstream
    pub upstream: String,
    /// Rate limit for this operation
    #[serde(default)]
    pub rate_limit: Option<u32>,
}
