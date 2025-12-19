//! Middleware module for request/response processing
//!
//! Implements a Tower-inspired middleware chain with support for:
//! - Authentication (JWT, API Key, Basic)
//! - Rate limiting
//! - Header manipulation
//! - Timeout handling
//! - Circuit breaker
//! - Retry policies

mod auth;
mod body_limit;
mod cache;
mod chain;
mod chaos;
mod compression;
mod concurrency;
mod cors;
mod headers;
mod hedging;
mod ip_filter;
mod rate_limit;
mod rate_limit_distributed;
mod request_id;
mod retry;
mod rewrite;
mod timeout;

pub use auth::{AuthMiddleware, AuthMiddlewareConfig, AuthResult, Jwk, Jwks, JwtClaims};
pub use body_limit::{
    BodyLimitConfig, BodyLimitExceeded, BodyLimitMiddleware, LimitedBody, LimitedBodyError,
    DEFAULT_MAX_BODY_SIZE,
};
pub use cache::{CacheConfig, CacheEntry, CacheMiddleware, CacheStats, ResponseCache};
pub use chain::*;
pub use chaos::{
    AbortConfig, AbortTiming, ChaosConfig, ChaosMiddleware, ChaosStats, CorruptionConfig,
    CorruptionType, ErrorConfig, LatencyConfig, LatencyDistribution, ThrottleConfig,
};
pub use compression::{CompressionAlgorithm, CompressionMiddleware};
pub use concurrency::{
    AdaptiveConcurrencyConfig, AdaptiveConcurrencyMiddleware, AdaptiveLimiter,
    AdaptiveLimiterBuilder, ConcurrencyAlgorithm, ConcurrencyStatsSnapshot,
};
pub use cors::{CorsConfig, CorsMiddleware};
pub use headers::HeadersMiddleware;
pub use hedging::{
    HedgingBudget, HedgingConfig, HedgingMiddleware, HedgingStats, LatencyStats, LatencyTracker,
    SpeculativeHedgingConfig,
};
pub use ip_filter::{common_ranges, IpFilterAction, IpFilterConfig, IpFilterMiddleware, IpRange};
pub use rate_limit::RateLimiter;
pub use rate_limit_distributed::{
    DistributedRateLimitConfig, DistributedRateLimiter, RateLimitInfo,
};
pub use request_id::{
    extract_request_id, RequestIdConfig, RequestIdGenerator, RequestIdMiddleware, X_CORRELATION_ID,
    X_REQUEST_ID, X_TRACE_ID,
};
pub use retry::{RetryMiddleware, RetryPolicy};
pub use rewrite::{path_utils, RewriteConfig, RewriteMiddleware, RewriteRule};
pub use timeout::{CircuitBreaker, CircuitState, TimeoutMiddleware};

use crate::config::MiddlewareConfig;
use crate::error::Result;
use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Type alias for the response body type
pub type BoxBody = Full<Bytes>;

/// A body type that can be either streaming (Incoming) or buffered (Full<Bytes>)
/// This allows middleware to work with both original requests and reconstructed ones
pub enum ProxyBody {
    /// Streaming body from incoming connection
    Streaming(Incoming),
    /// Buffered body that has been read
    Buffered(Full<Bytes>),
}

impl ProxyBody {
    /// Create a new buffered body from bytes
    pub fn buffered(bytes: Bytes) -> Self {
        ProxyBody::Buffered(Full::new(bytes))
    }

    /// Create a new empty body
    pub fn empty() -> Self {
        ProxyBody::Buffered(Full::new(Bytes::new()))
    }
}

impl From<Incoming> for ProxyBody {
    fn from(body: Incoming) -> Self {
        ProxyBody::Streaming(body)
    }
}

impl From<Full<Bytes>> for ProxyBody {
    fn from(body: Full<Bytes>) -> Self {
        ProxyBody::Buffered(body)
    }
}

impl From<Bytes> for ProxyBody {
    fn from(bytes: Bytes) -> Self {
        ProxyBody::Buffered(Full::new(bytes))
    }
}

impl Body for ProxyBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            ProxyBody::Streaming(body) => Pin::new(body).poll_frame(cx),
            ProxyBody::Buffered(body) => Pin::new(body)
                .poll_frame(cx)
                .map(|opt| opt.map(|res| res.map_err(|_| unreachable!()))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ProxyBody::Streaming(body) => body.is_end_stream(),
            ProxyBody::Buffered(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            ProxyBody::Streaming(body) => body.size_hint(),
            ProxyBody::Buffered(body) => body.size_hint(),
        }
    }
}

/// Type alias for HTTP request with our body type
pub type HttpRequest = Request<ProxyBody>;

/// Type alias for HTTP response with our body type
pub type HttpResponse = Response<BoxBody>;

/// Context passed through the middleware chain
#[derive(Clone)]
pub struct RequestContext {
    /// Unique request ID
    pub request_id: String,
    /// Client IP address
    pub client_ip: Option<String>,
    /// Start time of the request
    pub start_time: std::time::Instant,
    /// Upstream name (if resolved)
    pub upstream: Option<String>,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
}

impl RequestContext {
    /// Create a new request context
    pub fn new() -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            client_ip: None,
            start_time: std::time::Instant::now(),
            upstream: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Create context with client IP
    pub fn with_client_ip(mut self, ip: String) -> Self {
        self.client_ip = Some(ip);
        self
    }

    /// Get elapsed time since request start
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}

/// The next handler in the middleware chain
#[async_trait]
pub trait Next: Send + Sync {
    /// Call the next handler
    async fn run(&self, request: HttpRequest, ctx: RequestContext) -> Result<HttpResponse>;
}

/// Middleware trait for processing requests and responses
#[async_trait]
pub trait Middleware: Send + Sync {
    /// Process a request, optionally calling the next handler
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse>;

    /// Get the name of this middleware for logging
    fn name(&self) -> &'static str;
}

/// Create middleware from configuration
pub fn create_middleware(config: &MiddlewareConfig) -> Result<Vec<Arc<dyn Middleware>>> {
    let mut middlewares: Vec<Arc<dyn Middleware>> = Vec::new();

    // Chaos engineering (should be very early for fault injection)
    if let Some(chaos_config) = &config.chaos {
        let chaos = create_chaos_config(chaos_config);
        middlewares.push(Arc::new(ChaosMiddleware::new(chaos)));
    }

    // Authentication (should be very early in the chain)
    if let Some(auth_config) = &config.auth {
        middlewares.push(Arc::new(AuthMiddleware::from_config(auth_config)));
    }

    // CORS (should be early in the chain for preflight handling)
    if let Some(cors_config) = &config.cors {
        let cors = CorsConfig {
            allowed_origins: cors_config.allowed_origins.clone(),
            allowed_methods: cors_config.allowed_methods.clone(),
            allowed_headers: cors_config.allowed_headers.clone(),
            expose_headers: cors_config.expose_headers.clone(),
            allow_credentials: cors_config.allow_credentials,
            max_age: cors_config.max_age,
        };
        middlewares.push(Arc::new(CorsMiddleware::new(cors)));
    }

    // Rate limiting
    if let Some(rate_config) = &config.rate_limit {
        middlewares.push(Arc::new(RateLimiter::new(rate_config)?));
    }

    // Header manipulation
    if let Some(headers_config) = &config.headers {
        middlewares.push(Arc::new(HeadersMiddleware::new(headers_config)));
    }

    // Timeout
    if let Some(timeout_config) = &config.timeout {
        middlewares.push(Arc::new(TimeoutMiddleware::new(timeout_config)));
    }

    // Compression (should be late in the chain to compress final response)
    if let Some(compression_config) = &config.compression {
        middlewares.push(Arc::new(CompressionMiddleware::new(compression_config)));
    }

    // Request hedging (should be early to hedge entire middleware chain)
    if let Some(hedging_config) = &config.hedging {
        let hedging = create_hedging_config(hedging_config);
        middlewares.insert(0, Arc::new(HedgingMiddleware::new(hedging)));
    }

    // Adaptive concurrency (should be early to limit requests)
    if let Some(concurrency_config) = &config.adaptive_concurrency {
        let concurrency = create_concurrency_config(concurrency_config);
        middlewares.insert(0, Arc::new(AdaptiveConcurrencyMiddleware::new(concurrency)));
    }

    Ok(middlewares)
}

/// Helper to convert config definition to chaos config
fn create_chaos_config(def: &crate::config::ChaosConfigDef) -> ChaosConfig {
    let latency = def.latency.as_ref().map(|l| LatencyConfig {
        percentage: l.percentage,
        fixed: l
            .fixed
            .as_ref()
            .and_then(|s| humantime::parse_duration(s).ok()),
        min: l
            .min
            .as_ref()
            .and_then(|s| humantime::parse_duration(s).ok()),
        max: l
            .max
            .as_ref()
            .and_then(|s| humantime::parse_duration(s).ok()),
        distribution: match l.distribution.as_str() {
            "normal" => LatencyDistribution::Normal,
            "exponential" => LatencyDistribution::Exponential,
            "pareto" => LatencyDistribution::Pareto,
            _ => LatencyDistribution::Uniform,
        },
    });

    let error = def.error.as_ref().map(|e| ErrorConfig {
        percentage: e.percentage,
        status: e.status,
        message: if e.message.is_empty() {
            "Chaos Engineering: Injected Error".to_string()
        } else {
            e.message.clone()
        },
        headers: e.headers.clone(),
        grpc_status: e.grpc_status,
    });

    let abort = def.abort.as_ref().map(|a| AbortConfig {
        percentage: a.percentage,
        timing: match a.timing.as_str() {
            "during_request" => AbortTiming::DuringRequest,
            "before_response" => AbortTiming::BeforeResponse,
            _ => AbortTiming::BeforeRequest,
        },
    });

    let corruption = def.corruption.as_ref().map(|c| CorruptionConfig {
        percentage: c.percentage,
        corruption_type: match c.corruption_type.as_str() {
            "bit_flip" => CorruptionType::BitFlip,
            "replace" => CorruptionType::Replace,
            "duplicate" => CorruptionType::Duplicate,
            _ => CorruptionType::Truncate,
        },
        truncate_percentage: c.truncate_percentage,
        bit_flips: c.bit_flips,
    });

    let throttle = def.throttle.as_ref().map(|t| ThrottleConfig {
        percentage: t.percentage,
        bandwidth_bps: t.bandwidth_bps,
    });

    ChaosConfig {
        enabled: def.enabled,
        latency,
        error,
        abort,
        corruption,
        throttle,
        target_paths: def.target_paths.clone(),
        target_methods: def.target_methods.clone(),
        target_headers: def.target_headers.clone(),
    }
}

/// Helper to convert config definition to hedging config
fn create_hedging_config(def: &crate::config::HedgingConfigDef) -> HedgingConfig {
    HedgingConfig {
        enabled: def.enabled,
        delay_ms: def.delay_ms,
        max_hedges: def.max_hedges,
        budget_percent: def.budget_percent,
        budget_window_secs: def.budget_window_secs,
        safe_methods_only: def.safe_methods_only,
        success_codes: def.success_codes.clone(),
        hedgeable_codes: def.hedgeable_codes.clone(),
    }
}

/// Helper to convert config definition to adaptive concurrency config
fn create_concurrency_config(
    def: &crate::config::AdaptiveConcurrencyConfigDef,
) -> AdaptiveConcurrencyConfig {
    AdaptiveConcurrencyConfig {
        enabled: def.enabled,
        initial_limit: def.initial_limit,
        min_limit: def.min_limit,
        max_limit: def.max_limit,
        algorithm: match def.algorithm.as_str() {
            "aimd" => ConcurrencyAlgorithm::Aimd,
            "vegas" => ConcurrencyAlgorithm::Vegas,
            "fixed" => ConcurrencyAlgorithm::Fixed,
            _ => ConcurrencyAlgorithm::Gradient,
        },
        smoothing: def.smoothing,
        window_size: def.window_size,
        latency_tolerance: def.latency_tolerance,
        adjustment_interval_ms: def.adjustment_interval_ms,
        timeout_ms: def.timeout_ms,
    }
}

/// Build a middleware chain from configurations
pub fn build_middleware_chain(configs: &[MiddlewareConfig]) -> Result<Vec<Arc<dyn Middleware>>> {
    let mut all_middlewares = Vec::new();

    for config in configs {
        let middlewares = create_middleware(config)?;
        all_middlewares.extend(middlewares);
    }

    Ok(all_middlewares)
}
