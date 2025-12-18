//! Error types for Prism reverse proxy

use std::io;
use thiserror::Error;

/// Result type alias for Prism operations
pub type Result<T> = std::result::Result<T, PrismError>;

/// Main error type for Prism
#[derive(Error, Debug)]
pub enum PrismError {
    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Configuration file parsing errors
    #[error("Failed to parse configuration: {0}")]
    ConfigParse(String),

    /// Configuration validation errors
    #[error("Configuration validation failed: {0}")]
    ConfigValidation(String),

    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// TLS configuration errors
    #[error("TLS error: {0}")]
    Tls(String),

    /// Certificate loading errors
    #[error("Certificate error: {0}")]
    Certificate(String),

    /// Routing errors
    #[error("Routing error: {0}")]
    Routing(String),

    /// No matching route found
    #[error("No route found for request")]
    NoRoute,

    /// Upstream connection errors
    #[error("Upstream error: {0}")]
    Upstream(String),

    /// Connection pool errors
    #[error("Connection pool error: {0}")]
    Pool(String),

    /// Health check errors
    #[error("Health check error: {0}")]
    HealthCheck(String),

    /// All upstreams are unhealthy
    #[error("No healthy upstreams available for: {0}")]
    NoHealthyUpstreams(String),

    /// Middleware errors
    #[error("Middleware error: {0}")]
    Middleware(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Request timeout
    #[error("Request timeout")]
    Timeout,

    /// HTTP protocol errors
    #[error("HTTP error: {0}")]
    Http(String),

    /// Hyper errors
    #[error("Hyper error: {0}")]
    Hyper(String),

    /// Invalid request
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Server shutdown
    #[error("Server is shutting down")]
    Shutdown,

    /// Internal server error
    #[error("Internal error: {0}")]
    Internal(String),

    /// WebSocket errors
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    /// Authentication errors
    #[error("Authentication error: {0}")]
    Auth(String),

    /// Circuit breaker open
    #[error("Circuit breaker open for: {0}")]
    CircuitBreakerOpen(String),

    /// Chaos engineering injected failure
    #[error("Chaos injection: {0}")]
    Chaos(String),
}

impl From<hyper::Error> for PrismError {
    fn from(err: hyper::Error) -> Self {
        PrismError::Hyper(err.to_string())
    }
}

impl From<rustls::Error> for PrismError {
    fn from(err: rustls::Error) -> Self {
        PrismError::Tls(err.to_string())
    }
}

impl From<serde_yaml::Error> for PrismError {
    fn from(err: serde_yaml::Error) -> Self {
        PrismError::ConfigParse(err.to_string())
    }
}

impl From<toml::de::Error> for PrismError {
    fn from(err: toml::de::Error) -> Self {
        PrismError::ConfigParse(err.to_string())
    }
}

impl From<regex::Error> for PrismError {
    fn from(err: regex::Error) -> Self {
        PrismError::Routing(format!("Invalid regex pattern: {}", err))
    }
}

/// Error response that can be converted to HTTP response
#[derive(Debug, Clone)]
pub struct ErrorResponse {
    pub status: u16,
    pub message: String,
}

impl From<&PrismError> for ErrorResponse {
    fn from(err: &PrismError) -> Self {
        match err {
            PrismError::NoRoute => ErrorResponse {
                status: 404,
                message: "Not Found".to_string(),
            },
            PrismError::RateLimitExceeded => ErrorResponse {
                status: 429,
                message: "Too Many Requests".to_string(),
            },
            PrismError::Timeout => ErrorResponse {
                status: 504,
                message: "Gateway Timeout".to_string(),
            },
            PrismError::NoHealthyUpstreams(_) => ErrorResponse {
                status: 503,
                message: "Service Unavailable".to_string(),
            },
            PrismError::InvalidRequest(msg) => ErrorResponse {
                status: 400,
                message: msg.clone(),
            },
            PrismError::Auth(_) => ErrorResponse {
                status: 401,
                message: "Unauthorized".to_string(),
            },
            PrismError::CircuitBreakerOpen(_) => ErrorResponse {
                status: 503,
                message: "Service Unavailable".to_string(),
            },
            _ => ErrorResponse {
                status: 502,
                message: "Bad Gateway".to_string(),
            },
        }
    }
}
