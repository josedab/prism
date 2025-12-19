//! Request body size limit middleware
//!
//! Enforces maximum request body size to prevent memory exhaustion attacks.
//! Returns 413 Payload Too Large when limits are exceeded.
//!
//! Supports both:
//! - Early rejection based on Content-Length header
//! - Streaming body limit enforcement during consumption

use super::{HttpRequest, HttpResponse, Middleware, Next, ProxyBody, RequestContext};
use crate::error::Result;
use async_trait::async_trait;
use bytes::Bytes;
use http::{header, Response, StatusCode};
use http_body_util::Full;
use hyper::body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tracing::{debug, warn};

/// Default maximum body size (10 MB)
pub const DEFAULT_MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Error returned when body size limit is exceeded during streaming
#[derive(Debug, Clone)]
pub struct BodyLimitExceeded {
    /// Maximum allowed size
    pub max_size: usize,
    /// Size when limit was exceeded
    pub actual_size: usize,
}

impl std::fmt::Display for BodyLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Body size limit exceeded: {} bytes exceeds maximum of {} bytes",
            self.actual_size, self.max_size
        )
    }
}

impl std::error::Error for BodyLimitExceeded {}

pin_project! {
    /// A body wrapper that enforces size limits during streaming.
    ///
    /// This wraps a `ProxyBody` and tracks the total bytes consumed,
    /// returning an error if the limit is exceeded.
    pub struct LimitedBody {
        #[pin]
        inner: ProxyBody,
        max_size: usize,
        consumed: Arc<AtomicUsize>,
        exceeded: bool,
    }
}

impl LimitedBody {
    /// Create a new limited body wrapper
    pub fn new(body: ProxyBody, max_size: usize) -> Self {
        Self {
            inner: body,
            max_size,
            consumed: Arc::new(AtomicUsize::new(0)),
            exceeded: false,
        }
    }

    /// Get the current number of bytes consumed
    pub fn consumed(&self) -> usize {
        self.consumed.load(Ordering::Relaxed)
    }

    /// Check if the limit has been exceeded
    pub fn is_exceeded(&self) -> bool {
        self.exceeded
    }
}

impl Body for LimitedBody {
    type Data = Bytes;
    type Error = LimitedBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();

        // If already exceeded, return error
        if *this.exceeded {
            return Poll::Ready(Some(Err(LimitedBodyError::LimitExceeded(
                BodyLimitExceeded {
                    max_size: *this.max_size,
                    actual_size: this.consumed.load(Ordering::Relaxed),
                },
            ))));
        }

        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let new_consumed = this
                        .consumed
                        .fetch_add(data.len(), Ordering::Relaxed)
                        + data.len();

                    if new_consumed > *this.max_size {
                        *this.exceeded = true;
                        return Poll::Ready(Some(Err(LimitedBodyError::LimitExceeded(
                            BodyLimitExceeded {
                                max_size: *this.max_size,
                                actual_size: new_consumed,
                            },
                        ))));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(LimitedBodyError::Inner(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Error type for LimitedBody
#[derive(Debug)]
pub enum LimitedBodyError {
    /// The body size limit was exceeded
    LimitExceeded(BodyLimitExceeded),
    /// An error from the inner body
    Inner(hyper::Error),
}

impl std::fmt::Display for LimitedBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitedBodyError::LimitExceeded(e) => write!(f, "{}", e),
            LimitedBodyError::Inner(e) => write!(f, "Body error: {}", e),
        }
    }
}

impl std::error::Error for LimitedBodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LimitedBodyError::LimitExceeded(e) => Some(e),
            LimitedBodyError::Inner(e) => Some(e),
        }
    }
}

/// Body limit configuration
#[derive(Debug, Clone)]
pub struct BodyLimitConfig {
    /// Maximum request body size in bytes
    pub max_size: usize,
    /// Whether to check Content-Length header early
    pub check_content_length: bool,
    /// Custom error message
    pub error_message: Option<String>,
    /// Whether to include limit in error response
    pub include_limit_in_response: bool,
}

impl Default for BodyLimitConfig {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_BODY_SIZE,
            check_content_length: true,
            error_message: None,
            include_limit_in_response: true,
        }
    }
}

impl BodyLimitConfig {
    /// Create config with specific size limit
    pub fn with_limit(max_size: usize) -> Self {
        Self {
            max_size,
            ..Default::default()
        }
    }

    /// Parse size from string (e.g., "10MB", "1GB", "1024KB")
    pub fn parse_size(size_str: &str) -> Option<usize> {
        let size_str = size_str.trim().to_uppercase();

        let (num_part, multiplier) = if size_str.ends_with("GB") {
            (&size_str[..size_str.len() - 2], 1024 * 1024 * 1024)
        } else if size_str.ends_with("MB") {
            (&size_str[..size_str.len() - 2], 1024 * 1024)
        } else if size_str.ends_with("KB") {
            (&size_str[..size_str.len() - 2], 1024)
        } else if size_str.ends_with("B") {
            (&size_str[..size_str.len() - 1], 1)
        } else {
            // Assume bytes if no suffix
            (size_str.as_str(), 1)
        };

        num_part
            .trim()
            .parse::<usize>()
            .ok()
            .map(|n| n * multiplier)
    }

    /// Format size for display
    pub fn format_size(bytes: usize) -> String {
        const KB: usize = 1024;
        const MB: usize = KB * 1024;
        const GB: usize = MB * 1024;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} bytes", bytes)
        }
    }
}

/// Body limit middleware
pub struct BodyLimitMiddleware {
    config: BodyLimitConfig,
}

impl BodyLimitMiddleware {
    /// Create a new body limit middleware
    pub fn new(config: BodyLimitConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration
    pub fn default_config() -> Self {
        Self::new(BodyLimitConfig::default())
    }

    /// Create with specific size limit
    pub fn with_limit(max_size: usize) -> Self {
        Self::new(BodyLimitConfig::with_limit(max_size))
    }

    /// Create 413 Payload Too Large response
    fn payload_too_large_response(&self, content_length: Option<usize>) -> HttpResponse {
        let message = self.config.error_message.clone().unwrap_or_else(|| {
            if self.config.include_limit_in_response {
                format!(
                    "Request body too large. Maximum allowed size is {}.",
                    BodyLimitConfig::format_size(self.config.max_size)
                )
            } else {
                "Request body too large.".to_string()
            }
        });

        if let Some(len) = content_length {
            warn!(
                "Request body size {} exceeds limit {}",
                BodyLimitConfig::format_size(len),
                BodyLimitConfig::format_size(self.config.max_size)
            );
        }

        Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from(message)))
            .unwrap_or_else(|_| {
                // Fallback to minimal response if builder fails
                Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Full::new(Bytes::from("Request body too large")))
                    .expect("Minimal response builder should not fail")
            })
    }

    /// Check Content-Length header
    fn check_content_length_header(&self, request: &HttpRequest) -> Option<usize> {
        request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
    }
}

#[async_trait]
impl Middleware for BodyLimitMiddleware {
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        // Check Content-Length header if configured
        if self.config.check_content_length {
            if let Some(content_length) = self.check_content_length_header(&request) {
                if content_length > self.config.max_size {
                    debug!(
                        "Rejecting request: Content-Length {} exceeds limit {}",
                        content_length, self.config.max_size
                    );
                    return Ok(self.payload_too_large_response(Some(content_length)));
                }
            }
        }

        // Note: For streaming bodies, the actual size check would need to happen
        // during body consumption. This middleware provides early rejection based
        // on Content-Length header. Full streaming support would require wrapping
        // the body stream to count bytes.

        next.run(request, ctx).await
    }

    fn name(&self) -> &'static str {
        "body_limit"
    }
}

/// Response body limit (for logging/metrics, not rejection)
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ResponseBodyLimitConfig {
    /// Maximum response body size to buffer
    pub max_buffer_size: usize,
    /// Whether to truncate large responses for logging
    pub truncate_for_logging: bool,
}

impl Default for ResponseBodyLimitConfig {
    fn default() -> Self {
        Self {
            max_buffer_size: 1024 * 1024, // 1 MB
            truncate_for_logging: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size() {
        assert_eq!(BodyLimitConfig::parse_size("1024"), Some(1024));
        assert_eq!(BodyLimitConfig::parse_size("1KB"), Some(1024));
        assert_eq!(BodyLimitConfig::parse_size("1 KB"), Some(1024));
        assert_eq!(BodyLimitConfig::parse_size("10MB"), Some(10 * 1024 * 1024));
        assert_eq!(BodyLimitConfig::parse_size("1GB"), Some(1024 * 1024 * 1024));
        assert_eq!(BodyLimitConfig::parse_size("100B"), Some(100));
        assert_eq!(BodyLimitConfig::parse_size("invalid"), None);
    }

    #[test]
    fn test_format_size() {
        assert_eq!(BodyLimitConfig::format_size(500), "500 bytes");
        assert_eq!(BodyLimitConfig::format_size(1024), "1.00 KB");
        assert_eq!(BodyLimitConfig::format_size(1536), "1.50 KB");
        assert_eq!(BodyLimitConfig::format_size(1024 * 1024), "1.00 MB");
        assert_eq!(BodyLimitConfig::format_size(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_default_config() {
        let config = BodyLimitConfig::default();
        assert_eq!(config.max_size, DEFAULT_MAX_BODY_SIZE);
        assert!(config.check_content_length);
        assert!(config.include_limit_in_response);
    }

    #[test]
    fn test_with_limit() {
        let config = BodyLimitConfig::with_limit(5 * 1024 * 1024);
        assert_eq!(config.max_size, 5 * 1024 * 1024);
    }

    #[test]
    fn test_middleware_creation() {
        let middleware = BodyLimitMiddleware::with_limit(1024 * 1024);
        assert_eq!(middleware.config.max_size, 1024 * 1024);
    }

    #[test]
    fn test_payload_too_large_response() {
        let middleware = BodyLimitMiddleware::with_limit(1024);
        let response = middleware.payload_too_large_response(Some(2048));

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn test_body_limit_exceeded_error() {
        let error = BodyLimitExceeded {
            max_size: 1024,
            actual_size: 2048,
        };
        let message = error.to_string();
        assert!(message.contains("1024"));
        assert!(message.contains("2048"));
    }

    #[test]
    fn test_limited_body_error_display() {
        let limit_error = LimitedBodyError::LimitExceeded(BodyLimitExceeded {
            max_size: 1024,
            actual_size: 2048,
        });
        assert!(limit_error.to_string().contains("limit exceeded"));
    }

    #[tokio::test]
    async fn test_limited_body_within_limit() {
        use http_body_util::BodyExt;

        // Create a small body within limits
        let body = ProxyBody::buffered(Bytes::from("hello"));
        let mut limited = LimitedBody::new(body, 100);

        // Collect the body - should succeed
        let collected = (&mut limited).collect().await;
        assert!(collected.is_ok());
        assert!(!limited.is_exceeded());
        assert_eq!(limited.consumed(), 5);
    }

    #[tokio::test]
    async fn test_limited_body_exceeds_limit() {
        use http_body_util::BodyExt;

        // Create a body that exceeds the limit
        let body = ProxyBody::buffered(Bytes::from("hello world this is a long message"));
        let mut limited = LimitedBody::new(body, 10);

        // Collect the body - should fail
        let collected = (&mut limited).collect().await;
        assert!(collected.is_err());
        assert!(limited.is_exceeded());
    }

    #[test]
    fn test_limited_body_new() {
        let body = ProxyBody::buffered(Bytes::from("test"));
        let limited = LimitedBody::new(body, 1024);
        assert_eq!(limited.consumed(), 0);
        assert!(!limited.is_exceeded());
    }
}
