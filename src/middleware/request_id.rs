//! Request ID middleware for request tracing
//!
//! Generates unique request IDs and propagates them through the request/response cycle.
//! Supports reading existing IDs from incoming requests and forwarding to upstreams.

use super::{HttpRequest, HttpResponse, Middleware, Next, RequestContext};
use crate::error::Result;
use async_trait::async_trait;
use http::header::HeaderName;
use http::HeaderValue;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, Span};

/// Common request ID header names
pub const X_REQUEST_ID: &str = "x-request-id";
pub const X_CORRELATION_ID: &str = "x-correlation-id";
pub const X_TRACE_ID: &str = "x-trace-id";

/// Request ID configuration
#[derive(Debug, Clone)]
pub struct RequestIdConfig {
    /// Header name to use for request ID
    pub header_name: String,
    /// Whether to generate an ID if not present
    pub generate_if_missing: bool,
    /// Whether to trust incoming request IDs
    pub trust_incoming: bool,
    /// Prefix for generated IDs
    pub prefix: Option<String>,
    /// Whether to include in response
    pub include_in_response: bool,
    /// Additional headers to propagate as correlation IDs
    pub propagate_headers: Vec<String>,
}

impl Default for RequestIdConfig {
    fn default() -> Self {
        Self {
            header_name: X_REQUEST_ID.to_string(),
            generate_if_missing: true,
            trust_incoming: true,
            prefix: None,
            include_in_response: true,
            propagate_headers: vec![X_CORRELATION_ID.to_string(), X_TRACE_ID.to_string()],
        }
    }
}

/// Request ID generator
pub struct RequestIdGenerator {
    /// Counter for uniqueness within process
    counter: AtomicU64,
    /// Process start timestamp for uniqueness across restarts
    start_time: u64,
    /// Optional prefix
    prefix: Option<String>,
}

impl RequestIdGenerator {
    /// Create a new request ID generator
    pub fn new(prefix: Option<String>) -> Self {
        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            counter: AtomicU64::new(0),
            start_time,
            prefix,
        }
    }

    /// Generate a new unique request ID
    pub fn generate(&self) -> String {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);

        // Format: [prefix-]<timestamp_hex>-<counter_hex>-<random>
        let random: u32 = rand::random();

        match &self.prefix {
            Some(prefix) => format!(
                "{}-{:x}-{:x}-{:x}",
                prefix, self.start_time, counter, random
            ),
            None => format!("{:x}-{:x}-{:x}", self.start_time, counter, random),
        }
    }

    /// Generate a UUID v4 style request ID
    pub fn generate_uuid(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

impl Default for RequestIdGenerator {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Request ID middleware
pub struct RequestIdMiddleware {
    config: RequestIdConfig,
    generator: RequestIdGenerator,
    header_name: HeaderName,
}

impl RequestIdMiddleware {
    /// Create a new request ID middleware
    pub fn new(config: RequestIdConfig) -> Self {
        let header_name = HeaderName::try_from(config.header_name.as_str())
            .unwrap_or_else(|_| HeaderName::from_static(X_REQUEST_ID));

        let generator = RequestIdGenerator::new(config.prefix.clone());

        Self {
            config,
            generator,
            header_name,
        }
    }

    /// Create with default configuration
    pub fn default_config() -> Self {
        Self::new(RequestIdConfig::default())
    }

    /// Extract or generate request ID from request
    fn get_or_generate_id(&self, request: &HttpRequest) -> String {
        // Try to get existing ID if we trust incoming
        if self.config.trust_incoming {
            if let Some(value) = request.headers().get(&self.header_name) {
                if let Ok(id) = value.to_str() {
                    if !id.is_empty() {
                        debug!("Using existing request ID: {}", id);
                        return id.to_string();
                    }
                }
            }
        }

        // Generate new ID
        if self.config.generate_if_missing {
            let id = self.generator.generate();
            debug!("Generated new request ID: {}", id);
            id
        } else {
            String::new()
        }
    }
}

#[async_trait]
impl Middleware for RequestIdMiddleware {
    async fn process(
        &self,
        mut request: HttpRequest,
        mut ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        // Get or generate request ID
        let request_id = self.get_or_generate_id(&request);

        if !request_id.is_empty() {
            // Update context with request ID
            ctx.request_id = request_id.clone();

            // Add/update header on request (for upstream propagation)
            if let Ok(value) = HeaderValue::from_str(&request_id) {
                request
                    .headers_mut()
                    .insert(self.header_name.clone(), value);
            }

            // Update tracing span
            Span::current().record("request_id", &request_id);
        }

        // Process request
        let mut response = next.run(request, ctx).await?;

        // Add request ID to response if configured
        if self.config.include_in_response && !request_id.is_empty() {
            if let Ok(value) = HeaderValue::from_str(&request_id) {
                response
                    .headers_mut()
                    .insert(self.header_name.clone(), value);
            }
        }

        Ok(response)
    }

    fn name(&self) -> &'static str {
        "request_id"
    }
}

/// Extract request ID from headers (utility function)
pub fn extract_request_id(headers: &http::HeaderMap) -> Option<String> {
    // Try common header names in order of preference
    for header_name in &[X_REQUEST_ID, X_CORRELATION_ID, X_TRACE_ID] {
        if let Some(value) = headers.get(*header_name) {
            if let Ok(id) = value.to_str() {
                if !id.is_empty() {
                    return Some(id.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_id_generator() {
        let generator = RequestIdGenerator::new(None);

        let id1 = generator.generate();
        let id2 = generator.generate();

        assert!(!id1.is_empty());
        assert!(!id2.is_empty());
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_request_id_generator_with_prefix() {
        let generator = RequestIdGenerator::new(Some("prism".to_string()));

        let id = generator.generate();

        assert!(id.starts_with("prism-"));
    }

    #[test]
    fn test_request_id_uniqueness() {
        let generator = RequestIdGenerator::new(None);
        let mut ids = std::collections::HashSet::new();

        for _ in 0..10000 {
            let id = generator.generate();
            assert!(ids.insert(id), "Duplicate ID generated");
        }
    }

    #[test]
    fn test_default_config() {
        let config = RequestIdConfig::default();

        assert_eq!(config.header_name, X_REQUEST_ID);
        assert!(config.generate_if_missing);
        assert!(config.trust_incoming);
        assert!(config.include_in_response);
    }

    #[test]
    fn test_extract_request_id() {
        let mut headers = http::HeaderMap::new();

        // No headers
        assert!(extract_request_id(&headers).is_none());

        // With x-request-id
        headers.insert(X_REQUEST_ID, HeaderValue::from_static("test-123"));
        assert_eq!(extract_request_id(&headers), Some("test-123".to_string()));

        // Clear and test correlation id
        headers.clear();
        headers.insert(X_CORRELATION_ID, HeaderValue::from_static("corr-456"));
        assert_eq!(extract_request_id(&headers), Some("corr-456".to_string()));
    }

    #[test]
    fn test_uuid_generation() {
        let generator = RequestIdGenerator::new(None);
        let id = generator.generate_uuid();

        // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        assert_eq!(id.len(), 36);
        assert!(id.chars().filter(|c| *c == '-').count() == 4);
    }
}
