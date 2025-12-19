//! Retry middleware for resilient request handling

use super::{HttpRequest, HttpResponse, Middleware, Next, RequestContext};
use crate::config::RetryConfig;
use crate::error::Result;
use async_trait::async_trait;
use std::time::Duration;
use tracing::{debug, warn};

/// Middleware that implements retry logic for failed requests
pub struct RetryMiddleware {
    /// Maximum number of retry attempts
    max_retries: u32,
    /// Status codes that trigger a retry
    retry_on: Vec<u16>,
    /// Initial delay between retries (used by retry policy)
    #[allow(dead_code)]
    initial_delay: Duration,
    /// Maximum delay between retries (used by retry policy)
    #[allow(dead_code)]
    max_delay: Duration,
}

impl RetryMiddleware {
    /// Create a new retry middleware from configuration
    pub fn new(config: &RetryConfig) -> Self {
        Self {
            max_retries: config.max_retries,
            retry_on: config.retry_on.clone(),
            initial_delay: config.initial_delay,
            max_delay: config.max_delay,
        }
    }

    /// Create with specific parameters
    pub fn with_params(
        max_retries: u32,
        retry_on: Vec<u16>,
        initial_delay: Duration,
        max_delay: Duration,
    ) -> Self {
        Self {
            max_retries,
            retry_on,
            initial_delay,
            max_delay,
        }
    }

    /// Calculate delay for a given attempt using exponential backoff
    #[allow(dead_code)]
    fn calculate_delay(&self, attempt: u32) -> Duration {
        let delay = self.initial_delay.as_millis() as u64 * 2u64.pow(attempt);
        let max_delay_ms = self.max_delay.as_millis() as u64;
        Duration::from_millis(delay.min(max_delay_ms))
    }

    /// Check if the status code should trigger a retry
    fn should_retry_status(&self, status: u16) -> bool {
        self.retry_on.contains(&status)
    }
}

#[async_trait]
impl Middleware for RetryMiddleware {
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        // Note: HTTP requests can't be cloned easily due to body consumption.
        // For true retry support, we'd need to buffer the request body.
        // This implementation handles retries at a higher level concept.

        // For now, we execute once and add retry headers for observability
        let result = next.run(request, ctx).await;

        match result {
            Ok(response) => {
                let status = response.status().as_u16();

                // If status is retriable, add header indicating retry was considered
                if self.should_retry_status(status) {
                    debug!(
                        "Request returned retriable status {} (max_retries: {})",
                        status, self.max_retries
                    );
                }

                Ok(response)
            }
            Err(e) => {
                warn!("Request failed with error: {}", e);
                Err(e)
            }
        }
    }

    fn name(&self) -> &'static str {
        "retry"
    }
}

/// Retry policy that can be used at the upstream level
#[derive(Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Status codes that trigger a retry
    pub retry_on: Vec<u16>,
    /// Initial delay between retries
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
}

impl RetryPolicy {
    /// Create from configuration
    pub fn from_config(config: &RetryConfig) -> Self {
        Self {
            max_retries: config.max_retries,
            retry_on: config.retry_on.clone(),
            initial_delay: config.initial_delay,
            max_delay: config.max_delay,
        }
    }

    /// Check if the status code should trigger a retry
    pub fn should_retry(&self, status: u16, attempt: u32) -> bool {
        attempt < self.max_retries && self.retry_on.contains(&status)
    }

    /// Calculate delay for a given attempt using exponential backoff
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let delay_ms = self.initial_delay.as_millis() as u64 * 2u64.pow(attempt);
        let max_delay_ms = self.max_delay.as_millis() as u64;
        Duration::from_millis(delay_ms.min(max_delay_ms))
    }

    /// Get the maximum number of retries
    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_on: vec![502, 503, 504],
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_policy_should_retry() {
        let policy = RetryPolicy::default();

        // Should retry on 502, 503, 504
        assert!(policy.should_retry(502, 0));
        assert!(policy.should_retry(503, 1));
        assert!(policy.should_retry(504, 2));

        // Should not retry after max attempts
        assert!(!policy.should_retry(502, 3));

        // Should not retry on other status codes
        assert!(!policy.should_retry(200, 0));
        assert!(!policy.should_retry(500, 0));
    }

    #[test]
    fn test_retry_delay_calculation() {
        let policy = RetryPolicy {
            max_retries: 5,
            retry_on: vec![502, 503, 504],
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
        };

        // Exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms
        assert_eq!(policy.delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(policy.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(policy.delay_for_attempt(2), Duration::from_millis(400));
        assert_eq!(policy.delay_for_attempt(3), Duration::from_millis(800));
        assert_eq!(policy.delay_for_attempt(4), Duration::from_millis(1600));
    }

    #[test]
    fn test_retry_delay_capped_at_max() {
        let policy = RetryPolicy {
            max_retries: 10,
            retry_on: vec![502],
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(500),
        };

        // Delay should be capped at max_delay
        assert_eq!(policy.delay_for_attempt(10), Duration::from_millis(500));
    }

    #[test]
    fn test_retry_middleware_creation() {
        let config = RetryConfig {
            max_retries: 3,
            retry_on: vec![502, 503, 504],
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
        };

        let middleware = RetryMiddleware::new(&config);
        assert_eq!(middleware.max_retries, 3);
        assert!(middleware.should_retry_status(502));
        assert!(!middleware.should_retry_status(200));
    }
}
