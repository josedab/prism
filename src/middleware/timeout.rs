//! Timeout middleware

use super::{HttpRequest, HttpResponse, Middleware, Next, RequestContext};
use crate::config::TimeoutConfig;
use crate::error::Result;
use async_trait::async_trait;
use bytes::Bytes;
use http::Response;
use http_body_util::Full;
use std::time::Duration;
use tokio::time::timeout;

/// Middleware that enforces request timeouts
pub struct TimeoutMiddleware {
    /// Total request timeout
    request_timeout: Duration,
}

impl TimeoutMiddleware {
    /// Create a new timeout middleware from configuration
    pub fn new(config: &TimeoutConfig) -> Self {
        // Use the read timeout as the overall request timeout
        Self {
            request_timeout: config.read,
        }
    }

    /// Create with a specific timeout duration
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            request_timeout: timeout,
        }
    }
}

#[async_trait]
impl Middleware for TimeoutMiddleware {
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        match timeout(self.request_timeout, next.run(request, ctx)).await {
            Ok(result) => result,
            Err(_) => {
                // Timeout occurred
                Ok(Response::builder()
                    .status(504)
                    .header("X-Timeout", "true")
                    .body(Full::new(Bytes::from("Gateway Timeout")))
                    .unwrap())
            }
        }
    }

    fn name(&self) -> &'static str {
        "timeout"
    }
}

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker middleware
pub struct CircuitBreaker {
    state: std::sync::atomic::AtomicU8,
    failure_count: std::sync::atomic::AtomicU32,
    success_count: std::sync::atomic::AtomicU32,
    last_failure: std::sync::atomic::AtomicU64,
    failure_threshold: u32,
    success_threshold: u32,
    half_open_timeout_ms: u64,
}

const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(
        failure_threshold: u32,
        success_threshold: u32,
        half_open_timeout: Duration,
    ) -> Self {
        Self {
            state: std::sync::atomic::AtomicU8::new(STATE_CLOSED),
            failure_count: std::sync::atomic::AtomicU32::new(0),
            success_count: std::sync::atomic::AtomicU32::new(0),
            last_failure: std::sync::atomic::AtomicU64::new(0),
            failure_threshold,
            success_threshold,
            half_open_timeout_ms: half_open_timeout.as_millis() as u64,
        }
    }

    /// Get the current state
    pub fn state(&self) -> CircuitState {
        match self.state.load(std::sync::atomic::Ordering::Relaxed) {
            STATE_CLOSED => CircuitState::Closed,
            STATE_OPEN => CircuitState::Open,
            STATE_HALF_OPEN => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }

    /// Check if requests should be allowed
    pub fn should_allow(&self) -> bool {
        let state = self.state.load(std::sync::atomic::Ordering::Relaxed);

        match state {
            STATE_CLOSED => true,
            STATE_HALF_OPEN => true, // Allow limited requests
            STATE_OPEN => {
                // Check if we should transition to half-open
                let now = current_time_millis();
                let last = self.last_failure.load(std::sync::atomic::Ordering::Relaxed);

                if now.saturating_sub(last) > self.half_open_timeout_ms {
                    self.state
                        .store(STATE_HALF_OPEN, std::sync::atomic::Ordering::Relaxed);
                    self.success_count
                        .store(0, std::sync::atomic::Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }
            _ => true,
        }
    }

    /// Record a successful request
    pub fn record_success(&self) {
        let state = self.state.load(std::sync::atomic::Ordering::Relaxed);

        if state == STATE_HALF_OPEN {
            let count = self
                .success_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            if count >= self.success_threshold {
                self.state
                    .store(STATE_CLOSED, std::sync::atomic::Ordering::Relaxed);
                self.failure_count
                    .store(0, std::sync::atomic::Ordering::Relaxed);
            }
        } else if state == STATE_CLOSED {
            // Reset failure count on success in closed state
            self.failure_count
                .store(0, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Record a failed request
    pub fn record_failure(&self) {
        let state = self.state.load(std::sync::atomic::Ordering::Relaxed);
        let now = current_time_millis();
        self.last_failure
            .store(now, std::sync::atomic::Ordering::Relaxed);

        if state == STATE_HALF_OPEN {
            // Any failure in half-open goes back to open
            self.state
                .store(STATE_OPEN, std::sync::atomic::Ordering::Relaxed);
        } else if state == STATE_CLOSED {
            let count = self
                .failure_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            if count >= self.failure_threshold {
                self.state
                    .store(STATE_OPEN, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

fn current_time_millis() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[async_trait]
impl Middleware for CircuitBreaker {
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        if !self.should_allow() {
            return Ok(Response::builder()
                .status(503)
                .header("X-Circuit-Breaker", "open")
                .body(Full::new(Bytes::from("Service Unavailable - Circuit Open")))
                .unwrap());
        }

        match next.run(request, ctx).await {
            Ok(response) => {
                if response.status().is_server_error() {
                    self.record_failure();
                } else {
                    self.record_success();
                }
                Ok(response)
            }
            Err(e) => {
                self.record_failure();
                Err(e)
            }
        }
    }

    fn name(&self) -> &'static str {
        "circuit_breaker"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_states() {
        let cb = CircuitBreaker::new(3, 2, Duration::from_secs(30));

        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.should_allow());

        // Trigger failures
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();

        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_circuit_breaker_recovery() {
        let cb = CircuitBreaker::new(1, 2, Duration::from_millis(1));

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for half-open timeout
        std::thread::sleep(Duration::from_millis(10));

        // Should transition to half-open
        assert!(cb.should_allow());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Record successes
        cb.record_success();
        cb.record_success();

        assert_eq!(cb.state(), CircuitState::Closed);
    }
}
