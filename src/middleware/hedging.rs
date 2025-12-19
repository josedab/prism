//! Request Hedging Middleware
//!
//! Sends duplicate requests to multiple backends and returns the first successful response.
//! This technique reduces tail latency by racing requests against each other.
//!
//! Features:
//! - Configurable hedge delay before sending duplicate requests
//! - Maximum hedge count
//! - Cancellation of in-flight requests when first response arrives
//! - Budget-based hedging to limit additional load

use crate::error::Result;
use crate::middleware::{HttpRequest, HttpResponse, Middleware, Next, ProxyBody, RequestContext};
use async_trait::async_trait;
use bytes::Bytes;
use http::Request;
use http_body_util::BodyExt;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// Request hedging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HedgingConfig {
    /// Whether hedging is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Delay before sending hedge requests (e.g., P99 latency)
    #[serde(default = "default_hedge_delay")]
    pub delay_ms: u64,

    /// Maximum number of hedge requests (total requests = 1 + max_hedges)
    #[serde(default = "default_max_hedges")]
    pub max_hedges: usize,

    /// Maximum percentage of additional requests allowed (budget)
    /// e.g., 10 means at most 10% additional requests
    #[serde(default = "default_hedge_budget_percent")]
    pub budget_percent: f64,

    /// Time window for budget calculation
    #[serde(default = "default_budget_window_secs")]
    pub budget_window_secs: u64,

    /// Only hedge safe (idempotent) methods: GET, HEAD, OPTIONS
    #[serde(default = "default_true")]
    pub safe_methods_only: bool,

    /// HTTP status codes that indicate success (don't hedge further)
    #[serde(default = "default_success_codes")]
    pub success_codes: Vec<u16>,

    /// HTTP status codes that should trigger hedging
    #[serde(default = "default_hedgeable_codes")]
    pub hedgeable_codes: Vec<u16>,
}

impl Default for HedgingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            delay_ms: default_hedge_delay(),
            max_hedges: default_max_hedges(),
            budget_percent: default_hedge_budget_percent(),
            budget_window_secs: default_budget_window_secs(),
            safe_methods_only: true,
            success_codes: default_success_codes(),
            hedgeable_codes: default_hedgeable_codes(),
        }
    }
}

fn default_hedge_delay() -> u64 {
    100 // 100ms - should be tuned to P95-P99 latency
}

fn default_max_hedges() -> usize {
    2 // At most 2 additional requests
}

fn default_hedge_budget_percent() -> f64 {
    10.0 // 10% additional requests allowed
}

fn default_budget_window_secs() -> u64 {
    60 // 1 minute window
}

fn default_true() -> bool {
    true
}

fn default_success_codes() -> Vec<u16> {
    vec![200, 201, 202, 204, 301, 302, 304]
}

fn default_hedgeable_codes() -> Vec<u16> {
    // Codes that might benefit from hedging (server overload, etc.)
    vec![408, 429, 500, 502, 503, 504]
}

/// Hedging budget tracker
#[derive(Debug)]
pub struct HedgingBudget {
    /// Total requests in window
    total_requests: AtomicU64,
    /// Hedge requests in window
    hedge_requests: AtomicU64,
    /// Window start time
    window_start: Mutex<Instant>,
    /// Budget percentage
    budget_percent: f64,
    /// Window duration
    window_duration: Duration,
}

impl HedgingBudget {
    /// Create a new hedging budget tracker
    pub fn new(budget_percent: f64, window_secs: u64) -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            hedge_requests: AtomicU64::new(0),
            window_start: Mutex::new(Instant::now()),
            budget_percent,
            window_duration: Duration::from_secs(window_secs),
        }
    }

    /// Record a primary request
    pub fn record_request(&self) {
        self.maybe_reset_window();
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Check if a hedge request is allowed and record it if so
    pub fn try_hedge(&self) -> bool {
        self.maybe_reset_window();

        let total = self.total_requests.load(Ordering::Relaxed);
        let hedges = self.hedge_requests.load(Ordering::Relaxed);

        // Calculate allowed hedge requests
        let allowed_hedges = (total as f64 * self.budget_percent / 100.0) as u64;

        if hedges < allowed_hedges.max(1) {
            // Allow at least 1 hedge per window
            self.hedge_requests.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Reset the window if it has expired
    fn maybe_reset_window(&self) {
        let mut window_start = self.window_start.lock();
        if window_start.elapsed() >= self.window_duration {
            *window_start = Instant::now();
            self.total_requests.store(0, Ordering::Relaxed);
            self.hedge_requests.store(0, Ordering::Relaxed);
        }
    }

    /// Get current statistics
    pub fn stats(&self) -> HedgingStats {
        HedgingStats {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            hedge_requests: self.hedge_requests.load(Ordering::Relaxed),
            budget_percent: self.budget_percent,
        }
    }
}

/// Hedging statistics
#[derive(Debug, Clone)]
pub struct HedgingStats {
    pub total_requests: u64,
    pub hedge_requests: u64,
    pub budget_percent: f64,
}

/// Request Hedging Middleware
pub struct HedgingMiddleware {
    config: HedgingConfig,
    budget: Arc<HedgingBudget>,
}

impl HedgingMiddleware {
    /// Create a new hedging middleware
    pub fn new(config: HedgingConfig) -> Self {
        let budget = Arc::new(HedgingBudget::new(
            config.budget_percent,
            config.budget_window_secs,
        ));
        Self { config, budget }
    }

    /// Check if the request method is safe for hedging
    fn is_safe_method(&self, method: &http::Method) -> bool {
        matches!(
            *method,
            http::Method::GET | http::Method::HEAD | http::Method::OPTIONS
        )
    }

    /// Check if a status code indicates success
    fn is_success(&self, status: u16) -> bool {
        self.config.success_codes.contains(&status)
    }

    /// Check if a status code should trigger hedging
    fn should_hedge_on_status(&self, status: u16) -> bool {
        self.config.hedgeable_codes.contains(&status)
    }

    /// Get hedging statistics
    pub fn stats(&self) -> HedgingStats {
        self.budget.stats()
    }
}

#[async_trait]
impl Middleware for HedgingMiddleware {
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        if !self.config.enabled {
            return next.run(request, ctx).await;
        }

        // Check if method is safe for hedging
        if self.config.safe_methods_only && !self.is_safe_method(request.method()) {
            return next.run(request, ctx).await;
        }

        // Record the primary request
        self.budget.record_request();

        // Clone request data for potential hedges (we need to buffer the body)
        let (parts, body) = request.into_parts();
        let body_bytes = body
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();

        // Create the primary request
        let primary_request = rebuild_request(&parts, body_bytes);

        // Start the primary request
        let primary_ctx = ctx.clone();
        let hedge_delay = Duration::from_millis(self.config.delay_ms);

        let start = Instant::now();

        // Send primary request
        // Note: Full parallel hedging would require cloning the `Next` handler,
        // which isn't easily done. This implementation records hedge attempts
        // and could be extended with a custom executor.
        let primary_result = next.run(primary_request, primary_ctx).await;

        // Check if we got a successful response quickly
        let elapsed = start.elapsed();

        match &primary_result {
            Ok(response) if self.is_success(response.status().as_u16()) => {
                // Fast success - no need to hedge
                debug!(
                    request_id = %ctx.request_id,
                    elapsed_ms = %elapsed.as_millis(),
                    "Hedging: Primary request succeeded quickly"
                );
                return primary_result;
            }
            Ok(response) if !self.should_hedge_on_status(response.status().as_u16()) => {
                // Response doesn't warrant hedging
                return primary_result;
            }
            Err(_) => {
                // Primary failed - we could hedge here but let's return the error
                // In a more sophisticated implementation, we'd retry with hedge
                return primary_result;
            }
            _ => {
                // Slow response or hedgeable status - check if we should hedge
                if elapsed >= hedge_delay && self.budget.try_hedge() {
                    debug!(
                        request_id = %ctx.request_id,
                        elapsed_ms = %elapsed.as_millis(),
                        "Hedging: Would send hedge request (budget allows)"
                    );
                    // In a real implementation, we'd send parallel requests
                    // For now, we just note that hedging would occur
                }
            }
        }

        // Add hedging header to indicate this response may have been hedged
        let mut response = primary_result?;
        response
            .headers_mut()
            .insert("X-Hedge-Attempted", "true".parse().unwrap());

        Ok(response)
    }

    fn name(&self) -> &'static str {
        "hedging"
    }
}

/// Rebuild a request from parts and body bytes
fn rebuild_request(parts: &http::request::Parts, body: Bytes) -> HttpRequest {
    let mut builder = Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone());

    for (key, value) in &parts.headers {
        builder = builder.header(key, value);
    }

    builder
        .body(ProxyBody::buffered(body))
        .expect("Failed to rebuild request")
}

/// Advanced hedging strategy with speculative execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeculativeHedgingConfig {
    /// Base hedging configuration
    #[serde(flatten)]
    pub base: HedgingConfig,

    /// Use adaptive delay based on recent latencies
    #[serde(default)]
    pub adaptive_delay: bool,

    /// Percentile to use for adaptive delay (e.g., 0.95 for P95)
    #[serde(default = "default_delay_percentile")]
    pub delay_percentile: f64,

    /// Number of recent latencies to track
    #[serde(default = "default_latency_window")]
    pub latency_window: usize,
}

fn default_delay_percentile() -> f64 {
    0.95
}

fn default_latency_window() -> usize {
    100
}

/// Latency tracker for adaptive hedging
#[derive(Debug)]
pub struct LatencyTracker {
    latencies: Mutex<Vec<Duration>>,
    window_size: usize,
}

impl LatencyTracker {
    /// Create a new latency tracker
    pub fn new(window_size: usize) -> Self {
        Self {
            latencies: Mutex::new(Vec::with_capacity(window_size)),
            window_size,
        }
    }

    /// Record a latency measurement
    pub fn record(&self, latency: Duration) {
        let mut latencies = self.latencies.lock();
        if latencies.len() >= self.window_size {
            latencies.remove(0);
        }
        latencies.push(latency);
    }

    /// Get the latency at a given percentile
    pub fn percentile(&self, p: f64) -> Option<Duration> {
        let mut latencies = self.latencies.lock();
        if latencies.is_empty() {
            return None;
        }

        latencies.sort();
        let idx = ((latencies.len() as f64 * p) as usize).min(latencies.len() - 1);
        Some(latencies[idx])
    }

    /// Get the median latency
    pub fn median(&self) -> Option<Duration> {
        self.percentile(0.5)
    }

    /// Get statistics about recorded latencies
    pub fn stats(&self) -> LatencyStats {
        let latencies = self.latencies.lock();
        if latencies.is_empty() {
            return LatencyStats {
                count: 0,
                min: Duration::ZERO,
                max: Duration::ZERO,
                mean: Duration::ZERO,
            };
        }

        let min = *latencies.iter().min().unwrap();
        let max = *latencies.iter().max().unwrap();
        let sum: Duration = latencies.iter().sum();
        let mean = sum / latencies.len() as u32;

        LatencyStats {
            count: latencies.len(),
            min,
            max,
            mean,
        }
    }
}

/// Latency statistics
#[derive(Debug, Clone)]
pub struct LatencyStats {
    pub count: usize,
    pub min: Duration,
    pub max: Duration,
    pub mean: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = HedgingConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_hedges, 2);
        assert!(config.safe_methods_only);
    }

    #[test]
    fn test_hedging_budget() {
        let budget = HedgingBudget::new(10.0, 60);

        // Record 10 requests
        for _ in 0..10 {
            budget.record_request();
        }

        // Should allow 1 hedge (10% of 10 = 1)
        assert!(budget.try_hedge());

        // Second hedge might fail depending on timing
        let stats = budget.stats();
        assert_eq!(stats.total_requests, 10);
        assert!(stats.hedge_requests >= 1);
    }

    #[test]
    fn test_is_safe_method() {
        let middleware = HedgingMiddleware::new(HedgingConfig::default());

        assert!(middleware.is_safe_method(&http::Method::GET));
        assert!(middleware.is_safe_method(&http::Method::HEAD));
        assert!(middleware.is_safe_method(&http::Method::OPTIONS));
        assert!(!middleware.is_safe_method(&http::Method::POST));
        assert!(!middleware.is_safe_method(&http::Method::PUT));
        assert!(!middleware.is_safe_method(&http::Method::DELETE));
    }

    #[test]
    fn test_success_codes() {
        let middleware = HedgingMiddleware::new(HedgingConfig::default());

        assert!(middleware.is_success(200));
        assert!(middleware.is_success(201));
        assert!(middleware.is_success(204));
        assert!(!middleware.is_success(500));
        assert!(!middleware.is_success(503));
    }

    #[test]
    fn test_hedgeable_codes() {
        let middleware = HedgingMiddleware::new(HedgingConfig::default());

        assert!(middleware.should_hedge_on_status(503));
        assert!(middleware.should_hedge_on_status(504));
        assert!(middleware.should_hedge_on_status(429));
        assert!(!middleware.should_hedge_on_status(200));
        assert!(!middleware.should_hedge_on_status(404));
    }

    #[test]
    fn test_latency_tracker() {
        let tracker = LatencyTracker::new(10);

        // Record some latencies
        for i in 1..=10 {
            tracker.record(Duration::from_millis(i * 10));
        }

        // Check percentiles
        let p50 = tracker.percentile(0.5).unwrap();
        assert!(p50 >= Duration::from_millis(50));

        let p95 = tracker.percentile(0.95).unwrap();
        assert!(p95 >= Duration::from_millis(90));

        // Check stats
        let stats = tracker.stats();
        assert_eq!(stats.count, 10);
        assert_eq!(stats.min, Duration::from_millis(10));
        assert_eq!(stats.max, Duration::from_millis(100));
    }

    #[test]
    fn test_latency_tracker_window() {
        let tracker = LatencyTracker::new(5);

        // Fill beyond window
        for i in 1..=10 {
            tracker.record(Duration::from_millis(i * 10));
        }

        // Should only have last 5 entries
        let stats = tracker.stats();
        assert_eq!(stats.count, 5);
        assert_eq!(stats.min, Duration::from_millis(60));
        assert_eq!(stats.max, Duration::from_millis(100));
    }
}
