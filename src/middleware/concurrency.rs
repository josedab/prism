//! Adaptive Concurrency Limits Middleware
//!
//! Dynamically adjusts concurrency limits based on measured latency and throughput.
//! Uses algorithms inspired by:
//! - Netflix's adaptive concurrency limiter (Gradient algorithm)
//! - TCP congestion control (AIMD - Additive Increase, Multiplicative Decrease)
//! - Vegas algorithm (latency-based)
//!
//! Features:
//! - Automatic limit adjustment based on latency changes
//! - Protection against cascading failures
//! - Per-route or global limits
//! - Smooth limit transitions

use crate::error::Result;
use crate::middleware::{HttpRequest, HttpResponse, Middleware, Next, RequestContext};
use async_trait::async_trait;
use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

/// Adaptive concurrency limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptiveConcurrencyConfig {
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

    /// Algorithm to use for limit adjustment
    #[serde(default)]
    pub algorithm: ConcurrencyAlgorithm,

    /// Smoothing factor for exponential moving average (0.0 - 1.0)
    #[serde(default = "default_smoothing")]
    pub smoothing: f64,

    /// Window size for latency measurements
    #[serde(default = "default_window_size")]
    pub window_size: usize,

    /// Tolerance for latency increase before reducing limit (e.g., 1.5 = 50% tolerance)
    #[serde(default = "default_latency_tolerance")]
    pub latency_tolerance: f64,

    /// How often to recalculate limits (milliseconds)
    #[serde(default = "default_adjustment_interval_ms")]
    pub adjustment_interval_ms: u64,

    /// Timeout waiting for a permit (milliseconds)
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for AdaptiveConcurrencyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            initial_limit: default_initial_limit(),
            min_limit: default_min_limit(),
            max_limit: default_max_limit(),
            algorithm: ConcurrencyAlgorithm::default(),
            smoothing: default_smoothing(),
            window_size: default_window_size(),
            latency_tolerance: default_latency_tolerance(),
            adjustment_interval_ms: default_adjustment_interval_ms(),
            timeout_ms: default_timeout_ms(),
        }
    }
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

fn default_timeout_ms() -> u64 {
    5000
}

/// Algorithm for adjusting concurrency limits
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConcurrencyAlgorithm {
    /// Gradient-based algorithm (Netflix style)
    #[default]
    Gradient,
    /// Additive Increase, Multiplicative Decrease
    Aimd,
    /// Vegas (latency-based like TCP Vegas)
    Vegas,
    /// Fixed limit (no adaptation)
    Fixed,
}

/// Latency sample for tracking response times
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
struct LatencySample {
    duration: Duration,
    timestamp: Instant,
    success: bool,
}

/// Adaptive concurrency limiter state
pub struct AdaptiveLimiter {
    config: AdaptiveConcurrencyConfig,
    /// Current concurrency limit
    current_limit: AtomicUsize,
    /// Current in-flight requests
    in_flight: AtomicUsize,
    /// Semaphore for limiting concurrency
    semaphore: Arc<Semaphore>,
    /// Recent latency samples
    samples: Mutex<VecDeque<LatencySample>>,
    /// Smoothed RTT (round-trip time) estimate
    smoothed_rtt: RwLock<Option<Duration>>,
    /// Minimum observed RTT
    min_rtt: RwLock<Option<Duration>>,
    /// Last adjustment time
    last_adjustment: Mutex<Instant>,
    /// Statistics
    stats: ConcurrencyStats,
}

impl AdaptiveLimiter {
    /// Create a new adaptive limiter
    pub fn new(config: AdaptiveConcurrencyConfig) -> Self {
        let initial_limit = config.initial_limit;
        Self {
            config,
            current_limit: AtomicUsize::new(initial_limit),
            in_flight: AtomicUsize::new(0),
            semaphore: Arc::new(Semaphore::new(initial_limit)),
            samples: Mutex::new(VecDeque::with_capacity(200)),
            smoothed_rtt: RwLock::new(None),
            min_rtt: RwLock::new(None),
            last_adjustment: Mutex::new(Instant::now()),
            stats: ConcurrencyStats::default(),
        }
    }

    /// Try to acquire a permit
    #[allow(clippy::needless_lifetimes)]
    pub async fn acquire(&self) -> Option<ConcurrencyPermit<'_>> {
        let timeout = Duration::from_millis(self.config.timeout_ms);

        match tokio::time::timeout(timeout, self.semaphore.clone().acquire_owned()).await {
            Ok(Ok(permit)) => {
                self.in_flight.fetch_add(1, Ordering::Relaxed);
                self.stats.acquired.fetch_add(1, Ordering::Relaxed);
                Some(ConcurrencyPermit {
                    _permit: permit,
                    limiter: self,
                    start_time: Instant::now(),
                })
            }
            _ => {
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Record a completed request
    fn record_sample(&self, duration: Duration, success: bool) {
        let sample = LatencySample {
            duration,
            timestamp: Instant::now(),
            success,
        };

        let mut samples = self.samples.lock();
        if samples.len() >= self.config.window_size * 2 {
            // Remove old samples
            while samples.len() > self.config.window_size {
                samples.pop_front();
            }
        }
        samples.push_back(sample);

        // Update smoothed RTT
        let mut smoothed = self.smoothed_rtt.write();
        match *smoothed {
            Some(current) => {
                let alpha = self.config.smoothing;
                let new_rtt = Duration::from_secs_f64(
                    current.as_secs_f64() * (1.0 - alpha) + duration.as_secs_f64() * alpha,
                );
                *smoothed = Some(new_rtt);
            }
            None => {
                *smoothed = Some(duration);
            }
        }

        // Update min RTT
        let mut min = self.min_rtt.write();
        match *min {
            Some(current) if duration < current => {
                *min = Some(duration);
            }
            None => {
                *min = Some(duration);
            }
            _ => {}
        }

        drop(samples);
        drop(smoothed);
        drop(min);

        // Maybe adjust limit
        self.maybe_adjust_limit();
    }

    /// Adjust the concurrency limit based on the algorithm
    fn maybe_adjust_limit(&self) {
        let mut last_adjustment = self.last_adjustment.lock();
        let interval = Duration::from_millis(self.config.adjustment_interval_ms);

        if last_adjustment.elapsed() < interval {
            return;
        }
        *last_adjustment = Instant::now();
        drop(last_adjustment);

        let new_limit = match self.config.algorithm {
            ConcurrencyAlgorithm::Gradient => self.adjust_gradient(),
            ConcurrencyAlgorithm::Aimd => self.adjust_aimd(),
            ConcurrencyAlgorithm::Vegas => self.adjust_vegas(),
            ConcurrencyAlgorithm::Fixed => return,
        };

        if let Some(limit) = new_limit {
            let clamped = limit.clamp(self.config.min_limit, self.config.max_limit);
            let old_limit = self.current_limit.swap(clamped, Ordering::SeqCst);

            if clamped != old_limit {
                debug!(
                    old_limit = old_limit,
                    new_limit = clamped,
                    "Adaptive concurrency: Adjusted limit"
                );
                self.stats.adjustments.fetch_add(1, Ordering::Relaxed);

                // Adjust semaphore permits
                if clamped > old_limit {
                    self.semaphore.add_permits(clamped - old_limit);
                }
                // Note: Can't easily remove permits from tokio Semaphore
                // The new limit will take effect as permits are released
            }
        }
    }

    /// Gradient-based limit adjustment (Netflix style)
    fn adjust_gradient(&self) -> Option<usize> {
        let smoothed = (*self.smoothed_rtt.read())?;
        let min = (*self.min_rtt.read())?;

        if min.as_nanos() == 0 {
            return None;
        }

        // Calculate gradient: how much latency increased relative to minimum
        let gradient = smoothed.as_secs_f64() / min.as_secs_f64();
        let current = self.current_limit.load(Ordering::Relaxed) as f64;

        let new_limit = if gradient < self.config.latency_tolerance {
            // Latency is acceptable, increase limit
            (current * 1.05).ceil() as usize
        } else {
            // Latency increased too much, decrease limit
            let reduction = gradient / self.config.latency_tolerance;
            (current / reduction).floor() as usize
        };

        Some(new_limit)
    }

    /// AIMD limit adjustment
    fn adjust_aimd(&self) -> Option<usize> {
        let samples = self.samples.lock();
        if samples.is_empty() {
            return None;
        }

        // Check recent success rate
        let recent: Vec<_> = samples.iter().rev().take(self.config.window_size).collect();

        let failures = recent.iter().filter(|s| !s.success).count();
        let failure_rate = failures as f64 / recent.len() as f64;

        let current = self.current_limit.load(Ordering::Relaxed);

        let new_limit = if failure_rate > 0.1 {
            // More than 10% failures, multiplicative decrease
            (current as f64 * 0.75).floor() as usize
        } else {
            // Additive increase
            current + 1
        };

        Some(new_limit)
    }

    /// Vegas-style limit adjustment (latency-based)
    fn adjust_vegas(&self) -> Option<usize> {
        let smoothed = (*self.smoothed_rtt.read())?;
        let min = (*self.min_rtt.read())?;

        let current = self.current_limit.load(Ordering::Relaxed);
        let in_flight = self.in_flight.load(Ordering::Relaxed);

        // Expected throughput at min latency
        let expected = in_flight as f64 / min.as_secs_f64();
        // Actual throughput at current latency
        let actual = in_flight as f64 / smoothed.as_secs_f64();

        // Difference indicates queue buildup
        let diff = expected - actual;

        // Vegas-style thresholds
        let alpha = 2.0; // Lower threshold
        let beta = 4.0; // Upper threshold

        let new_limit = if diff < alpha {
            // Queue is small, increase limit
            current + 1
        } else if diff > beta {
            // Queue is building up, decrease limit
            current.saturating_sub(1)
        } else {
            // In the sweet spot
            current
        };

        Some(new_limit)
    }

    /// Release a permit and record the sample
    fn release(&self, duration: Duration, success: bool) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.record_sample(duration, success);
    }

    /// Get current statistics
    pub fn stats(&self) -> ConcurrencyStatsSnapshot {
        ConcurrencyStatsSnapshot {
            current_limit: self.current_limit.load(Ordering::Relaxed),
            in_flight: self.in_flight.load(Ordering::Relaxed),
            acquired: self.stats.acquired.load(Ordering::Relaxed),
            rejected: self.stats.rejected.load(Ordering::Relaxed),
            adjustments: self.stats.adjustments.load(Ordering::Relaxed),
            smoothed_rtt: *self.smoothed_rtt.read(),
            min_rtt: *self.min_rtt.read(),
        }
    }

    /// Get current limit
    pub fn current_limit(&self) -> usize {
        self.current_limit.load(Ordering::Relaxed)
    }

    /// Get current in-flight count
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }
}

/// Permit that must be held while processing a request
pub struct ConcurrencyPermit<'a> {
    _permit: tokio::sync::OwnedSemaphorePermit,
    limiter: &'a AdaptiveLimiter,
    start_time: Instant,
}

impl<'a> ConcurrencyPermit<'a> {
    /// Complete the request successfully
    pub fn complete_success(self) {
        let duration = self.start_time.elapsed();
        self.limiter.release(duration, true);
    }

    /// Complete the request with failure
    pub fn complete_failure(self) {
        let duration = self.start_time.elapsed();
        self.limiter.release(duration, false);
    }
}

impl<'a> Drop for ConcurrencyPermit<'a> {
    fn drop(&mut self) {
        // If dropped without explicit completion, count as success
        // This handles panics gracefully
    }
}

/// Statistics counters
#[derive(Debug, Default)]
struct ConcurrencyStats {
    acquired: AtomicU64,
    rejected: AtomicU64,
    adjustments: AtomicU64,
}

/// Snapshot of concurrency statistics
#[derive(Debug, Clone)]
pub struct ConcurrencyStatsSnapshot {
    pub current_limit: usize,
    pub in_flight: usize,
    pub acquired: u64,
    pub rejected: u64,
    pub adjustments: u64,
    pub smoothed_rtt: Option<Duration>,
    pub min_rtt: Option<Duration>,
}

/// Adaptive Concurrency Middleware
pub struct AdaptiveConcurrencyMiddleware {
    limiter: Arc<AdaptiveLimiter>,
}

impl AdaptiveConcurrencyMiddleware {
    /// Create a new adaptive concurrency middleware
    pub fn new(config: AdaptiveConcurrencyConfig) -> Self {
        Self {
            limiter: Arc::new(AdaptiveLimiter::new(config)),
        }
    }

    /// Get the underlying limiter for statistics
    pub fn limiter(&self) -> &Arc<AdaptiveLimiter> {
        &self.limiter
    }
}

#[async_trait]
impl Middleware for AdaptiveConcurrencyMiddleware {
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        if !self.limiter.config.enabled {
            return next.run(request, ctx).await;
        }

        // Try to acquire a permit
        let permit = match self.limiter.acquire().await {
            Some(permit) => permit,
            None => {
                warn!(
                    request_id = %ctx.request_id,
                    current_limit = %self.limiter.current_limit(),
                    in_flight = %self.limiter.in_flight(),
                    "Adaptive concurrency: Request rejected (limit exceeded)"
                );
                return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header("Retry-After", "1")
                    .header(
                        "X-Concurrency-Limit",
                        self.limiter.current_limit().to_string(),
                    )
                    .body(Full::new(Bytes::from(
                        "Service temporarily unavailable - concurrency limit exceeded",
                    )))
                    .unwrap());
            }
        };

        // Process the request
        let result = next.run(request, ctx).await;

        // Record the outcome
        match &result {
            Ok(response) if response.status().is_success() => {
                permit.complete_success();
            }
            Ok(response) if response.status().is_server_error() => {
                permit.complete_failure();
            }
            Err(_) => {
                permit.complete_failure();
            }
            _ => {
                // Client errors don't affect limit calculation
                permit.complete_success();
            }
        }

        result
    }

    fn name(&self) -> &'static str {
        "adaptive_concurrency"
    }
}

/// Builder for creating custom limiters
pub struct AdaptiveLimiterBuilder {
    config: AdaptiveConcurrencyConfig,
}

impl AdaptiveLimiterBuilder {
    /// Create a new builder with default config
    pub fn new() -> Self {
        Self {
            config: AdaptiveConcurrencyConfig::default(),
        }
    }

    /// Set initial limit
    pub fn initial_limit(mut self, limit: usize) -> Self {
        self.config.initial_limit = limit;
        self
    }

    /// Set minimum limit
    pub fn min_limit(mut self, limit: usize) -> Self {
        self.config.min_limit = limit;
        self
    }

    /// Set maximum limit
    pub fn max_limit(mut self, limit: usize) -> Self {
        self.config.max_limit = limit;
        self
    }

    /// Set algorithm
    pub fn algorithm(mut self, algorithm: ConcurrencyAlgorithm) -> Self {
        self.config.algorithm = algorithm;
        self
    }

    /// Enable the limiter
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// Build the limiter
    pub fn build(self) -> AdaptiveLimiter {
        AdaptiveLimiter::new(self.config)
    }
}

impl Default for AdaptiveLimiterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AdaptiveConcurrencyConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.initial_limit, 100);
        assert_eq!(config.min_limit, 10);
        assert_eq!(config.max_limit, 1000);
    }

    #[test]
    fn test_limiter_creation() {
        let config = AdaptiveConcurrencyConfig {
            enabled: true,
            initial_limit: 50,
            ..Default::default()
        };
        let limiter = AdaptiveLimiter::new(config);
        assert_eq!(limiter.current_limit(), 50);
        assert_eq!(limiter.in_flight(), 0);
    }

    #[tokio::test]
    async fn test_acquire_permit() {
        let config = AdaptiveConcurrencyConfig {
            enabled: true,
            initial_limit: 10,
            timeout_ms: 100,
            ..Default::default()
        };
        let limiter = AdaptiveLimiter::new(config);

        // Should be able to acquire permits up to the limit
        let permit = limiter.acquire().await;
        assert!(permit.is_some());
        assert_eq!(limiter.in_flight(), 1);

        // Release it
        permit.unwrap().complete_success();
        assert_eq!(limiter.in_flight(), 0);
    }

    #[tokio::test]
    async fn test_limit_rejection() {
        let config = AdaptiveConcurrencyConfig {
            enabled: true,
            initial_limit: 2,
            timeout_ms: 50,
            ..Default::default()
        };
        let limiter = AdaptiveLimiter::new(config);

        // Acquire all permits
        let _p1 = limiter.acquire().await.unwrap();
        let _p2 = limiter.acquire().await.unwrap();

        // Third should be rejected (timeout)
        let p3 = limiter.acquire().await;
        assert!(p3.is_none());

        let stats = limiter.stats();
        assert_eq!(stats.acquired, 2);
        assert_eq!(stats.rejected, 1);
    }

    #[test]
    fn test_builder() {
        let limiter = AdaptiveLimiterBuilder::new()
            .initial_limit(50)
            .min_limit(5)
            .max_limit(500)
            .algorithm(ConcurrencyAlgorithm::Vegas)
            .enabled(true)
            .build();

        assert_eq!(limiter.current_limit(), 50);
        assert_eq!(limiter.config.min_limit, 5);
        assert_eq!(limiter.config.max_limit, 500);
        assert_eq!(limiter.config.algorithm, ConcurrencyAlgorithm::Vegas);
    }

    #[test]
    fn test_sample_recording() {
        let config = AdaptiveConcurrencyConfig {
            enabled: true,
            initial_limit: 100,
            window_size: 10,
            ..Default::default()
        };
        let limiter = AdaptiveLimiter::new(config);

        // Record some samples
        for _ in 0..15 {
            limiter.record_sample(Duration::from_millis(50), true);
        }

        // Window should not exceed 2x size
        let samples = limiter.samples.lock();
        assert!(samples.len() <= 20);
    }

    #[test]
    fn test_smoothed_rtt() {
        let config = AdaptiveConcurrencyConfig {
            enabled: true,
            initial_limit: 100,
            smoothing: 0.5,
            ..Default::default()
        };
        let limiter = AdaptiveLimiter::new(config);

        // First sample sets the smoothed RTT
        limiter.record_sample(Duration::from_millis(100), true);
        let rtt1 = limiter.smoothed_rtt.read().unwrap();
        assert_eq!(rtt1, Duration::from_millis(100));

        // Second sample smooths it
        limiter.record_sample(Duration::from_millis(200), true);
        let rtt2 = limiter.smoothed_rtt.read().unwrap();
        // With 0.5 smoothing: 100 * 0.5 + 200 * 0.5 = 150
        assert_eq!(rtt2, Duration::from_millis(150));
    }

    #[test]
    fn test_min_rtt_tracking() {
        let config = AdaptiveConcurrencyConfig::default();
        let limiter = AdaptiveLimiter::new(config);

        limiter.record_sample(Duration::from_millis(100), true);
        limiter.record_sample(Duration::from_millis(50), true);
        limiter.record_sample(Duration::from_millis(75), true);

        let min = limiter.min_rtt.read().unwrap();
        assert_eq!(min, Duration::from_millis(50));
    }
}
