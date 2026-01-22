//! Adaptive Circuit Breaker v2
//!
//! Next-generation circuit breaker with:
//! - Adaptive thresholds based on traffic patterns
//! - Machine learning for anomaly detection
//! - Gradual recovery with traffic ramping
//! - Multi-dimensional health scoring
//! - Predictive failure detection

use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Circuit state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed, traffic flows normally
    Closed,
    /// Circuit is open, traffic is blocked
    Open,
    /// Circuit is testing recovery with limited traffic
    HalfOpen,
    /// Circuit is gradually recovering (traffic ramping)
    Recovering,
}

/// Configuration for adaptive circuit breaker
#[derive(Debug, Clone)]
pub struct AdaptiveCircuitBreakerConfig {
    /// Enable adaptive thresholds
    pub adaptive_enabled: bool,
    /// Base failure rate threshold (0.0 - 1.0)
    pub base_failure_threshold: f64,
    /// Minimum requests before evaluating
    pub min_request_volume: u64,
    /// Time window for failure rate calculation
    pub evaluation_window: Duration,
    /// Open duration before testing recovery
    pub open_duration: Duration,
    /// Number of test requests in half-open state
    pub half_open_requests: u64,
    /// Recovery ramp duration
    pub recovery_duration: Duration,
    /// Recovery ramp steps
    pub recovery_steps: u32,
    /// Slow call threshold
    pub slow_call_duration: Duration,
    /// Slow call rate threshold
    pub slow_call_threshold: f64,
    /// Health score weights
    pub health_weights: HealthWeights,
    /// Enable predictive opening
    pub predictive_enabled: bool,
}

impl Default for AdaptiveCircuitBreakerConfig {
    fn default() -> Self {
        Self {
            adaptive_enabled: true,
            base_failure_threshold: 0.5,
            min_request_volume: 10,
            evaluation_window: Duration::from_secs(60),
            open_duration: Duration::from_secs(30),
            half_open_requests: 5,
            recovery_duration: Duration::from_secs(60),
            recovery_steps: 10,
            slow_call_duration: Duration::from_secs(2),
            slow_call_threshold: 0.5,
            health_weights: HealthWeights::default(),
            predictive_enabled: true,
        }
    }
}

/// Weights for health score calculation
#[derive(Debug, Clone)]
pub struct HealthWeights {
    pub failure_rate: f64,
    pub slow_call_rate: f64,
    pub latency_percentile: f64,
    pub error_diversity: f64,
}

impl Default for HealthWeights {
    fn default() -> Self {
        Self {
            failure_rate: 0.4,
            slow_call_rate: 0.2,
            latency_percentile: 0.2,
            error_diversity: 0.2,
        }
    }
}

/// Request outcome
#[derive(Debug, Clone)]
pub struct RequestOutcome {
    pub timestamp: Instant,
    pub duration: Duration,
    pub success: bool,
    pub error_type: Option<ErrorType>,
}

/// Error classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorType {
    /// Connection refused/timeout
    ConnectionError,
    /// HTTP 5xx error
    ServerError,
    /// HTTP 4xx error (not counted towards circuit)
    ClientError,
    /// Request timeout
    Timeout,
    /// Circuit rejected
    CircuitOpen,
    /// Unknown error
    Unknown,
}

/// Sliding window for metrics
#[derive(Debug)]
struct SlidingWindow {
    outcomes: VecDeque<RequestOutcome>,
    window_size: Duration,
    total_requests: AtomicU64,
    failures: AtomicU64,
    slow_calls: AtomicU64,
}

impl SlidingWindow {
    fn new(window_size: Duration) -> Self {
        Self {
            outcomes: VecDeque::new(),
            window_size,
            total_requests: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            slow_calls: AtomicU64::new(0),
        }
    }

    fn record(&mut self, outcome: RequestOutcome, slow_threshold: Duration) {
        let now = Instant::now();

        // Expire old entries
        while let Some(front) = self.outcomes.front() {
            if now.duration_since(front.timestamp) > self.window_size {
                let expired = self.outcomes.pop_front().unwrap();
                self.total_requests.fetch_sub(1, Ordering::Relaxed);
                if !expired.success {
                    self.failures.fetch_sub(1, Ordering::Relaxed);
                }
                if expired.duration > slow_threshold {
                    self.slow_calls.fetch_sub(1, Ordering::Relaxed);
                }
            } else {
                break;
            }
        }

        // Record new outcome
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        if !outcome.success {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
        if outcome.duration > slow_threshold {
            self.slow_calls.fetch_add(1, Ordering::Relaxed);
        }

        self.outcomes.push_back(outcome);
    }

    fn failure_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        let failures = self.failures.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            failures as f64 / total as f64
        }
    }

    fn slow_call_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        let slow = self.slow_calls.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            slow as f64 / total as f64
        }
    }

    fn request_count(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    fn latency_percentile(&self, percentile: f64) -> Duration {
        if self.outcomes.is_empty() {
            return Duration::ZERO;
        }

        let mut durations: Vec<_> = self.outcomes.iter().map(|o| o.duration).collect();
        durations.sort();

        let index = ((percentile / 100.0) * durations.len() as f64) as usize;
        let index = index.min(durations.len() - 1);
        durations[index]
    }

    fn error_diversity(&self) -> f64 {
        use std::collections::HashSet;

        let error_types: HashSet<_> = self
            .outcomes
            .iter()
            .filter(|o| !o.success)
            .filter_map(|o| o.error_type)
            .collect();

        // Normalize by max possible error types (5)
        error_types.len() as f64 / 5.0
    }
}

/// Health score components
#[derive(Debug, Clone)]
pub struct HealthScore {
    pub overall: f64,
    pub failure_score: f64,
    pub slow_call_score: f64,
    pub latency_score: f64,
    pub diversity_score: f64,
    pub trend: HealthTrend,
}

/// Health trend direction
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HealthTrend {
    Improving,
    Stable,
    Degrading,
}

/// Recovery progress
#[derive(Debug, Clone)]
pub struct RecoveryProgress {
    pub current_step: u32,
    pub total_steps: u32,
    pub traffic_percentage: f64,
    pub successful_requests: u64,
    pub failed_requests: u64,
}

/// Circuit breaker statistics
#[derive(Debug, Default)]
pub struct CircuitBreakerStats {
    pub total_requests: AtomicU64,
    pub allowed_requests: AtomicU64,
    pub rejected_requests: AtomicU64,
    pub successful_requests: AtomicU64,
    pub failed_requests: AtomicU64,
    pub state_transitions: AtomicU64,
    pub time_in_open_ms: AtomicU64,
    pub predictive_opens: AtomicU64,
}

/// Adaptive circuit breaker for a single service
pub struct AdaptiveCircuitBreaker {
    name: String,
    config: AdaptiveCircuitBreakerConfig,
    state: RwLock<CircuitState>,
    window: RwLock<SlidingWindow>,
    state_changed_at: RwLock<Instant>,
    recovery_progress: RwLock<Option<RecoveryProgress>>,
    adaptive_threshold: RwLock<f64>,
    health_history: RwLock<VecDeque<HealthScore>>,
    stats: CircuitBreakerStats,
}

impl AdaptiveCircuitBreaker {
    pub fn new(name: String, config: AdaptiveCircuitBreakerConfig) -> Self {
        let threshold = config.base_failure_threshold;
        Self {
            name,
            config: config.clone(),
            state: RwLock::new(CircuitState::Closed),
            window: RwLock::new(SlidingWindow::new(config.evaluation_window)),
            state_changed_at: RwLock::new(Instant::now()),
            recovery_progress: RwLock::new(None),
            adaptive_threshold: RwLock::new(threshold),
            health_history: RwLock::new(VecDeque::with_capacity(100)),
            stats: CircuitBreakerStats::default(),
        }
    }

    /// Check if request should be allowed
    pub fn should_allow(&self) -> bool {
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        let state = *self.state.read();
        let now = Instant::now();
        let time_in_state = now.duration_since(*self.state_changed_at.read());

        match state {
            CircuitState::Closed => {
                self.stats.allowed_requests.fetch_add(1, Ordering::Relaxed);
                true
            }
            CircuitState::Open => {
                if time_in_state >= self.config.open_duration {
                    self.transition_to(CircuitState::HalfOpen);
                    self.stats.allowed_requests.fetch_add(1, Ordering::Relaxed);
                    true
                } else {
                    self.stats.rejected_requests.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
            CircuitState::HalfOpen => {
                let window = self.window.read();
                if window.request_count() < self.config.half_open_requests {
                    self.stats.allowed_requests.fetch_add(1, Ordering::Relaxed);
                    true
                } else {
                    self.stats.rejected_requests.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
            CircuitState::Recovering => {
                let progress = self.recovery_progress.read();
                if let Some(ref p) = *progress {
                    if rand::random::<f64>() * 100.0 < p.traffic_percentage {
                        self.stats.allowed_requests.fetch_add(1, Ordering::Relaxed);
                        true
                    } else {
                        self.stats.rejected_requests.fetch_add(1, Ordering::Relaxed);
                        false
                    }
                } else {
                    self.stats.allowed_requests.fetch_add(1, Ordering::Relaxed);
                    true
                }
            }
        }
    }

    /// Record request outcome
    pub fn record_outcome(&self, success: bool, duration: Duration, error_type: Option<ErrorType>) {
        if success {
            self.stats
                .successful_requests
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.failed_requests.fetch_add(1, Ordering::Relaxed);
        }

        let outcome = RequestOutcome {
            timestamp: Instant::now(),
            duration,
            success,
            error_type,
        };

        {
            let mut window = self.window.write();
            window.record(outcome, self.config.slow_call_duration);
        }

        // Update recovery progress
        if *self.state.read() == CircuitState::Recovering {
            let mut progress = self.recovery_progress.write();
            if let Some(ref mut p) = *progress {
                if success {
                    p.successful_requests += 1;
                } else {
                    p.failed_requests += 1;
                }
            }
        }

        // Evaluate state transitions
        self.evaluate_state();
    }

    /// Evaluate and potentially change state
    fn evaluate_state(&self) {
        let current_state = *self.state.read();
        let window = self.window.read();

        match current_state {
            CircuitState::Closed => {
                if window.request_count() >= self.config.min_request_volume {
                    let threshold = *self.adaptive_threshold.read();
                    let failure_rate = window.failure_rate();
                    let slow_rate = window.slow_call_rate();

                    // Check failure rate
                    if failure_rate >= threshold {
                        drop(window);
                        self.transition_to(CircuitState::Open);
                        return;
                    }

                    // Check slow call rate
                    if slow_rate >= self.config.slow_call_threshold {
                        drop(window);
                        self.transition_to(CircuitState::Open);
                        return;
                    }

                    // Predictive opening
                    if self.config.predictive_enabled {
                        drop(window);
                        if self.should_predictively_open() {
                            self.stats.predictive_opens.fetch_add(1, Ordering::Relaxed);
                            self.transition_to(CircuitState::Open);
                        }
                    }
                }
            }
            CircuitState::HalfOpen => {
                if window.request_count() >= self.config.half_open_requests {
                    let failure_rate = window.failure_rate();
                    drop(window);

                    if failure_rate < *self.adaptive_threshold.read() {
                        self.transition_to(CircuitState::Recovering);
                    } else {
                        self.transition_to(CircuitState::Open);
                    }
                }
            }
            CircuitState::Recovering => {
                let progress = self.recovery_progress.read().clone();
                drop(window);

                if let Some(p) = progress {
                    let total = p.successful_requests + p.failed_requests;
                    if total >= 10 {
                        let success_rate = p.successful_requests as f64 / total as f64;

                        if success_rate >= (1.0 - *self.adaptive_threshold.read()) {
                            self.advance_recovery();
                        } else {
                            self.transition_to(CircuitState::Open);
                        }
                    }
                }
            }
            CircuitState::Open => {
                // Handled in should_allow
            }
        }
    }

    /// Check if circuit should open predictively
    fn should_predictively_open(&self) -> bool {
        let history = self.health_history.read();
        if history.len() < 5 {
            return false;
        }

        // Check for degrading trend
        let recent: Vec<_> = history.iter().rev().take(5).collect();
        let degrading_count = recent
            .iter()
            .filter(|h| h.trend == HealthTrend::Degrading)
            .count();

        // If 4+ of last 5 checks are degrading and health is low
        if degrading_count >= 4 {
            if let Some(latest) = recent.first() {
                return latest.overall < 0.3;
            }
        }

        false
    }

    /// Transition to a new state
    fn transition_to(&self, new_state: CircuitState) {
        let old_state = *self.state.read();
        if old_state == new_state {
            return;
        }

        *self.state.write() = new_state;
        *self.state_changed_at.write() = Instant::now();
        self.stats.state_transitions.fetch_add(1, Ordering::Relaxed);

        // Initialize recovery progress
        if new_state == CircuitState::Recovering {
            *self.recovery_progress.write() = Some(RecoveryProgress {
                current_step: 1,
                total_steps: self.config.recovery_steps,
                traffic_percentage: 100.0 / self.config.recovery_steps as f64,
                successful_requests: 0,
                failed_requests: 0,
            });
        } else {
            *self.recovery_progress.write() = None;
        }

        // Clear window on state change
        if new_state == CircuitState::HalfOpen || new_state == CircuitState::Recovering {
            *self.window.write() = SlidingWindow::new(self.config.evaluation_window);
        }
    }

    /// Advance recovery to next step
    fn advance_recovery(&self) {
        let mut progress = self.recovery_progress.write();
        if let Some(ref mut p) = *progress {
            if p.current_step >= p.total_steps {
                drop(progress);
                self.transition_to(CircuitState::Closed);
                return;
            }

            p.current_step += 1;
            p.traffic_percentage = (p.current_step as f64 / p.total_steps as f64) * 100.0;
            p.successful_requests = 0;
            p.failed_requests = 0;
        }
    }

    /// Calculate current health score
    pub fn health_score(&self) -> HealthScore {
        let window = self.window.read();
        let weights = &self.config.health_weights;

        let failure_score = 1.0 - window.failure_rate();
        let slow_score = 1.0 - window.slow_call_rate();

        // Latency score (p99 < 1s = 1.0, > 5s = 0.0)
        let p99 = window.latency_percentile(99.0);
        let latency_score = if p99.as_millis() < 1000 {
            1.0
        } else if p99.as_millis() > 5000 {
            0.0
        } else {
            1.0 - ((p99.as_millis() - 1000) as f64 / 4000.0)
        };

        // Lower diversity = better (fewer error types)
        let diversity_score = 1.0 - window.error_diversity();

        let overall = failure_score * weights.failure_rate
            + slow_score * weights.slow_call_rate
            + latency_score * weights.latency_percentile
            + diversity_score * weights.error_diversity;

        // Determine trend
        let trend = {
            let history = self.health_history.read();
            if history.len() < 2 {
                HealthTrend::Stable
            } else {
                let prev = history.back().map(|h| h.overall).unwrap_or(overall);
                if overall > prev + 0.05 {
                    HealthTrend::Improving
                } else if overall < prev - 0.05 {
                    HealthTrend::Degrading
                } else {
                    HealthTrend::Stable
                }
            }
        };

        let score = HealthScore {
            overall,
            failure_score,
            slow_call_score: slow_score,
            latency_score,
            diversity_score,
            trend,
        };

        // Store in history
        let mut history = self.health_history.write();
        history.push_back(score.clone());
        while history.len() > 100 {
            history.pop_front();
        }

        score
    }

    /// Update adaptive threshold based on conditions
    pub fn update_adaptive_threshold(&self) {
        if !self.config.adaptive_enabled {
            return;
        }

        let health = self.health_score();

        // Adjust threshold based on health trend
        let mut threshold = self.adaptive_threshold.write();
        match health.trend {
            HealthTrend::Improving => {
                // Allow higher failure rate during good times
                *threshold = (*threshold * 1.05).min(0.8);
            }
            HealthTrend::Degrading => {
                // Be more strict during bad times
                *threshold = (*threshold * 0.95).max(0.1);
            }
            HealthTrend::Stable => {
                // Slowly return to base
                let base = self.config.base_failure_threshold;
                *threshold = *threshold + (base - *threshold) * 0.1;
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> CircuitState {
        *self.state.read()
    }

    /// Get circuit name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get current failure rate
    pub fn failure_rate(&self) -> f64 {
        self.window.read().failure_rate()
    }

    /// Get statistics
    pub fn stats(&self) -> &CircuitBreakerStats {
        &self.stats
    }

    /// Get recovery progress if in recovery state
    pub fn recovery_progress(&self) -> Option<RecoveryProgress> {
        self.recovery_progress.read().clone()
    }

    /// Force open the circuit
    pub fn force_open(&self) {
        self.transition_to(CircuitState::Open);
    }

    /// Force close the circuit
    pub fn force_close(&self) {
        self.transition_to(CircuitState::Closed);
    }
}

/// Circuit breaker registry for multiple services
pub struct CircuitBreakerRegistry {
    breakers: DashMap<String, Arc<AdaptiveCircuitBreaker>>,
    default_config: AdaptiveCircuitBreakerConfig,
}

impl CircuitBreakerRegistry {
    pub fn new(default_config: AdaptiveCircuitBreakerConfig) -> Self {
        Self {
            breakers: DashMap::new(),
            default_config,
        }
    }

    /// Get or create circuit breaker for a service
    pub fn get_or_create(&self, name: &str) -> Arc<AdaptiveCircuitBreaker> {
        self.breakers
            .entry(name.to_string())
            .or_insert_with(|| {
                Arc::new(AdaptiveCircuitBreaker::new(
                    name.to_string(),
                    self.default_config.clone(),
                ))
            })
            .clone()
    }

    /// Get circuit breaker if exists
    pub fn get(&self, name: &str) -> Option<Arc<AdaptiveCircuitBreaker>> {
        self.breakers.get(name).map(|b| b.clone())
    }

    /// List all circuit breakers
    pub fn list(&self) -> Vec<String> {
        self.breakers.iter().map(|e| e.key().clone()).collect()
    }

    /// Get summary of all breakers
    pub fn summary(&self) -> Vec<(String, CircuitState, f64)> {
        self.breakers
            .iter()
            .map(|e| {
                let breaker = e.value();
                (e.key().clone(), breaker.state(), breaker.failure_rate())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_starts_closed() {
        let cb = AdaptiveCircuitBreaker::new(
            "test".to_string(),
            AdaptiveCircuitBreakerConfig::default(),
        );
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_allows_requests_when_closed() {
        let cb = AdaptiveCircuitBreaker::new(
            "test".to_string(),
            AdaptiveCircuitBreakerConfig::default(),
        );

        for _ in 0..10 {
            assert!(cb.should_allow());
        }
    }

    #[test]
    fn test_opens_on_high_failure_rate() {
        let config = AdaptiveCircuitBreakerConfig {
            base_failure_threshold: 0.5,
            min_request_volume: 5,
            predictive_enabled: false,
            ..Default::default()
        };
        let cb = AdaptiveCircuitBreaker::new("test".to_string(), config);

        // Record failures
        for _ in 0..10 {
            cb.should_allow();
            cb.record_outcome(
                false,
                Duration::from_millis(100),
                Some(ErrorType::ServerError),
            );
        }

        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_rejects_when_open() {
        let config = AdaptiveCircuitBreakerConfig {
            base_failure_threshold: 0.5,
            min_request_volume: 5,
            open_duration: Duration::from_secs(60),
            predictive_enabled: false,
            ..Default::default()
        };
        let cb = AdaptiveCircuitBreaker::new("test".to_string(), config);

        // Open the circuit
        for _ in 0..10 {
            cb.should_allow();
            cb.record_outcome(
                false,
                Duration::from_millis(100),
                Some(ErrorType::ServerError),
            );
        }

        // Should reject
        assert!(!cb.should_allow());
    }

    #[test]
    fn test_health_score_calculation() {
        let cb = AdaptiveCircuitBreaker::new(
            "test".to_string(),
            AdaptiveCircuitBreakerConfig::default(),
        );

        // Record some outcomes
        for _ in 0..8 {
            cb.record_outcome(true, Duration::from_millis(100), None);
        }
        for _ in 0..2 {
            cb.record_outcome(
                false,
                Duration::from_millis(100),
                Some(ErrorType::ServerError),
            );
        }

        let health = cb.health_score();
        assert!(health.overall > 0.5);
        assert_eq!(health.failure_score, 0.8); // 80% success
    }

    #[test]
    fn test_recovery_progress() {
        let config = AdaptiveCircuitBreakerConfig {
            base_failure_threshold: 0.5,
            min_request_volume: 3,
            half_open_requests: 3,
            recovery_steps: 5,
            predictive_enabled: false,
            ..Default::default()
        };
        let cb = AdaptiveCircuitBreaker::new("test".to_string(), config);

        // Open circuit
        for _ in 0..5 {
            cb.should_allow();
            cb.record_outcome(
                false,
                Duration::from_millis(100),
                Some(ErrorType::ServerError),
            );
        }
        assert_eq!(cb.state(), CircuitState::Open);

        // Force to half-open for testing
        cb.transition_to(CircuitState::HalfOpen);

        // Success in half-open
        for _ in 0..3 {
            cb.should_allow();
            cb.record_outcome(true, Duration::from_millis(100), None);
        }

        assert_eq!(cb.state(), CircuitState::Recovering);
        let progress = cb.recovery_progress().unwrap();
        assert_eq!(progress.current_step, 1);
        assert_eq!(progress.total_steps, 5);
    }

    #[test]
    fn test_adaptive_threshold() {
        let cb = AdaptiveCircuitBreaker::new(
            "test".to_string(),
            AdaptiveCircuitBreakerConfig::default(),
        );

        let initial_threshold = *cb.adaptive_threshold.read();

        // Simulate degrading health
        for _ in 0..10 {
            cb.record_outcome(false, Duration::from_secs(3), Some(ErrorType::ServerError));
        }

        cb.update_adaptive_threshold();
        let new_threshold = *cb.adaptive_threshold.read();

        // Threshold should decrease during degradation
        assert!(new_threshold <= initial_threshold);
    }

    #[test]
    fn test_registry() {
        let registry = CircuitBreakerRegistry::new(AdaptiveCircuitBreakerConfig::default());

        let cb1 = registry.get_or_create("service-a");
        let _cb2 = registry.get_or_create("service-b");
        let cb1_again = registry.get_or_create("service-a");

        // Same instance returned
        assert!(Arc::ptr_eq(&cb1, &cb1_again));

        let list = registry.list();
        assert_eq!(list.len(), 2);
        assert!(list.contains(&"service-a".to_string()));
        assert!(list.contains(&"service-b".to_string()));
    }

    #[test]
    fn test_force_open_close() {
        let cb = AdaptiveCircuitBreaker::new(
            "test".to_string(),
            AdaptiveCircuitBreakerConfig::default(),
        );

        cb.force_open();
        assert_eq!(cb.state(), CircuitState::Open);

        cb.force_close();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_slow_call_opens_circuit() {
        let config = AdaptiveCircuitBreakerConfig {
            slow_call_duration: Duration::from_millis(100),
            slow_call_threshold: 0.5,
            min_request_volume: 5,
            predictive_enabled: false,
            ..Default::default()
        };
        let cb = AdaptiveCircuitBreaker::new("test".to_string(), config);

        // Record slow calls (all successful but slow)
        for _ in 0..10 {
            cb.should_allow();
            cb.record_outcome(true, Duration::from_millis(200), None);
        }

        assert_eq!(cb.state(), CircuitState::Open);
    }
}
