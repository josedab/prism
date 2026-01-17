//! Service Level Objective (SLO) Tracking
//!
//! Provides comprehensive SLO tracking and error budget management:
//!
//! - **Availability SLOs**: Success rate targets (e.g., 99.9% availability)
//! - **Latency SLOs**: Percentile latency targets (e.g., P99 < 100ms)
//! - **Error Budget**: Remaining allowance for failures within SLO window
//! - **Burn Rate**: Rate at which error budget is being consumed
//! - **Multi-window SLO**: Support for rolling windows (hourly, daily, monthly)
//!
//! ## Example Configuration
//!
//! ```yaml
//! observability:
//!   slo:
//!     enabled: true
//!     targets:
//!       - name: "api-availability"
//!         type: availability
//!         target: 0.999  # 99.9% success rate
//!         window: 30d
//!         routes:
//!           - "/api/*"
//!
//!       - name: "api-latency-p99"
//!         type: latency
//!         percentile: 0.99
//!         threshold_ms: 100
//!         window: 7d
//!         routes:
//!           - "/api/*"
//! ```

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

/// SLO configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloConfig {
    /// Whether SLO tracking is enabled
    #[serde(default)]
    pub enabled: bool,

    /// SLO targets
    #[serde(default)]
    pub targets: Vec<SloTarget>,

    /// Alerting configuration
    #[serde(default)]
    pub alerting: Option<SloAlertingConfig>,

    /// Burn rate windows for multi-window alerting
    #[serde(default)]
    pub burn_rate_windows: Vec<BurnRateWindow>,
}

impl Default for SloConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            targets: Vec::new(),
            alerting: None,
            burn_rate_windows: vec![
                BurnRateWindow {
                    name: "fast".to_string(),
                    short_window_minutes: 5,
                    long_window_minutes: 60,
                    burn_rate_threshold: 14.4, // Consume 30-day budget in 2 days
                },
                BurnRateWindow {
                    name: "slow".to_string(),
                    short_window_minutes: 30,
                    long_window_minutes: 360,
                    burn_rate_threshold: 6.0, // Consume 30-day budget in 5 days
                },
            ],
        }
    }
}

/// Individual SLO target definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloTarget {
    /// Name of the SLO (e.g., "api-availability")
    pub name: String,

    /// Type of SLO
    #[serde(rename = "type")]
    pub slo_type: SloType,

    /// Target value (0.0 to 1.0 for availability, milliseconds for latency)
    pub target: f64,

    /// SLO window (e.g., "30d", "7d", "1h")
    #[serde(default = "default_window")]
    pub window: String,

    /// Routes to track (glob patterns)
    #[serde(default)]
    pub routes: Vec<String>,

    /// Methods to track (empty = all methods)
    #[serde(default)]
    pub methods: Vec<String>,

    /// For latency SLOs: the percentile to track
    #[serde(default = "default_percentile")]
    pub percentile: f64,

    /// For latency SLOs: threshold in milliseconds
    #[serde(default)]
    pub threshold_ms: u64,

    /// Labels for this SLO
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

fn default_window() -> String {
    "30d".to_string()
}

fn default_percentile() -> f64 {
    0.99
}

/// Type of SLO
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SloType {
    /// Availability SLO: percentage of successful requests
    Availability,
    /// Latency SLO: percentage of requests under threshold
    Latency,
    /// Throughput SLO: requests per second target
    Throughput,
    /// Error rate SLO: maximum error rate allowed
    ErrorRate,
}

/// Burn rate window configuration for multi-window alerting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnRateWindow {
    /// Name of this window (e.g., "fast", "slow")
    pub name: String,
    /// Short window duration in minutes
    pub short_window_minutes: u64,
    /// Long window duration in minutes
    pub long_window_minutes: u64,
    /// Burn rate threshold to trigger alert
    pub burn_rate_threshold: f64,
}

/// Alerting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloAlertingConfig {
    /// Enable alerting
    #[serde(default)]
    pub enabled: bool,
    /// Webhook URL for alerts
    pub webhook_url: Option<String>,
    /// Alert on error budget exhaustion percentage (e.g., 0.5 = 50% consumed)
    #[serde(default = "default_alert_threshold")]
    pub budget_alert_threshold: f64,
    /// Cool-down period between alerts (seconds)
    #[serde(default = "default_cooldown")]
    pub alert_cooldown_secs: u64,
}

fn default_alert_threshold() -> f64 {
    0.5
}

fn default_cooldown() -> u64 {
    300
}

/// SLO tracking manager
pub struct SloTracker {
    /// Configuration
    config: SloConfig,
    /// Tracked SLOs
    slos: Arc<RwLock<HashMap<String, SloState>>>,
    /// Request samples for latency percentile calculation
    latency_samples: Arc<RwLock<HashMap<String, LatencySampler>>>,
    /// Global statistics
    stats: Arc<SloStats>,
}

/// State for a single SLO
#[derive(Debug, Clone)]
pub struct SloState {
    /// SLO target configuration
    pub target: SloTarget,
    /// Total requests in current window
    pub total_requests: u64,
    /// Successful requests (for availability) or requests within threshold (for latency)
    pub good_requests: u64,
    /// Window start time
    pub window_start: Instant,
    /// Window duration
    pub window_duration: Duration,
    /// Current success rate / SLI
    pub current_sli: f64,
    /// Error budget remaining (0.0 to 1.0)
    pub error_budget_remaining: f64,
    /// Burn rate (error budget consumption rate)
    pub burn_rate: f64,
    /// Time series for burn rate calculation
    pub time_series: VecDeque<SloSample>,
    /// Last alert time
    pub last_alert: Option<Instant>,
}

/// A sample point for SLO time series
#[derive(Debug, Clone)]
pub struct SloSample {
    /// Timestamp
    pub timestamp: Instant,
    /// Total requests at this point
    pub total: u64,
    /// Good requests at this point
    pub good: u64,
}

/// Latency sampler using reservoir sampling
#[derive(Debug, Clone)]
pub struct LatencySampler {
    /// Sample buffer (sorted for percentile calculation)
    samples: Vec<u64>,
    /// Maximum samples to keep
    max_samples: usize,
    /// Total samples seen
    total_count: u64,
    /// Sample index for reservoir sampling
    sample_index: u64,
}

impl LatencySampler {
    pub fn new(max_samples: usize) -> Self {
        Self {
            samples: Vec::with_capacity(max_samples),
            max_samples,
            total_count: 0,
            sample_index: 0,
        }
    }

    pub fn add_sample(&mut self, latency_ms: u64) {
        self.total_count += 1;
        self.sample_index += 1;

        if self.samples.len() < self.max_samples {
            self.samples.push(latency_ms);
        } else {
            // Reservoir sampling
            let idx = rand::random::<usize>() % self.sample_index as usize;
            if idx < self.max_samples {
                self.samples[idx] = latency_ms;
            }
        }
    }

    pub fn percentile(&self, p: f64) -> Option<u64> {
        if self.samples.is_empty() {
            return None;
        }

        let mut sorted = self.samples.clone();
        sorted.sort_unstable();

        let idx = ((sorted.len() as f64 * p).ceil() as usize).saturating_sub(1);
        Some(sorted[idx.min(sorted.len() - 1)])
    }

    pub fn reset(&mut self) {
        self.samples.clear();
        self.total_count = 0;
        self.sample_index = 0;
    }
}

/// Global SLO statistics
pub struct SloStats {
    /// Total requests tracked
    pub total_requests: AtomicU64,
    /// Total good requests
    pub good_requests: AtomicU64,
    /// Total error budget alerts fired
    pub alerts_fired: AtomicU64,
    /// Current burn rate alerts active
    pub active_burn_rate_alerts: AtomicU64,
}

impl SloStats {
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            good_requests: AtomicU64::new(0),
            alerts_fired: AtomicU64::new(0),
            active_burn_rate_alerts: AtomicU64::new(0),
        }
    }
}

impl Default for SloStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of SLO state for export
#[derive(Debug, Clone, Serialize)]
pub struct SloSnapshot {
    /// SLO name
    pub name: String,
    /// SLO type
    pub slo_type: SloType,
    /// Target value
    pub target: f64,
    /// Current SLI (Service Level Indicator)
    pub current_sli: f64,
    /// Whether SLO is being met
    pub slo_met: bool,
    /// Error budget remaining (0.0 to 1.0)
    pub error_budget_remaining: f64,
    /// Error budget consumed (0.0 to 1.0)
    pub error_budget_consumed: f64,
    /// Current burn rate
    pub burn_rate: f64,
    /// Estimated time to exhaust error budget (seconds)
    pub time_to_exhaustion_secs: Option<u64>,
    /// Total requests in window
    pub total_requests: u64,
    /// Good requests in window
    pub good_requests: u64,
    /// Window duration in seconds
    pub window_secs: u64,
}

/// SLO alert
#[derive(Debug, Clone, Serialize)]
pub struct SloAlert {
    /// Alert timestamp
    pub timestamp: u64,
    /// SLO name
    pub slo_name: String,
    /// Alert type
    pub alert_type: SloAlertType,
    /// Current SLI
    pub current_sli: f64,
    /// Target SLI
    pub target_sli: f64,
    /// Error budget remaining
    pub error_budget_remaining: f64,
    /// Burn rate
    pub burn_rate: f64,
    /// Severity
    pub severity: AlertSeverity,
    /// Message
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SloAlertType {
    /// Error budget threshold exceeded
    ErrorBudgetThreshold,
    /// High burn rate detected
    BurnRate,
    /// SLO violation (SLI below target)
    SloViolation,
    /// Error budget exhausted
    BudgetExhausted,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl SloTracker {
    /// Create a new SLO tracker
    pub fn new(config: SloConfig) -> Self {
        let mut slos = HashMap::new();

        // Initialize SLO states
        for target in &config.targets {
            let window_duration = parse_duration(&target.window).unwrap_or(Duration::from_secs(30 * 24 * 3600));

            slos.insert(
                target.name.clone(),
                SloState {
                    target: target.clone(),
                    total_requests: 0,
                    good_requests: 0,
                    window_start: Instant::now(),
                    window_duration,
                    current_sli: 1.0,
                    error_budget_remaining: 1.0,
                    burn_rate: 0.0,
                    time_series: VecDeque::with_capacity(1440), // Store up to 24h of minute samples
                    last_alert: None,
                },
            );
        }

        Self {
            config,
            slos: Arc::new(RwLock::new(slos)),
            latency_samples: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(SloStats::new()),
        }
    }

    /// Record a request for SLO tracking
    pub fn record_request(
        &self,
        route: &str,
        method: &str,
        status: u16,
        latency_ms: u64,
    ) {
        if !self.config.enabled {
            return;
        }

        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        let is_success = (200..400).contains(&status);
        if is_success {
            self.stats.good_requests.fetch_add(1, Ordering::Relaxed);
        }

        let mut slos = self.slos.write();

        for (name, state) in slos.iter_mut() {
            // Check if this request matches the SLO's route/method filters
            if !self.matches_filters(&state.target, route, method) {
                continue;
            }

            // Check for window rollover
            if state.window_start.elapsed() >= state.window_duration {
                self.reset_window(state);
            }

            state.total_requests += 1;

            match state.target.slo_type {
                SloType::Availability | SloType::ErrorRate => {
                    if is_success {
                        state.good_requests += 1;
                    }
                }
                SloType::Latency => {
                    if latency_ms <= state.target.threshold_ms {
                        state.good_requests += 1;
                    }

                    // Record latency sample
                    let mut samples = self.latency_samples.write();
                    samples
                        .entry(name.clone())
                        .or_insert_with(|| LatencySampler::new(10000))
                        .add_sample(latency_ms);
                }
                SloType::Throughput => {
                    // Throughput SLOs track requests per second differently
                    state.good_requests += 1;
                }
            }

            // Update SLI and error budget
            self.update_sli_and_budget(state);

            // Add time series sample (every minute)
            if state.time_series.is_empty()
                || state.time_series.back().map_or(true, |s| {
                    s.timestamp.elapsed() >= Duration::from_secs(60)
                })
            {
                state.time_series.push_back(SloSample {
                    timestamp: Instant::now(),
                    total: state.total_requests,
                    good: state.good_requests,
                });

                // Keep only last 24 hours of samples
                while state.time_series.len() > 1440 {
                    state.time_series.pop_front();
                }
            }

            // Update burn rate
            self.update_burn_rate(state);
        }
    }

    /// Check if request matches SLO filters
    fn matches_filters(&self, target: &SloTarget, route: &str, method: &str) -> bool {
        // Check method filter
        if !target.methods.is_empty() && !target.methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
            return false;
        }

        // Check route filter
        if target.routes.is_empty() {
            return true;
        }

        for pattern in &target.routes {
            if Self::matches_glob(pattern, route) {
                return true;
            }
        }

        false
    }

    /// Simple glob matching for routes
    fn matches_glob(pattern: &str, route: &str) -> bool {
        if pattern == "*" || pattern == "/*" {
            return true;
        }

        if let Some(prefix) = pattern.strip_suffix("/*") {
            return route.starts_with(prefix) || route == prefix;
        }

        if let Some(prefix) = pattern.strip_suffix("*") {
            return route.starts_with(prefix);
        }

        pattern == route
    }

    /// Reset SLO window
    fn reset_window(&self, state: &mut SloState) {
        debug!("Resetting SLO window for: {}", state.target.name);
        state.total_requests = 0;
        state.good_requests = 0;
        state.window_start = Instant::now();
        state.time_series.clear();
        state.current_sli = 1.0;
        state.error_budget_remaining = 1.0;
        state.burn_rate = 0.0;

        // Reset latency samples
        let mut samples = self.latency_samples.write();
        if let Some(sampler) = samples.get_mut(&state.target.name) {
            sampler.reset();
        }
    }

    /// Update SLI and error budget
    fn update_sli_and_budget(&self, state: &mut SloState) {
        if state.total_requests == 0 {
            state.current_sli = 1.0;
            state.error_budget_remaining = 1.0;
            return;
        }

        // Calculate current SLI
        state.current_sli = state.good_requests as f64 / state.total_requests as f64;

        // Calculate error budget
        // Error budget = (1 - target) is the allowed error rate
        // Error budget remaining = how much of that budget is left
        let target = state.target.target;
        let allowed_error_rate = 1.0 - target;

        if allowed_error_rate <= 0.0 {
            // 100% SLO target - any error exhausts budget
            state.error_budget_remaining = if state.current_sli >= 1.0 { 1.0 } else { 0.0 };
        } else {
            let current_error_rate = 1.0 - state.current_sli;
            let budget_consumed = current_error_rate / allowed_error_rate;
            state.error_budget_remaining = (1.0 - budget_consumed).max(0.0).min(1.0);
        }
    }

    /// Update burn rate calculation
    fn update_burn_rate(&self, state: &mut SloState) {
        if state.time_series.len() < 2 {
            state.burn_rate = 0.0;
            return;
        }

        // Calculate burn rate over the last hour (or available time)
        let now = Instant::now();
        let hour_ago = now.checked_sub(Duration::from_secs(3600)).unwrap_or(now);

        let recent_samples: Vec<_> = state
            .time_series
            .iter()
            .filter(|s| s.timestamp >= hour_ago)
            .collect();

        if recent_samples.len() < 2 {
            state.burn_rate = 0.0;
            return;
        }

        let first = recent_samples.first().unwrap();
        let last = recent_samples.last().unwrap();

        let total_delta = last.total.saturating_sub(first.total);
        let good_delta = last.good.saturating_sub(first.good);

        if total_delta == 0 {
            state.burn_rate = 0.0;
            return;
        }

        let recent_error_rate = 1.0 - (good_delta as f64 / total_delta as f64);
        let target = state.target.target;
        let allowed_error_rate = 1.0 - target;

        if allowed_error_rate <= 0.0 {
            state.burn_rate = if recent_error_rate > 0.0 { f64::INFINITY } else { 0.0 };
        } else {
            // Burn rate = actual error rate / allowed error rate
            state.burn_rate = recent_error_rate / allowed_error_rate;
        }
    }

    /// Get snapshot of all SLOs
    pub fn snapshot(&self) -> Vec<SloSnapshot> {
        let slos = self.slos.read();
        let _latency_samples = self.latency_samples.read();

        slos.values()
            .map(|state| {
                // Use count-based SLI for all types:
                // - Availability: successful requests / total requests
                // - Latency: requests under threshold / total requests
                // - ErrorRate: successful requests / total requests
                let current_sli = state.current_sli;

                // Calculate time to exhaustion
                let time_to_exhaustion = if state.burn_rate > 1.0 && state.error_budget_remaining > 0.0 {
                    // Hours remaining = budget remaining * window hours / burn rate
                    let window_hours = state.window_duration.as_secs() as f64 / 3600.0;
                    let hours_remaining = state.error_budget_remaining * window_hours / state.burn_rate;
                    Some((hours_remaining * 3600.0) as u64)
                } else {
                    None
                };

                SloSnapshot {
                    name: state.target.name.clone(),
                    slo_type: state.target.slo_type,
                    target: state.target.target,
                    current_sli,
                    slo_met: current_sli >= state.target.target,
                    error_budget_remaining: state.error_budget_remaining,
                    error_budget_consumed: 1.0 - state.error_budget_remaining,
                    burn_rate: state.burn_rate,
                    time_to_exhaustion_secs: time_to_exhaustion,
                    total_requests: state.total_requests,
                    good_requests: state.good_requests,
                    window_secs: state.window_duration.as_secs(),
                }
            })
            .collect()
    }

    /// Get snapshot for a specific SLO
    pub fn get_slo(&self, name: &str) -> Option<SloSnapshot> {
        self.snapshot().into_iter().find(|s| s.name == name)
    }

    /// Check for alerts and return any that should be fired
    pub fn check_alerts(&self) -> Vec<SloAlert> {
        if self.config.alerting.as_ref().map_or(true, |a| !a.enabled) {
            return Vec::new();
        }

        let alerting = self.config.alerting.as_ref().unwrap();
        let mut alerts = Vec::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cooldown = Duration::from_secs(alerting.alert_cooldown_secs);

        let mut slos = self.slos.write();

        for state in slos.values_mut() {
            // Skip if in cooldown
            if let Some(last_alert) = state.last_alert {
                if last_alert.elapsed() < cooldown {
                    continue;
                }
            }

            // Check error budget threshold
            let budget_consumed = 1.0 - state.error_budget_remaining;
            if budget_consumed >= alerting.budget_alert_threshold {
                let severity = if budget_consumed >= 0.9 {
                    AlertSeverity::Critical
                } else if budget_consumed >= 0.7 {
                    AlertSeverity::Warning
                } else {
                    AlertSeverity::Info
                };

                alerts.push(SloAlert {
                    timestamp: now,
                    slo_name: state.target.name.clone(),
                    alert_type: SloAlertType::ErrorBudgetThreshold,
                    current_sli: state.current_sli,
                    target_sli: state.target.target,
                    error_budget_remaining: state.error_budget_remaining,
                    burn_rate: state.burn_rate,
                    severity,
                    message: format!(
                        "Error budget {:.1}% consumed for SLO '{}'",
                        budget_consumed * 100.0,
                        state.target.name
                    ),
                });

                state.last_alert = Some(Instant::now());
            }

            // Check burn rate thresholds
            for window in &self.config.burn_rate_windows {
                if state.burn_rate >= window.burn_rate_threshold {
                    alerts.push(SloAlert {
                        timestamp: now,
                        slo_name: state.target.name.clone(),
                        alert_type: SloAlertType::BurnRate,
                        current_sli: state.current_sli,
                        target_sli: state.target.target,
                        error_budget_remaining: state.error_budget_remaining,
                        burn_rate: state.burn_rate,
                        severity: AlertSeverity::Warning,
                        message: format!(
                            "High burn rate ({:.1}x) detected for SLO '{}' in {} window",
                            state.burn_rate, state.target.name, window.name
                        ),
                    });

                    state.last_alert = Some(Instant::now());
                    break; // Only one burn rate alert per SLO
                }
            }

            // Check for budget exhaustion
            if state.error_budget_remaining <= 0.0 {
                alerts.push(SloAlert {
                    timestamp: now,
                    slo_name: state.target.name.clone(),
                    alert_type: SloAlertType::BudgetExhausted,
                    current_sli: state.current_sli,
                    target_sli: state.target.target,
                    error_budget_remaining: 0.0,
                    burn_rate: state.burn_rate,
                    severity: AlertSeverity::Critical,
                    message: format!(
                        "Error budget exhausted for SLO '{}'",
                        state.target.name
                    ),
                });

                state.last_alert = Some(Instant::now());
            }
        }

        if !alerts.is_empty() {
            self.stats.alerts_fired.fetch_add(alerts.len() as u64, Ordering::Relaxed);
            for alert in &alerts {
                warn!(
                    slo = %alert.slo_name,
                    severity = ?alert.severity,
                    message = %alert.message,
                    "SLO alert"
                );
            }
        }

        alerts
    }

    /// Export SLO metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        let snapshots = self.snapshot();
        let mut output = String::new();

        // SLI metric
        output.push_str("# HELP prism_slo_sli Current Service Level Indicator\n");
        output.push_str("# TYPE prism_slo_sli gauge\n");
        for snap in &snapshots {
            output.push_str(&format!(
                "prism_slo_sli{{name=\"{}\",type=\"{:?}\"}} {:.6}\n",
                snap.name, snap.slo_type, snap.current_sli
            ));
        }

        // Target metric
        output.push_str("\n# HELP prism_slo_target SLO target value\n");
        output.push_str("# TYPE prism_slo_target gauge\n");
        for snap in &snapshots {
            output.push_str(&format!(
                "prism_slo_target{{name=\"{}\",type=\"{:?}\"}} {:.6}\n",
                snap.name, snap.slo_type, snap.target
            ));
        }

        // Error budget remaining
        output.push_str("\n# HELP prism_slo_error_budget_remaining Error budget remaining (0-1)\n");
        output.push_str("# TYPE prism_slo_error_budget_remaining gauge\n");
        for snap in &snapshots {
            output.push_str(&format!(
                "prism_slo_error_budget_remaining{{name=\"{}\"}} {:.6}\n",
                snap.name, snap.error_budget_remaining
            ));
        }

        // Burn rate
        output.push_str("\n# HELP prism_slo_burn_rate Current error budget burn rate\n");
        output.push_str("# TYPE prism_slo_burn_rate gauge\n");
        for snap in &snapshots {
            output.push_str(&format!(
                "prism_slo_burn_rate{{name=\"{}\"}} {:.6}\n",
                snap.name, snap.burn_rate
            ));
        }

        // Request totals
        output.push_str("\n# HELP prism_slo_total_requests Total requests in SLO window\n");
        output.push_str("# TYPE prism_slo_total_requests counter\n");
        for snap in &snapshots {
            output.push_str(&format!(
                "prism_slo_total_requests{{name=\"{}\"}} {}\n",
                snap.name, snap.total_requests
            ));
        }

        output.push_str("\n# HELP prism_slo_good_requests Good requests in SLO window\n");
        output.push_str("# TYPE prism_slo_good_requests counter\n");
        for snap in &snapshots {
            output.push_str(&format!(
                "prism_slo_good_requests{{name=\"{}\"}} {}\n",
                snap.name, snap.good_requests
            ));
        }

        // SLO compliance (boolean)
        output.push_str("\n# HELP prism_slo_compliance Whether SLO is currently met (1=yes, 0=no)\n");
        output.push_str("# TYPE prism_slo_compliance gauge\n");
        for snap in &snapshots {
            output.push_str(&format!(
                "prism_slo_compliance{{name=\"{}\"}} {}\n",
                snap.name,
                if snap.slo_met { 1 } else { 0 }
            ));
        }

        output
    }

    /// Get global statistics
    pub fn stats(&self) -> SloStatsSnapshot {
        SloStatsSnapshot {
            total_requests: self.stats.total_requests.load(Ordering::Relaxed),
            good_requests: self.stats.good_requests.load(Ordering::Relaxed),
            alerts_fired: self.stats.alerts_fired.load(Ordering::Relaxed),
            active_slos: self.slos.read().len() as u64,
        }
    }
}

/// Snapshot of global SLO statistics
#[derive(Debug, Clone, Serialize)]
pub struct SloStatsSnapshot {
    pub total_requests: u64,
    pub good_requests: u64,
    pub alerts_fired: u64,
    pub active_slos: u64,
}

/// Parse duration string like "30d", "7d", "1h"
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: u64 = num_str.parse().ok()?;

    match unit {
        "s" => Some(Duration::from_secs(num)),
        "m" => Some(Duration::from_secs(num * 60)),
        "h" => Some(Duration::from_secs(num * 3600)),
        "d" => Some(Duration::from_secs(num * 24 * 3600)),
        "w" => Some(Duration::from_secs(num * 7 * 24 * 3600)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slo_config_defaults() {
        let config = SloConfig::default();
        assert!(!config.enabled);
        assert!(config.targets.is_empty());
        assert_eq!(config.burn_rate_windows.len(), 2);
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30d"), Some(Duration::from_secs(30 * 24 * 3600)));
        assert_eq!(parse_duration("7d"), Some(Duration::from_secs(7 * 24 * 3600)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("60s"), Some(Duration::from_secs(60)));
        assert_eq!(parse_duration("1w"), Some(Duration::from_secs(7 * 24 * 3600)));
        assert!(parse_duration("invalid").is_none());
    }

    #[test]
    fn test_latency_sampler() {
        let mut sampler = LatencySampler::new(100);

        // Add samples
        for i in 1..=100 {
            sampler.add_sample(i);
        }

        // Check percentiles
        let p50 = sampler.percentile(0.5).unwrap();
        assert!(p50 >= 45 && p50 <= 55); // Should be around 50

        let p99 = sampler.percentile(0.99).unwrap();
        assert!(p99 >= 95 && p99 <= 100); // Should be high
    }

    #[test]
    fn test_slo_tracker_availability() {
        let config = SloConfig {
            enabled: true,
            targets: vec![SloTarget {
                name: "test-availability".to_string(),
                slo_type: SloType::Availability,
                target: 0.99, // 99% availability
                window: "1h".to_string(),
                routes: vec!["/api/*".to_string()],
                methods: vec![],
                percentile: 0.99,
                threshold_ms: 0,
                labels: HashMap::new(),
            }],
            alerting: None,
            burn_rate_windows: vec![],
        };

        let tracker = SloTracker::new(config);

        // Record 99 successful requests
        for _ in 0..99 {
            tracker.record_request("/api/users", "GET", 200, 50);
        }

        // Record 1 failed request
        tracker.record_request("/api/users", "GET", 500, 50);

        let snapshots = tracker.snapshot();
        assert_eq!(snapshots.len(), 1);

        let snap = &snapshots[0];
        assert_eq!(snap.name, "test-availability");
        assert!((snap.current_sli - 0.99).abs() < 0.001);
        assert!(snap.slo_met); // 99% target, 99% actual
    }

    #[test]
    fn test_slo_tracker_latency() {
        let config = SloConfig {
            enabled: true,
            targets: vec![SloTarget {
                name: "test-latency".to_string(),
                slo_type: SloType::Latency,
                target: 0.95, // 95% of requests under threshold
                window: "1h".to_string(),
                routes: vec![],
                methods: vec![],
                percentile: 0.95,
                threshold_ms: 100, // 100ms threshold
                labels: HashMap::new(),
            }],
            alerting: None,
            burn_rate_windows: vec![],
        };

        let tracker = SloTracker::new(config);

        // Record 95 fast requests
        for _ in 0..95 {
            tracker.record_request("/api/test", "GET", 200, 50);
        }

        // Record 5 slow requests
        for _ in 0..5 {
            tracker.record_request("/api/test", "GET", 200, 200);
        }

        let snapshots = tracker.snapshot();
        assert_eq!(snapshots.len(), 1);

        let snap = &snapshots[0];
        assert_eq!(snap.name, "test-latency");
        assert!((snap.current_sli - 0.95).abs() < 0.01);
    }

    #[test]
    fn test_error_budget_calculation() {
        let config = SloConfig {
            enabled: true,
            targets: vec![SloTarget {
                name: "budget-test".to_string(),
                slo_type: SloType::Availability,
                target: 0.99, // 99% = 1% error budget
                window: "30d".to_string(),
                routes: vec![],
                methods: vec![],
                percentile: 0.99,
                threshold_ms: 0,
                labels: HashMap::new(),
            }],
            alerting: None,
            burn_rate_windows: vec![],
        };

        let tracker = SloTracker::new(config);

        // Record 98 successful, 2 failed = 98% success (below 99% target)
        for _ in 0..98 {
            tracker.record_request("/test", "GET", 200, 10);
        }
        for _ in 0..2 {
            tracker.record_request("/test", "GET", 500, 10);
        }

        let snap = tracker.get_slo("budget-test").unwrap();

        // Current SLI = 98%, Target = 99%
        // Error rate = 2%, Allowed = 1%
        // Budget consumed = 2/1 = 200% (capped at 100%)
        assert!(!snap.slo_met);
        assert_eq!(snap.error_budget_remaining, 0.0);
    }

    #[test]
    fn test_glob_matching() {
        assert!(SloTracker::matches_glob("/api/*", "/api/users"));
        assert!(SloTracker::matches_glob("/api/*", "/api/users/123"));
        assert!(SloTracker::matches_glob("/api/*", "/api"));
        assert!(!SloTracker::matches_glob("/api/*", "/other"));

        assert!(SloTracker::matches_glob("*", "/anything"));
        assert!(SloTracker::matches_glob("/*", "/anything"));

        assert!(SloTracker::matches_glob("/exact", "/exact"));
        assert!(!SloTracker::matches_glob("/exact", "/exact/more"));
    }

    #[test]
    fn test_prometheus_export() {
        let config = SloConfig {
            enabled: true,
            targets: vec![SloTarget {
                name: "export-test".to_string(),
                slo_type: SloType::Availability,
                target: 0.999,
                window: "7d".to_string(),
                routes: vec![],
                methods: vec![],
                percentile: 0.99,
                threshold_ms: 0,
                labels: HashMap::new(),
            }],
            alerting: None,
            burn_rate_windows: vec![],
        };

        let tracker = SloTracker::new(config);
        tracker.record_request("/test", "GET", 200, 10);

        let output = tracker.export_prometheus();
        assert!(output.contains("prism_slo_sli"));
        assert!(output.contains("prism_slo_target"));
        assert!(output.contains("prism_slo_error_budget_remaining"));
        assert!(output.contains("prism_slo_burn_rate"));
        assert!(output.contains("prism_slo_compliance"));
        assert!(output.contains("export-test"));
    }
}
