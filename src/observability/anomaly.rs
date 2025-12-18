//! AI/ML-based Anomaly Detection
//!
//! Provides intelligent anomaly detection for reverse proxy traffic:
//! - Statistical anomaly detection (Z-score, IQR, Moving Average)
//! - Latency spike detection
//! - Error rate anomaly detection
//! - Traffic pattern analysis
//! - DDoS/Bot detection heuristics
//! - Request fingerprinting
//!
//! # Architecture
//! ```text
//! ┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │  Metrics    │───▶│  Feature        │───▶│  Anomaly        │
//! │  Collector  │    │  Extractor      │    │  Detectors      │
//! └─────────────┘    └─────────────────┘    └─────────────────┘
//!                                                   │
//!                                                   ▼
//!                                           ┌─────────────────┐
//!                                           │  Alert          │
//!                                           │  System         │
//!                                           └─────────────────┘
//! ```

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Anomaly detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnomalyConfig {
    /// Enable anomaly detection
    #[serde(default)]
    pub enabled: bool,

    /// Z-score threshold for statistical anomalies
    #[serde(default = "default_zscore_threshold")]
    pub zscore_threshold: f64,

    /// Window size for moving statistics
    #[serde(default = "default_window_size")]
    pub window_size: usize,

    /// Minimum samples before detection activates
    #[serde(default = "default_min_samples")]
    pub min_samples: usize,

    /// Latency spike threshold (multiplier of baseline)
    #[serde(default = "default_latency_spike_threshold")]
    pub latency_spike_threshold: f64,

    /// Error rate threshold percentage
    #[serde(default = "default_error_rate_threshold")]
    pub error_rate_threshold: f64,

    /// Enable DDoS detection heuristics
    #[serde(default = "default_true")]
    pub ddos_detection: bool,

    /// Requests per second threshold per IP for DDoS
    #[serde(default = "default_rps_threshold")]
    pub rps_threshold_per_ip: u64,

    /// Enable bot detection
    #[serde(default = "default_true")]
    pub bot_detection: bool,

    /// Alert cooldown to prevent spam
    #[serde(default = "default_alert_cooldown_secs")]
    pub alert_cooldown_secs: u64,

    /// Features to analyze
    #[serde(default)]
    pub features: FeatureConfig,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            zscore_threshold: default_zscore_threshold(),
            window_size: default_window_size(),
            min_samples: default_min_samples(),
            latency_spike_threshold: default_latency_spike_threshold(),
            error_rate_threshold: default_error_rate_threshold(),
            ddos_detection: true,
            rps_threshold_per_ip: default_rps_threshold(),
            bot_detection: true,
            alert_cooldown_secs: default_alert_cooldown_secs(),
            features: FeatureConfig::default(),
        }
    }
}

fn default_zscore_threshold() -> f64 {
    3.0
}

fn default_window_size() -> usize {
    1000
}

fn default_min_samples() -> usize {
    100
}

fn default_latency_spike_threshold() -> f64 {
    5.0
}

fn default_error_rate_threshold() -> f64 {
    10.0
}

fn default_true() -> bool {
    true
}

fn default_rps_threshold() -> u64 {
    100
}

fn default_alert_cooldown_secs() -> u64 {
    60
}

/// Features to analyze for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureConfig {
    /// Analyze latency patterns
    #[serde(default = "default_true")]
    pub latency: bool,

    /// Analyze error rates
    #[serde(default = "default_true")]
    pub error_rate: bool,

    /// Analyze request rates
    #[serde(default = "default_true")]
    pub request_rate: bool,

    /// Analyze response sizes
    #[serde(default)]
    pub response_size: bool,

    /// Analyze user agent patterns
    #[serde(default = "default_true")]
    pub user_agent: bool,

    /// Analyze geographic distribution
    #[serde(default)]
    pub geo_distribution: bool,
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self {
            latency: true,
            error_rate: true,
            request_rate: true,
            response_size: false,
            user_agent: true,
            geo_distribution: false,
        }
    }
}

/// Types of anomalies detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Latency spike detected
    LatencySpike,
    /// High error rate
    ErrorRateSpike,
    /// Unusual traffic pattern
    TrafficAnomaly,
    /// Potential DDoS attack
    PotentialDDoS,
    /// Bot-like behavior
    BotDetected,
    /// Unusual request pattern
    UnusualPattern,
    /// Response size anomaly
    ResponseSizeAnomaly,
    /// Time-based anomaly (unusual timing)
    TimeAnomaly,
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalyType::LatencySpike => write!(f, "latency_spike"),
            AnomalyType::ErrorRateSpike => write!(f, "error_rate_spike"),
            AnomalyType::TrafficAnomaly => write!(f, "traffic_anomaly"),
            AnomalyType::PotentialDDoS => write!(f, "potential_ddos"),
            AnomalyType::BotDetected => write!(f, "bot_detected"),
            AnomalyType::UnusualPattern => write!(f, "unusual_pattern"),
            AnomalyType::ResponseSizeAnomaly => write!(f, "response_size_anomaly"),
            AnomalyType::TimeAnomaly => write!(f, "time_anomaly"),
        }
    }
}

/// Severity levels for anomalies
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// An anomaly alert
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyAlert {
    /// Type of anomaly
    pub anomaly_type: AnomalyType,
    /// Severity level
    pub severity: Severity,
    /// Anomaly score (0.0 - 1.0)
    pub score: f64,
    /// Human readable description
    pub description: String,
    /// Affected resource (IP, path, etc.)
    pub resource: Option<String>,
    /// Detection timestamp
    pub timestamp: u64,
    /// Additional context
    pub context: HashMap<String, String>,
}

/// Request sample for analysis
#[derive(Debug, Clone)]
pub struct RequestSample {
    pub timestamp: Instant,
    pub client_ip: Option<IpAddr>,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub latency: Duration,
    pub response_size: usize,
    pub user_agent: Option<String>,
}

/// Anomaly detector engine
pub struct AnomalyDetector {
    config: AnomalyConfig,

    // Statistical trackers
    latency_stats: RwLock<RollingStats>,
    error_rate_stats: RwLock<ErrorRateTracker>,
    request_rate_stats: RwLock<RequestRateTracker>,
    response_size_stats: RwLock<RollingStats>,

    // IP-based tracking for DDoS/bot detection
    ip_tracker: RwLock<HashMap<IpAddr, IpStats>>,

    // User agent fingerprinting
    ua_tracker: RwLock<UserAgentTracker>,

    // Recent alerts (for cooldown)
    recent_alerts: RwLock<VecDeque<(AnomalyType, Instant)>>,

    // Counters
    total_samples: AtomicU64,
    total_anomalies: AtomicU64,

    start_time: Instant,
}

impl AnomalyDetector {
    /// Create a new anomaly detector
    pub fn new(config: AnomalyConfig) -> Self {
        Self {
            latency_stats: RwLock::new(RollingStats::new(config.window_size)),
            error_rate_stats: RwLock::new(ErrorRateTracker::new(config.window_size)),
            request_rate_stats: RwLock::new(RequestRateTracker::new()),
            response_size_stats: RwLock::new(RollingStats::new(config.window_size)),
            ip_tracker: RwLock::new(HashMap::new()),
            ua_tracker: RwLock::new(UserAgentTracker::new()),
            recent_alerts: RwLock::new(VecDeque::with_capacity(100)),
            total_samples: AtomicU64::new(0),
            total_anomalies: AtomicU64::new(0),
            start_time: Instant::now(),
            config,
        }
    }

    /// Analyze a request sample and return any detected anomalies
    pub fn analyze(&self, sample: &RequestSample) -> Vec<AnomalyAlert> {
        if !self.config.enabled {
            return Vec::new();
        }

        self.total_samples.fetch_add(1, Ordering::Relaxed);

        let mut alerts = Vec::new();

        // Run detectors BEFORE updating stats (compare against historical baseline)
        if self.config.features.latency {
            if let Some(alert) = self.detect_latency_anomaly(sample) {
                alerts.push(alert);
            }
        }

        if self.config.features.error_rate {
            if let Some(alert) = self.detect_error_rate_anomaly(sample) {
                alerts.push(alert);
            }
        }

        if self.config.features.response_size {
            if let Some(alert) = self.detect_response_size_anomaly(sample) {
                alerts.push(alert);
            }
        }

        // Update statistics AFTER detection
        self.update_stats(sample);

        // IP/UA based detection runs after stats update (needs tracking data)
        if self.config.ddos_detection {
            if let Some(alert) = self.detect_ddos(sample) {
                alerts.push(alert);
            }
        }

        if self.config.bot_detection {
            if let Some(alert) = self.detect_bot(sample) {
                alerts.push(alert);
            }
        }

        // Filter by cooldown
        let alerts: Vec<_> = alerts
            .into_iter()
            .filter(|a| self.check_cooldown(a.anomaly_type))
            .collect();

        self.total_anomalies
            .fetch_add(alerts.len() as u64, Ordering::Relaxed);

        alerts
    }

    /// Update internal statistics with new sample
    fn update_stats(&self, sample: &RequestSample) {
        // Update latency stats
        let latency_ms = sample.latency.as_secs_f64() * 1000.0;
        self.latency_stats.write().push(latency_ms);

        // Update error rate
        let is_error = sample.status_code >= 500;
        self.error_rate_stats.write().push(is_error);

        // Update request rate
        self.request_rate_stats.write().record(sample.timestamp);

        // Update response size
        self.response_size_stats
            .write()
            .push(sample.response_size as f64);

        // Update IP tracking
        if let Some(ip) = sample.client_ip {
            let mut tracker = self.ip_tracker.write();
            let stats = tracker.entry(ip).or_insert_with(IpStats::new);
            stats.record_request(sample);
        }

        // Update UA tracking
        if let Some(ua) = &sample.user_agent {
            self.ua_tracker.write().record(ua, sample.client_ip);
        }
    }

    /// Detect latency anomalies using Z-score
    fn detect_latency_anomaly(&self, sample: &RequestSample) -> Option<AnomalyAlert> {
        let stats = self.latency_stats.read();

        if stats.count() < self.config.min_samples {
            return None;
        }

        let latency_ms = sample.latency.as_secs_f64() * 1000.0;
        let zscore = stats.zscore(latency_ms);

        if zscore.abs() > self.config.zscore_threshold {
            let mean = stats.mean();
            let severity = if zscore > self.config.zscore_threshold * 2.0 {
                Severity::High
            } else if zscore > self.config.zscore_threshold * 1.5 {
                Severity::Medium
            } else {
                Severity::Low
            };

            let mut context = HashMap::new();
            context.insert("latency_ms".to_string(), format!("{:.2}", latency_ms));
            context.insert("mean_ms".to_string(), format!("{:.2}", mean));
            context.insert("zscore".to_string(), format!("{:.2}", zscore));
            context.insert("path".to_string(), sample.path.clone());

            return Some(AnomalyAlert {
                anomaly_type: AnomalyType::LatencySpike,
                severity,
                score: (zscore.abs() / (self.config.zscore_threshold * 3.0)).min(1.0),
                description: format!(
                    "Latency spike detected: {:.2}ms (mean: {:.2}ms, z-score: {:.2})",
                    latency_ms, mean, zscore
                ),
                resource: Some(sample.path.clone()),
                timestamp: self.current_timestamp(),
                context,
            });
        }

        None
    }

    /// Detect error rate anomalies
    fn detect_error_rate_anomaly(&self, _sample: &RequestSample) -> Option<AnomalyAlert> {
        let tracker = self.error_rate_stats.read();
        let error_rate = tracker.error_rate() * 100.0;

        if error_rate > self.config.error_rate_threshold
            && tracker.count() >= self.config.min_samples
        {
            let severity = if error_rate > self.config.error_rate_threshold * 3.0 {
                Severity::Critical
            } else if error_rate > self.config.error_rate_threshold * 2.0 {
                Severity::High
            } else {
                Severity::Medium
            };

            let mut context = HashMap::new();
            context.insert("error_rate".to_string(), format!("{:.2}%", error_rate));
            context.insert(
                "threshold".to_string(),
                format!("{}%", self.config.error_rate_threshold),
            );

            return Some(AnomalyAlert {
                anomaly_type: AnomalyType::ErrorRateSpike,
                severity,
                score: (error_rate / 100.0).min(1.0),
                description: format!(
                    "High error rate detected: {:.2}% (threshold: {}%)",
                    error_rate, self.config.error_rate_threshold
                ),
                resource: None,
                timestamp: self.current_timestamp(),
                context,
            });
        }

        None
    }

    /// Detect potential DDoS attacks
    fn detect_ddos(&self, sample: &RequestSample) -> Option<AnomalyAlert> {
        let ip = sample.client_ip?;
        let tracker = self.ip_tracker.read();
        let ip_stats = tracker.get(&ip)?;

        let rps = ip_stats.requests_per_second();

        if rps > self.config.rps_threshold_per_ip as f64 {
            let severity = if rps > self.config.rps_threshold_per_ip as f64 * 5.0 {
                Severity::Critical
            } else if rps > self.config.rps_threshold_per_ip as f64 * 2.0 {
                Severity::High
            } else {
                Severity::Medium
            };

            let mut context = HashMap::new();
            context.insert("client_ip".to_string(), ip.to_string());
            context.insert("rps".to_string(), format!("{:.2}", rps));
            context.insert(
                "threshold".to_string(),
                format!("{}", self.config.rps_threshold_per_ip),
            );
            context.insert(
                "total_requests".to_string(),
                format!("{}", ip_stats.total_requests),
            );

            return Some(AnomalyAlert {
                anomaly_type: AnomalyType::PotentialDDoS,
                severity,
                score: (rps / (self.config.rps_threshold_per_ip as f64 * 10.0)).min(1.0),
                description: format!(
                    "Potential DDoS: {} requests/sec from {} (threshold: {})",
                    rps as u64, ip, self.config.rps_threshold_per_ip
                ),
                resource: Some(ip.to_string()),
                timestamp: self.current_timestamp(),
                context,
            });
        }

        None
    }

    /// Detect bot-like behavior
    fn detect_bot(&self, sample: &RequestSample) -> Option<AnomalyAlert> {
        let ua = sample.user_agent.as_ref()?;

        // Check for common bot indicators
        let bot_indicators = [
            ("curl", 0.3),
            ("wget", 0.3),
            ("python-requests", 0.4),
            ("go-http-client", 0.3),
            ("scrapy", 0.8),
            ("bot", 0.6),
            ("crawler", 0.6),
            ("spider", 0.6),
            ("headless", 0.7),
            ("phantomjs", 0.8),
            ("selenium", 0.8),
        ];

        let ua_lower = ua.to_lowercase();
        let mut max_score: f64 = 0.0;
        let mut detected_indicator = None;

        for (indicator, score) in &bot_indicators {
            if ua_lower.contains(indicator) && *score > max_score {
                max_score = *score;
                detected_indicator = Some(*indicator);
            }
        }

        // Check request patterns from this UA
        let tracker = self.ua_tracker.read();
        if let Some(ua_stats) = tracker.stats.get(ua) {
            // High request volume from single UA
            if ua_stats.request_count > 1000 {
                max_score = max_score.max(0.5);
            }
            // Single IP per UA (unusual for browsers)
            if ua_stats.unique_ips.len() == 1 && ua_stats.request_count > 100 {
                max_score = max_score.max(0.4);
            }
        }

        if max_score >= 0.5 {
            let severity = if max_score >= 0.8 {
                Severity::High
            } else if max_score >= 0.6 {
                Severity::Medium
            } else {
                Severity::Low
            };

            let mut context = HashMap::new();
            context.insert("user_agent".to_string(), ua.clone());
            if let Some(indicator) = detected_indicator {
                context.insert("indicator".to_string(), indicator.to_string());
            }
            if let Some(ip) = sample.client_ip {
                context.insert("client_ip".to_string(), ip.to_string());
            }

            return Some(AnomalyAlert {
                anomaly_type: AnomalyType::BotDetected,
                severity,
                score: max_score,
                description: format!("Bot-like behavior detected (score: {:.2})", max_score),
                resource: sample.client_ip.map(|ip| ip.to_string()),
                timestamp: self.current_timestamp(),
                context,
            });
        }

        None
    }

    /// Detect response size anomalies
    fn detect_response_size_anomaly(&self, sample: &RequestSample) -> Option<AnomalyAlert> {
        let stats = self.response_size_stats.read();

        if stats.count() < self.config.min_samples {
            return None;
        }

        let zscore = stats.zscore(sample.response_size as f64);

        if zscore.abs() > self.config.zscore_threshold {
            let severity = if zscore.abs() > self.config.zscore_threshold * 2.0 {
                Severity::Medium
            } else {
                Severity::Low
            };

            let mut context = HashMap::new();
            context.insert("size".to_string(), format!("{}", sample.response_size));
            context.insert("mean".to_string(), format!("{:.0}", stats.mean()));
            context.insert("zscore".to_string(), format!("{:.2}", zscore));

            return Some(AnomalyAlert {
                anomaly_type: AnomalyType::ResponseSizeAnomaly,
                severity,
                score: (zscore.abs() / (self.config.zscore_threshold * 3.0)).min(1.0),
                description: format!(
                    "Unusual response size: {} bytes (mean: {:.0})",
                    sample.response_size,
                    stats.mean()
                ),
                resource: Some(sample.path.clone()),
                timestamp: self.current_timestamp(),
                context,
            });
        }

        None
    }

    /// Check if we're still in cooldown for this anomaly type
    fn check_cooldown(&self, anomaly_type: AnomalyType) -> bool {
        let cooldown = Duration::from_secs(self.config.alert_cooldown_secs);
        let now = Instant::now();

        let mut alerts = self.recent_alerts.write();

        // Clean old alerts
        while let Some((_, time)) = alerts.front() {
            if now.duration_since(*time) > cooldown {
                alerts.pop_front();
            } else {
                break;
            }
        }

        // Check if this type is in cooldown
        let in_cooldown = alerts.iter().any(|(t, _)| *t == anomaly_type);

        if !in_cooldown {
            alerts.push_back((anomaly_type, now));
        }

        !in_cooldown
    }

    /// Get current timestamp in milliseconds
    fn current_timestamp(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }

    /// Get detector statistics
    pub fn stats(&self) -> AnomalyStats {
        AnomalyStats {
            total_samples: self.total_samples.load(Ordering::Relaxed),
            total_anomalies: self.total_anomalies.load(Ordering::Relaxed),
            latency_mean: self.latency_stats.read().mean(),
            latency_stddev: self.latency_stats.read().stddev(),
            error_rate: self.error_rate_stats.read().error_rate() * 100.0,
            tracked_ips: self.ip_tracker.read().len(),
            tracked_user_agents: self.ua_tracker.read().stats.len(),
            uptime_secs: self.start_time.elapsed().as_secs(),
        }
    }

    /// Clean up stale tracking data
    pub fn gc(&self) {
        let stale_threshold = Duration::from_secs(3600); // 1 hour
        let now = Instant::now();

        // Clean IP tracker
        let mut ip_tracker = self.ip_tracker.write();
        ip_tracker.retain(|_, stats| now.duration_since(stats.first_seen) < stale_threshold);

        // Clean UA tracker
        let mut ua_tracker = self.ua_tracker.write();
        ua_tracker
            .stats
            .retain(|_, stats| now.duration_since(stats.first_seen) < stale_threshold);
    }
}

/// Rolling statistics calculator
#[derive(Debug)]
struct RollingStats {
    values: VecDeque<f64>,
    sum: f64,
    sum_sq: f64,
    capacity: usize,
}

impl RollingStats {
    fn new(capacity: usize) -> Self {
        Self {
            values: VecDeque::with_capacity(capacity),
            sum: 0.0,
            sum_sq: 0.0,
            capacity,
        }
    }

    fn push(&mut self, value: f64) {
        if self.values.len() >= self.capacity {
            if let Some(old) = self.values.pop_front() {
                self.sum -= old;
                self.sum_sq -= old * old;
            }
        }
        self.values.push_back(value);
        self.sum += value;
        self.sum_sq += value * value;
    }

    fn count(&self) -> usize {
        self.values.len()
    }

    fn mean(&self) -> f64 {
        if self.values.is_empty() {
            return 0.0;
        }
        self.sum / self.values.len() as f64
    }

    fn variance(&self) -> f64 {
        if self.values.len() < 2 {
            return 0.0;
        }
        let n = self.values.len() as f64;
        let mean = self.mean();
        (self.sum_sq / n) - (mean * mean)
    }

    fn stddev(&self) -> f64 {
        self.variance().sqrt()
    }

    fn zscore(&self, value: f64) -> f64 {
        let stddev = self.stddev();
        if stddev == 0.0 {
            return 0.0;
        }
        (value - self.mean()) / stddev
    }
}

/// Error rate tracker
#[derive(Debug)]
struct ErrorRateTracker {
    errors: VecDeque<bool>,
    error_count: usize,
    capacity: usize,
}

impl ErrorRateTracker {
    fn new(capacity: usize) -> Self {
        Self {
            errors: VecDeque::with_capacity(capacity),
            error_count: 0,
            capacity,
        }
    }

    fn push(&mut self, is_error: bool) {
        if self.errors.len() >= self.capacity {
            if let Some(old) = self.errors.pop_front() {
                if old {
                    self.error_count -= 1;
                }
            }
        }
        self.errors.push_back(is_error);
        if is_error {
            self.error_count += 1;
        }
    }

    fn count(&self) -> usize {
        self.errors.len()
    }

    fn error_rate(&self) -> f64 {
        if self.errors.is_empty() {
            return 0.0;
        }
        self.error_count as f64 / self.errors.len() as f64
    }
}

/// Request rate tracker
#[derive(Debug)]
#[allow(dead_code)]
struct RequestRateTracker {
    timestamps: VecDeque<Instant>,
    window: Duration,
}

impl RequestRateTracker {
    fn new() -> Self {
        Self {
            timestamps: VecDeque::with_capacity(10000),
            window: Duration::from_secs(60),
        }
    }

    fn record(&mut self, timestamp: Instant) {
        // Clean old timestamps
        while let Some(ts) = self.timestamps.front() {
            if timestamp.duration_since(*ts) > self.window {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
        self.timestamps.push_back(timestamp);
    }

    #[allow(dead_code)]
    fn requests_per_second(&self) -> f64 {
        if self.timestamps.len() < 2 {
            return 0.0;
        }

        let duration = self
            .timestamps
            .back()
            .unwrap()
            .duration_since(*self.timestamps.front().unwrap());

        if duration.as_secs_f64() == 0.0 {
            return 0.0;
        }

        self.timestamps.len() as f64 / duration.as_secs_f64()
    }
}

/// Per-IP statistics
#[derive(Debug)]
struct IpStats {
    total_requests: u64,
    first_seen: Instant,
    last_seen: Instant,
    error_count: u64,
    paths_accessed: std::collections::HashSet<String>,
}

impl IpStats {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            total_requests: 0,
            first_seen: now,
            last_seen: now,
            error_count: 0,
            paths_accessed: std::collections::HashSet::new(),
        }
    }

    fn record_request(&mut self, sample: &RequestSample) {
        self.total_requests += 1;
        self.last_seen = sample.timestamp;
        if sample.status_code >= 400 {
            self.error_count += 1;
        }
        if self.paths_accessed.len() < 1000 {
            self.paths_accessed.insert(sample.path.clone());
        }
    }

    fn requests_per_second(&self) -> f64 {
        let duration = self.last_seen.duration_since(self.first_seen);
        if duration.as_secs_f64() < 1.0 {
            return self.total_requests as f64;
        }
        self.total_requests as f64 / duration.as_secs_f64()
    }
}

/// User agent statistics
#[derive(Debug)]
struct UaStats {
    request_count: u64,
    unique_ips: std::collections::HashSet<IpAddr>,
    first_seen: Instant,
}

/// User agent tracker
#[derive(Debug)]
struct UserAgentTracker {
    stats: HashMap<String, UaStats>,
}

impl UserAgentTracker {
    fn new() -> Self {
        Self {
            stats: HashMap::new(),
        }
    }

    fn record(&mut self, user_agent: &str, ip: Option<IpAddr>) {
        let stats = self
            .stats
            .entry(user_agent.to_string())
            .or_insert_with(|| UaStats {
                request_count: 0,
                unique_ips: std::collections::HashSet::new(),
                first_seen: Instant::now(),
            });

        stats.request_count += 1;
        if let Some(ip) = ip {
            if stats.unique_ips.len() < 10000 {
                stats.unique_ips.insert(ip);
            }
        }
    }
}

/// Anomaly detection statistics
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyStats {
    pub total_samples: u64,
    pub total_anomalies: u64,
    pub latency_mean: f64,
    pub latency_stddev: f64,
    pub error_rate: f64,
    pub tracked_ips: usize,
    pub tracked_user_agents: usize,
    pub uptime_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AnomalyConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.zscore_threshold, 3.0);
        assert_eq!(config.window_size, 1000);
    }

    #[test]
    fn test_rolling_stats() {
        let mut stats = RollingStats::new(5);

        for i in 1..=5 {
            stats.push(i as f64);
        }

        assert_eq!(stats.count(), 5);
        assert_eq!(stats.mean(), 3.0);

        // Test rolling behavior
        stats.push(6.0);
        assert_eq!(stats.count(), 5);
        assert_eq!(stats.mean(), 4.0); // (2+3+4+5+6)/5
    }

    #[test]
    fn test_error_rate_tracker() {
        let mut tracker = ErrorRateTracker::new(10);

        for i in 0..10 {
            tracker.push(i % 3 == 0); // 4 errors (0, 3, 6, 9)
        }

        assert_eq!(tracker.count(), 10);
        assert!((tracker.error_rate() - 0.4).abs() < 0.01);
    }

    #[test]
    fn test_zscore_calculation() {
        let mut stats = RollingStats::new(100);

        // Add values with known distribution
        for i in 0..100 {
            stats.push((i as f64) % 10.0);
        }

        let mean = stats.mean();
        let zscore_mean = stats.zscore(mean);
        assert!(zscore_mean.abs() < 0.01); // Z-score of mean should be ~0
    }

    #[test]
    fn test_anomaly_detector_creation() {
        let config = AnomalyConfig::default();
        let detector = AnomalyDetector::new(config);

        let stats = detector.stats();
        assert_eq!(stats.total_samples, 0);
        assert_eq!(stats.total_anomalies, 0);
    }

    #[test]
    fn test_latency_spike_detection() {
        let mut config = AnomalyConfig::default();
        config.enabled = true;
        config.min_samples = 10;
        config.zscore_threshold = 2.0;

        let detector = AnomalyDetector::new(config);

        // Add normal samples with more variance for reliable stddev
        for i in 0..50 {
            let sample = RequestSample {
                timestamp: Instant::now(),
                client_ip: None,
                method: "GET".to_string(),
                path: "/test".to_string(),
                status_code: 200,
                latency: Duration::from_millis(100 + (i % 20) * 2), // 100-138ms range
                response_size: 1000,
                user_agent: None,
            };
            detector.analyze(&sample);
        }

        // Add anomalous sample - much higher than baseline
        let anomaly_sample = RequestSample {
            timestamp: Instant::now(),
            client_ip: None,
            method: "GET".to_string(),
            path: "/slow".to_string(),
            status_code: 200,
            latency: Duration::from_millis(1000), // ~10x above normal mean
            response_size: 1000,
            user_agent: None,
        };

        let alerts = detector.analyze(&anomaly_sample);
        assert!(alerts
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::LatencySpike));
    }

    #[test]
    fn test_bot_detection() {
        let mut config = AnomalyConfig::default();
        config.enabled = true;
        config.bot_detection = true;

        let detector = AnomalyDetector::new(config);

        let sample = RequestSample {
            timestamp: Instant::now(),
            client_ip: Some("1.2.3.4".parse().unwrap()),
            method: "GET".to_string(),
            path: "/".to_string(),
            status_code: 200,
            latency: Duration::from_millis(100),
            response_size: 1000,
            user_agent: Some("scrapy/2.0".to_string()),
        };

        let alerts = detector.analyze(&sample);
        assert!(alerts
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::BotDetected));
    }

    #[test]
    fn test_anomaly_type_display() {
        assert_eq!(AnomalyType::LatencySpike.to_string(), "latency_spike");
        assert_eq!(AnomalyType::PotentialDDoS.to_string(), "potential_ddos");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn test_cooldown() {
        let mut config = AnomalyConfig::default();
        config.enabled = true;
        config.alert_cooldown_secs = 1;
        config.min_samples = 1;
        config.bot_detection = true;

        let detector = AnomalyDetector::new(config);

        let sample = RequestSample {
            timestamp: Instant::now(),
            client_ip: Some("1.2.3.4".parse().unwrap()),
            method: "GET".to_string(),
            path: "/".to_string(),
            status_code: 200,
            latency: Duration::from_millis(100),
            response_size: 1000,
            user_agent: Some("scrapy/2.0".to_string()),
        };

        // First detection should trigger
        let alerts1 = detector.analyze(&sample);
        let bot_alerts1: Vec<_> = alerts1
            .iter()
            .filter(|a| a.anomaly_type == AnomalyType::BotDetected)
            .collect();

        // Second immediate detection should be in cooldown
        let alerts2 = detector.analyze(&sample);
        let bot_alerts2: Vec<_> = alerts2
            .iter()
            .filter(|a| a.anomaly_type == AnomalyType::BotDetected)
            .collect();

        // First should have alert, second should be filtered by cooldown
        assert!(!bot_alerts1.is_empty());
        assert!(bot_alerts2.is_empty());
    }
}
