//! Machine Learning Module
//!
//! Provides ML-powered features:
//! - Smart load balancing using reinforcement learning
//! - Request classification (bot detection, traffic type)
//! - Latency prediction
//! - Predictive autoscaling
//! - Adaptive compression

use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::trace;

// ============================================================================
// Smart Load Balancing (Reinforcement Learning)
// ============================================================================

/// Configuration for smart load balancing
#[derive(Debug, Clone)]
pub struct SmartLBConfig {
    /// Learning rate for Q-learning updates
    pub learning_rate: f64,
    /// Discount factor for future rewards
    pub discount_factor: f64,
    /// Exploration rate (epsilon-greedy)
    pub exploration_rate: f64,
    /// Minimum exploration rate
    pub min_exploration_rate: f64,
    /// Exploration decay rate
    pub exploration_decay: f64,
    /// Window size for moving averages
    pub window_size: usize,
    /// How often to update weights
    pub update_interval: Duration,
}

impl Default for SmartLBConfig {
    fn default() -> Self {
        Self {
            learning_rate: 0.1,
            discount_factor: 0.95,
            exploration_rate: 0.2,
            min_exploration_rate: 0.01,
            exploration_decay: 0.995,
            window_size: 100,
            update_interval: Duration::from_secs(10),
        }
    }
}

/// State features for a backend server
#[derive(Debug, Clone, Default)]
pub struct ServerState {
    /// Average response latency (ms)
    pub avg_latency_ms: f64,
    /// Error rate (0-1)
    pub error_rate: f64,
    /// Current connections
    pub connections: u64,
    /// Requests per second
    pub rps: f64,
    /// Queue depth estimate
    pub queue_depth: f64,
    /// CPU utilization (if available)
    pub cpu_utilization: f64,
    /// Memory utilization (if available)
    pub memory_utilization: f64,
}

impl ServerState {
    /// Convert to feature vector
    pub fn to_features(&self) -> Vec<f64> {
        vec![
            self.avg_latency_ms / 1000.0, // Normalize to seconds
            self.error_rate,
            (self.connections as f64).ln().max(0.0) / 10.0, // Log-scale
            self.rps.ln().max(0.0) / 10.0,
            self.queue_depth / 100.0,
            self.cpu_utilization,
            self.memory_utilization,
        ]
    }
}

/// Q-values for a server
#[derive(Debug, Clone)]
struct QValues {
    /// Value estimate
    value: f64,
    /// Update count
    updates: u64,
    /// Recent rewards
    rewards: VecDeque<f64>,
}

impl Default for QValues {
    fn default() -> Self {
        Self {
            value: 0.0,
            updates: 0,
            rewards: VecDeque::with_capacity(100),
        }
    }
}

/// Smart load balancer using reinforcement learning
pub struct SmartLoadBalancer {
    config: RwLock<SmartLBConfig>,
    /// Q-values for each server
    q_values: DashMap<String, QValues>,
    /// Server states
    states: DashMap<String, ServerState>,
    /// Current exploration rate
    exploration_rate: RwLock<f64>,
    /// Statistics
    stats: SmartLBStats,
    /// Last update time
    #[allow(dead_code)]
    last_update: RwLock<Instant>,
}

/// Statistics for smart load balancing
#[derive(Debug, Default)]
pub struct SmartLBStats {
    /// Total selections made
    pub selections: AtomicU64,
    /// Exploration selections
    pub explorations: AtomicU64,
    /// Exploitation selections
    pub exploitations: AtomicU64,
    /// Q-value updates
    pub updates: AtomicU64,
}

impl SmartLoadBalancer {
    /// Create a new smart load balancer
    pub fn new(config: SmartLBConfig) -> Arc<Self> {
        let exploration_rate = config.exploration_rate;
        Arc::new(Self {
            config: RwLock::new(config),
            q_values: DashMap::new(),
            states: DashMap::new(),
            exploration_rate: RwLock::new(exploration_rate),
            stats: SmartLBStats::default(),
            last_update: RwLock::new(Instant::now()),
        })
    }

    /// Select the best server using epsilon-greedy
    pub fn select_server(&self, servers: &[String]) -> Option<String> {
        if servers.is_empty() {
            return None;
        }

        self.stats.selections.fetch_add(1, Ordering::Relaxed);

        let epsilon = *self.exploration_rate.read();

        // Epsilon-greedy exploration
        if rand::random::<f64>() < epsilon {
            self.stats.explorations.fetch_add(1, Ordering::Relaxed);
            let idx = rand::random::<usize>() % servers.len();
            return Some(servers[idx].clone());
        }

        self.stats.exploitations.fetch_add(1, Ordering::Relaxed);

        // Find server with best Q-value
        let mut best_server = &servers[0];
        let mut best_value = f64::NEG_INFINITY;

        for server in servers {
            let value = self.q_values.get(server).map(|q| q.value).unwrap_or(0.0);

            if value > best_value {
                best_value = value;
                best_server = server;
            }
        }

        Some(best_server.clone())
    }

    /// Update Q-value based on reward
    pub fn update(&self, server: &str, reward: f64) {
        let config = self.config.read();

        let mut q = self.q_values.entry(server.to_string()).or_default();

        // Q-learning update
        q.value = q.value + config.learning_rate * (reward - q.value);
        q.updates += 1;

        // Track recent rewards
        q.rewards.push_back(reward);
        if q.rewards.len() > config.window_size {
            q.rewards.pop_front();
        }

        self.stats.updates.fetch_add(1, Ordering::Relaxed);

        // Decay exploration rate
        drop(config);
        self.decay_exploration();

        trace!("Updated Q-value for {}: {:.4}", server, q.value);
    }

    /// Calculate reward from request outcome
    pub fn calculate_reward(&self, latency_ms: u64, success: bool, _server: &str) -> f64 {
        // Reward function:
        // - Positive for fast, successful requests
        // - Negative for slow or failed requests
        // - Scaled to roughly [-1, 1]

        if !success {
            return -1.0;
        }

        // Reward based on latency (assumes 500ms is acceptable baseline)
        let latency_reward = 1.0 - (latency_ms as f64 / 500.0).min(2.0);

        latency_reward.clamp(-1.0, 1.0)
    }

    /// Update server state
    pub fn update_state(&self, server: &str, state: ServerState) {
        self.states.insert(server.to_string(), state);
    }

    /// Get server state
    pub fn get_state(&self, server: &str) -> Option<ServerState> {
        self.states.get(server).map(|s| s.clone())
    }

    /// Decay exploration rate
    fn decay_exploration(&self) {
        let config = self.config.read();
        let mut rate = self.exploration_rate.write();

        *rate = (*rate * config.exploration_decay).max(config.min_exploration_rate);
    }

    /// Get current exploration rate
    pub fn exploration_rate(&self) -> f64 {
        *self.exploration_rate.read()
    }

    /// Get Q-value for a server
    pub fn get_q_value(&self, server: &str) -> f64 {
        self.q_values.get(server).map(|q| q.value).unwrap_or(0.0)
    }

    /// Get all Q-values
    pub fn all_q_values(&self) -> HashMap<String, f64> {
        self.q_values
            .iter()
            .map(|e| (e.key().clone(), e.value().value))
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> &SmartLBStats {
        &self.stats
    }
}

// ============================================================================
// Request Classification
// ============================================================================

/// Request classification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestClass {
    /// Normal browser user
    Browser,
    /// API client
    Api,
    /// Mobile app
    Mobile,
    /// Known good bot (search engines, etc.)
    GoodBot,
    /// Suspicious bot
    SuspiciousBot,
    /// Known bad bot/attack
    BadBot,
    /// Automated tool
    Tool,
    /// Unknown
    Unknown,
}

/// Features for request classification
#[derive(Debug, Clone, Default)]
pub struct RequestFeatures {
    /// User-Agent header
    pub user_agent: Option<String>,
    /// Accept header
    pub accept: Option<String>,
    /// Accept-Language header
    pub accept_language: Option<String>,
    /// Accept-Encoding header
    pub accept_encoding: Option<String>,
    /// Has cookies
    pub has_cookies: bool,
    /// Has referer
    pub has_referer: bool,
    /// Request rate from this IP
    pub request_rate: f64,
    /// Geographic region
    pub geo_region: Option<String>,
    /// TLS version
    pub tls_version: Option<String>,
    /// HTTP version
    pub http_version: String,
    /// Request path pattern
    pub path_pattern: String,
    /// Time since last request
    pub time_since_last_ms: Option<u64>,
}

/// Request classifier
pub struct RequestClassifier {
    /// Known good bot patterns
    good_bot_patterns: Vec<String>,
    /// Known bad bot patterns
    bad_bot_patterns: Vec<String>,
    /// Browser patterns
    browser_patterns: Vec<String>,
    /// API client patterns
    api_patterns: Vec<String>,
    /// Classification cache
    cache: DashMap<String, (RequestClass, Instant)>,
    /// Cache TTL
    cache_ttl: Duration,
    /// Statistics
    stats: ClassifierStats,
}

/// Classification statistics
#[derive(Debug, Default)]
pub struct ClassifierStats {
    pub total_classified: AtomicU64,
    pub browser: AtomicU64,
    pub api: AtomicU64,
    pub mobile: AtomicU64,
    pub good_bot: AtomicU64,
    pub suspicious_bot: AtomicU64,
    pub bad_bot: AtomicU64,
    pub tool: AtomicU64,
    pub unknown: AtomicU64,
    pub cache_hits: AtomicU64,
}

impl RequestClassifier {
    /// Create a new classifier with default patterns
    pub fn new() -> Self {
        Self {
            good_bot_patterns: vec![
                "Googlebot".to_string(),
                "Bingbot".to_string(),
                "Slurp".to_string(),
                "DuckDuckBot".to_string(),
                "Baiduspider".to_string(),
                "YandexBot".to_string(),
                "facebookexternalhit".to_string(),
                "Twitterbot".to_string(),
                "LinkedInBot".to_string(),
            ],
            bad_bot_patterns: vec![
                "Scrapy".to_string(),
                "Wget".to_string(),
                "HTTrack".to_string(),
                "sqlmap".to_string(),
                "nikto".to_string(),
                "Nessus".to_string(),
            ],
            browser_patterns: vec![
                "Mozilla".to_string(),
                "Chrome".to_string(),
                "Safari".to_string(),
                "Firefox".to_string(),
                "Edge".to_string(),
                "Opera".to_string(),
            ],
            api_patterns: vec![
                "curl".to_string(),
                "python-requests".to_string(),
                "axios".to_string(),
                "okhttp".to_string(),
                "Go-http-client".to_string(),
            ],
            cache: DashMap::new(),
            cache_ttl: Duration::from_secs(300),
            stats: ClassifierStats::default(),
        }
    }

    /// Classify a request
    pub fn classify(&self, features: &RequestFeatures) -> RequestClass {
        self.stats.total_classified.fetch_add(1, Ordering::Relaxed);

        // Check cache first
        if let Some(ua) = &features.user_agent {
            if let Some(entry) = self.cache.get(ua) {
                if entry.1.elapsed() < self.cache_ttl {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return entry.0.clone();
                }
            }
        }

        let class = self.do_classify(features);

        // Update stats
        match &class {
            RequestClass::Browser => self.stats.browser.fetch_add(1, Ordering::Relaxed),
            RequestClass::Api => self.stats.api.fetch_add(1, Ordering::Relaxed),
            RequestClass::Mobile => self.stats.mobile.fetch_add(1, Ordering::Relaxed),
            RequestClass::GoodBot => self.stats.good_bot.fetch_add(1, Ordering::Relaxed),
            RequestClass::SuspiciousBot => {
                self.stats.suspicious_bot.fetch_add(1, Ordering::Relaxed)
            }
            RequestClass::BadBot => self.stats.bad_bot.fetch_add(1, Ordering::Relaxed),
            RequestClass::Tool => self.stats.tool.fetch_add(1, Ordering::Relaxed),
            RequestClass::Unknown => self.stats.unknown.fetch_add(1, Ordering::Relaxed),
        };

        // Cache result
        if let Some(ua) = &features.user_agent {
            self.cache
                .insert(ua.clone(), (class.clone(), Instant::now()));
        }

        class
    }

    fn do_classify(&self, features: &RequestFeatures) -> RequestClass {
        let ua = features.user_agent.as_deref().unwrap_or("");

        // Check for known bad bots first
        for pattern in &self.bad_bot_patterns {
            if ua.to_lowercase().contains(&pattern.to_lowercase()) {
                return RequestClass::BadBot;
            }
        }

        // Check for known good bots
        for pattern in &self.good_bot_patterns {
            if ua.to_lowercase().contains(&pattern.to_lowercase()) {
                return RequestClass::GoodBot;
            }
        }

        // Check for API clients
        for pattern in &self.api_patterns {
            if ua.to_lowercase().contains(&pattern.to_lowercase()) {
                return RequestClass::Api;
            }
        }

        // Check for mobile
        if ua.contains("Mobile") || ua.contains("Android") || ua.contains("iPhone") {
            return RequestClass::Mobile;
        }

        // Check for browsers
        let is_browser = self.browser_patterns.iter().any(|p| ua.contains(p));

        if is_browser {
            // Additional checks for browser authenticity
            let has_browser_headers =
                features.accept_language.is_some() && features.accept_encoding.is_some();

            if has_browser_headers {
                return RequestClass::Browser;
            } else {
                return RequestClass::SuspiciousBot;
            }
        }

        // High request rate without browser characteristics
        if features.request_rate > 10.0 && !features.has_cookies {
            return RequestClass::SuspiciousBot;
        }

        // Empty or missing User-Agent
        if ua.is_empty() {
            return RequestClass::Tool;
        }

        RequestClass::Unknown
    }

    /// Get classification statistics
    pub fn stats(&self) -> &ClassifierStats {
        &self.stats
    }
}

impl Default for RequestClassifier {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Latency Prediction
// ============================================================================

/// Latency predictor configuration
#[derive(Debug, Clone)]
pub struct LatencyPredictorConfig {
    /// History window size
    pub history_size: usize,
    /// Exponential smoothing alpha
    pub smoothing_alpha: f64,
    /// Update threshold (minimum samples before prediction)
    pub min_samples: usize,
}

impl Default for LatencyPredictorConfig {
    fn default() -> Self {
        Self {
            history_size: 1000,
            smoothing_alpha: 0.3,
            min_samples: 10,
        }
    }
}

/// Latency predictor using exponential smoothing
pub struct LatencyPredictor {
    config: LatencyPredictorConfig,
    /// Per-route latency history
    history: DashMap<String, LatencyHistory>,
}

struct LatencyHistory {
    samples: VecDeque<u64>,
    ema: f64,
    variance: f64,
    last_update: Instant,
}

impl LatencyPredictor {
    /// Create a new latency predictor
    pub fn new(config: LatencyPredictorConfig) -> Self {
        Self {
            config,
            history: DashMap::new(),
        }
    }

    /// Record a latency observation
    pub fn record(&self, route: &str, latency_ms: u64) {
        let mut entry = self
            .history
            .entry(route.to_string())
            .or_insert_with(|| LatencyHistory {
                samples: VecDeque::with_capacity(self.config.history_size),
                ema: latency_ms as f64,
                variance: 0.0,
                last_update: Instant::now(),
            });

        // Add sample
        entry.samples.push_back(latency_ms);
        if entry.samples.len() > self.config.history_size {
            entry.samples.pop_front();
        }

        // Update EMA
        let alpha = self.config.smoothing_alpha;
        let old_ema = entry.ema;
        entry.ema = alpha * latency_ms as f64 + (1.0 - alpha) * old_ema;

        // Update variance (using Welford's online algorithm)
        let diff = latency_ms as f64 - old_ema;
        entry.variance = (1.0 - alpha) * (entry.variance + alpha * diff * diff);

        entry.last_update = Instant::now();
    }

    /// Predict latency for a route
    pub fn predict(&self, route: &str) -> Option<LatencyPrediction> {
        self.history.get(route).and_then(|h| {
            if h.samples.len() < self.config.min_samples {
                return None;
            }

            let std_dev = h.variance.sqrt();

            Some(LatencyPrediction {
                predicted_ms: h.ema,
                confidence_low_ms: (h.ema - 2.0 * std_dev).max(0.0),
                confidence_high_ms: h.ema + 2.0 * std_dev,
                sample_count: h.samples.len(),
                last_update: h.last_update,
            })
        })
    }

    /// Get percentile latency
    pub fn percentile(&self, route: &str, p: f64) -> Option<u64> {
        self.history.get(route).and_then(|h| {
            if h.samples.is_empty() {
                return None;
            }

            let mut sorted: Vec<_> = h.samples.iter().copied().collect();
            sorted.sort();

            let idx = ((p / 100.0) * sorted.len() as f64) as usize;
            sorted.get(idx.min(sorted.len() - 1)).copied()
        })
    }
}

/// Latency prediction result
#[derive(Debug, Clone)]
pub struct LatencyPrediction {
    /// Predicted latency (ms)
    pub predicted_ms: f64,
    /// Lower bound (95% confidence)
    pub confidence_low_ms: f64,
    /// Upper bound (95% confidence)
    pub confidence_high_ms: f64,
    /// Number of samples used
    pub sample_count: usize,
    /// Last update time
    pub last_update: Instant,
}

// ============================================================================
// Predictive Autoscaling
// ============================================================================

/// Autoscaling prediction
#[derive(Debug, Clone)]
pub struct ScalingPrediction {
    /// Predicted RPS in next interval
    pub predicted_rps: f64,
    /// Recommended instance count
    pub recommended_instances: u32,
    /// Confidence (0-1)
    pub confidence: f64,
    /// Predicted time until scaling needed
    pub scale_in: Option<Duration>,
}

/// Traffic pattern analyzer for autoscaling
pub struct TrafficAnalyzer {
    /// Per-minute traffic counts
    minute_counts: RwLock<VecDeque<(Instant, u64)>>,
    /// Historical patterns by hour of day
    #[allow(dead_code)]
    hourly_patterns: RwLock<[f64; 24]>,
    /// Maximum instances
    max_instances: u32,
    /// RPS per instance capacity
    rps_per_instance: f64,
}

impl TrafficAnalyzer {
    /// Create a new traffic analyzer
    pub fn new(max_instances: u32, rps_per_instance: f64) -> Self {
        Self {
            minute_counts: RwLock::new(VecDeque::with_capacity(60)),
            hourly_patterns: RwLock::new([1.0; 24]),
            max_instances,
            rps_per_instance,
        }
    }

    /// Record traffic
    pub fn record(&self, count: u64) {
        let mut counts = self.minute_counts.write();
        counts.push_back((Instant::now(), count));

        // Keep last hour
        let hour_ago = Instant::now() - Duration::from_secs(3600);
        while counts.front().map(|(t, _)| *t < hour_ago).unwrap_or(false) {
            counts.pop_front();
        }
    }

    /// Predict future traffic
    pub fn predict(&self, horizon: Duration) -> ScalingPrediction {
        let counts = self.minute_counts.read();

        if counts.len() < 5 {
            return ScalingPrediction {
                predicted_rps: 0.0,
                recommended_instances: 1,
                confidence: 0.0,
                scale_in: None,
            };
        }

        // Calculate current RPS trend
        let recent: Vec<_> = counts.iter().rev().take(5).collect();
        let current_rps = recent.iter().map(|(_, c)| *c as f64).sum::<f64>() / 5.0 / 60.0;

        // Simple linear extrapolation
        let trend = if recent.len() >= 2 {
            let first = recent.last().map(|(_, c)| *c as f64).unwrap_or(0.0);
            let last = recent.first().map(|(_, c)| *c as f64).unwrap_or(0.0);
            (last - first) / recent.len() as f64
        } else {
            0.0
        };

        let horizon_minutes = horizon.as_secs_f64() / 60.0;
        let predicted_rps = (current_rps + trend * horizon_minutes).max(0.0);

        // Calculate recommended instances
        let needed = (predicted_rps / self.rps_per_instance).ceil() as u32;
        let recommended = needed.clamp(1, self.max_instances);

        ScalingPrediction {
            predicted_rps,
            recommended_instances: recommended,
            confidence: (counts.len() as f64 / 60.0).min(1.0),
            scale_in: if trend > 0.0 {
                Some(Duration::from_secs_f64(
                    ((self.rps_per_instance - current_rps) / trend * 60.0).max(0.0),
                ))
            } else {
                None
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smart_lb_select() {
        let config = SmartLBConfig::default();
        let lb = SmartLoadBalancer::new(config);

        let servers = vec!["s1".to_string(), "s2".to_string(), "s3".to_string()];

        // Should select a server
        let selected = lb.select_server(&servers);
        assert!(selected.is_some());
    }

    #[test]
    fn test_smart_lb_update() {
        let config = SmartLBConfig::default();
        let lb = SmartLoadBalancer::new(config);

        lb.update("server1", 0.5);
        lb.update("server1", 0.8);

        let q = lb.get_q_value("server1");
        assert!(q > 0.0);
    }

    #[test]
    fn test_reward_calculation() {
        let config = SmartLBConfig::default();
        let lb = SmartLoadBalancer::new(config);

        // Fast successful request
        let reward = lb.calculate_reward(100, true, "s1");
        assert!(reward > 0.0);

        // Failed request
        let reward = lb.calculate_reward(100, false, "s1");
        assert_eq!(reward, -1.0);

        // Slow request
        let reward = lb.calculate_reward(1000, true, "s1");
        assert!(reward < 0.5);
    }

    #[test]
    fn test_request_classifier() {
        let classifier = RequestClassifier::new();

        // Browser
        let features = RequestFeatures {
            user_agent: Some("Mozilla/5.0 Chrome/91.0".to_string()),
            accept_language: Some("en-US".to_string()),
            accept_encoding: Some("gzip".to_string()),
            ..Default::default()
        };
        assert_eq!(classifier.classify(&features), RequestClass::Browser);

        // Good bot
        let features = RequestFeatures {
            user_agent: Some("Googlebot/2.1".to_string()),
            ..Default::default()
        };
        assert_eq!(classifier.classify(&features), RequestClass::GoodBot);

        // API client
        let features = RequestFeatures {
            user_agent: Some("python-requests/2.25.1".to_string()),
            ..Default::default()
        };
        assert_eq!(classifier.classify(&features), RequestClass::Api);
    }

    #[test]
    fn test_latency_predictor() {
        let config = LatencyPredictorConfig {
            min_samples: 3,
            ..Default::default()
        };
        let predictor = LatencyPredictor::new(config);

        // Record samples
        for i in 0..10 {
            predictor.record("/api/test", 100 + i * 10);
        }

        let prediction = predictor.predict("/api/test");
        assert!(prediction.is_some());

        let p = prediction.unwrap();
        assert!(p.predicted_ms > 0.0);
        assert!(p.sample_count >= 3);
    }

    #[test]
    fn test_traffic_analyzer() {
        let analyzer = TrafficAnalyzer::new(10, 1000.0);

        // Record some traffic
        for _ in 0..10 {
            analyzer.record(1000);
        }

        let prediction = analyzer.predict(Duration::from_secs(300));
        assert!(prediction.confidence > 0.0);
    }
}
