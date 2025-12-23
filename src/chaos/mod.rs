//! Chaos Engineering
//!
//! Built-in fault injection for testing system resilience:
//! - Latency injection (fixed or random delay)
//! - Error injection (HTTP errors, connection resets)
//! - Bandwidth throttling
//! - Partition simulation
//! - CPU/Memory stress testing
//!
//! Safely test how your system handles failures.

use bytes::Bytes;
use http::{Request, StatusCode};
use parking_lot::RwLock;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Chaos engineering configuration
#[derive(Debug, Clone)]
pub struct ChaosConfig {
    /// Global enable/disable for chaos features
    pub enabled: bool,
    /// Default probability for faults (0.0 - 1.0)
    pub default_probability: f64,
    /// Safety: maximum percentage of requests to affect
    pub max_affected_percentage: f64,
    /// Dry run mode (log but don't inject)
    pub dry_run: bool,
    /// Routes/paths to target (empty = all)
    pub target_paths: Vec<String>,
    /// Routes/paths to exclude
    pub exclude_paths: Vec<String>,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Off by default for safety
            default_probability: 0.1,
            max_affected_percentage: 50.0,
            dry_run: false,
            target_paths: Vec::new(),
            exclude_paths: vec![
                "/health".to_string(),
                "/ready".to_string(),
                "/metrics".to_string(),
            ],
        }
    }
}

/// Types of chaos faults
#[derive(Debug, Clone)]
pub enum FaultType {
    /// Add latency to requests
    Latency(LatencyFault),
    /// Return error responses
    Error(ErrorFault),
    /// Abort connections
    Abort(AbortFault),
    /// Throttle bandwidth
    Throttle(ThrottleFault),
    /// Corrupt response data
    Corrupt(CorruptFault),
    /// Simulate partition (drop requests)
    Partition(PartitionFault),
}

/// Latency injection configuration
#[derive(Debug, Clone)]
pub struct LatencyFault {
    /// Fixed delay to add
    pub fixed_delay: Option<Duration>,
    /// Random delay range (min, max)
    pub random_delay: Option<(Duration, Duration)>,
    /// Probability of injecting latency (0.0 - 1.0)
    pub probability: f64,
    /// Apply to request, response, or both
    pub phase: FaultPhase,
}

impl Default for LatencyFault {
    fn default() -> Self {
        Self {
            fixed_delay: Some(Duration::from_millis(100)),
            random_delay: None,
            probability: 0.1,
            phase: FaultPhase::Request,
        }
    }
}

/// Error injection configuration
#[derive(Debug, Clone)]
pub struct ErrorFault {
    /// HTTP status code to return
    pub status_code: StatusCode,
    /// Error body
    pub body: Option<String>,
    /// Probability of injecting error (0.0 - 1.0)
    pub probability: f64,
    /// Custom headers to include
    pub headers: HashMap<String, String>,
}

impl Default for ErrorFault {
    fn default() -> Self {
        Self {
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            body: Some("Chaos fault injected".to_string()),
            probability: 0.1,
            headers: HashMap::new(),
        }
    }
}

/// Connection abort configuration
#[derive(Debug, Clone)]
pub struct AbortFault {
    /// When to abort (before/during request)
    pub abort_at: AbortPoint,
    /// Probability of aborting
    pub probability: f64,
    /// Delay before abort
    pub delay: Option<Duration>,
}

impl Default for AbortFault {
    fn default() -> Self {
        Self {
            abort_at: AbortPoint::BeforeUpstream,
            probability: 0.05,
            delay: None,
        }
    }
}

/// Bandwidth throttling configuration
#[derive(Debug, Clone)]
pub struct ThrottleFault {
    /// Bytes per second limit
    pub bytes_per_second: u64,
    /// Probability of throttling
    pub probability: f64,
    /// Apply to upload, download, or both
    pub direction: ThrottleDirection,
}

impl Default for ThrottleFault {
    fn default() -> Self {
        Self {
            bytes_per_second: 1024, // 1 KB/s
            probability: 0.1,
            direction: ThrottleDirection::Both,
        }
    }
}

/// Response corruption configuration
#[derive(Debug, Clone)]
pub struct CorruptFault {
    /// Probability of corruption
    pub probability: f64,
    /// Corruption type
    pub corruption_type: CorruptionType,
    /// Percentage of data to corrupt
    pub corruption_percentage: f64,
}

impl Default for CorruptFault {
    fn default() -> Self {
        Self {
            probability: 0.05,
            corruption_type: CorruptionType::RandomBytes,
            corruption_percentage: 10.0,
        }
    }
}

/// Partition simulation configuration
#[derive(Debug, Clone)]
pub struct PartitionFault {
    /// Probability of partition
    pub probability: f64,
    /// Duration of partition
    pub duration: Duration,
    /// Drop vs delay behavior
    pub behavior: PartitionBehavior,
}

impl Default for PartitionFault {
    fn default() -> Self {
        Self {
            probability: 0.02,
            duration: Duration::from_secs(10),
            behavior: PartitionBehavior::Drop,
        }
    }
}

/// When to apply the fault
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPhase {
    Request,
    Response,
    Both,
}

/// When to abort the connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortPoint {
    /// Before connecting to upstream
    BeforeUpstream,
    /// After connecting but before sending request
    AfterConnect,
    /// While receiving response
    DuringResponse,
}

/// Direction for bandwidth throttling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleDirection {
    Upload,
    Download,
    Both,
}

/// Type of data corruption
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptionType {
    /// Replace random bytes
    RandomBytes,
    /// Truncate response
    Truncate,
    /// Duplicate chunks
    Duplicate,
    /// Flip bits
    BitFlip,
}

/// Partition behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionBehavior {
    /// Drop requests silently
    Drop,
    /// Delay requests until partition ends
    Delay,
    /// Return error
    Error,
}

/// Result of fault injection
#[derive(Debug, Clone)]
pub enum FaultResult {
    /// No fault applied
    None,
    /// Latency was injected
    LatencyInjected(Duration),
    /// Error response was injected
    ErrorInjected(StatusCode),
    /// Connection was aborted
    Aborted,
    /// Bandwidth was throttled
    Throttled(u64),
    /// Data was corrupted
    Corrupted,
    /// Partition was simulated
    Partitioned,
}

/// Statistics for chaos engineering
#[derive(Debug, Default)]
pub struct ChaosStats {
    /// Total requests processed
    pub total_requests: AtomicU64,
    /// Latency faults injected
    pub latency_faults: AtomicU64,
    /// Error faults injected
    pub error_faults: AtomicU64,
    /// Aborts injected
    pub abort_faults: AtomicU64,
    /// Throttle faults injected
    pub throttle_faults: AtomicU64,
    /// Corruption faults injected
    pub corrupt_faults: AtomicU64,
    /// Partition faults injected
    pub partition_faults: AtomicU64,
    /// Faults skipped (dry run)
    pub dry_run_skipped: AtomicU64,
}

impl ChaosStats {
    /// Total faults injected
    pub fn total_faults(&self) -> u64 {
        self.latency_faults.load(Ordering::Relaxed)
            + self.error_faults.load(Ordering::Relaxed)
            + self.abort_faults.load(Ordering::Relaxed)
            + self.throttle_faults.load(Ordering::Relaxed)
            + self.corrupt_faults.load(Ordering::Relaxed)
            + self.partition_faults.load(Ordering::Relaxed)
    }

    /// Fault rate percentage
    pub fn fault_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        (self.total_faults() as f64 / total as f64) * 100.0
    }
}

/// Chaos engine for fault injection
pub struct ChaosEngine {
    config: RwLock<ChaosConfig>,
    faults: RwLock<Vec<FaultRule>>,
    stats: Arc<ChaosStats>,
    rng: RwLock<StdRng>,
    enabled: AtomicBool,
    partition_active: AtomicBool,
    partition_end: RwLock<Option<Instant>>,
}

/// A fault injection rule
#[derive(Debug, Clone)]
pub struct FaultRule {
    /// Unique identifier
    pub id: String,
    /// Fault type
    pub fault: FaultType,
    /// Target path pattern (regex)
    pub path_pattern: Option<String>,
    /// Target methods
    pub methods: Vec<String>,
    /// Additional match conditions
    pub conditions: Vec<FaultCondition>,
    /// Is this rule active?
    pub active: bool,
    /// Priority (higher = first)
    pub priority: i32,
}

/// Conditions for applying a fault
#[derive(Debug, Clone)]
pub enum FaultCondition {
    /// Match header value
    Header { name: String, value: String },
    /// Match query parameter
    QueryParam { name: String, value: String },
    /// Time-based (only during certain hours)
    TimeWindow { start_hour: u8, end_hour: u8 },
    /// Rate-based (every Nth request)
    NthRequest(u64),
}

impl ChaosEngine {
    /// Create a new chaos engine
    pub fn new(config: ChaosConfig) -> Arc<Self> {
        let enabled = config.enabled;
        Arc::new(Self {
            config: RwLock::new(config),
            faults: RwLock::new(Vec::new()),
            stats: Arc::new(ChaosStats::default()),
            rng: RwLock::new(StdRng::from_entropy()),
            enabled: AtomicBool::new(enabled),
            partition_active: AtomicBool::new(false),
            partition_end: RwLock::new(None),
        })
    }

    /// Check if chaos is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Enable chaos engineering
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
        info!("Chaos engineering ENABLED");
    }

    /// Disable chaos engineering
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
        info!("Chaos engineering DISABLED");
    }

    /// Add a fault rule
    pub fn add_rule(&self, rule: FaultRule) {
        let mut faults = self.faults.write();
        faults.push(rule.clone());
        faults.sort_by(|a, b| b.priority.cmp(&a.priority));
        info!("Added chaos rule: {}", rule.id);
    }

    /// Remove a fault rule
    pub fn remove_rule(&self, id: &str) {
        let mut faults = self.faults.write();
        faults.retain(|r| r.id != id);
        info!("Removed chaos rule: {}", id);
    }

    /// Get all active rules
    pub fn rules(&self) -> Vec<FaultRule> {
        self.faults.read().clone()
    }

    /// Clear all rules
    pub fn clear_rules(&self) {
        self.faults.write().clear();
        info!("Cleared all chaos rules");
    }

    /// Get statistics
    pub fn stats(&self) -> Arc<ChaosStats> {
        self.stats.clone()
    }

    /// Check if path should be excluded
    fn is_excluded(&self, path: &str) -> bool {
        let config = self.config.read();
        for exclude in &config.exclude_paths {
            if path.starts_with(exclude) {
                return true;
            }
        }
        false
    }

    /// Check if path matches target
    fn matches_target(&self, path: &str) -> bool {
        let config = self.config.read();
        if config.target_paths.is_empty() {
            return true;
        }
        for target in &config.target_paths {
            if path.starts_with(target) {
                return true;
            }
        }
        false
    }

    /// Should inject fault based on probability
    fn should_inject(&self, probability: f64) -> bool {
        let mut rng = self.rng.write();
        rng.gen::<f64>() < probability
    }

    /// Process a request through chaos
    pub async fn process_request<B>(&self, request: &Request<B>) -> Option<FaultResult> {
        if !self.is_enabled() {
            return None;
        }

        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        let path = request.uri().path();

        // Check exclusions
        if self.is_excluded(path) {
            return None;
        }

        // Check targets
        if !self.matches_target(path) {
            return None;
        }

        // Check for active partition
        if self.partition_active.load(Ordering::Relaxed) {
            if let Some(end) = *self.partition_end.read() {
                if Instant::now() < end {
                    self.stats.partition_faults.fetch_add(1, Ordering::Relaxed);
                    return Some(FaultResult::Partitioned);
                } else {
                    self.partition_active.store(false, Ordering::Relaxed);
                }
            }
        }

        // Check fault rules
        let rules: Vec<_> = self
            .faults
            .read()
            .iter()
            .filter(|r| r.active)
            .cloned()
            .collect();
        for rule in rules {
            if let Some(result) = self.apply_rule(&rule).await {
                return Some(result);
            }
        }

        None
    }

    /// Apply a fault rule
    async fn apply_rule(&self, rule: &FaultRule) -> Option<FaultResult> {
        let dry_run = self.config.read().dry_run;

        match &rule.fault {
            FaultType::Latency(latency) => {
                if !self.should_inject(latency.probability) {
                    return None;
                }

                let delay = if let Some(fixed) = latency.fixed_delay {
                    fixed
                } else if let Some((min, max)) = latency.random_delay {
                    let mut rng = self.rng.write();
                    let range = max.as_millis() - min.as_millis();
                    let delay_ms = min.as_millis() + rng.gen_range(0..=range as u64) as u128;
                    Duration::from_millis(delay_ms as u64)
                } else {
                    return None;
                };

                if dry_run {
                    debug!("DRY RUN: Would inject {}ms latency", delay.as_millis());
                    self.stats.dry_run_skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                sleep(delay).await;
                self.stats.latency_faults.fetch_add(1, Ordering::Relaxed);
                debug!("Injected {}ms latency", delay.as_millis());
                Some(FaultResult::LatencyInjected(delay))
            }

            FaultType::Error(error) => {
                if !self.should_inject(error.probability) {
                    return None;
                }

                if dry_run {
                    debug!("DRY RUN: Would inject {} error", error.status_code);
                    self.stats.dry_run_skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                self.stats.error_faults.fetch_add(1, Ordering::Relaxed);
                debug!("Injected {} error", error.status_code);
                Some(FaultResult::ErrorInjected(error.status_code))
            }

            FaultType::Abort(abort) => {
                if !self.should_inject(abort.probability) {
                    return None;
                }

                if let Some(delay) = abort.delay {
                    sleep(delay).await;
                }

                if dry_run {
                    debug!("DRY RUN: Would abort connection");
                    self.stats.dry_run_skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                self.stats.abort_faults.fetch_add(1, Ordering::Relaxed);
                debug!("Aborting connection");
                Some(FaultResult::Aborted)
            }

            FaultType::Throttle(throttle) => {
                if !self.should_inject(throttle.probability) {
                    return None;
                }

                if dry_run {
                    debug!(
                        "DRY RUN: Would throttle to {} B/s",
                        throttle.bytes_per_second
                    );
                    self.stats.dry_run_skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                self.stats.throttle_faults.fetch_add(1, Ordering::Relaxed);
                debug!("Throttling to {} B/s", throttle.bytes_per_second);
                Some(FaultResult::Throttled(throttle.bytes_per_second))
            }

            FaultType::Corrupt(_corrupt) => {
                // Corruption is applied to response body, not here
                None
            }

            FaultType::Partition(partition) => {
                if !self.should_inject(partition.probability) {
                    return None;
                }

                if dry_run {
                    debug!(
                        "DRY RUN: Would simulate partition for {:?}",
                        partition.duration
                    );
                    self.stats.dry_run_skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                // Activate partition
                self.partition_active.store(true, Ordering::Relaxed);
                *self.partition_end.write() = Some(Instant::now() + partition.duration);

                self.stats.partition_faults.fetch_add(1, Ordering::Relaxed);
                warn!("Simulating partition for {:?}", partition.duration);
                Some(FaultResult::Partitioned)
            }
        }
    }

    /// Corrupt response body
    pub fn corrupt_body(&self, body: &mut Bytes, config: &CorruptFault) -> bool {
        if !self.should_inject(config.probability) {
            return false;
        }

        if self.config.read().dry_run {
            debug!("DRY RUN: Would corrupt response body");
            return false;
        }

        let mut data = body.to_vec();
        let corrupt_count =
            ((data.len() as f64 * config.corruption_percentage / 100.0) as usize).max(1);

        let mut rng = self.rng.write();

        match config.corruption_type {
            CorruptionType::RandomBytes => {
                for _ in 0..corrupt_count {
                    if !data.is_empty() {
                        let idx = rng.gen_range(0..data.len());
                        data[idx] = rng.gen();
                    }
                }
            }
            CorruptionType::Truncate => {
                let new_len = data.len().saturating_sub(corrupt_count);
                data.truncate(new_len);
            }
            CorruptionType::Duplicate => {
                if data.len() > 10 {
                    let start = rng.gen_range(0..data.len() - 10);
                    let chunk: Vec<u8> = data[start..start + 10].to_vec();
                    let insert_at = rng.gen_range(0..data.len());
                    for (i, byte) in chunk.into_iter().enumerate() {
                        data.insert(insert_at + i, byte);
                    }
                }
            }
            CorruptionType::BitFlip => {
                for _ in 0..corrupt_count {
                    if !data.is_empty() {
                        let idx = rng.gen_range(0..data.len());
                        let bit = rng.gen_range(0..8);
                        data[idx] ^= 1 << bit;
                    }
                }
            }
        }

        *body = Bytes::from(data);
        self.stats.corrupt_faults.fetch_add(1, Ordering::Relaxed);
        debug!("Corrupted response body");
        true
    }
}

/// Chaos engineering presets for common scenarios
pub struct ChaosPresets;

impl ChaosPresets {
    /// Create network latency simulation
    pub fn network_latency(delay_ms: u64, probability: f64) -> FaultRule {
        FaultRule {
            id: "network-latency".to_string(),
            fault: FaultType::Latency(LatencyFault {
                fixed_delay: Some(Duration::from_millis(delay_ms)),
                random_delay: None,
                probability,
                phase: FaultPhase::Request,
            }),
            path_pattern: None,
            methods: vec![],
            conditions: vec![],
            active: true,
            priority: 10,
        }
    }

    /// Create intermittent 500 errors
    pub fn server_errors(probability: f64) -> FaultRule {
        FaultRule {
            id: "server-errors".to_string(),
            fault: FaultType::Error(ErrorFault {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                body: Some("Simulated server error".to_string()),
                probability,
                headers: HashMap::new(),
            }),
            path_pattern: None,
            methods: vec![],
            conditions: vec![],
            active: true,
            priority: 20,
        }
    }

    /// Create connection abort scenario
    pub fn connection_reset(probability: f64) -> FaultRule {
        FaultRule {
            id: "connection-reset".to_string(),
            fault: FaultType::Abort(AbortFault {
                abort_at: AbortPoint::DuringResponse,
                probability,
                delay: Some(Duration::from_millis(100)),
            }),
            path_pattern: None,
            methods: vec![],
            conditions: vec![],
            active: true,
            priority: 30,
        }
    }

    /// Create slow network simulation
    pub fn slow_network(bytes_per_second: u64, probability: f64) -> FaultRule {
        FaultRule {
            id: "slow-network".to_string(),
            fault: FaultType::Throttle(ThrottleFault {
                bytes_per_second,
                probability,
                direction: ThrottleDirection::Both,
            }),
            path_pattern: None,
            methods: vec![],
            conditions: vec![],
            active: true,
            priority: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chaos_config_default() {
        let config = ChaosConfig::default();
        assert!(!config.enabled);
        assert!(!config.exclude_paths.is_empty());
    }

    #[test]
    fn test_engine_enable_disable() {
        let engine = ChaosEngine::new(ChaosConfig::default());
        assert!(!engine.is_enabled());

        engine.enable();
        assert!(engine.is_enabled());

        engine.disable();
        assert!(!engine.is_enabled());
    }

    #[test]
    fn test_add_remove_rules() {
        let engine = ChaosEngine::new(ChaosConfig::default());

        engine.add_rule(ChaosPresets::network_latency(100, 0.1));
        assert_eq!(engine.rules().len(), 1);

        engine.add_rule(ChaosPresets::server_errors(0.05));
        assert_eq!(engine.rules().len(), 2);

        engine.remove_rule("network-latency");
        assert_eq!(engine.rules().len(), 1);

        engine.clear_rules();
        assert_eq!(engine.rules().len(), 0);
    }

    #[tokio::test]
    async fn test_disabled_no_injection() {
        let engine = ChaosEngine::new(ChaosConfig::default());
        engine.add_rule(ChaosPresets::server_errors(1.0)); // 100% probability

        let request = Request::builder().uri("/api/test").body(()).unwrap();

        // Engine is disabled, should not inject
        let result = engine.process_request(&request).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_excluded_paths() {
        let mut config = ChaosConfig::default();
        config.enabled = true;
        let engine = ChaosEngine::new(config);
        engine.add_rule(ChaosPresets::server_errors(1.0));

        let request = Request::builder().uri("/health").body(()).unwrap();

        // /health is excluded by default
        let result = engine.process_request(&request).await;
        assert!(result.is_none());
    }

    #[test]
    fn test_stats() {
        let stats = ChaosStats::default();
        stats.total_requests.store(100, Ordering::Relaxed);
        stats.latency_faults.store(10, Ordering::Relaxed);
        stats.error_faults.store(5, Ordering::Relaxed);

        assert_eq!(stats.total_faults(), 15);
        assert_eq!(stats.fault_rate(), 15.0);
    }

    #[test]
    fn test_presets() {
        let latency = ChaosPresets::network_latency(100, 0.1);
        assert_eq!(latency.id, "network-latency");
        assert!(latency.active);

        let errors = ChaosPresets::server_errors(0.05);
        assert_eq!(errors.id, "server-errors");

        let reset = ChaosPresets::connection_reset(0.01);
        assert_eq!(reset.id, "connection-reset");
    }

    #[test]
    fn test_corruption() {
        let engine = ChaosEngine::new(ChaosConfig {
            enabled: true,
            dry_run: false,
            ..Default::default()
        });

        let config = CorruptFault {
            probability: 1.0,
            corruption_type: CorruptionType::BitFlip,
            corruption_percentage: 50.0,
        };

        let original = Bytes::from("hello world");
        let mut data = original.clone();

        let corrupted = engine.corrupt_body(&mut data, &config);
        assert!(corrupted);
        assert_ne!(data, original);
    }
}
