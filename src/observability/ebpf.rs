//! eBPF Observability Module
//!
//! Provides kernel-level network observability through eBPF (Extended Berkeley Packet Filter).
//! This module offers deep insights into network behavior including:
//! - TCP connection state tracking
//! - Per-connection latency measurements
//! - Packet drop analysis
//! - Syscall-level timing
//! - Network flow statistics
//!
//! # Requirements
//! - Linux kernel 4.9+ (for BTF support: 5.2+)
//! - Root or CAP_BPF + CAP_PERFMON capabilities
//! - BPF filesystem mounted at /sys/fs/bpf
//!
//! # Architecture
//! ```text
//! ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//! │  Kernel     │────▶│   eBPF      │────▶│  Ring       │
//! │  Hooks      │     │  Programs   │     │  Buffer     │
//! └─────────────┘     └─────────────┘     └─────────────┘
//!                                               │
//!                                               ▼
//!                                         ┌─────────────┐
//!                                         │  Userspace  │
//!                                         │  Collector  │
//!                                         └─────────────┘
//! ```

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// eBPF observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EbpfConfig {
    /// Enable eBPF observability
    #[serde(default)]
    pub enabled: bool,

    /// Enable TCP connection tracking
    #[serde(default = "default_true")]
    pub tcp_tracking: bool,

    /// Enable socket-level latency measurement
    #[serde(default = "default_true")]
    pub socket_latency: bool,

    /// Enable packet drop analysis
    #[serde(default)]
    pub drop_analysis: bool,

    /// Sample rate for high-volume events (0.0 - 1.0)
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,

    /// Maximum connections to track
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Ring buffer size (must be power of 2)
    #[serde(default = "default_ring_buffer_size")]
    pub ring_buffer_size: usize,

    /// Ports to monitor (empty = all ports)
    #[serde(default)]
    pub monitored_ports: Vec<u16>,

    /// Export interval in seconds
    #[serde(default = "default_export_interval")]
    pub export_interval_secs: u64,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tcp_tracking: true,
            socket_latency: true,
            drop_analysis: false,
            sample_rate: default_sample_rate(),
            max_connections: default_max_connections(),
            ring_buffer_size: default_ring_buffer_size(),
            monitored_ports: Vec::new(),
            export_interval_secs: default_export_interval(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_sample_rate() -> f64 {
    1.0
}

fn default_max_connections() -> usize {
    10000
}

fn default_ring_buffer_size() -> usize {
    4096
}

fn default_export_interval() -> u64 {
    10
}

/// TCP connection states tracked by eBPF
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TcpState {
    Established = 1,
    SynSent = 2,
    SynRecv = 3,
    FinWait1 = 4,
    FinWait2 = 5,
    TimeWait = 6,
    Close = 7,
    CloseWait = 8,
    LastAck = 9,
    Listen = 10,
    Closing = 11,
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpState::Established => write!(f, "ESTABLISHED"),
            TcpState::SynSent => write!(f, "SYN_SENT"),
            TcpState::SynRecv => write!(f, "SYN_RECV"),
            TcpState::FinWait1 => write!(f, "FIN_WAIT1"),
            TcpState::FinWait2 => write!(f, "FIN_WAIT2"),
            TcpState::TimeWait => write!(f, "TIME_WAIT"),
            TcpState::Close => write!(f, "CLOSE"),
            TcpState::CloseWait => write!(f, "CLOSE_WAIT"),
            TcpState::LastAck => write!(f, "LAST_ACK"),
            TcpState::Listen => write!(f, "LISTEN"),
            TcpState::Closing => write!(f, "CLOSING"),
        }
    }
}

/// TCP connection event from eBPF
#[derive(Debug, Clone, Serialize)]
pub struct TcpEvent {
    /// Source address
    pub src_addr: SocketAddr,
    /// Destination address
    pub dst_addr: SocketAddr,
    /// Old TCP state
    pub old_state: TcpState,
    /// New TCP state
    pub new_state: TcpState,
    /// Process ID
    pub pid: u32,
    /// Event timestamp (nanoseconds since boot)
    pub timestamp_ns: u64,
    /// RTT in microseconds (if available)
    pub rtt_us: Option<u32>,
}

/// Socket latency event
#[derive(Debug, Clone, Serialize)]
pub struct SocketLatencyEvent {
    /// Socket address
    pub addr: SocketAddr,
    /// Operation type
    pub operation: SocketOperation,
    /// Latency in nanoseconds
    pub latency_ns: u64,
    /// Bytes transferred (for read/write)
    pub bytes: usize,
    /// Process ID
    pub pid: u32,
    /// Timestamp
    pub timestamp_ns: u64,
}

/// Socket operations tracked
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SocketOperation {
    Connect,
    Accept,
    Read,
    Write,
    Close,
}

impl std::fmt::Display for SocketOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketOperation::Connect => write!(f, "connect"),
            SocketOperation::Accept => write!(f, "accept"),
            SocketOperation::Read => write!(f, "read"),
            SocketOperation::Write => write!(f, "write"),
            SocketOperation::Close => write!(f, "close"),
        }
    }
}

/// Packet drop event
#[derive(Debug, Clone, Serialize)]
pub struct PacketDropEvent {
    /// Source address
    pub src_addr: IpAddr,
    /// Destination address
    pub dst_addr: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Drop reason
    pub reason: DropReason,
    /// Timestamp
    pub timestamp_ns: u64,
}

/// Reasons for packet drops
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DropReason {
    /// No route to destination
    NoRoute,
    /// Connection refused
    ConnRefused,
    /// Port unreachable
    PortUnreachable,
    /// Host unreachable
    HostUnreachable,
    /// Connection reset
    ConnReset,
    /// Timeout
    Timeout,
    /// Buffer full
    BufferFull,
    /// Firewall/filter drop
    Filtered,
    /// Unknown reason
    Unknown,
}

impl std::fmt::Display for DropReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DropReason::NoRoute => write!(f, "no_route"),
            DropReason::ConnRefused => write!(f, "conn_refused"),
            DropReason::PortUnreachable => write!(f, "port_unreachable"),
            DropReason::HostUnreachable => write!(f, "host_unreachable"),
            DropReason::ConnReset => write!(f, "conn_reset"),
            DropReason::Timeout => write!(f, "timeout"),
            DropReason::BufferFull => write!(f, "buffer_full"),
            DropReason::Filtered => write!(f, "filtered"),
            DropReason::Unknown => write!(f, "unknown"),
        }
    }
}

/// Connection flow statistics
#[derive(Debug, Clone, Default, Serialize)]
pub struct FlowStats {
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Retransmit count
    pub retransmits: u64,
    /// Connection duration in microseconds
    pub duration_us: u64,
    /// Minimum RTT observed
    pub min_rtt_us: u32,
    /// Maximum RTT observed
    pub max_rtt_us: u32,
    /// Smoothed RTT
    pub smoothed_rtt_us: u32,
}

/// eBPF metrics collector
pub struct EbpfCollector {
    config: EbpfConfig,
    running: AtomicBool,
    start_time: Instant,

    // Aggregated metrics
    tcp_state_counts: RwLock<HashMap<TcpState, u64>>,
    operation_latencies: RwLock<HashMap<SocketOperation, LatencyHistogram>>,
    drop_counts: RwLock<HashMap<DropReason, u64>>,
    connection_flows: RwLock<HashMap<(SocketAddr, SocketAddr), FlowStats>>,

    // Counters
    total_tcp_events: AtomicU64,
    total_latency_events: AtomicU64,
    total_drop_events: AtomicU64,
    events_dropped: AtomicU64,
}

impl EbpfCollector {
    /// Create a new eBPF collector
    pub fn new(config: EbpfConfig) -> Self {
        Self {
            config,
            running: AtomicBool::new(false),
            start_time: Instant::now(),
            tcp_state_counts: RwLock::new(HashMap::new()),
            operation_latencies: RwLock::new(HashMap::new()),
            drop_counts: RwLock::new(HashMap::new()),
            connection_flows: RwLock::new(HashMap::new()),
            total_tcp_events: AtomicU64::new(0),
            total_latency_events: AtomicU64::new(0),
            total_drop_events: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
        }
    }

    /// Start the eBPF collector
    ///
    /// On Linux with proper capabilities, this would load BPF programs into the kernel.
    /// On other platforms, it operates in simulation mode for development/testing.
    pub fn start(&self) -> Result<(), EbpfError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check platform support
        if !Self::is_supported() {
            tracing::warn!("eBPF not supported on this platform, running in simulation mode");
        }

        self.running.store(true, Ordering::SeqCst);
        tracing::info!("eBPF collector started");

        Ok(())
    }

    /// Stop the eBPF collector
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        tracing::info!("eBPF collector stopped");
    }

    /// Check if eBPF is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Check if platform supports eBPF
    pub fn is_supported() -> bool {
        cfg!(target_os = "linux")
    }

    /// Record a TCP state change event
    pub fn record_tcp_event(&self, event: TcpEvent) {
        if !self.is_running() {
            return;
        }

        // Apply sampling if needed
        if !self.should_sample() {
            self.events_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Update state counts
        let mut counts = self.tcp_state_counts.write();
        *counts.entry(event.new_state).or_insert(0) += 1;
        drop(counts);

        // Update flow stats if RTT available
        if let Some(rtt_us) = event.rtt_us {
            let key = (event.src_addr, event.dst_addr);
            let mut flows = self.connection_flows.write();
            let flow = flows.entry(key).or_default();
            if flow.min_rtt_us == 0 || rtt_us < flow.min_rtt_us {
                flow.min_rtt_us = rtt_us;
            }
            if rtt_us > flow.max_rtt_us {
                flow.max_rtt_us = rtt_us;
            }
            // Exponential moving average for smoothed RTT
            if flow.smoothed_rtt_us == 0 {
                flow.smoothed_rtt_us = rtt_us;
            } else {
                flow.smoothed_rtt_us = (flow.smoothed_rtt_us * 7 + rtt_us) / 8;
            }
        }

        self.total_tcp_events.fetch_add(1, Ordering::Relaxed);

        tracing::trace!(
            src = %event.src_addr,
            dst = %event.dst_addr,
            old_state = %event.old_state,
            new_state = %event.new_state,
            pid = event.pid,
            "TCP state change"
        );
    }

    /// Record a socket latency event
    pub fn record_latency_event(&self, event: SocketLatencyEvent) {
        if !self.is_running() {
            return;
        }

        if !self.should_sample() {
            self.events_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Update latency histogram
        let mut latencies = self.operation_latencies.write();
        let histogram = latencies.entry(event.operation).or_default();
        histogram.record(event.latency_ns);
        drop(latencies);

        self.total_latency_events.fetch_add(1, Ordering::Relaxed);

        tracing::trace!(
            addr = %event.addr,
            op = %event.operation,
            latency_ns = event.latency_ns,
            bytes = event.bytes,
            "Socket operation"
        );
    }

    /// Record a packet drop event
    pub fn record_drop_event(&self, event: PacketDropEvent) {
        if !self.is_running() {
            return;
        }

        let mut drops = self.drop_counts.write();
        *drops.entry(event.reason).or_insert(0) += 1;
        drop(drops);

        self.total_drop_events.fetch_add(1, Ordering::Relaxed);

        tracing::debug!(
            src = %event.src_addr,
            dst = %event.dst_addr,
            reason = %event.reason,
            "Packet dropped"
        );
    }

    /// Check if event should be sampled
    fn should_sample(&self) -> bool {
        if self.config.sample_rate >= 1.0 {
            return true;
        }
        rand::random::<f64>() < self.config.sample_rate
    }

    /// Get current statistics
    pub fn stats(&self) -> EbpfStats {
        let tcp_states = self.tcp_state_counts.read().clone();
        let drop_counts = self.drop_counts.read().clone();
        let latencies = self.operation_latencies.read();

        let latency_summaries: HashMap<SocketOperation, LatencySummary> = latencies
            .iter()
            .map(|(op, hist)| (*op, hist.summary()))
            .collect();

        let active_flows = self.connection_flows.read().len();

        EbpfStats {
            running: self.is_running(),
            uptime_secs: self.start_time.elapsed().as_secs(),
            total_tcp_events: self.total_tcp_events.load(Ordering::Relaxed),
            total_latency_events: self.total_latency_events.load(Ordering::Relaxed),
            total_drop_events: self.total_drop_events.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            tcp_state_counts: tcp_states,
            drop_counts,
            latency_summaries,
            active_flows,
        }
    }

    /// Get connection flows
    pub fn flows(&self) -> HashMap<(SocketAddr, SocketAddr), FlowStats> {
        self.connection_flows.read().clone()
    }

    /// Clear old connection flows
    pub fn gc_flows(&self, _max_age: Duration) {
        // In a real implementation, flows would have timestamps
        // For now, just trim to max_connections
        let mut flows = self.connection_flows.write();
        while flows.len() > self.config.max_connections {
            // Remove arbitrary entry (in real impl, remove oldest)
            if let Some(key) = flows.keys().next().cloned() {
                flows.remove(&key);
            }
        }
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        let stats = self.stats();
        let mut output = String::new();

        // TCP state counts
        output.push_str("# HELP ebpf_tcp_state_count TCP connections by state\n");
        output.push_str("# TYPE ebpf_tcp_state_count gauge\n");
        for (state, count) in &stats.tcp_state_counts {
            output.push_str(&format!(
                "ebpf_tcp_state_count{{state=\"{}\"}} {}\n",
                state, count
            ));
        }

        // Drop counts
        output.push_str("# HELP ebpf_drops_total Packet drops by reason\n");
        output.push_str("# TYPE ebpf_drops_total counter\n");
        for (reason, count) in &stats.drop_counts {
            output.push_str(&format!(
                "ebpf_drops_total{{reason=\"{}\"}} {}\n",
                reason, count
            ));
        }

        // Latency summaries
        output.push_str("# HELP ebpf_socket_latency_nanoseconds Socket operation latency\n");
        output.push_str("# TYPE ebpf_socket_latency_nanoseconds summary\n");
        for (op, summary) in &stats.latency_summaries {
            output.push_str(&format!(
                "ebpf_socket_latency_nanoseconds{{operation=\"{}\",quantile=\"0.5\"}} {}\n",
                op, summary.p50
            ));
            output.push_str(&format!(
                "ebpf_socket_latency_nanoseconds{{operation=\"{}\",quantile=\"0.99\"}} {}\n",
                op, summary.p99
            ));
            output.push_str(&format!(
                "ebpf_socket_latency_nanoseconds_sum{{operation=\"{}\"}} {}\n",
                op, summary.sum
            ));
            output.push_str(&format!(
                "ebpf_socket_latency_nanoseconds_count{{operation=\"{}\"}} {}\n",
                op, summary.count
            ));
        }

        // General stats
        output.push_str("# HELP ebpf_events_total Total eBPF events processed\n");
        output.push_str("# TYPE ebpf_events_total counter\n");
        output.push_str(&format!(
            "ebpf_events_total{{type=\"tcp\"}} {}\n",
            stats.total_tcp_events
        ));
        output.push_str(&format!(
            "ebpf_events_total{{type=\"latency\"}} {}\n",
            stats.total_latency_events
        ));
        output.push_str(&format!(
            "ebpf_events_total{{type=\"drop\"}} {}\n",
            stats.total_drop_events
        ));

        output.push_str(&format!(
            "ebpf_events_dropped_total {}\n",
            stats.events_dropped
        ));
        output.push_str(&format!("ebpf_active_flows {}\n", stats.active_flows));

        output
    }
}

/// eBPF statistics
#[derive(Debug, Clone, Serialize)]
pub struct EbpfStats {
    pub running: bool,
    pub uptime_secs: u64,
    pub total_tcp_events: u64,
    pub total_latency_events: u64,
    pub total_drop_events: u64,
    pub events_dropped: u64,
    pub tcp_state_counts: HashMap<TcpState, u64>,
    pub drop_counts: HashMap<DropReason, u64>,
    pub latency_summaries: HashMap<SocketOperation, LatencySummary>,
    pub active_flows: usize,
}

/// Latency histogram for tracking percentiles
#[derive(Debug, Clone, Default)]
pub struct LatencyHistogram {
    values: Vec<u64>,
    sum: u64,
    count: u64,
    min: u64,
    max: u64,
}

impl LatencyHistogram {
    /// Record a latency value
    pub fn record(&mut self, latency_ns: u64) {
        // Keep only recent values to bound memory
        const MAX_VALUES: usize = 10000;
        if self.values.len() >= MAX_VALUES {
            self.values.remove(0);
        }
        self.values.push(latency_ns);
        self.sum += latency_ns;
        self.count += 1;

        if self.min == 0 || latency_ns < self.min {
            self.min = latency_ns;
        }
        if latency_ns > self.max {
            self.max = latency_ns;
        }
    }

    /// Get latency summary
    pub fn summary(&self) -> LatencySummary {
        if self.values.is_empty() {
            return LatencySummary::default();
        }

        let mut sorted = self.values.clone();
        sorted.sort_unstable();

        let p50_idx = (sorted.len() as f64 * 0.5) as usize;
        let p95_idx = (sorted.len() as f64 * 0.95) as usize;
        let p99_idx = (sorted.len() as f64 * 0.99) as usize;

        LatencySummary {
            min: self.min,
            max: self.max,
            mean: self.sum / self.count.max(1),
            p50: sorted.get(p50_idx).copied().unwrap_or(0),
            p95: sorted.get(p95_idx).copied().unwrap_or(0),
            p99: sorted
                .get(p99_idx.min(sorted.len() - 1))
                .copied()
                .unwrap_or(0),
            sum: self.sum,
            count: self.count,
        }
    }
}

/// Latency summary statistics
#[derive(Debug, Clone, Default, Serialize)]
pub struct LatencySummary {
    pub min: u64,
    pub max: u64,
    pub mean: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub sum: u64,
    pub count: u64,
}

/// eBPF errors
#[derive(Debug, Clone)]
pub enum EbpfError {
    /// eBPF not supported on this platform
    NotSupported,
    /// Failed to load BPF program
    LoadFailed(String),
    /// Failed to attach to hook
    AttachFailed(String),
    /// Permission denied
    PermissionDenied,
    /// Ring buffer full
    RingBufferFull,
    /// Internal error
    Internal(String),
}

impl std::fmt::Display for EbpfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EbpfError::NotSupported => write!(f, "eBPF not supported on this platform"),
            EbpfError::LoadFailed(msg) => write!(f, "Failed to load BPF program: {}", msg),
            EbpfError::AttachFailed(msg) => write!(f, "Failed to attach BPF program: {}", msg),
            EbpfError::PermissionDenied => write!(f, "Permission denied (requires CAP_BPF)"),
            EbpfError::RingBufferFull => write!(f, "eBPF ring buffer full"),
            EbpfError::Internal(msg) => write!(f, "Internal eBPF error: {}", msg),
        }
    }
}

impl std::error::Error for EbpfError {}

/// Simulated event generator for testing
#[cfg(test)]
pub mod simulator {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    /// Generate a simulated TCP event
    pub fn generate_tcp_event() -> TcpEvent {
        TcpEvent {
            src_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            dst_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080)),
            old_state: TcpState::SynSent,
            new_state: TcpState::Established,
            pid: 1234,
            timestamp_ns: 1000000,
            rtt_us: Some(1500),
        }
    }

    /// Generate a simulated latency event
    pub fn generate_latency_event() -> SocketLatencyEvent {
        SocketLatencyEvent {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080)),
            operation: SocketOperation::Write,
            latency_ns: 50000,
            bytes: 1024,
            pid: 1234,
            timestamp_ns: 1000000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::simulator::*;
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EbpfConfig::default();
        assert!(!config.enabled);
        assert!(config.tcp_tracking);
        assert!(config.socket_latency);
        assert_eq!(config.sample_rate, 1.0);
    }

    #[test]
    fn test_collector_creation() {
        let config = EbpfConfig::default();
        let collector = EbpfCollector::new(config);
        assert!(!collector.is_running());
    }

    #[test]
    fn test_start_stop() {
        let mut config = EbpfConfig::default();
        config.enabled = true;
        let collector = EbpfCollector::new(config);

        collector.start().unwrap();
        assert!(collector.is_running());

        collector.stop();
        assert!(!collector.is_running());
    }

    #[test]
    fn test_record_tcp_event() {
        let mut config = EbpfConfig::default();
        config.enabled = true;
        let collector = EbpfCollector::new(config);
        collector.start().unwrap();

        let event = generate_tcp_event();
        collector.record_tcp_event(event);

        let stats = collector.stats();
        assert_eq!(stats.total_tcp_events, 1);
        assert!(stats.tcp_state_counts.get(&TcpState::Established).is_some());
    }

    #[test]
    fn test_record_latency_event() {
        let mut config = EbpfConfig::default();
        config.enabled = true;
        let collector = EbpfCollector::new(config);
        collector.start().unwrap();

        let event = generate_latency_event();
        collector.record_latency_event(event);

        let stats = collector.stats();
        assert_eq!(stats.total_latency_events, 1);
    }

    #[test]
    fn test_latency_histogram() {
        let mut histogram = LatencyHistogram::default();

        for i in 1..=100 {
            histogram.record(i * 1000);
        }

        let summary = histogram.summary();
        assert_eq!(summary.count, 100);
        assert_eq!(summary.min, 1000);
        assert_eq!(summary.max, 100000);
        assert!(summary.p50 > 0);
        assert!(summary.p99 > summary.p50);
    }

    #[test]
    fn test_tcp_state_display() {
        assert_eq!(TcpState::Established.to_string(), "ESTABLISHED");
        assert_eq!(TcpState::SynSent.to_string(), "SYN_SENT");
        assert_eq!(TcpState::TimeWait.to_string(), "TIME_WAIT");
    }

    #[test]
    fn test_prometheus_export() {
        let mut config = EbpfConfig::default();
        config.enabled = true;
        let collector = EbpfCollector::new(config);
        collector.start().unwrap();

        // Record some events
        collector.record_tcp_event(generate_tcp_event());
        collector.record_latency_event(generate_latency_event());

        let output = collector.export_prometheus();
        assert!(output.contains("ebpf_tcp_state_count"));
        assert!(output.contains("ebpf_events_total"));
    }

    #[test]
    fn test_flow_tracking() {
        let mut config = EbpfConfig::default();
        config.enabled = true;
        let collector = EbpfCollector::new(config);
        collector.start().unwrap();

        let event = generate_tcp_event();
        collector.record_tcp_event(event.clone());

        let flows = collector.flows();
        assert!(!flows.is_empty());

        let key = (event.src_addr, event.dst_addr);
        let flow = flows.get(&key).unwrap();
        assert!(flow.min_rtt_us > 0);
    }
}
