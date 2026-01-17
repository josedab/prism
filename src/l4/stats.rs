//! Layer 4 Statistics Tracking
//!
//! Provides statistics collection for L4 proxies including connection counts,
//! bytes transferred, and error rates.

use super::L4Protocol;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

/// L4 proxy statistics
pub struct L4Stats {
    /// TCP statistics
    tcp: L4ProtocolStats,
    /// UDP statistics
    udp: L4ProtocolStats,
    /// Per-upstream statistics
    upstreams: RwLock<HashMap<String, UpstreamStats>>,
}

/// Protocol-level statistics
pub struct L4ProtocolStats {
    /// Total connections/sessions
    pub total_connections: AtomicU64,
    /// Active connections/sessions
    pub active_connections: AtomicU64,
    /// Total bytes received from clients
    pub bytes_received: AtomicU64,
    /// Total bytes sent to clients
    pub bytes_sent: AtomicU64,
    /// Connection errors
    pub connection_errors: AtomicU64,
    /// Upstream connection failures
    pub upstream_failures: AtomicU64,
    /// Connection timeouts
    pub timeouts: AtomicU64,
}

/// Per-upstream statistics
pub struct UpstreamStats {
    /// Server address
    pub address: String,
    /// Total connections to this upstream
    pub total_connections: AtomicU64,
    /// Active connections
    pub active_connections: AtomicU64,
    /// Bytes sent to upstream
    pub bytes_sent: AtomicU64,
    /// Bytes received from upstream
    pub bytes_received: AtomicU64,
    /// Failed connections
    pub failures: AtomicU64,
    /// Health check passes
    pub health_check_passes: AtomicU64,
    /// Health check failures
    pub health_check_failures: AtomicU64,
}

/// Snapshot of L4 statistics
#[derive(Debug, Clone)]
pub struct L4StatsSnapshot {
    pub tcp: ProtocolStatsSnapshot,
    pub udp: ProtocolStatsSnapshot,
    pub upstreams: Vec<UpstreamStatsSnapshot>,
}

/// Snapshot of protocol statistics
#[derive(Debug, Clone)]
pub struct ProtocolStatsSnapshot {
    pub total_connections: u64,
    pub active_connections: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub connection_errors: u64,
    pub upstream_failures: u64,
    pub timeouts: u64,
}

/// Snapshot of upstream statistics
#[derive(Debug, Clone)]
pub struct UpstreamStatsSnapshot {
    pub address: String,
    pub total_connections: u64,
    pub active_connections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub failures: u64,
    pub health_check_passes: u64,
    pub health_check_failures: u64,
}

impl L4Stats {
    /// Create new L4 statistics tracker
    pub fn new() -> Self {
        Self {
            tcp: L4ProtocolStats::new(),
            udp: L4ProtocolStats::new(),
            upstreams: RwLock::new(HashMap::new()),
        }
    }

    /// Get TCP statistics
    pub fn tcp(&self) -> &L4ProtocolStats {
        &self.tcp
    }

    /// Get UDP statistics
    pub fn udp(&self) -> &L4ProtocolStats {
        &self.udp
    }

    /// Record a connection/session for the given protocol
    pub fn record_connection(&self, protocol: L4Protocol) {
        match protocol {
            L4Protocol::Tcp => self.record_tcp_connection(),
            L4Protocol::Udp => self.record_udp_session(),
        }
    }

    /// Record a disconnection for the given protocol
    pub fn record_disconnect(&self, protocol: L4Protocol) {
        match protocol {
            L4Protocol::Tcp => self.record_tcp_close(),
            L4Protocol::Udp => self.record_udp_session_close(),
        }
    }

    /// Record bytes transferred for the given protocol
    pub fn record_bytes(&self, protocol: L4Protocol, received: u64, sent: u64) {
        match protocol {
            L4Protocol::Tcp => self.record_tcp_bytes(received, sent),
            L4Protocol::Udp => self.record_udp_bytes(received, sent),
        }
    }

    /// Record an error for the given protocol
    pub fn record_error(&self, protocol: L4Protocol, _error_type: &str) {
        match protocol {
            L4Protocol::Tcp => self.record_tcp_error(),
            L4Protocol::Udp => self.record_udp_error(),
        }
    }

    /// Record a new TCP connection
    pub fn record_tcp_connection(&self) {
        self.tcp.total_connections.fetch_add(1, Ordering::Relaxed);
        self.tcp.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record TCP connection closed
    pub fn record_tcp_close(&self) {
        self.tcp.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record TCP bytes transferred
    pub fn record_tcp_bytes(&self, received: u64, sent: u64) {
        self.tcp.bytes_received.fetch_add(received, Ordering::Relaxed);
        self.tcp.bytes_sent.fetch_add(sent, Ordering::Relaxed);
    }

    /// Record TCP connection error
    pub fn record_tcp_error(&self) {
        self.tcp.connection_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record TCP upstream failure
    pub fn record_tcp_upstream_failure(&self) {
        self.tcp.upstream_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record TCP timeout
    pub fn record_tcp_timeout(&self) {
        self.tcp.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a new UDP session
    pub fn record_udp_session(&self) {
        self.udp.total_connections.fetch_add(1, Ordering::Relaxed);
        self.udp.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record UDP session closed
    pub fn record_udp_session_close(&self) {
        self.udp.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record UDP bytes transferred
    pub fn record_udp_bytes(&self, received: u64, sent: u64) {
        self.udp.bytes_received.fetch_add(received, Ordering::Relaxed);
        self.udp.bytes_sent.fetch_add(sent, Ordering::Relaxed);
    }

    /// Record UDP error
    pub fn record_udp_error(&self) {
        self.udp.connection_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record UDP upstream failure
    pub fn record_udp_upstream_failure(&self) {
        self.udp.upstream_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record connection to upstream
    pub async fn record_upstream_connection(&self, address: &str) {
        let mut upstreams = self.upstreams.write().await;
        let stats = upstreams
            .entry(address.to_string())
            .or_insert_with(|| UpstreamStats::new(address.to_string()));
        stats.total_connections.fetch_add(1, Ordering::Relaxed);
        stats.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record upstream connection closed
    pub async fn record_upstream_close(&self, address: &str) {
        let upstreams = self.upstreams.read().await;
        if let Some(stats) = upstreams.get(address) {
            stats.active_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Record bytes transferred to/from upstream
    pub async fn record_upstream_bytes(&self, address: &str, sent: u64, received: u64) {
        let upstreams = self.upstreams.read().await;
        if let Some(stats) = upstreams.get(address) {
            stats.bytes_sent.fetch_add(sent, Ordering::Relaxed);
            stats.bytes_received.fetch_add(received, Ordering::Relaxed);
        }
    }

    /// Record upstream failure
    pub async fn record_upstream_failure(&self, address: &str) {
        let mut upstreams = self.upstreams.write().await;
        let stats = upstreams
            .entry(address.to_string())
            .or_insert_with(|| UpstreamStats::new(address.to_string()));
        stats.failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record health check result
    pub async fn record_health_check(&self, address: &str, passed: bool) {
        let mut upstreams = self.upstreams.write().await;
        let stats = upstreams
            .entry(address.to_string())
            .or_insert_with(|| UpstreamStats::new(address.to_string()));
        if passed {
            stats.health_check_passes.fetch_add(1, Ordering::Relaxed);
        } else {
            stats.health_check_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get a snapshot of all statistics
    pub async fn snapshot(&self) -> L4StatsSnapshot {
        let upstreams = self.upstreams.read().await;
        let upstream_snapshots: Vec<UpstreamStatsSnapshot> = upstreams
            .values()
            .map(|s| s.snapshot())
            .collect();

        L4StatsSnapshot {
            tcp: self.tcp.snapshot(),
            udp: self.udp.snapshot(),
            upstreams: upstream_snapshots,
        }
    }
}

impl Default for L4Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl L4ProtocolStats {
    /// Create new protocol statistics
    pub fn new() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            connection_errors: AtomicU64::new(0),
            upstream_failures: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
        }
    }

    /// Get a snapshot of the statistics
    pub fn snapshot(&self) -> ProtocolStatsSnapshot {
        ProtocolStatsSnapshot {
            total_connections: self.total_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            connection_errors: self.connection_errors.load(Ordering::Relaxed),
            upstream_failures: self.upstream_failures.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
        }
    }
}

impl Default for L4ProtocolStats {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamStats {
    /// Create new upstream statistics
    pub fn new(address: String) -> Self {
        Self {
            address,
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            health_check_passes: AtomicU64::new(0),
            health_check_failures: AtomicU64::new(0),
        }
    }

    /// Get a snapshot of the statistics
    pub fn snapshot(&self) -> UpstreamStatsSnapshot {
        UpstreamStatsSnapshot {
            address: self.address.clone(),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            health_check_passes: self.health_check_passes.load(Ordering::Relaxed),
            health_check_failures: self.health_check_failures.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_new() {
        let stats = L4Stats::new();
        assert_eq!(stats.tcp.total_connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.udp.total_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_tcp_stats() {
        let stats = L4Stats::new();

        stats.record_tcp_connection();
        assert_eq!(stats.tcp.total_connections.load(Ordering::Relaxed), 1);
        assert_eq!(stats.tcp.active_connections.load(Ordering::Relaxed), 1);

        stats.record_tcp_bytes(100, 200);
        assert_eq!(stats.tcp.bytes_received.load(Ordering::Relaxed), 100);
        assert_eq!(stats.tcp.bytes_sent.load(Ordering::Relaxed), 200);

        stats.record_tcp_close();
        assert_eq!(stats.tcp.active_connections.load(Ordering::Relaxed), 0);

        stats.record_tcp_error();
        assert_eq!(stats.tcp.connection_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_udp_stats() {
        let stats = L4Stats::new();

        stats.record_udp_session();
        assert_eq!(stats.udp.total_connections.load(Ordering::Relaxed), 1);
        assert_eq!(stats.udp.active_connections.load(Ordering::Relaxed), 1);

        stats.record_udp_bytes(50, 100);
        assert_eq!(stats.udp.bytes_received.load(Ordering::Relaxed), 50);
        assert_eq!(stats.udp.bytes_sent.load(Ordering::Relaxed), 100);

        stats.record_udp_session_close();
        assert_eq!(stats.udp.active_connections.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_upstream_stats() {
        let stats = L4Stats::new();

        stats.record_upstream_connection("10.0.0.1:5432").await;
        stats.record_upstream_bytes("10.0.0.1:5432", 100, 200).await;
        stats.record_upstream_close("10.0.0.1:5432").await;

        let snapshot = stats.snapshot().await;
        assert_eq!(snapshot.upstreams.len(), 1);
        assert_eq!(snapshot.upstreams[0].total_connections, 1);
        assert_eq!(snapshot.upstreams[0].active_connections, 0);
        assert_eq!(snapshot.upstreams[0].bytes_sent, 100);
        assert_eq!(snapshot.upstreams[0].bytes_received, 200);
    }

    #[test]
    fn test_protocol_stats_snapshot() {
        let stats = L4ProtocolStats::new();
        stats.total_connections.store(10, Ordering::Relaxed);
        stats.active_connections.store(5, Ordering::Relaxed);
        stats.bytes_received.store(1000, Ordering::Relaxed);
        stats.bytes_sent.store(2000, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.total_connections, 10);
        assert_eq!(snapshot.active_connections, 5);
        assert_eq!(snapshot.bytes_received, 1000);
        assert_eq!(snapshot.bytes_sent, 2000);
    }
}
