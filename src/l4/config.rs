//! Layer 4 Proxy Configuration Types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Complete L4 proxy configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L4Config {
    /// L4 listeners
    #[serde(default)]
    pub listeners: Vec<L4ListenerConfig>,

    /// L4 upstreams
    #[serde(default)]
    pub upstreams: HashMap<String, L4UpstreamConfig>,
}

/// L4 listener configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L4ListenerConfig {
    /// Listener name for identification
    pub name: String,

    /// Bind address (e.g., "0.0.0.0:5432")
    pub address: String,

    /// Protocol (tcp or udp)
    pub protocol: L4Protocol,

    /// Upstream to forward to
    pub upstream: String,

    /// Connection timeout for TCP
    #[serde(default = "default_connect_timeout")]
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,

    /// Idle timeout before closing connection
    #[serde(default = "default_idle_timeout")]
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,

    /// Maximum concurrent connections (0 = unlimited)
    #[serde(default)]
    pub max_connections: usize,

    /// Enable TCP keepalive
    #[serde(default = "default_true")]
    pub tcp_keepalive: bool,

    /// TCP keepalive interval
    #[serde(default = "default_keepalive_interval")]
    #[serde(with = "humantime_serde")]
    pub keepalive_interval: Duration,

    /// Enable TCP nodelay
    #[serde(default = "default_true")]
    pub tcp_nodelay: bool,

    /// Buffer size for proxying
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Enable proxy protocol (v1 or v2)
    #[serde(default)]
    pub proxy_protocol: Option<ProxyProtocolVersion>,

    /// TLS configuration for TCP
    #[serde(default)]
    pub tls: Option<L4TlsConfig>,
}

/// L4 protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L4Protocol {
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
}

/// Proxy Protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolVersion {
    /// Proxy Protocol v1 (text)
    V1,
    /// Proxy Protocol v2 (binary)
    V2,
}

/// L4 TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L4TlsConfig {
    /// Path to certificate file
    pub cert: String,

    /// Path to private key file
    pub key: String,

    /// Enable client certificate verification
    #[serde(default)]
    pub client_auth: bool,

    /// Path to CA certificate for client verification
    pub client_ca: Option<String>,

    /// TLS passthrough (don't terminate, just forward)
    #[serde(default)]
    pub passthrough: bool,
}

/// L4 upstream configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L4UpstreamConfig {
    /// Backend servers
    pub servers: Vec<L4ServerConfig>,

    /// Load balancing algorithm
    #[serde(default)]
    pub load_balancing: L4LoadBalancing,

    /// Health check configuration
    #[serde(default)]
    pub health_check: Option<L4HealthCheckConfig>,

    /// Connection pool size per server
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,

    /// Enable connection pooling
    #[serde(default = "default_true")]
    pub connection_pooling: bool,
}

/// L4 backend server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L4ServerConfig {
    /// Server address (e.g., "10.0.0.1:5432")
    pub address: String,

    /// Server weight for weighted load balancing
    #[serde(default = "default_weight")]
    pub weight: u32,

    /// Maximum connections to this server
    #[serde(default)]
    pub max_connections: usize,

    /// Enable TLS to upstream
    #[serde(default)]
    pub tls: bool,
}

/// L4 load balancing algorithm
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L4LoadBalancing {
    /// Round-robin distribution
    #[default]
    RoundRobin,
    /// Least connections
    LeastConnections,
    /// IP hash (sticky sessions)
    IpHash,
    /// Random selection
    Random,
    /// Weighted round-robin
    WeightedRoundRobin,
}

/// L4 health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L4HealthCheckConfig {
    /// Health check type
    #[serde(default)]
    pub check_type: L4HealthCheckType,

    /// Check interval
    #[serde(default = "default_health_interval")]
    #[serde(with = "humantime_serde")]
    pub interval: Duration,

    /// Check timeout
    #[serde(default = "default_health_timeout")]
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,

    /// Healthy threshold (successes to mark healthy)
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,

    /// Unhealthy threshold (failures to mark unhealthy)
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// UDP probe payload (hex encoded)
    pub udp_probe: Option<String>,

    /// Expected UDP response (hex encoded, optional)
    pub udp_expect: Option<String>,
}

/// L4 health check type
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L4HealthCheckType {
    /// TCP connect check
    #[default]
    TcpConnect,
    /// UDP probe check
    UdpProbe,
}

// Default value functions

fn default_connect_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_idle_timeout() -> Duration {
    Duration::from_secs(300)
}

fn default_keepalive_interval() -> Duration {
    Duration::from_secs(60)
}

fn default_buffer_size() -> usize {
    65536 // 64KB
}

fn default_pool_size() -> usize {
    10
}

fn default_weight() -> u32 {
    1
}

fn default_health_interval() -> Duration {
    Duration::from_secs(5)
}

fn default_health_timeout() -> Duration {
    Duration::from_secs(3)
}

fn default_healthy_threshold() -> u32 {
    2
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_true() -> bool {
    true
}

impl Default for L4ListenerConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            address: "0.0.0.0:0".to_string(),
            protocol: L4Protocol::Tcp,
            upstream: String::new(),
            connect_timeout: default_connect_timeout(),
            idle_timeout: default_idle_timeout(),
            max_connections: 0,
            tcp_keepalive: true,
            keepalive_interval: default_keepalive_interval(),
            tcp_nodelay: true,
            buffer_size: default_buffer_size(),
            proxy_protocol: None,
            tls: None,
        }
    }
}

impl Default for L4UpstreamConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            load_balancing: L4LoadBalancing::default(),
            health_check: None,
            pool_size: default_pool_size(),
            connection_pooling: true,
        }
    }
}

impl Default for L4HealthCheckConfig {
    fn default() -> Self {
        Self {
            check_type: L4HealthCheckType::default(),
            interval: default_health_interval(),
            timeout: default_health_timeout(),
            healthy_threshold: default_healthy_threshold(),
            unhealthy_threshold: default_unhealthy_threshold(),
            udp_probe: None,
            udp_expect: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = L4Config::default();
        assert!(config.listeners.is_empty());
        assert!(config.upstreams.is_empty());
    }

    #[test]
    fn test_listener_defaults() {
        let listener = L4ListenerConfig::default();
        assert_eq!(listener.connect_timeout, Duration::from_secs(10));
        assert_eq!(listener.idle_timeout, Duration::from_secs(300));
        assert!(listener.tcp_keepalive);
        assert!(listener.tcp_nodelay);
    }

    #[test]
    fn test_load_balancing_variants() {
        assert_eq!(L4LoadBalancing::default(), L4LoadBalancing::RoundRobin);
    }
}
