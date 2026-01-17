//! Layer 4 (TCP/UDP) Proxy Module
//!
//! Provides TCP and UDP load balancing for databases, message queues,
//! and other non-HTTP services.
//!
//! # Features
//!
//! - **TCP Proxying**: Connection-based load balancing with health checks
//! - **UDP Proxying**: Datagram-based load balancing
//! - **Connection Pooling**: Reuse upstream connections for TCP
//! - **Health Checks**: TCP connect and UDP probe health checks
//! - **Load Balancing**: Round-robin, least-connections, IP hash
//!
//! # Example Configuration
//!
//! ```yaml
//! l4_listeners:
//!   - name: postgres
//!     address: "0.0.0.0:5432"
//!     protocol: tcp
//!     upstream: postgres_cluster
//!
//!   - name: dns
//!     address: "0.0.0.0:53"
//!     protocol: udp
//!     upstream: dns_servers
//!
//! l4_upstreams:
//!   postgres_cluster:
//!     servers:
//!       - address: "10.0.0.1:5432"
//!       - address: "10.0.0.2:5432"
//!     load_balancing: least_connections
//!     health_check:
//!       type: tcp_connect
//!       interval: 5s
//!
//!   dns_servers:
//!     servers:
//!       - address: "8.8.8.8:53"
//!       - address: "8.8.4.4:53"
//!     load_balancing: round_robin
//! ```

mod config;
mod health;
mod proxy;
mod stats;

pub use config::*;
pub use health::*;
pub use proxy::*;
pub use stats::*;

use crate::error::Result;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

/// Layer 4 Proxy Manager
///
/// Manages multiple L4 listeners and their upstream connections.
pub struct L4ProxyManager {
    /// TCP proxies
    tcp_proxies: Vec<Arc<TcpProxy>>,
    /// UDP proxies
    udp_proxies: Vec<Arc<UdpProxy>>,
    /// Health checker
    health_checker: Arc<L4HealthChecker>,
    /// Statistics
    stats: Arc<L4Stats>,
}

impl L4ProxyManager {
    /// Create a new L4 proxy manager from configuration
    pub fn new(config: &L4Config) -> Result<Self> {
        let stats = Arc::new(L4Stats::new());
        let health_checker = Arc::new(L4HealthChecker::new());

        let mut tcp_proxies = Vec::new();
        let mut udp_proxies = Vec::new();

        for listener_config in &config.listeners {
            match listener_config.protocol {
                L4Protocol::Tcp => {
                    let upstream_config = config
                        .upstreams
                        .get(&listener_config.upstream)
                        .ok_or_else(|| {
                            crate::error::PrismError::Config(format!(
                                "Unknown L4 upstream: {}",
                                listener_config.upstream
                            ))
                        })?;

                    let proxy = TcpProxy::new(
                        listener_config.clone(),
                        upstream_config.clone(),
                        stats.clone(),
                    );
                    tcp_proxies.push(Arc::new(proxy));
                }
                L4Protocol::Udp => {
                    let upstream_config = config
                        .upstreams
                        .get(&listener_config.upstream)
                        .ok_or_else(|| {
                            crate::error::PrismError::Config(format!(
                                "Unknown L4 upstream: {}",
                                listener_config.upstream
                            ))
                        })?;

                    let proxy = UdpProxy::new(
                        listener_config.clone(),
                        upstream_config.clone(),
                        stats.clone(),
                    );
                    udp_proxies.push(Arc::new(proxy));
                }
            }
        }

        Ok(Self {
            tcp_proxies,
            udp_proxies,
            health_checker,
            stats,
        })
    }

    /// Start all L4 proxies
    pub async fn start(&self, shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        info!(
            "Starting L4 proxy manager with {} TCP and {} UDP proxies",
            self.tcp_proxies.len(),
            self.udp_proxies.len()
        );

        let mut handles = Vec::new();

        // Start TCP proxies
        for proxy in &self.tcp_proxies {
            let proxy = proxy.clone();
            let shutdown = shutdown_rx.resubscribe();
            let handle = tokio::spawn(async move {
                if let Err(e) = proxy.run(shutdown).await {
                    tracing::error!("TCP proxy error: {}", e);
                }
            });
            handles.push(handle);
        }

        // Start UDP proxies
        for proxy in &self.udp_proxies {
            let proxy = proxy.clone();
            let shutdown = shutdown_rx.resubscribe();
            let handle = tokio::spawn(async move {
                if let Err(e) = proxy.run(shutdown).await {
                    tracing::error!("UDP proxy error: {}", e);
                }
            });
            handles.push(handle);
        }

        // Start health checks
        let health_checker = self.health_checker.clone();
        let tcp_proxies = self.tcp_proxies.clone();
        let udp_proxies = self.udp_proxies.clone();
        let shutdown = shutdown_rx.resubscribe();
        tokio::spawn(async move {
            health_checker
                .run(tcp_proxies, udp_proxies, shutdown)
                .await;
        });

        // Wait for all proxies to complete
        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }

    /// Get statistics
    pub fn stats(&self) -> &L4Stats {
        &self.stats
    }

    /// Get number of TCP proxies
    pub fn tcp_proxy_count(&self) -> usize {
        self.tcp_proxies.len()
    }

    /// Get number of UDP proxies
    pub fn udp_proxy_count(&self) -> usize {
        self.udp_proxies.len()
    }
}
