//! Layer 4 Health Checking
//!
//! Provides health checking for L4 upstreams via TCP connect and UDP probe checks.

use crate::l4::{L4HealthCheckConfig, L4HealthCheckType, TcpProxy, UdpProxy};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::broadcast;
use tokio::time::{interval, timeout};
use tracing::{debug, info, warn};

/// L4 Health Checker
///
/// Performs periodic health checks on L4 upstream servers.
pub struct L4HealthChecker {
    /// Check results cache
    results: Arc<tokio::sync::RwLock<HashMap<String, HealthStatus>>>,
}

/// Health status for a server
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// Whether the server is healthy
    pub healthy: bool,
    /// Consecutive successes
    pub successes: u32,
    /// Consecutive failures
    pub failures: u32,
    /// Last check time
    pub last_check: std::time::Instant,
    /// Last error message if any
    pub last_error: Option<String>,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            healthy: true, // Assume healthy until proven otherwise
            successes: 0,
            failures: 0,
            last_check: std::time::Instant::now(),
            last_error: None,
        }
    }
}

impl L4HealthChecker {
    /// Create a new health checker
    pub fn new() -> Self {
        Self {
            results: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Run health checks for all proxies
    pub async fn run(
        &self,
        tcp_proxies: Vec<Arc<TcpProxy>>,
        udp_proxies: Vec<Arc<UdpProxy>>,
        mut shutdown: broadcast::Receiver<()>,
    ) {
        info!("Starting L4 health checker");

        // Collect all health check configs
        let mut check_tasks = Vec::new();

        // TCP proxy health checks
        for proxy in &tcp_proxies {
            if let Some(health_config) = proxy.health_check_config() {
                let servers = proxy.server_addresses();
                let proxy = proxy.clone();
                let config = health_config.clone();
                let results = self.results.clone();

                let task = tokio::spawn(async move {
                    run_tcp_health_checks(proxy, servers, config, results).await;
                });
                check_tasks.push(task);
            }
        }

        // UDP proxy health checks
        for proxy in &udp_proxies {
            if let Some(health_config) = proxy.health_check_config() {
                let servers = proxy.server_addresses();
                let proxy = proxy.clone();
                let config = health_config.clone();
                let results = self.results.clone();

                let task = tokio::spawn(async move {
                    run_udp_health_checks(proxy, servers, config, results).await;
                });
                check_tasks.push(task);
            }
        }

        // Wait for shutdown signal
        let _ = shutdown.recv().await;
        info!("L4 health checker shutting down");

        // Cancel all health check tasks
        for task in check_tasks {
            task.abort();
        }
    }

    /// Get health status for a server
    pub async fn get_status(&self, server: &str) -> Option<HealthStatus> {
        self.results.read().await.get(server).cloned()
    }

    /// Check if a server is healthy
    pub async fn is_healthy(&self, server: &str) -> bool {
        self.results
            .read()
            .await
            .get(server)
            .map(|s| s.healthy)
            .unwrap_or(true) // Assume healthy if no status
    }
}

impl Default for L4HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Run TCP health checks for a set of servers
async fn run_tcp_health_checks(
    proxy: Arc<TcpProxy>,
    servers: Vec<String>,
    config: L4HealthCheckConfig,
    results: Arc<tokio::sync::RwLock<HashMap<String, HealthStatus>>>,
) {
    let mut check_interval = interval(config.interval);

    loop {
        check_interval.tick().await;

        for server in &servers {
            let healthy = match config.check_type {
                L4HealthCheckType::TcpConnect => {
                    tcp_connect_check(server, config.timeout).await
                }
                L4HealthCheckType::UdpProbe => {
                    // Shouldn't happen for TCP proxy, but handle gracefully
                    warn!("UDP probe configured for TCP proxy, using TCP connect instead");
                    tcp_connect_check(server, config.timeout).await
                }
            };

            // Update health status
            let mut results_guard = results.write().await;
            let status = results_guard
                .entry(server.clone())
                .or_insert_with(HealthStatus::default);

            status.last_check = std::time::Instant::now();

            match healthy {
                Ok(()) => {
                    status.successes += 1;
                    status.failures = 0;
                    status.last_error = None;

                    if !status.healthy && status.successes >= config.healthy_threshold {
                        info!("Server {} is now healthy", server);
                        status.healthy = true;
                        proxy.set_server_health(server, true).await;
                    }
                }
                Err(e) => {
                    status.failures += 1;
                    status.successes = 0;
                    status.last_error = Some(e.clone());

                    if status.healthy && status.failures >= config.unhealthy_threshold {
                        warn!("Server {} is now unhealthy: {}", server, e);
                        status.healthy = false;
                        proxy.set_server_health(server, false).await;
                    }
                }
            }
        }
    }
}

/// Run UDP health checks for a set of servers
async fn run_udp_health_checks(
    proxy: Arc<UdpProxy>,
    servers: Vec<String>,
    config: L4HealthCheckConfig,
    results: Arc<tokio::sync::RwLock<HashMap<String, HealthStatus>>>,
) {
    let mut check_interval = interval(config.interval);

    loop {
        check_interval.tick().await;

        for server in &servers {
            let healthy = match config.check_type {
                L4HealthCheckType::UdpProbe => {
                    udp_probe_check(
                        server,
                        config.timeout,
                        config.udp_probe.as_deref(),
                        config.udp_expect.as_deref(),
                    )
                    .await
                }
                L4HealthCheckType::TcpConnect => {
                    // Allow TCP connect check for UDP proxy (check if host is reachable)
                    tcp_connect_check(server, config.timeout).await
                }
            };

            // Update health status
            let mut results_guard = results.write().await;
            let status = results_guard
                .entry(server.clone())
                .or_insert_with(HealthStatus::default);

            status.last_check = std::time::Instant::now();

            match healthy {
                Ok(()) => {
                    status.successes += 1;
                    status.failures = 0;
                    status.last_error = None;

                    if !status.healthy && status.successes >= config.healthy_threshold {
                        info!("Server {} is now healthy", server);
                        status.healthy = true;
                        proxy.set_server_health(server, true).await;
                    }
                }
                Err(e) => {
                    status.failures += 1;
                    status.successes = 0;
                    status.last_error = Some(e.clone());

                    if status.healthy && status.failures >= config.unhealthy_threshold {
                        warn!("Server {} is now unhealthy: {}", server, e);
                        status.healthy = false;
                        proxy.set_server_health(server, false).await;
                    }
                }
            }
        }
    }
}

/// Perform a TCP connect health check
async fn tcp_connect_check(server: &str, check_timeout: Duration) -> Result<(), String> {
    let addr: SocketAddr = server
        .parse()
        .map_err(|e| format!("Invalid address: {}", e))?;

    match timeout(check_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => {
            debug!("TCP connect check passed for {}", server);
            Ok(())
        }
        Ok(Err(e)) => Err(format!("Connection failed: {}", e)),
        Err(_) => Err("Connection timed out".to_string()),
    }
}

/// Perform a UDP probe health check
async fn udp_probe_check(
    server: &str,
    check_timeout: Duration,
    probe: Option<&str>,
    expect: Option<&str>,
) -> Result<(), String> {
    let addr: SocketAddr = server
        .parse()
        .map_err(|e| format!("Invalid address: {}", e))?;

    // Bind to random local port
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to bind socket: {}", e))?;

    socket
        .connect(addr)
        .await
        .map_err(|e| format!("Failed to connect: {}", e))?;

    // Decode and send probe if configured
    let probe_data = if let Some(hex) = probe {
        hex::decode(hex).map_err(|e| format!("Invalid hex probe: {}", e))?
    } else {
        // Default: empty probe (just check for any response)
        vec![0u8; 1]
    };

    socket
        .send(&probe_data)
        .await
        .map_err(|e| format!("Failed to send probe: {}", e))?;

    // Wait for response
    let mut buf = vec![0u8; 1024];
    match timeout(check_timeout, socket.recv(&mut buf)).await {
        Ok(Ok(len)) => {
            // Check expected response if configured
            if let Some(expected_hex) = expect {
                let expected =
                    hex::decode(expected_hex).map_err(|e| format!("Invalid hex expect: {}", e))?;

                if buf[..len] != expected[..] {
                    return Err("Response didn't match expected".to_string());
                }
            }
            debug!("UDP probe check passed for {}", server);
            Ok(())
        }
        Ok(Err(e)) => Err(format!("Receive failed: {}", e)),
        Err(_) => Err("Response timed out".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_default() {
        let status = HealthStatus::default();
        assert!(status.healthy);
        assert_eq!(status.successes, 0);
        assert_eq!(status.failures, 0);
        assert!(status.last_error.is_none());
    }

    #[test]
    fn test_health_checker_new() {
        let checker = L4HealthChecker::new();
        // Just verify it can be created
        assert!(Arc::strong_count(&checker.results) == 1);
    }

    #[tokio::test]
    async fn test_tcp_connect_check_invalid_address() {
        let result = tcp_connect_check("invalid:address", Duration::from_secs(1)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tcp_connect_check_unreachable() {
        // Try to connect to a port that's unlikely to be open
        let result = tcp_connect_check("127.0.0.1:59999", Duration::from_millis(100)).await;
        assert!(result.is_err());
    }
}
