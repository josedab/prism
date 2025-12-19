//! Health checking for upstream servers

use super::ServerState;
use crate::config::{HealthCheckConfig, HealthCheckType};
use crate::error::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{interval, timeout};
use tracing::{debug, info, warn};

/// Health checker for upstream servers
pub struct HealthChecker {
    /// Health check configuration
    config: HealthCheckConfig,
    /// Servers to check
    servers: Vec<Arc<ServerState>>,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(config: HealthCheckConfig, servers: Vec<Arc<ServerState>>) -> Self {
        Self { config, servers }
    }

    /// Run the health checker (blocking)
    pub async fn run(&self) {
        let mut check_interval = interval(self.config.interval);

        loop {
            check_interval.tick().await;

            for server in &self.servers {
                if !server.server.enabled {
                    continue;
                }

                let result = self.check_server(server).await;

                match result {
                    Ok(true) => {
                        if !server.is_healthy() {
                            info!("Server {} is now healthy", server.server.address);
                        }
                        server.mark_healthy();
                    }
                    Ok(false) | Err(_) => {
                        if server.is_healthy() {
                            warn!("Server {} is now unhealthy", server.server.address);
                        }
                        server.mark_unhealthy();
                    }
                }
            }
        }
    }

    /// Check a single server
    async fn check_server(&self, server: &ServerState) -> Result<bool> {
        let check_timeout = self.config.timeout;

        match timeout(check_timeout, self.perform_check(server)).await {
            Ok(result) => result,
            Err(_) => {
                debug!("Health check timeout for {}", server.server.address);
                Ok(false)
            }
        }
    }

    /// Perform the actual health check
    async fn perform_check(&self, server: &ServerState) -> Result<bool> {
        match &self.config.check_type {
            HealthCheckType::Tcp => self.tcp_check(server).await,
            HealthCheckType::Http => self.http_check(server).await,
        }
    }

    /// TCP health check - just connect and disconnect
    async fn tcp_check(&self, server: &ServerState) -> Result<bool> {
        match TcpStream::connect(server.server.address).await {
            Ok(_) => {
                debug!("TCP health check passed for {}", server.server.address);
                Ok(true)
            }
            Err(e) => {
                debug!(
                    "TCP health check failed for {}: {}",
                    server.server.address, e
                );
                Ok(false)
            }
        }
    }

    /// HTTP health check - send a request and check response
    async fn http_check(&self, server: &ServerState) -> Result<bool> {
        let mut stream = match TcpStream::connect(server.server.address).await {
            Ok(s) => s,
            Err(e) => {
                debug!(
                    "HTTP health check connection failed for {}: {}",
                    server.server.address, e
                );
                return Ok(false);
            }
        };

        // Build HTTP request
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.config.path, server.server.address
        );

        // Send request
        if let Err(e) = stream.write_all(request.as_bytes()).await {
            debug!(
                "HTTP health check write failed for {}: {}",
                server.server.address, e
            );
            return Ok(false);
        }

        // Read response
        let mut response = vec![0u8; 1024];
        let n = match stream.read(&mut response).await {
            Ok(n) => n,
            Err(e) => {
                debug!(
                    "HTTP health check read failed for {}: {}",
                    server.server.address, e
                );
                return Ok(false);
            }
        };

        // Parse status code from response
        let response_str = String::from_utf8_lossy(&response[..n]);
        let status_ok = parse_status_code(&response_str)
            .map(|code| code == self.config.expected_status)
            .unwrap_or(false);

        if status_ok {
            debug!("HTTP health check passed for {}", server.server.address);
        } else {
            debug!(
                "HTTP health check failed for {} (unexpected status)",
                server.server.address
            );
        }

        Ok(status_ok)
    }
}

/// Parse HTTP status code from response
fn parse_status_code(response: &str) -> Option<u16> {
    // HTTP/1.1 200 OK
    let first_line = response.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

/// Passive health checker that tracks failures
#[allow(dead_code)]
pub struct PassiveHealthChecker {
    /// Failure threshold before marking unhealthy
    failure_threshold: u32,
    /// Success threshold before marking healthy
    success_threshold: u32,
}

impl PassiveHealthChecker {
    /// Create a new passive health checker
    pub fn new(failure_threshold: u32, success_threshold: u32) -> Self {
        Self {
            failure_threshold,
            success_threshold,
        }
    }

    /// Record a successful request
    pub fn record_success(&self, server: &ServerState) {
        // Reset failure counter and potentially mark healthy
        // This is handled in ServerState::mark_healthy()
        server.mark_healthy();
    }

    /// Record a failed request
    pub fn record_failure(&self, server: &ServerState) {
        // Increment failure counter and potentially mark unhealthy
        // This is handled in ServerState::mark_unhealthy()
        server.mark_unhealthy();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_status_code() {
        assert_eq!(parse_status_code("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(parse_status_code("HTTP/1.1 404 Not Found"), Some(404));
        assert_eq!(
            parse_status_code("HTTP/1.1 500 Internal Server Error"),
            Some(500)
        );
        assert_eq!(parse_status_code("invalid"), None);
    }

    #[test]
    fn test_parse_status_code_http10() {
        assert_eq!(parse_status_code("HTTP/1.0 200 OK"), Some(200));
    }
}
