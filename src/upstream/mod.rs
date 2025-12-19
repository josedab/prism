//! Upstream module for managing backend connections
//!
//! Provides:
//! - Connection pooling
//! - Health checking
//! - Load balancing algorithms
//! - Upstream management

mod balancer;
mod health;
mod pool;

pub use balancer::*;
pub use health::*;
pub use pool::*;

use crate::config::{CircuitBreakerConfig, ServerConfig, UpstreamConfig};
use crate::error::{PrismError, Result};
use crate::middleware::{CircuitBreaker, RetryPolicy};
use dashmap::DashMap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

/// A backend server
#[derive(Debug, Clone)]
pub struct Server {
    /// Server address
    pub address: SocketAddr,
    /// Weight for load balancing
    pub weight: u32,
    /// Whether the server is enabled
    pub enabled: bool,
}

impl Server {
    /// Create a new server from configuration
    pub fn from_config(config: &ServerConfig) -> Result<Self> {
        let address = config.address.parse().map_err(|e| {
            PrismError::Config(format!(
                "Invalid server address '{}': {}",
                config.address, e
            ))
        })?;

        Ok(Self {
            address,
            weight: config.weight,
            enabled: config.enabled,
        })
    }
}

/// Health status of a server
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Server is healthy
    Healthy,
    /// Server is unhealthy
    Unhealthy,
    /// Health status unknown
    Unknown,
}

/// Reason why server selection failed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionFailureReason {
    /// All servers have open circuit breakers
    CircuitOpen,
    /// All servers are unhealthy (failed health checks)
    AllUnhealthy,
    /// No servers configured
    NoServers,
}

/// Runtime state of a server
pub struct ServerState {
    /// The server configuration
    pub server: Server,
    /// Current health status
    health_status: std::sync::atomic::AtomicU8,
    /// Consecutive failures
    consecutive_failures: AtomicU64,
    /// Consecutive successes
    consecutive_successes: AtomicU64,
    /// Active connections
    active_connections: AtomicU64,
    /// Total requests
    total_requests: AtomicU64,
    /// Total errors
    total_errors: AtomicU64,
    /// Last health check time (unix millis)
    #[allow(dead_code)]
    last_check: AtomicU64,
    /// Circuit breaker for this server
    circuit_breaker: Option<CircuitBreaker>,
}

const HEALTH_HEALTHY: u8 = 0;
const HEALTH_UNHEALTHY: u8 = 1;
const HEALTH_UNKNOWN: u8 = 2;

impl ServerState {
    /// Create a new server state
    pub fn new(server: Server) -> Self {
        Self {
            server,
            health_status: std::sync::atomic::AtomicU8::new(HEALTH_UNKNOWN),
            consecutive_failures: AtomicU64::new(0),
            consecutive_successes: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            last_check: AtomicU64::new(0),
            circuit_breaker: None,
        }
    }

    /// Create a new server state with circuit breaker
    pub fn with_circuit_breaker(server: Server, config: &CircuitBreakerConfig) -> Self {
        Self {
            server,
            health_status: std::sync::atomic::AtomicU8::new(HEALTH_UNKNOWN),
            consecutive_failures: AtomicU64::new(0),
            consecutive_successes: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            last_check: AtomicU64::new(0),
            circuit_breaker: Some(CircuitBreaker::new(
                config.failure_threshold,
                config.success_threshold,
                config.half_open_timeout,
            )),
        }
    }

    /// Get the current health status
    pub fn health_status(&self) -> HealthStatus {
        match self.health_status.load(Ordering::Relaxed) {
            HEALTH_HEALTHY => HealthStatus::Healthy,
            HEALTH_UNHEALTHY => HealthStatus::Unhealthy,
            _ => HealthStatus::Unknown,
        }
    }

    /// Check if the server is healthy
    pub fn is_healthy(&self) -> bool {
        self.health_status() == HealthStatus::Healthy
    }

    /// Mark the server as healthy
    pub fn mark_healthy(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.consecutive_successes.fetch_add(1, Ordering::Relaxed);
        self.health_status.store(HEALTH_HEALTHY, Ordering::Relaxed);
    }

    /// Mark the server as unhealthy
    pub fn mark_unhealthy(&self) {
        self.consecutive_successes.store(0, Ordering::Relaxed);
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        self.health_status
            .store(HEALTH_UNHEALTHY, Ordering::Relaxed);
    }

    /// Record start of a request
    pub fn start_request(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record end of a request
    pub fn end_request(&self, success: bool) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        if !success {
            self.total_errors.fetch_add(1, Ordering::Relaxed);
        }

        // Update circuit breaker
        if let Some(cb) = &self.circuit_breaker {
            if success {
                cb.record_success();
            } else {
                cb.record_failure();
            }
        }
    }

    /// Check if requests should be allowed through circuit breaker
    pub fn circuit_allows(&self) -> bool {
        self.circuit_breaker
            .as_ref()
            .map(|cb| cb.should_allow())
            .unwrap_or(true)
    }

    /// Get the circuit breaker state
    pub fn circuit_state(&self) -> Option<crate::middleware::CircuitState> {
        self.circuit_breaker.as_ref().map(|cb| cb.state())
    }

    /// Get active connection count
    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Get total request count
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Get total error count
    pub fn total_errors(&self) -> u64 {
        self.total_errors.load(Ordering::Relaxed)
    }
}

/// An upstream backend group
pub struct Upstream {
    /// Upstream name
    pub name: String,
    /// Servers in this upstream
    servers: Vec<Arc<ServerState>>,
    /// Load balancer
    balancer: Box<dyn LoadBalancer>,
    /// Health checker (optional)
    health_checker: Option<Arc<HealthChecker>>,
    /// Connection pool
    pool: Arc<ConnectionPool>,
    /// Retry policy (optional)
    retry_policy: Option<RetryPolicy>,
    /// Configuration
    #[allow(dead_code)]
    config: UpstreamConfig,
}

impl Upstream {
    /// Create a new upstream from configuration
    pub fn new(name: String, config: UpstreamConfig) -> Result<Self> {
        let cb_config = config.circuit_breaker.as_ref();
        let servers: Vec<Arc<ServerState>> = config
            .servers
            .iter()
            .map(|s| {
                Server::from_config(s).map(|srv| {
                    Arc::new(if let Some(cb) = cb_config {
                        ServerState::with_circuit_breaker(srv, cb)
                    } else {
                        ServerState::new(srv)
                    })
                })
            })
            .collect::<Result<Vec<_>>>()?;

        if servers.is_empty() {
            return Err(PrismError::Config(format!(
                "Upstream '{}' has no servers",
                name
            )));
        }

        let balancer = create_balancer(&config.load_balancing, &servers);

        let health_checker = config
            .health_check
            .as_ref()
            .map(|hc| Arc::new(HealthChecker::new(hc.clone(), servers.clone())));

        let pool = Arc::new(ConnectionPool::new(&config.pool));

        let retry_policy = config.retry.as_ref().map(RetryPolicy::from_config);

        info!(
            "Created upstream '{}' with {} servers, algorithm: {:?}",
            name,
            servers.len(),
            config.load_balancing
        );

        Ok(Self {
            name,
            servers,
            balancer,
            health_checker,
            pool,
            retry_policy,
            config,
        })
    }

    /// Get the retry policy for this upstream
    pub fn retry_policy(&self) -> Option<&RetryPolicy> {
        self.retry_policy.as_ref()
    }

    /// Get a healthy server using the load balancing algorithm
    pub fn select_server(&self) -> Option<Arc<ServerState>> {
        // Get list of healthy servers that also pass circuit breaker check
        let healthy: Vec<&Arc<ServerState>> = self
            .servers
            .iter()
            .filter(|s| s.server.enabled && s.is_healthy() && s.circuit_allows())
            .collect();

        if healthy.is_empty() {
            // If no healthy servers, try servers with unknown status that pass circuit breaker
            let unknown: Vec<&Arc<ServerState>> = self
                .servers
                .iter()
                .filter(|s| {
                    s.server.enabled
                        && s.health_status() == HealthStatus::Unknown
                        && s.circuit_allows()
                })
                .collect();

            if unknown.is_empty() {
                warn!(
                    "No healthy servers available for upstream '{}' (circuit breaker may be open)",
                    self.name
                );
                return None;
            }

            return self.balancer.select(&unknown).cloned();
        }

        self.balancer.select(&healthy).cloned()
    }

    /// Get all servers
    pub fn servers(&self) -> &[Arc<ServerState>] {
        &self.servers
    }

    /// Get the connection pool
    pub fn pool(&self) -> &Arc<ConnectionPool> {
        &self.pool
    }

    /// Start health checking
    pub fn start_health_checks(&self) -> Option<tokio::task::JoinHandle<()>> {
        self.health_checker.as_ref().map(|hc| {
            let checker = hc.clone();
            tokio::spawn(async move {
                checker.run().await;
            })
        })
    }

    /// Check why server selection failed
    /// Returns a tuple of (any_healthy, any_circuit_open)
    pub fn selection_failure_reason(&self) -> SelectionFailureReason {
        let mut has_unhealthy = false;
        let mut has_circuit_open = false;
        let mut has_healthy_but_circuit_open = false;

        for server in &self.servers {
            if !server.server.enabled {
                continue;
            }

            let is_healthy = server.is_healthy() || server.health_status() == HealthStatus::Unknown;
            let circuit_open = !server.circuit_allows();

            if !is_healthy {
                has_unhealthy = true;
            }
            if circuit_open {
                has_circuit_open = true;
            }
            if is_healthy && circuit_open {
                has_healthy_but_circuit_open = true;
            }
        }

        if has_healthy_but_circuit_open || (has_circuit_open && !has_unhealthy) {
            // Servers are healthy but circuit is open
            SelectionFailureReason::CircuitOpen
        } else if has_unhealthy {
            // Servers are unhealthy
            SelectionFailureReason::AllUnhealthy
        } else {
            SelectionFailureReason::NoServers
        }
    }

    /// Get upstream statistics
    pub fn stats(&self) -> UpstreamStats {
        let mut total_requests = 0;
        let mut total_errors = 0;
        let mut active_connections = 0;
        let mut healthy_count = 0;
        let mut servers = Vec::new();

        for server in &self.servers {
            let server_requests = server.total_requests();
            let server_errors = server.total_errors();
            let server_connections = server.active_connections();
            let is_healthy = server.is_healthy();

            total_requests += server_requests;
            total_errors += server_errors;
            active_connections += server_connections;
            if is_healthy {
                healthy_count += 1;
            }

            servers.push(ServerInfo {
                address: server.server.address.to_string(),
                healthy: is_healthy,
                weight: server.server.weight,
                active_connections: server_connections,
                total_requests: server_requests,
            });
        }

        UpstreamStats {
            name: self.name.clone(),
            server_count: self.servers.len(),
            healthy_count,
            total_requests,
            total_errors,
            active_connections,
            servers,
        }
    }
}

/// Upstream statistics
#[derive(Debug, Clone)]
pub struct UpstreamStats {
    pub name: String,
    pub server_count: usize,
    pub healthy_count: usize,
    pub total_requests: u64,
    pub total_errors: u64,
    pub active_connections: u64,
    pub servers: Vec<ServerInfo>,
}

/// Server info for stats
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub address: String,
    pub healthy: bool,
    pub weight: u32,
    pub active_connections: u64,
    pub total_requests: u64,
}

/// Manager for all upstreams
pub struct UpstreamManager {
    upstreams: DashMap<String, Arc<Upstream>>,
}

impl UpstreamManager {
    /// Create a new upstream manager
    pub fn new() -> Self {
        Self {
            upstreams: DashMap::new(),
        }
    }

    /// Create from configuration
    pub fn from_config(configs: &HashMap<String, UpstreamConfig>) -> Result<Self> {
        let manager = Self::new();

        for (name, config) in configs {
            let upstream = Upstream::new(name.clone(), config.clone())?;
            manager.upstreams.insert(name.clone(), Arc::new(upstream));
        }

        Ok(manager)
    }

    /// Get an upstream by name
    pub fn get(&self, name: &str) -> Option<Arc<Upstream>> {
        self.upstreams.get(name).map(|r| r.value().clone())
    }

    /// Start health checking for all upstreams
    pub fn start_health_checks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();

        for entry in self.upstreams.iter() {
            if let Some(handle) = entry.value().start_health_checks() {
                handles.push(handle);
            }
        }

        handles
    }

    /// Get statistics for all upstreams
    pub fn stats(&self) -> Vec<UpstreamStats> {
        self.upstreams
            .iter()
            .map(|entry| entry.value().stats())
            .collect()
    }
}

impl Default for UpstreamManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_server_state_circuit_breaker() {
        let server = Server {
            address: "127.0.0.1:8080".parse().unwrap(),
            weight: 1,
            enabled: true,
        };

        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            half_open_timeout: Duration::from_secs(30),
        };

        let state = ServerState::with_circuit_breaker(server, &config);

        // Initially circuit should allow requests
        assert!(state.circuit_allows());

        // Record failures to trigger circuit open
        state.end_request(false);
        state.end_request(false);
        state.end_request(false);

        // Circuit should now be open
        assert!(!state.circuit_allows());
    }

    #[test]
    fn test_server_state_without_circuit_breaker() {
        let server = Server {
            address: "127.0.0.1:8080".parse().unwrap(),
            weight: 1,
            enabled: true,
        };

        let state = ServerState::new(server);

        // Without circuit breaker, should always allow
        assert!(state.circuit_allows());

        // Even after failures, should still allow
        state.end_request(false);
        state.end_request(false);
        state.end_request(false);

        assert!(state.circuit_allows());
    }

    #[test]
    fn test_selection_failure_reason_enum() {
        assert_eq!(
            SelectionFailureReason::CircuitOpen,
            SelectionFailureReason::CircuitOpen
        );
        assert_ne!(
            SelectionFailureReason::CircuitOpen,
            SelectionFailureReason::AllUnhealthy
        );
    }
}
