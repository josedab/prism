//! Envoy configuration migration
//!
//! Converts Envoy proxy configuration (YAML/JSON) to Prism configuration.

use super::{MigrationResult, MigrationStats, MigrationWarning, WarningLevel};
use crate::config::Config;
use crate::error::{PrismError, Result};
use serde::Deserialize;
use std::path::Path;

/// Migrate Envoy configuration to Prism
pub fn migrate(input: &Path) -> Result<MigrationResult> {
    let content = std::fs::read_to_string(input).map_err(|e| {
        PrismError::Config(format!("Failed to read Envoy config file: {}", e))
    })?;

    let parser = EnvoyParser::new();
    parser.parse(&content)
}

/// Envoy configuration parser
pub struct EnvoyParser {
    warnings: Vec<MigrationWarning>,
    stats: MigrationStats,
}

impl EnvoyParser {
    pub fn new() -> Self {
        Self {
            warnings: Vec::new(),
            stats: MigrationStats::default(),
        }
    }

    /// Parse Envoy configuration
    pub fn parse(mut self, content: &str) -> Result<MigrationResult> {
        // Try YAML first, then JSON
        let envoy_config: EnvoyBootstrap = serde_yaml::from_str(content)
            .or_else(|_| serde_json::from_str(content))
            .map_err(|e| PrismError::Config(format!("Failed to parse Envoy config: {}", e)))?;

        let mut config = Config::default();

        // Process static resources
        if let Some(static_resources) = &envoy_config.static_resources {
            // Process listeners
            for listener in &static_resources.listeners {
                self.process_listener(listener, &mut config);
            }

            // Process clusters (upstreams)
            for cluster in &static_resources.clusters {
                self.process_cluster(cluster, &mut config);
            }
        }

        // Process admin interface
        if let Some(admin) = &envoy_config.admin {
            if let Some(address) = &admin.address {
                if let Some(socket_address) = &address.socket_address {
                    self.warnings.push(
                        MigrationWarning::new(
                            WarningLevel::Info,
                            format!(
                                "Envoy admin interface at {}:{} - configure Prism admin separately",
                                socket_address.address, socket_address.port_value
                            ),
                        )
                        .with_suggestion("Configure admin section in Prism config"),
                    );
                }
            }
        }

        Ok(MigrationResult {
            config,
            warnings: self.warnings,
            stats: self.stats,
        })
    }

    fn process_listener(&mut self, listener: &EnvoyListener, config: &mut Config) {
        self.stats.directives_processed += 1;

        let address = listener
            .address
            .as_ref()
            .and_then(|a| a.socket_address.as_ref())
            .map(|s| format!("{}:{}", s.address, s.port_value))
            .unwrap_or_else(|| "0.0.0.0:8080".to_string());

        let listener_config = crate::config::ListenerConfig {
            address,
            protocol: crate::config::Protocol::Http,
            tls: None,
            max_connections: 10000,
        };

        // Process filter chains
        for filter_chain in &listener.filter_chains {
            // Check for TLS
            if let Some(tls_context) = &filter_chain.transport_socket {
                if tls_context.name == "envoy.transport_sockets.tls" {
                    self.warnings.push(
                        MigrationWarning::new(
                            WarningLevel::Warning,
                            "TLS configuration requires manual certificate path setup",
                        )
                        .with_suggestion("Update cert_path and key_path in the generated config"),
                    );
                }
            }

            // Process HTTP filters
            for filter in &filter_chain.filters {
                self.process_filter(filter, config);
            }
        }

        config.listeners.push(listener_config);
        self.stats.listeners += 1;
    }

    fn process_filter(&mut self, filter: &EnvoyFilter, config: &mut Config) {
        self.stats.directives_processed += 1;

        match filter.name.as_str() {
            "envoy.filters.network.http_connection_manager" => {
                if let Some(typed_config) = &filter.typed_config {
                    self.process_http_connection_manager(typed_config, config);
                }
            }
            "envoy.filters.network.tcp_proxy" => {
                self.warnings.push(
                    MigrationWarning::new(
                        WarningLevel::Info,
                        "TCP proxy filter detected - use Prism L4 proxy module",
                    )
                    .with_suggestion("Configure l4 section for TCP proxying"),
                );
            }
            _ => {
                self.warnings.push(MigrationWarning::new(
                    WarningLevel::Warning,
                    format!("Unsupported filter type: {}", filter.name),
                ));
                self.stats.directives_skipped += 1;
            }
        }
    }

    fn process_http_connection_manager(
        &mut self,
        typed_config: &serde_json::Value,
        config: &mut Config,
    ) {
        // Extract route configuration
        if let Some(route_config) = typed_config.get("route_config") {
            self.process_route_config(route_config, config);
        }

        // Check for RDS (Route Discovery Service)
        if typed_config.get("rds").is_some() {
            self.warnings.push(
                MigrationWarning::new(
                    WarningLevel::Warning,
                    "RDS (Route Discovery Service) not supported - using static routes",
                )
                .with_suggestion("Convert RDS routes to static configuration"),
            );
        }

        // Check for access log
        if typed_config.get("access_log").is_some() {
            self.warnings.push(MigrationWarning::new(
                WarningLevel::Info,
                "Access logging configured - Prism uses observability.access_log",
            ));
        }
    }

    fn process_route_config(&mut self, route_config: &serde_json::Value, config: &mut Config) {
        if let Some(virtual_hosts) = route_config.get("virtual_hosts").and_then(|v| v.as_array()) {
            for vhost in virtual_hosts {
                self.process_virtual_host(vhost, config);
            }
        }
    }

    fn process_virtual_host(&mut self, vhost: &serde_json::Value, config: &mut Config) {
        let domains = vhost
            .get("domains")
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if let Some(routes) = vhost.get("routes").and_then(|r| r.as_array()) {
            for route in routes {
                self.process_route(route, &domains, config);
            }
        }
    }

    fn process_route(
        &mut self,
        route: &serde_json::Value,
        domains: &[String],
        config: &mut Config,
    ) {
        self.stats.directives_processed += 1;

        let mut match_config = crate::config::MatchConfig {
            host: None,
            path: None,
            path_prefix: None,
            path_regex: None,
            headers: std::collections::HashMap::new(),
            methods: Vec::new(),
        };

        // Set host matcher if domains specified
        if !domains.is_empty() && !domains.contains(&"*".to_string()) {
            match_config.host = Some(domains[0].clone());
        }

        // Process match conditions
        if let Some(match_rule) = route.get("match") {
            if let Some(prefix) = match_rule.get("prefix").and_then(|p| p.as_str()) {
                match_config.path_prefix = Some(prefix.to_string());
            }
            if let Some(path) = match_rule.get("path").and_then(|p| p.as_str()) {
                match_config.path = Some(path.to_string());
            }
            if let Some(regex) = match_rule.get("safe_regex").and_then(|r| r.get("regex")).and_then(|r| r.as_str()) {
                match_config.path_regex = Some(regex.to_string());
            }
        }

        let mut route_config = crate::config::RouteConfig {
            match_config,
            upstream: None,
            handler: None,
            middlewares: Vec::new(),
            rewrite: None,
            priority: 0,
        };

        // Process route action
        if let Some(route_action) = route.get("route") {
            if let Some(cluster) = route_action.get("cluster").and_then(|c| c.as_str()) {
                route_config.upstream = Some(cluster.to_string());
            }

            // Check for weighted clusters
            if let Some(weighted_clusters) = route_action.get("weighted_clusters") {
                self.warnings.push(
                    MigrationWarning::new(
                        WarningLevel::Info,
                        "Weighted clusters detected - use Prism traffic_split",
                    )
                    .with_suggestion("Configure traffic_split for weighted routing"),
                );

                // Use first cluster as primary
                if let Some(clusters) = weighted_clusters.get("clusters").and_then(|c| c.as_array()) {
                    if let Some(first) = clusters.first() {
                        if let Some(name) = first.get("name").and_then(|n| n.as_str()) {
                            route_config.upstream = Some(name.to_string());
                        }
                    }
                }
            }
        }

        // Process redirect
        if route.get("redirect").is_some() {
            self.warnings.push(
                MigrationWarning::new(WarningLevel::Warning, "Redirect action not directly supported")
                    .with_suggestion("Use Prism middleware for redirects"),
            );
            self.stats.directives_skipped += 1;
        }

        // Only add route if it has a valid upstream
        if route_config.upstream.is_some() {
            config.routes.push(route_config);
            self.stats.routes += 1;
        }
    }

    fn process_cluster(&mut self, cluster: &EnvoyCluster, config: &mut Config) {
        self.stats.directives_processed += 1;

        let mut servers = Vec::new();

        // Process endpoints
        if let Some(load_assignment) = &cluster.load_assignment {
            for endpoint in &load_assignment.endpoints {
                for lb_endpoint in &endpoint.lb_endpoints {
                    if let Some(ep) = &lb_endpoint.endpoint {
                        if let Some(addr) = &ep.address {
                            if let Some(socket_addr) = &addr.socket_address {
                                servers.push(crate::config::ServerConfig {
                                    address: format!(
                                        "{}:{}",
                                        socket_addr.address, socket_addr.port_value
                                    ),
                                    weight: lb_endpoint.load_balancing_weight.map(|w| w as u32).unwrap_or(1),
                                    enabled: true,
                                });
                            }
                        }
                    }
                }
            }
        }

        let upstream_config = crate::config::UpstreamConfig {
            servers,
            health_check: None,
            load_balancing: self.convert_lb_policy(&cluster.lb_policy),
            pool: crate::config::PoolConfig::default(),
            connect_timeout: std::time::Duration::from_secs(5),
            request_timeout: std::time::Duration::from_secs(30),
            circuit_breaker: None,
            retry: None,
        };

        // Process health checks
        if !cluster.health_checks.is_empty() {
            self.warnings.push(MigrationWarning::new(
                WarningLevel::Info,
                format!(
                    "Health checks configured for cluster '{}' - configure in upstream health_check",
                    cluster.name
                ),
            ));
        }

        // Process circuit breakers
        if cluster.circuit_breakers.is_some() {
            self.warnings.push(MigrationWarning::new(
                WarningLevel::Info,
                format!(
                    "Circuit breaker configured for cluster '{}' - configure in upstream circuit_breaker",
                    cluster.name
                ),
            ));
        }

        // Process TLS context
        if cluster.transport_socket.is_some() {
            self.warnings.push(
                MigrationWarning::new(
                    WarningLevel::Warning,
                    format!("Upstream TLS for cluster '{}' requires manual configuration", cluster.name),
                )
                .with_suggestion("Configure upstream TLS settings in Prism"),
            );
        }

        config.upstreams.insert(cluster.name.clone(), upstream_config);
        self.stats.upstreams += 1;
    }

    fn convert_lb_policy(&self, policy: &Option<String>) -> crate::config::LoadBalancingAlgorithm {
        match policy.as_deref() {
            Some("ROUND_ROBIN") => crate::config::LoadBalancingAlgorithm::RoundRobin,
            Some("LEAST_REQUEST") => crate::config::LoadBalancingAlgorithm::LeastConnections,
            Some("RANDOM") => crate::config::LoadBalancingAlgorithm::Random,
            Some("RING_HASH") | Some("MAGLEV") => crate::config::LoadBalancingAlgorithm::IpHash,
            _ => crate::config::LoadBalancingAlgorithm::RoundRobin,
        }
    }
}

impl Default for EnvoyParser {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Envoy Configuration Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct EnvoyBootstrap {
    pub static_resources: Option<StaticResources>,
    pub admin: Option<EnvoyAdmin>,
    #[serde(default)]
    pub node: Option<EnvoyNode>,
}

#[derive(Debug, Deserialize)]
pub struct StaticResources {
    #[serde(default)]
    pub listeners: Vec<EnvoyListener>,
    #[serde(default)]
    pub clusters: Vec<EnvoyCluster>,
}

#[derive(Debug, Deserialize)]
pub struct EnvoyAdmin {
    pub address: Option<EnvoyAddress>,
}

#[derive(Debug, Deserialize)]
pub struct EnvoyNode {
    pub id: Option<String>,
    pub cluster: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EnvoyListener {
    pub name: Option<String>,
    pub address: Option<EnvoyAddress>,
    #[serde(default)]
    pub filter_chains: Vec<FilterChain>,
}

#[derive(Debug, Deserialize)]
pub struct EnvoyAddress {
    pub socket_address: Option<SocketAddress>,
}

#[derive(Debug, Deserialize)]
pub struct SocketAddress {
    pub address: String,
    pub port_value: u16,
    pub protocol: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FilterChain {
    #[serde(default)]
    pub filters: Vec<EnvoyFilter>,
    pub transport_socket: Option<TransportSocket>,
}

#[derive(Debug, Deserialize)]
pub struct EnvoyFilter {
    pub name: String,
    pub typed_config: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct TransportSocket {
    pub name: String,
    pub typed_config: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct EnvoyCluster {
    pub name: String,
    #[serde(rename = "type")]
    pub cluster_type: Option<String>,
    pub lb_policy: Option<String>,
    pub load_assignment: Option<ClusterLoadAssignment>,
    #[serde(default)]
    pub health_checks: Vec<HealthCheck>,
    pub circuit_breakers: Option<CircuitBreakers>,
    pub transport_socket: Option<TransportSocket>,
    pub connect_timeout: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClusterLoadAssignment {
    pub cluster_name: Option<String>,
    #[serde(default)]
    pub endpoints: Vec<LocalityLbEndpoints>,
}

#[derive(Debug, Deserialize)]
pub struct LocalityLbEndpoints {
    #[serde(default)]
    pub lb_endpoints: Vec<LbEndpoint>,
}

#[derive(Debug, Deserialize)]
pub struct LbEndpoint {
    pub endpoint: Option<Endpoint>,
    pub load_balancing_weight: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct Endpoint {
    pub address: Option<EnvoyAddress>,
}

#[derive(Debug, Deserialize)]
pub struct HealthCheck {
    pub timeout: Option<String>,
    pub interval: Option<String>,
    pub unhealthy_threshold: Option<u32>,
    pub healthy_threshold: Option<u32>,
    pub http_health_check: Option<HttpHealthCheck>,
}

#[derive(Debug, Deserialize)]
pub struct HttpHealthCheck {
    pub path: Option<String>,
    pub host: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CircuitBreakers {
    #[serde(default)]
    pub thresholds: Vec<CircuitBreakerThreshold>,
}

#[derive(Debug, Deserialize)]
pub struct CircuitBreakerThreshold {
    pub priority: Option<String>,
    pub max_connections: Option<u32>,
    pub max_pending_requests: Option<u32>,
    pub max_requests: Option<u32>,
    pub max_retries: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_envoy_config() {
        let config = r#"
static_resources:
  listeners:
    - name: listener_0
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                route_config:
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: backend_cluster
  clusters:
    - name: backend_cluster
      lb_policy: ROUND_ROBIN
      load_assignment:
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: 3000
"#;

        let parser = EnvoyParser::new();
        let result = parser.parse(config).unwrap();

        assert_eq!(result.stats.listeners, 1);
        assert_eq!(result.stats.upstreams, 1);
        assert_eq!(result.stats.routes, 1);
        assert!(result.config.upstreams.contains_key("backend_cluster"));
    }
}
