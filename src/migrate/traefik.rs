//! Traefik configuration migration
//!
//! Converts Traefik proxy configuration (YAML/TOML) to Prism configuration.

use super::{MigrationResult, MigrationStats, MigrationWarning, WarningLevel};
use crate::config::Config;
use crate::error::{PrismError, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Migrate Traefik configuration to Prism
pub fn migrate(input: &Path) -> Result<MigrationResult> {
    let content = std::fs::read_to_string(input).map_err(|e| {
        PrismError::Config(format!("Failed to read Traefik config file: {}", e))
    })?;

    let parser = TraefikParser::new();
    parser.parse(&content, input)
}

/// Traefik configuration parser
pub struct TraefikParser {
    warnings: Vec<MigrationWarning>,
    stats: MigrationStats,
}

impl TraefikParser {
    pub fn new() -> Self {
        Self {
            warnings: Vec::new(),
            stats: MigrationStats::default(),
        }
    }

    /// Parse Traefik configuration
    pub fn parse(mut self, content: &str, path: &Path) -> Result<MigrationResult> {
        // Determine format based on extension
        let is_toml = path.extension().map(|e| e == "toml").unwrap_or(false);

        let traefik_config: TraefikConfig = if is_toml {
            toml::from_str(content)
                .map_err(|e| PrismError::Config(format!("Failed to parse Traefik TOML: {}", e)))?
        } else {
            serde_yaml::from_str(content)
                .map_err(|e| PrismError::Config(format!("Failed to parse Traefik YAML: {}", e)))?
        };

        let mut config = Config::default();

        // Process entry points (listeners)
        if let Some(entry_points) = &traefik_config.entry_points {
            for (name, ep) in entry_points {
                self.process_entry_point(name, ep, &mut config);
            }
        }

        // Process HTTP configuration (routers, services, middlewares)
        if let Some(http) = &traefik_config.http {
            // Process services first (upstreams)
            if let Some(services) = &http.services {
                for (name, service) in services {
                    self.process_service(name, service, &mut config);
                }
            }

            // Process routers (routes)
            if let Some(routers) = &http.routers {
                for (name, router) in routers {
                    self.process_router(name, router, &mut config);
                }
            }

            // Note about middlewares
            if let Some(middlewares) = &http.middlewares {
                for (name, middleware) in middlewares {
                    self.process_middleware(name, middleware);
                }
            }
        }

        // Process TCP configuration
        if traefik_config.tcp.is_some() {
            self.warnings.push(
                MigrationWarning::new(
                    WarningLevel::Info,
                    "TCP configuration detected - use Prism L4 proxy module",
                )
                .with_suggestion("Configure l4 section for TCP proxying"),
            );
        }

        // Process providers
        if let Some(providers) = &traefik_config.providers {
            self.process_providers(providers);
        }

        Ok(MigrationResult {
            config,
            warnings: self.warnings,
            stats: self.stats,
        })
    }

    fn process_entry_point(&mut self, name: &str, ep: &EntryPoint, config: &mut Config) {
        self.stats.directives_processed += 1;

        let address = ep.address.clone().unwrap_or_else(|| ":8080".to_string());
        let normalized_address = if address.starts_with(':') {
            format!("0.0.0.0{}", address)
        } else {
            address
        };

        let mut listener_config = crate::config::ListenerConfig {
            address: normalized_address,
            protocol: crate::config::Protocol::Http,
            tls: None,
            max_connections: 10000,
        };

        // Process TLS if configured
        if ep.tls.is_some() {
            listener_config.tls = Some(crate::config::TlsConfig {
                cert: "cert.pem".into(),
                key: "key.pem".into(),
                alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                min_version: "1.2".to_string(),
                client_auth: crate::config::ClientAuthMode::None,
                client_ca: None,
            });

            self.warnings.push(
                MigrationWarning::new(
                    WarningLevel::Warning,
                    format!("TLS for entry point '{}' requires manual certificate setup", name),
                )
                .with_suggestion("Update cert_path and key_path in the generated config"),
            );
        }

        // Check for HTTP/3
        if ep.http3.is_some() {
            self.warnings.push(MigrationWarning::new(
                WarningLevel::Info,
                format!("HTTP/3 enabled for entry point '{}' - configure http3 in Prism", name),
            ));
        }

        config.listeners.push(listener_config);
        self.stats.listeners += 1;
    }

    fn process_service(&mut self, name: &str, service: &TraefikService, config: &mut Config) {
        self.stats.directives_processed += 1;

        if let Some(load_balancer) = &service.load_balancer {
            let mut servers = Vec::new();

            // Process servers
            if let Some(svrs) = &load_balancer.servers {
                for server in svrs {
                    let address = server.url.as_ref()
                        .map(|url| {
                            // Extract host:port from URL
                            url.trim_start_matches("http://")
                                .trim_start_matches("https://")
                                .to_string()
                        })
                        .unwrap_or_default();

                    if !address.is_empty() {
                        servers.push(crate::config::ServerConfig {
                            address,
                            weight: server.weight.map(|w| w as u32).unwrap_or(1),
                            enabled: true,
                        });
                    }
                }
            }

            let upstream_config = crate::config::UpstreamConfig {
                servers,
                health_check: None,
                load_balancing: crate::config::LoadBalancingAlgorithm::RoundRobin,
                pool: crate::config::PoolConfig::default(),
                connect_timeout: std::time::Duration::from_secs(5),
                request_timeout: std::time::Duration::from_secs(30),
                circuit_breaker: None,
                retry: None,
            };

            // Check for sticky sessions
            if load_balancer.sticky.is_some() {
                self.warnings.push(MigrationWarning::new(
                    WarningLevel::Info,
                    format!("Sticky sessions for service '{}' - configure session affinity in Prism", name),
                ));
            }

            config.upstreams.insert(name.to_string(), upstream_config);
            self.stats.upstreams += 1;
        } else if service.weighted.is_some() {
            self.warnings.push(
                MigrationWarning::new(
                    WarningLevel::Warning,
                    format!("Weighted service '{}' - use Prism traffic_split", name),
                )
                .with_suggestion("Configure traffic_split for weighted routing"),
            );
            self.stats.directives_skipped += 1;
        } else if service.mirroring.is_some() {
            self.warnings.push(
                MigrationWarning::new(
                    WarningLevel::Warning,
                    format!("Mirroring service '{}' - use Prism shadowing module", name),
                )
                .with_suggestion("Configure shadowing for traffic mirroring"),
            );
            self.stats.directives_skipped += 1;
        }
    }

    fn process_router(&mut self, name: &str, router: &TraefikRouter, config: &mut Config) {
        self.stats.directives_processed += 1;

        let mut match_config = crate::config::MatchConfig {
            host: None,
            path: None,
            path_prefix: None,
            path_regex: None,
            headers: HashMap::new(),
            methods: Vec::new(),
        };

        // Parse rule
        if let Some(rule) = &router.rule {
            self.parse_traefik_rule(rule, &mut match_config);
        }

        let route_config = crate::config::RouteConfig {
            match_config,
            upstream: router.service.clone(),
            handler: None,
            middlewares: Vec::new(),
            rewrite: None,
            priority: router.priority.unwrap_or(0),
        };

        // Check for middlewares
        if let Some(middlewares) = &router.middlewares {
            if !middlewares.is_empty() {
                self.warnings.push(MigrationWarning::new(
                    WarningLevel::Info,
                    format!(
                        "Router '{}' uses middlewares: {} - configure in route middleware section",
                        name,
                        middlewares.join(", ")
                    ),
                ));
            }
        }

        // Check for TLS
        if router.tls.is_some() {
            self.warnings.push(MigrationWarning::new(
                WarningLevel::Info,
                format!("Router '{}' has TLS configuration - ensure listener has TLS enabled", name),
            ));
        }

        config.routes.push(route_config);
        self.stats.routes += 1;
    }

    fn parse_traefik_rule(&mut self, rule: &str, match_config: &mut crate::config::MatchConfig) {
        // Parse Traefik rule syntax
        // Examples: Host(`example.com`), PathPrefix(`/api`), Host(`example.com`) && PathPrefix(`/api`)

        let parts: Vec<&str> = rule.split("&&").map(|s| s.trim()).collect();

        for part in parts {
            if let Some(host) = extract_function_arg(part, "Host") {
                match_config.host = Some(host);
            } else if let Some(prefix) = extract_function_arg(part, "PathPrefix") {
                match_config.path_prefix = Some(prefix);
            } else if let Some(path) = extract_function_arg(part, "Path") {
                match_config.path = Some(path);
            } else if let Some(regex) = extract_function_arg(part, "PathRegexp") {
                match_config.path_regex = Some(regex);
            } else if part.contains("Headers") || part.contains("HeadersRegexp") {
                self.warnings.push(MigrationWarning::new(
                    WarningLevel::Info,
                    format!("Header matching rule: {} - configure in route headers", part),
                ));
            } else if part.contains("Method") {
                if let Some(methods) = extract_function_args(part, "Method") {
                    match_config.methods = methods;
                }
            }
        }
    }

    fn process_middleware(&mut self, name: &str, middleware: &TraefikMiddleware) {
        self.stats.directives_processed += 1;

        if middleware.add_prefix.is_some() {
            self.warnings.push(MigrationWarning::new(
                WarningLevel::Info,
                format!("Middleware '{}' (addPrefix) - use path rewriting in route", name),
            ));
        }

        if middleware.strip_prefix.is_some() {
            self.warnings.push(MigrationWarning::new(
                WarningLevel::Info,
                format!("Middleware '{}' (stripPrefix) - use rewrite in route", name),
            ));
        }

        if middleware.headers.is_some() {
            self.warnings.push(MigrationWarning::new(
                WarningLevel::Info,
                format!("Middleware '{}' (headers) - configure headers middleware", name),
            ));
        }

        if middleware.rate_limit.is_some() {
            self.warnings.push(MigrationWarning::new(
                WarningLevel::Info,
                format!("Middleware '{}' (rateLimit) - use Prism rate_limit middleware", name),
            ));
        }

        if middleware.basic_auth.is_some() || middleware.forward_auth.is_some() {
            self.warnings.push(MigrationWarning::new(
                WarningLevel::Info,
                format!("Middleware '{}' (auth) - configure Prism auth middleware", name),
            ));
        }

        if middleware.compress.is_some() {
            self.warnings.push(MigrationWarning::new(
                WarningLevel::Info,
                format!("Middleware '{}' (compress) - use Prism compression middleware", name),
            ));
        }
    }

    fn process_providers(&mut self, providers: &TraefikProviders) {
        if providers.docker.is_some() {
            self.warnings.push(
                MigrationWarning::new(
                    WarningLevel::Warning,
                    "Docker provider not supported - use static configuration",
                )
                .with_suggestion("Consider using Prism's Kubernetes Gateway API support"),
            );
        }

        if providers.kubernetes_crd.is_some() || providers.kubernetes_ingress.is_some() {
            self.warnings.push(MigrationWarning::new(
                WarningLevel::Info,
                "Kubernetes provider detected - use Prism's Kubernetes Gateway API support",
            ));
        }

        if providers.file.is_some() {
            self.warnings.push(MigrationWarning::new(
                WarningLevel::Info,
                "File provider - merge all file configurations for migration",
            ));
        }
    }
}

impl Default for TraefikParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract single argument from Traefik function syntax: FuncName(`arg`)
fn extract_function_arg(s: &str, func_name: &str) -> Option<String> {
    let pattern = format!("{}(`", func_name);
    if let Some(start) = s.find(&pattern) {
        let rest = &s[start + pattern.len()..];
        if let Some(end) = rest.find("`)") {
            return Some(rest[..end].to_string());
        }
    }
    None
}

/// Extract multiple arguments from Traefik function syntax
fn extract_function_args(s: &str, func_name: &str) -> Option<Vec<String>> {
    let pattern = format!("{}(", func_name);
    if let Some(start) = s.find(&pattern) {
        let rest = &s[start + pattern.len()..];
        if let Some(end) = rest.find(')') {
            let args_str = &rest[..end];
            let args: Vec<String> = args_str
                .split(',')
                .map(|a| a.trim().trim_matches('`').to_string())
                .filter(|a| !a.is_empty())
                .collect();
            if !args.is_empty() {
                return Some(args);
            }
        }
    }
    None
}

// ============================================================================
// Traefik Configuration Types
// ============================================================================

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TraefikConfig {
    pub entry_points: Option<HashMap<String, EntryPoint>>,
    pub http: Option<HttpConfig>,
    pub tcp: Option<TcpConfig>,
    pub providers: Option<TraefikProviders>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EntryPoint {
    pub address: Option<String>,
    pub http3: Option<serde_json::Value>,
    pub tls: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
pub struct HttpConfig {
    pub routers: Option<HashMap<String, TraefikRouter>>,
    pub services: Option<HashMap<String, TraefikService>>,
    pub middlewares: Option<HashMap<String, TraefikMiddleware>>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TraefikRouter {
    pub entry_points: Option<Vec<String>>,
    pub rule: Option<String>,
    pub service: Option<String>,
    pub middlewares: Option<Vec<String>>,
    pub priority: Option<i32>,
    pub tls: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TraefikService {
    pub load_balancer: Option<LoadBalancer>,
    pub weighted: Option<serde_json::Value>,
    pub mirroring: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalancer {
    pub servers: Option<Vec<Server>>,
    pub sticky: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Server {
    pub url: Option<String>,
    pub weight: Option<i32>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TraefikMiddleware {
    pub add_prefix: Option<serde_json::Value>,
    pub strip_prefix: Option<serde_json::Value>,
    pub headers: Option<serde_json::Value>,
    pub rate_limit: Option<serde_json::Value>,
    pub basic_auth: Option<serde_json::Value>,
    pub forward_auth: Option<serde_json::Value>,
    pub compress: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
pub struct TcpConfig {
    pub routers: Option<serde_json::Value>,
    pub services: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TraefikProviders {
    pub docker: Option<serde_json::Value>,
    pub file: Option<serde_json::Value>,
    pub kubernetes_crd: Option<serde_json::Value>,
    pub kubernetes_ingress: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_function_arg() {
        assert_eq!(
            extract_function_arg("Host(`example.com`)", "Host"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_function_arg("PathPrefix(`/api`)", "PathPrefix"),
            Some("/api".to_string())
        );
    }

    #[test]
    fn test_basic_traefik_config() {
        let config = r#"
entryPoints:
  web:
    address: ":8080"

http:
  routers:
    my-router:
      rule: "Host(`example.com`) && PathPrefix(`/api`)"
      service: my-service

  services:
    my-service:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:3000"
"#;

        let parser = TraefikParser::new();
        let result = parser.parse(config, Path::new("traefik.yml")).unwrap();

        assert_eq!(result.stats.listeners, 1);
        assert_eq!(result.stats.upstreams, 1);
        assert_eq!(result.stats.routes, 1);
    }
}
