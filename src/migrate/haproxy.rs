//! HAProxy configuration migration
//!
//! Converts HAProxy configuration files to Prism configuration.
//! Supports:
//! - Global and defaults sections
//! - Frontend definitions (listeners)
//! - Backend definitions (upstreams)
//! - ACLs and use_backend rules (routes)
//! - Server options (health checks, weights)

use super::{MigrationResult, MigrationStats, MigrationWarning, WarningLevel};
use crate::config::{
    Config, HealthCheckConfig, ListenerConfig, LoadBalancingAlgorithm, MatchConfig, PoolConfig,
    Protocol, RouteConfig, ServerConfig, TlsConfig, UpstreamConfig,
};
use crate::error::{PrismError, Result};
use std::collections::HashMap;
use std::path::Path;

/// Migrate HAProxy configuration to Prism
pub fn migrate(input: &Path) -> Result<MigrationResult> {
    let content = std::fs::read_to_string(input).map_err(|e| {
        PrismError::Config(format!("Failed to read HAProxy config file: {}", e))
    })?;

    let parser = HAProxyParser::new();
    parser.parse(&content)
}

/// HAProxy configuration parser
pub struct HAProxyParser {
    warnings: Vec<MigrationWarning>,
    stats: MigrationStats,
}

impl HAProxyParser {
    pub fn new() -> Self {
        Self {
            warnings: Vec::new(),
            stats: MigrationStats::default(),
        }
    }

    /// Parse HAProxy configuration
    pub fn parse(mut self, content: &str) -> Result<MigrationResult> {
        let mut config = Config::default();

        let sections = self.parse_sections(content);
        let mut defaults = HAProxyDefaults::default();
        let mut frontends: HashMap<String, HAProxyFrontend> = HashMap::new();
        let mut backends: HashMap<String, HAProxyBackend> = HashMap::new();
        let mut listens: HashMap<String, HAProxyListen> = HashMap::new();

        // Process sections
        for section in sections {
            match section.section_type.as_str() {
                "global" => self.process_global(&section),
                "defaults" => {
                    defaults = self.parse_defaults(&section);
                }
                "frontend" => {
                    if let Some(name) = section.name.clone() {
                        let frontend = self.parse_frontend(&section, &defaults);
                        frontends.insert(name, frontend);
                    }
                }
                "backend" => {
                    if let Some(name) = section.name.clone() {
                        let backend = self.parse_backend(&section, &defaults);
                        backends.insert(name, backend);
                    }
                }
                "listen" => {
                    if let Some(name) = section.name.clone() {
                        let listen = self.parse_listen(&section, &defaults);
                        listens.insert(name, listen);
                    }
                }
                _ => {
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Warning,
                        format!("Unknown section type: {}", section.section_type),
                    ));
                }
            }
        }

        // Convert frontends to listeners and routes
        for (name, frontend) in &frontends {
            self.convert_frontend(name, frontend, &backends, &mut config);
        }

        // Convert backends to upstreams
        for (name, backend) in &backends {
            self.convert_backend(name, backend, &mut config);
        }

        // Convert listen sections (combined frontend+backend)
        for (name, listen) in &listens {
            self.convert_listen(name, listen, &mut config);
        }

        Ok(MigrationResult {
            config,
            warnings: self.warnings,
            stats: self.stats,
        })
    }

    fn parse_sections(&self, content: &str) -> Vec<HAProxySection> {
        let mut sections = Vec::new();
        let mut current_section: Option<HAProxySection> = None;

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Check for section start
            let section_keywords = ["global", "defaults", "frontend", "backend", "listen"];
            let mut is_section_start = false;

            for keyword in &section_keywords {
                if line.starts_with(keyword) {
                    // Save current section
                    if let Some(section) = current_section.take() {
                        sections.push(section);
                    }

                    // Parse section header
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    let name = if parts.len() > 1 {
                        Some(parts[1].to_string())
                    } else {
                        None
                    };

                    current_section = Some(HAProxySection {
                        section_type: keyword.to_string(),
                        name,
                        lines: Vec::new(),
                    });
                    is_section_start = true;
                    break;
                }
            }

            // Add line to current section
            if !is_section_start {
                if let Some(ref mut section) = current_section {
                    section.lines.push(line.to_string());
                }
            }
        }

        // Don't forget the last section
        if let Some(section) = current_section {
            sections.push(section);
        }

        sections
    }

    fn process_global(&mut self, section: &HAProxySection) {
        self.stats.directives_processed += section.lines.len();

        for line in &section.lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            match parts[0] {
                "maxconn" => {
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Info,
                        format!(
                            "Global maxconn: {} - configure per-listener",
                            parts.get(1).unwrap_or(&"?")
                        ),
                    ));
                }
                "log" => {
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Info,
                        "Logging configured - use Prism observability settings",
                    ));
                }
                "ssl-default-bind-ciphers" | "ssl-default-bind-ciphersuites" => {
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Info,
                        "SSL cipher configuration - configure in listener TLS settings",
                    ));
                }
                "tune.ssl.default-dh-param" => {
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Info,
                        "DH param size - Prism uses modern key exchange",
                    ));
                }
                _ => {
                    self.stats.directives_skipped += 1;
                }
            }
        }
    }

    fn parse_defaults(&mut self, section: &HAProxySection) -> HAProxyDefaults {
        let mut defaults = HAProxyDefaults::default();
        self.stats.directives_processed += section.lines.len();

        for line in &section.lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            match parts[0] {
                "mode" => {
                    defaults.mode = parts.get(1).map(|s| s.to_string());
                }
                "timeout" => {
                    if parts.len() >= 3 {
                        match parts[1] {
                            "connect" => defaults.timeout_connect = parse_haproxy_time(parts[2]),
                            "client" => defaults.timeout_client = parse_haproxy_time(parts[2]),
                            "server" => defaults.timeout_server = parse_haproxy_time(parts[2]),
                            "http-request" => {
                                defaults.timeout_http_request = parse_haproxy_time(parts[2])
                            }
                            "http-keep-alive" => {
                                defaults.timeout_http_keep_alive = parse_haproxy_time(parts[2])
                            }
                            _ => {}
                        }
                    }
                }
                "balance" => {
                    defaults.balance = parts.get(1).map(|s| s.to_string());
                }
                "option" => {
                    if let Some(opt) = parts.get(1) {
                        defaults.options.push(opt.to_string());
                    }
                }
                "retries" => {
                    defaults.retries = parts.get(1).and_then(|s| s.parse().ok());
                }
                "maxconn" => {
                    defaults.maxconn = parts.get(1).and_then(|s| s.parse().ok());
                }
                _ => {}
            }
        }

        defaults
    }

    fn parse_frontend(
        &mut self,
        section: &HAProxySection,
        defaults: &HAProxyDefaults,
    ) -> HAProxyFrontend {
        let mut frontend = HAProxyFrontend {
            binds: Vec::new(),
            default_backend: None,
            acls: Vec::new(),
            use_backends: Vec::new(),
            mode: defaults.mode.clone(),
            options: defaults.options.clone(),
            timeout_client: defaults.timeout_client,
            maxconn: defaults.maxconn,
        };

        self.stats.directives_processed += section.lines.len();

        for line in &section.lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            match parts[0] {
                "bind" => {
                    if let Some(addr) = parts.get(1) {
                        let bind = HAProxyBind {
                            address: addr.to_string(),
                            ssl: line.contains(" ssl"),
                            ssl_cert: extract_param(line, "crt"),
                            alpn: extract_param(line, "alpn"),
                        };
                        frontend.binds.push(bind);
                    }
                }
                "default_backend" => {
                    frontend.default_backend = parts.get(1).map(|s| s.to_string());
                }
                "acl" => {
                    if parts.len() >= 3 {
                        let acl = HAProxyAcl {
                            name: parts[1].to_string(),
                            condition: parts[2..].join(" "),
                        };
                        frontend.acls.push(acl);
                    }
                }
                "use_backend" => {
                    if parts.len() >= 2 {
                        let backend_name = parts[1].to_string();
                        let condition = if line.contains(" if ") {
                            line.split(" if ").nth(1).map(|s| s.trim().to_string())
                        } else {
                            None
                        };
                        frontend.use_backends.push((backend_name, condition));
                    }
                }
                "mode" => {
                    frontend.mode = parts.get(1).map(|s| s.to_string());
                }
                "option" => {
                    if let Some(opt) = parts.get(1) {
                        frontend.options.push(opt.to_string());
                    }
                }
                "timeout" => {
                    if parts.len() >= 3 && parts[1] == "client" {
                        frontend.timeout_client = parse_haproxy_time(parts[2]);
                    }
                }
                "maxconn" => {
                    frontend.maxconn = parts.get(1).and_then(|s| s.parse().ok());
                }
                "http-request" | "http-response" => {
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Info,
                        format!("{} rule - use Prism middleware", parts[0]),
                    ));
                }
                _ => {
                    self.stats.directives_skipped += 1;
                }
            }
        }

        frontend
    }

    fn parse_backend(
        &mut self,
        section: &HAProxySection,
        defaults: &HAProxyDefaults,
    ) -> HAProxyBackend {
        let mut backend = HAProxyBackend {
            servers: Vec::new(),
            balance: defaults.balance.clone(),
            mode: defaults.mode.clone(),
            options: defaults.options.clone(),
            timeout_connect: defaults.timeout_connect,
            timeout_server: defaults.timeout_server,
            retries: defaults.retries,
            health_check: None,
        };

        self.stats.directives_processed += section.lines.len();

        for line in &section.lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            match parts[0] {
                "server" => {
                    if parts.len() >= 3 {
                        let server = HAProxyServer {
                            name: parts[1].to_string(),
                            address: parts[2].to_string(),
                            weight: extract_int_param(line, "weight"),
                            check: line.contains(" check"),
                            backup: line.contains(" backup"),
                            maxconn: extract_int_param(line, "maxconn"),
                            ssl: line.contains(" ssl"),
                        };
                        backend.servers.push(server);
                    }
                }
                "balance" => {
                    backend.balance = parts.get(1).map(|s| s.to_string());
                }
                "mode" => {
                    backend.mode = parts.get(1).map(|s| s.to_string());
                }
                "option" => {
                    if let Some(opt) = parts.get(1) {
                        backend.options.push(opt.to_string());

                        if opt == &"httpchk" {
                            // Extract health check path
                            let path = parts
                                .get(3)
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "/".to_string());
                            backend.health_check = Some(HAProxyHealthCheck {
                                path: Some(path),
                                interval: None,
                                fall: None,
                                rise: None,
                            });
                        }
                    }
                }
                "timeout" => {
                    if parts.len() >= 3 {
                        match parts[1] {
                            "connect" => backend.timeout_connect = parse_haproxy_time(parts[2]),
                            "server" => backend.timeout_server = parse_haproxy_time(parts[2]),
                            _ => {}
                        }
                    }
                }
                "retries" => {
                    backend.retries = parts.get(1).and_then(|s| s.parse().ok());
                }
                "http-check" => {
                    if parts.get(1) == Some(&"expect") {
                        self.warnings.push(MigrationWarning::new(
                            WarningLevel::Info,
                            "http-check expect - configure expected_status in health check",
                        ));
                    }
                }
                _ => {
                    self.stats.directives_skipped += 1;
                }
            }
        }

        backend
    }

    fn parse_listen(
        &mut self,
        section: &HAProxySection,
        defaults: &HAProxyDefaults,
    ) -> HAProxyListen {
        // Listen section is a combined frontend+backend
        let mut listen = HAProxyListen {
            binds: Vec::new(),
            servers: Vec::new(),
            balance: defaults.balance.clone(),
            mode: defaults.mode.clone(),
            options: defaults.options.clone(),
            timeout_connect: defaults.timeout_connect,
            timeout_client: defaults.timeout_client,
            timeout_server: defaults.timeout_server,
            health_check: None,
        };

        self.stats.directives_processed += section.lines.len();

        for line in &section.lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            match parts[0] {
                "bind" => {
                    if let Some(addr) = parts.get(1) {
                        let bind = HAProxyBind {
                            address: addr.to_string(),
                            ssl: line.contains(" ssl"),
                            ssl_cert: extract_param(line, "crt"),
                            alpn: extract_param(line, "alpn"),
                        };
                        listen.binds.push(bind);
                    }
                }
                "server" => {
                    if parts.len() >= 3 {
                        let server = HAProxyServer {
                            name: parts[1].to_string(),
                            address: parts[2].to_string(),
                            weight: extract_int_param(line, "weight"),
                            check: line.contains(" check"),
                            backup: line.contains(" backup"),
                            maxconn: extract_int_param(line, "maxconn"),
                            ssl: line.contains(" ssl"),
                        };
                        listen.servers.push(server);
                    }
                }
                "balance" => {
                    listen.balance = parts.get(1).map(|s| s.to_string());
                }
                "mode" => {
                    listen.mode = parts.get(1).map(|s| s.to_string());
                }
                "option" => {
                    if let Some(opt) = parts.get(1) {
                        listen.options.push(opt.to_string());

                        if opt == &"httpchk" {
                            let path = parts
                                .get(3)
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "/".to_string());
                            listen.health_check = Some(HAProxyHealthCheck {
                                path: Some(path),
                                interval: None,
                                fall: None,
                                rise: None,
                            });
                        }
                    }
                }
                "timeout" => {
                    if parts.len() >= 3 {
                        match parts[1] {
                            "connect" => listen.timeout_connect = parse_haproxy_time(parts[2]),
                            "client" => listen.timeout_client = parse_haproxy_time(parts[2]),
                            "server" => listen.timeout_server = parse_haproxy_time(parts[2]),
                            _ => {}
                        }
                    }
                }
                _ => {
                    self.stats.directives_skipped += 1;
                }
            }
        }

        listen
    }

    fn convert_frontend(
        &mut self,
        name: &str,
        frontend: &HAProxyFrontend,
        _backends: &HashMap<String, HAProxyBackend>,
        config: &mut Config,
    ) {
        // Create listeners for each bind
        for bind in &frontend.binds {
            let address = normalize_haproxy_address(&bind.address);

            let protocol = if frontend.mode.as_deref() == Some("tcp") {
                Protocol::Http // Prism uses Http for TCP mode too at listener level
            } else if bind.ssl {
                Protocol::Https
            } else {
                Protocol::Http
            };

            let tls = if bind.ssl {
                let cert_path = bind
                    .ssl_cert
                    .clone()
                    .unwrap_or_else(|| "cert.pem".to_string());

                self.warnings.push(
                    MigrationWarning::new(
                        WarningLevel::Warning,
                        format!("Frontend '{}' has SSL - verify certificate paths", name),
                    )
                    .with_suggestion("Update cert and key paths in the generated config"),
                );

                Some(TlsConfig {
                    cert: cert_path.into(),
                    key: "key.pem".into(),
                    alpn: bind
                        .alpn
                        .as_ref()
                        .map(|a| a.split(',').map(|s| s.trim().to_string()).collect())
                        .unwrap_or_else(|| vec!["h2".to_string(), "http/1.1".to_string()]),
                    min_version: "1.2".to_string(),
                    client_auth: crate::config::ClientAuthMode::None,
                    client_ca: None,
                })
            } else {
                None
            };

            let listener = ListenerConfig {
                address,
                protocol,
                tls,
                max_connections: frontend.maxconn.unwrap_or(10000) as usize,
            };

            config.listeners.push(listener);
            self.stats.listeners += 1;
        }

        // Create routes from use_backend rules
        for (backend_name, condition) in &frontend.use_backends {
            let match_config = if let Some(cond) = condition {
                self.convert_acl_condition(cond, &frontend.acls)
            } else {
                MatchConfig {
                    host: None,
                    path: None,
                    path_prefix: Some("/".to_string()),
                    path_regex: None,
                    headers: HashMap::new(),
                    methods: Vec::new(),
                }
            };

            let route = RouteConfig {
                match_config,
                upstream: Some(backend_name.clone()),
                handler: None,
                middlewares: Vec::new(),
                rewrite: None,
                priority: 0,
            };

            config.routes.push(route);
            self.stats.routes += 1;
        }

        // Create default route if default_backend is set
        if let Some(default_backend) = &frontend.default_backend {
            let route = RouteConfig {
                match_config: MatchConfig {
                    host: None,
                    path: None,
                    path_prefix: Some("/".to_string()),
                    path_regex: None,
                    headers: HashMap::new(),
                    methods: Vec::new(),
                },
                upstream: Some(default_backend.clone()),
                handler: None,
                middlewares: Vec::new(),
                rewrite: None,
                priority: 1000, // Low priority (higher number) for catch-all
            };

            config.routes.push(route);
            self.stats.routes += 1;
        }

        // Note about options
        for opt in &frontend.options {
            match opt.as_str() {
                "httplog" => {
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Info,
                        "httplog - use Prism access logging",
                    ));
                }
                "forwardfor" => {
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Info,
                        "forwardfor - X-Forwarded-For is handled automatically",
                    ));
                }
                "http-server-close" => {
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Info,
                        "http-server-close - connection handling is automatic",
                    ));
                }
                _ => {}
            }
        }
    }

    fn convert_backend(&mut self, name: &str, backend: &HAProxyBackend, config: &mut Config) {
        // Convert servers
        let servers: Vec<ServerConfig> = backend
            .servers
            .iter()
            .map(|server| {
                // Note about upstream SSL
                if server.ssl {
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Info,
                        format!(
                            "Server '{}' in backend '{}' uses SSL - configure upstream TLS",
                            server.name, name
                        ),
                    ));
                }

                // Note about backup servers
                if server.backup {
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Info,
                        format!(
                            "Server '{}' is a backup server - Prism doesn't have backup server support yet",
                            server.name
                        ),
                    ));
                }

                ServerConfig {
                    address: server.address.clone(),
                    weight: server.weight.unwrap_or(1) as u32,
                    enabled: true,
                }
            })
            .collect();

        // Build health check config
        let health_check = if backend.health_check.is_some()
            || backend.servers.iter().any(|s| s.check)
        {
            let hc = backend.health_check.as_ref();
            Some(HealthCheckConfig {
                check_type: crate::config::HealthCheckType::Http,
                path: hc
                    .and_then(|h| h.path.clone())
                    .unwrap_or_else(|| "/health".to_string()),
                expected_status: 200,
                interval: hc
                    .and_then(|h| h.interval)
                    .unwrap_or(std::time::Duration::from_secs(10)),
                timeout: backend
                    .timeout_connect
                    .unwrap_or(std::time::Duration::from_secs(5)),
                unhealthy_threshold: hc.and_then(|h| h.fall).unwrap_or(3),
                healthy_threshold: hc.and_then(|h| h.rise).unwrap_or(2),
            })
        } else {
            None
        };

        // Build retry config
        let retry = backend.retries.map(|r| crate::config::RetryConfig {
            max_retries: r,
            retry_on: vec![502, 503, 504],
            initial_delay: std::time::Duration::from_millis(100),
            max_delay: std::time::Duration::from_secs(5),
        });

        let upstream = UpstreamConfig {
            servers,
            health_check,
            load_balancing: self.convert_balance_algorithm(backend.balance.as_deref()),
            pool: PoolConfig::default(),
            connect_timeout: backend
                .timeout_connect
                .unwrap_or(std::time::Duration::from_secs(5)),
            request_timeout: backend
                .timeout_server
                .unwrap_or(std::time::Duration::from_secs(30)),
            circuit_breaker: None,
            retry,
        };

        config.upstreams.insert(name.to_string(), upstream);
        self.stats.upstreams += 1;
    }

    fn convert_listen(&mut self, name: &str, listen: &HAProxyListen, config: &mut Config) {
        // Create listeners
        for bind in &listen.binds {
            let address = normalize_haproxy_address(&bind.address);

            let protocol = if listen.mode.as_deref() == Some("tcp") {
                Protocol::Http
            } else if bind.ssl {
                Protocol::Https
            } else {
                Protocol::Http
            };

            let tls = if bind.ssl {
                Some(TlsConfig {
                    cert: bind
                        .ssl_cert
                        .clone()
                        .unwrap_or_else(|| "cert.pem".to_string())
                        .into(),
                    key: "key.pem".into(),
                    alpn: bind
                        .alpn
                        .as_ref()
                        .map(|a| a.split(',').map(|s| s.trim().to_string()).collect())
                        .unwrap_or_else(|| vec!["h2".to_string(), "http/1.1".to_string()]),
                    min_version: "1.2".to_string(),
                    client_auth: crate::config::ClientAuthMode::None,
                    client_ca: None,
                })
            } else {
                None
            };

            let listener = ListenerConfig {
                address,
                protocol,
                tls,
                max_connections: 10000,
            };

            config.listeners.push(listener);
            self.stats.listeners += 1;
        }

        // Create upstream from servers
        let upstream_name = format!("{}_backend", name);

        let servers: Vec<ServerConfig> = listen
            .servers
            .iter()
            .map(|s| ServerConfig {
                address: s.address.clone(),
                weight: s.weight.unwrap_or(1) as u32,
                enabled: true,
            })
            .collect();

        // Build health check config
        let health_check =
            if listen.health_check.is_some() || listen.servers.iter().any(|s| s.check) {
                let hc = listen.health_check.as_ref();
                Some(HealthCheckConfig {
                    check_type: crate::config::HealthCheckType::Http,
                    path: hc
                        .and_then(|h| h.path.clone())
                        .unwrap_or_else(|| "/health".to_string()),
                    expected_status: 200,
                    interval: hc
                        .and_then(|h| h.interval)
                        .unwrap_or(std::time::Duration::from_secs(10)),
                    timeout: listen
                        .timeout_connect
                        .unwrap_or(std::time::Duration::from_secs(5)),
                    unhealthy_threshold: hc.and_then(|h| h.fall).unwrap_or(3),
                    healthy_threshold: hc.and_then(|h| h.rise).unwrap_or(2),
                })
            } else {
                None
            };

        let upstream = UpstreamConfig {
            servers,
            health_check,
            load_balancing: self.convert_balance_algorithm(listen.balance.as_deref()),
            pool: PoolConfig::default(),
            connect_timeout: listen
                .timeout_connect
                .unwrap_or(std::time::Duration::from_secs(5)),
            request_timeout: listen
                .timeout_server
                .unwrap_or(std::time::Duration::from_secs(30)),
            circuit_breaker: None,
            retry: None,
        };

        config.upstreams.insert(upstream_name.clone(), upstream);
        self.stats.upstreams += 1;

        // Create route
        let route = RouteConfig {
            match_config: MatchConfig {
                host: None,
                path: None,
                path_prefix: Some("/".to_string()),
                path_regex: None,
                headers: HashMap::new(),
                methods: Vec::new(),
            },
            upstream: Some(upstream_name),
            handler: None,
            middlewares: Vec::new(),
            rewrite: None,
            priority: 0,
        };

        config.routes.push(route);
        self.stats.routes += 1;
    }

    fn convert_acl_condition(&mut self, condition: &str, acls: &[HAProxyAcl]) -> MatchConfig {
        let mut match_config = MatchConfig {
            host: None,
            path: None,
            path_prefix: None,
            path_regex: None,
            headers: HashMap::new(),
            methods: Vec::new(),
        };

        // Find referenced ACLs
        for word in condition.split_whitespace() {
            // Skip logical operators
            if word == "or" || word == "||" || word == "!" {
                continue;
            }

            // Find ACL by name
            if let Some(acl) = acls.iter().find(|a| a.name == word) {
                self.parse_acl_to_matcher(&acl.condition, &mut match_config);
            }
        }

        // If no ACL matched, try parsing the condition directly
        if match_config.path_prefix.is_none()
            && match_config.path.is_none()
            && match_config.host.is_none()
            && match_config.methods.is_empty()
        {
            self.parse_acl_to_matcher(condition, &mut match_config);
        }

        // Ensure we have at least a path prefix
        if match_config.path_prefix.is_none()
            && match_config.path.is_none()
            && match_config.path_regex.is_none()
        {
            match_config.path_prefix = Some("/".to_string());
        }

        match_config
    }

    fn parse_acl_to_matcher(&mut self, condition: &str, match_config: &mut MatchConfig) {
        let parts: Vec<&str> = condition.split_whitespace().collect();
        if parts.is_empty() {
            return;
        }

        match parts[0] {
            "path" | "path_beg" => {
                if let Some(path) = parts.get(1) {
                    match_config.path_prefix = Some(path.to_string());
                }
            }
            "path_end" => {
                if let Some(suffix) = parts.get(1) {
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Info,
                        format!(
                            "path_end '{}' - use path_regex for suffix matching",
                            suffix
                        ),
                    ));
                }
            }
            "path_reg" => {
                if let Some(regex) = parts.get(1) {
                    match_config.path_regex = Some(regex.to_string());
                }
            }
            "hdr" | "hdr_beg" | "hdr_end" | "hdr_reg" => {
                // Header matching
                if let Some(header_name) =
                    parts.get(1).map(|s| s.trim_matches(|c| c == '(' || c == ')'))
                {
                    if header_name.to_lowercase() == "host" {
                        if let Some(value) = parts.get(2) {
                            match_config.host = Some(value.to_string());
                        }
                    } else {
                        self.warnings.push(MigrationWarning::new(
                            WarningLevel::Info,
                            format!(
                                "Header ACL '{}' - configure in route headers",
                                header_name
                            ),
                        ));
                    }
                }
            }
            "method" => {
                let methods: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
                if !methods.is_empty() {
                    match_config.methods = methods;
                }
            }
            "src" => {
                self.warnings.push(MigrationWarning::new(
                    WarningLevel::Info,
                    "Source IP ACL - use IP allowlist middleware",
                ));
            }
            _ => {
                self.warnings.push(MigrationWarning::new(
                    WarningLevel::Warning,
                    format!("Unsupported ACL type: {}", parts[0]),
                ));
            }
        }
    }

    fn convert_balance_algorithm(&self, balance: Option<&str>) -> LoadBalancingAlgorithm {
        match balance {
            Some("roundrobin") => LoadBalancingAlgorithm::RoundRobin,
            Some("leastconn") => LoadBalancingAlgorithm::LeastConnections,
            Some("source") => LoadBalancingAlgorithm::IpHash,
            Some("uri") => LoadBalancingAlgorithm::ConsistentHash,
            Some("random") => LoadBalancingAlgorithm::Random,
            Some("first") => LoadBalancingAlgorithm::RoundRobin, // No direct equivalent
            _ => LoadBalancingAlgorithm::RoundRobin,
        }
    }
}

impl Default for HAProxyParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse HAProxy time format (e.g., "30s", "1m", "500ms", "30000")
fn parse_haproxy_time(s: &str) -> Option<std::time::Duration> {
    let s = s.trim();

    if let Some(rest) = s.strip_suffix("ms") {
        rest.parse::<u64>()
            .ok()
            .map(std::time::Duration::from_millis)
    } else if let Some(rest) = s.strip_suffix('s') {
        rest.parse::<u64>().ok().map(std::time::Duration::from_secs)
    } else if let Some(rest) = s.strip_suffix('m') {
        rest.parse::<u64>()
            .ok()
            .map(|mins| std::time::Duration::from_secs(mins * 60))
    } else if let Some(rest) = s.strip_suffix('h') {
        rest.parse::<u64>()
            .ok()
            .map(|hours| std::time::Duration::from_secs(hours * 3600))
    } else if let Some(rest) = s.strip_suffix('d') {
        rest.parse::<u64>()
            .ok()
            .map(|days| std::time::Duration::from_secs(days * 86400))
    } else {
        // Default is milliseconds
        s.parse::<u64>()
            .ok()
            .map(std::time::Duration::from_millis)
    }
}

/// Normalize HAProxy bind address
fn normalize_haproxy_address(addr: &str) -> String {
    let addr = addr.trim();

    // Handle *:port or :port format
    if addr.starts_with('*') {
        return addr.replacen('*', "0.0.0.0", 1);
    }
    if addr.starts_with(':') {
        return format!("0.0.0.0{}", addr);
    }

    addr.to_string()
}

/// Extract parameter value from HAProxy line (e.g., "crt /path/to/cert")
fn extract_param(line: &str, param: &str) -> Option<String> {
    let pattern = format!(" {} ", param);
    if let Some(pos) = line.find(&pattern) {
        let rest = &line[pos + pattern.len()..];
        let end = rest.find(' ').unwrap_or(rest.len());
        Some(rest[..end].to_string())
    } else {
        None
    }
}

/// Extract integer parameter value
fn extract_int_param(line: &str, param: &str) -> Option<i32> {
    extract_param(line, param).and_then(|s| s.parse().ok())
}

// ============================================================================
// HAProxy Configuration Types
// ============================================================================

#[derive(Debug)]
struct HAProxySection {
    section_type: String,
    name: Option<String>,
    lines: Vec<String>,
}

#[derive(Debug, Default)]
struct HAProxyDefaults {
    mode: Option<String>,
    timeout_connect: Option<std::time::Duration>,
    timeout_client: Option<std::time::Duration>,
    timeout_server: Option<std::time::Duration>,
    #[allow(dead_code)]
    timeout_http_request: Option<std::time::Duration>,
    #[allow(dead_code)]
    timeout_http_keep_alive: Option<std::time::Duration>,
    balance: Option<String>,
    options: Vec<String>,
    retries: Option<u32>,
    maxconn: Option<u32>,
}

#[derive(Debug)]
struct HAProxyFrontend {
    binds: Vec<HAProxyBind>,
    default_backend: Option<String>,
    acls: Vec<HAProxyAcl>,
    use_backends: Vec<(String, Option<String>)>,
    mode: Option<String>,
    options: Vec<String>,
    timeout_client: Option<std::time::Duration>,
    maxconn: Option<u32>,
}

#[derive(Debug)]
struct HAProxyBind {
    address: String,
    ssl: bool,
    ssl_cert: Option<String>,
    alpn: Option<String>,
}

#[derive(Debug)]
struct HAProxyAcl {
    name: String,
    condition: String,
}

#[derive(Debug)]
struct HAProxyBackend {
    servers: Vec<HAProxyServer>,
    balance: Option<String>,
    #[allow(dead_code)]
    mode: Option<String>,
    options: Vec<String>,
    timeout_connect: Option<std::time::Duration>,
    timeout_server: Option<std::time::Duration>,
    retries: Option<u32>,
    health_check: Option<HAProxyHealthCheck>,
}

#[derive(Debug)]
struct HAProxyServer {
    name: String,
    address: String,
    weight: Option<i32>,
    check: bool,
    backup: bool,
    #[allow(dead_code)]
    maxconn: Option<i32>,
    ssl: bool,
}

#[derive(Debug)]
struct HAProxyHealthCheck {
    path: Option<String>,
    interval: Option<std::time::Duration>,
    fall: Option<u32>,
    rise: Option<u32>,
}

#[derive(Debug)]
struct HAProxyListen {
    binds: Vec<HAProxyBind>,
    servers: Vec<HAProxyServer>,
    balance: Option<String>,
    mode: Option<String>,
    options: Vec<String>,
    timeout_connect: Option<std::time::Duration>,
    #[allow(dead_code)]
    timeout_client: Option<std::time::Duration>,
    timeout_server: Option<std::time::Duration>,
    health_check: Option<HAProxyHealthCheck>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_haproxy_time() {
        assert_eq!(
            parse_haproxy_time("30s"),
            Some(std::time::Duration::from_secs(30))
        );
        assert_eq!(
            parse_haproxy_time("500ms"),
            Some(std::time::Duration::from_millis(500))
        );
        assert_eq!(
            parse_haproxy_time("1m"),
            Some(std::time::Duration::from_secs(60))
        );
        assert_eq!(
            parse_haproxy_time("30000"),
            Some(std::time::Duration::from_millis(30000))
        );
    }

    #[test]
    fn test_normalize_address() {
        assert_eq!(normalize_haproxy_address("*:8080"), "0.0.0.0:8080");
        assert_eq!(normalize_haproxy_address(":8080"), "0.0.0.0:8080");
        assert_eq!(
            normalize_haproxy_address("127.0.0.1:8080"),
            "127.0.0.1:8080"
        );
    }

    #[test]
    fn test_basic_haproxy_config() {
        let config = r#"
global
    maxconn 4096

defaults
    mode http
    timeout connect 5s
    timeout client 50s
    timeout server 50s

frontend http_front
    bind *:80
    default_backend http_back

backend http_back
    balance roundrobin
    server server1 127.0.0.1:3000 check
    server server2 127.0.0.1:3001 check
"#;

        let parser = HAProxyParser::new();
        let result = parser.parse(config).unwrap();

        assert_eq!(result.stats.listeners, 1);
        assert_eq!(result.stats.upstreams, 1);
        assert_eq!(result.stats.routes, 1);
    }

    #[test]
    fn test_listen_section() {
        let config = r#"
listen stats
    bind *:8404
    mode http
    stats enable
    stats uri /stats
"#;

        let parser = HAProxyParser::new();
        let result = parser.parse(config).unwrap();

        assert_eq!(result.stats.listeners, 1);
    }
}
