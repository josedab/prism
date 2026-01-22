//! Nginx configuration migration
//!
//! Parses nginx.conf files and converts them to Prism configuration.

use crate::config::*;
use crate::error::{PrismError, Result};
use crate::migrate::{MigrationResult, MigrationStats, MigrationWarning, WarningLevel};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

/// Migrate Nginx configuration to Prism
pub fn migrate(input: &Path) -> Result<MigrationResult> {
    let content = fs::read_to_string(input)
        .map_err(|e| PrismError::Config(format!("Failed to read nginx config: {}", e)))?;

    let parser = NginxParser::new(&content);
    parser.parse()
}

/// Nginx configuration parser
struct NginxParser<'a> {
    content: &'a str,
    position: usize,
    line: usize,
    warnings: Vec<MigrationWarning>,
    stats: MigrationStats,
}

impl<'a> NginxParser<'a> {
    fn new(content: &'a str) -> Self {
        Self {
            content,
            position: 0,
            line: 1,
            warnings: Vec::new(),
            stats: MigrationStats::default(),
        }
    }

    fn parse(mut self) -> Result<MigrationResult> {
        let mut config = Config {
            listeners: Vec::new(),
            upstreams: HashMap::new(),
            routes: Vec::new(),
            observability: ObservabilityConfig::default(),
            admin: None,
            global: GlobalConfig::default(),
            spiffe: None,
            io_uring: None,
            xds: None,
            kubernetes: None,
            edge: None,
            plugins: None,
            http3: None,
            l4: None,
            anomaly_detection: None,
            ebpf: None,
            graphql: None,
            llm_gateway: None,
            gitops: None,
        };

        // Parse the content
        let directives = self.parse_directives()?;

        // Process directives
        for directive in directives {
            self.process_directive(&directive, &mut config)?;
        }

        Ok(MigrationResult {
            config,
            warnings: self.warnings,
            stats: self.stats,
        })
    }

    fn parse_directives(&mut self) -> Result<Vec<NginxDirective>> {
        let mut directives = Vec::new();

        while self.position < self.content.len() {
            self.skip_whitespace_and_comments();

            if self.position >= self.content.len() {
                break;
            }

            if let Some(directive) = self.parse_directive()? {
                directives.push(directive);
            }
        }

        Ok(directives)
    }

    fn parse_directive(&mut self) -> Result<Option<NginxDirective>> {
        self.skip_whitespace_and_comments();

        if self.position >= self.content.len() {
            return Ok(None);
        }

        // Check for closing brace
        if self.current_char() == Some('}') {
            return Ok(None);
        }

        // Parse directive name
        let name = self.parse_word()?;
        if name.is_empty() {
            return Ok(None);
        }

        self.skip_whitespace();

        // Parse arguments
        let mut args = Vec::new();
        while self.position < self.content.len() {
            let c = self.current_char();

            if c == Some(';') {
                self.position += 1;
                break;
            }

            if c == Some('{') {
                self.position += 1;
                // Parse block
                let block = self.parse_block()?;
                return Ok(Some(NginxDirective {
                    name,
                    args,
                    block: Some(block),
                    line: self.line,
                }));
            }

            if c == Some('}') {
                break;
            }

            let arg = self.parse_argument()?;
            if !arg.is_empty() {
                args.push(arg);
            }

            self.skip_whitespace();
        }

        Ok(Some(NginxDirective {
            name,
            args,
            block: None,
            line: self.line,
        }))
    }

    fn parse_block(&mut self) -> Result<Vec<NginxDirective>> {
        let mut directives = Vec::new();

        loop {
            self.skip_whitespace_and_comments();

            if self.position >= self.content.len() {
                break;
            }

            if self.current_char() == Some('}') {
                self.position += 1;
                break;
            }

            if let Some(directive) = self.parse_directive()? {
                directives.push(directive);
            }
        }

        Ok(directives)
    }

    fn parse_word(&mut self) -> Result<String> {
        let mut word = String::new();

        while self.position < self.content.len() {
            let c = self.current_char().unwrap();
            if c.is_alphanumeric() || c == '_' || c == '-' {
                word.push(c);
                self.position += 1;
            } else {
                break;
            }
        }

        Ok(word)
    }

    fn parse_argument(&mut self) -> Result<String> {
        self.skip_whitespace();

        if self.position >= self.content.len() {
            return Ok(String::new());
        }

        let c = self.current_char().unwrap();

        // Handle quoted strings
        if c == '"' || c == '\'' {
            return self.parse_quoted_string(c);
        }

        // Handle regular arguments
        let mut arg = String::new();
        while self.position < self.content.len() {
            let c = self.current_char().unwrap();
            if c.is_whitespace() || c == ';' || c == '{' || c == '}' {
                break;
            }
            arg.push(c);
            self.position += 1;
        }

        Ok(arg)
    }

    fn parse_quoted_string(&mut self, quote: char) -> Result<String> {
        self.position += 1; // Skip opening quote
        let mut s = String::new();

        while self.position < self.content.len() {
            let c = self.current_char().unwrap();

            if c == quote {
                self.position += 1;
                break;
            }

            if c == '\\' && self.position + 1 < self.content.len() {
                self.position += 1;
                let next = self.current_char().unwrap();
                s.push(next);
                self.position += 1;
                continue;
            }

            if c == '\n' {
                self.line += 1;
            }

            s.push(c);
            self.position += 1;
        }

        Ok(s)
    }

    fn skip_whitespace(&mut self) {
        while self.position < self.content.len() {
            let c = self.current_char().unwrap();
            if c == '\n' {
                self.line += 1;
                self.position += 1;
            } else if c.is_whitespace() {
                self.position += 1;
            } else {
                break;
            }
        }
    }

    fn skip_whitespace_and_comments(&mut self) {
        while self.position < self.content.len() {
            self.skip_whitespace();

            if self.current_char() == Some('#') {
                // Skip comment
                while self.position < self.content.len() && self.current_char() != Some('\n') {
                    self.position += 1;
                }
            } else {
                break;
            }
        }
    }

    fn current_char(&self) -> Option<char> {
        self.content[self.position..].chars().next()
    }

    fn process_directive(&mut self, directive: &NginxDirective, config: &mut Config) -> Result<()> {
        self.stats.directives_processed += 1;

        match directive.name.as_str() {
            "http" => {
                if let Some(block) = &directive.block {
                    for d in block {
                        self.process_http_directive(d, config)?;
                    }
                }
            }
            "events" => {
                // Events block - mostly not applicable
                self.warnings.push(MigrationWarning::new(
                    WarningLevel::Info,
                    "events block directives ignored - Prism uses Tokio's event loop",
                ).with_location(format!("line {}", directive.line)));
                self.stats.directives_skipped += 1;
            }
            "worker_processes" => {
                if let Some(arg) = directive.args.first() {
                    if arg != "auto" {
                        if let Ok(n) = arg.parse::<usize>() {
                            config.global.worker_threads = Some(n);
                        }
                    }
                }
            }
            "worker_connections" => {
                self.warnings.push(MigrationWarning::new(
                    WarningLevel::Info,
                    "worker_connections mapped to listener max_connections",
                ));
            }
            _ => {
                self.stats.directives_skipped += 1;
                self.warnings.push(MigrationWarning::new(
                    WarningLevel::Info,
                    format!("Top-level directive '{}' not supported", directive.name),
                ).with_location(format!("line {}", directive.line)));
            }
        }

        Ok(())
    }

    fn process_http_directive(&mut self, directive: &NginxDirective, config: &mut Config) -> Result<()> {
        self.stats.directives_processed += 1;

        match directive.name.as_str() {
            "server" => {
                if let Some(block) = &directive.block {
                    self.process_server_block(block, config)?;
                }
            }
            "upstream" => {
                if let Some(name) = directive.args.first() {
                    if let Some(block) = &directive.block {
                        self.process_upstream_block(name, block, config)?;
                    }
                }
            }
            "gzip" => {
                if directive.args.first().map(|s| s.as_str()) == Some("on") {
                    // Will be handled per-route
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Info,
                        "Global gzip enabled - add compression middleware to routes",
                    ));
                }
            }
            "client_max_body_size" => {
                if let Some(size) = directive.args.first() {
                    if let Some(bytes) = parse_size(size) {
                        config.global.max_body_size = bytes;
                    }
                }
            }
            "keepalive_timeout" => {
                // Mapped to pool idle_timeout in upstreams
                self.warnings.push(MigrationWarning::new(
                    WarningLevel::Info,
                    "keepalive_timeout mapped to upstream pool idle_timeout",
                ));
            }
            "access_log" | "error_log" => {
                // Logging is handled differently in Prism
                self.warnings.push(MigrationWarning::new(
                    WarningLevel::Info,
                    format!("{} configuration differs - see observability.access_log", directive.name),
                ));
            }
            "include" => {
                self.warnings.push(MigrationWarning::new(
                    WarningLevel::Warning,
                    format!("include directive found: {} - please merge manually",
                        directive.args.first().unwrap_or(&String::new())),
                ).with_location(format!("line {}", directive.line)));
            }
            _ => {
                self.stats.directives_skipped += 1;
            }
        }

        Ok(())
    }

    fn process_server_block(&mut self, block: &[NginxDirective], config: &mut Config) -> Result<()> {
        let mut listen_address = "0.0.0.0:80".to_string();
        let mut server_name: Option<String> = None;
        let mut is_ssl = false;
        let mut ssl_cert: Option<String> = None;
        let mut ssl_key: Option<String> = None;
        let mut locations: Vec<(String, Vec<NginxDirective>)> = Vec::new();
        let mut default_proxy_pass: Option<String> = None;

        for directive in block {
            self.stats.directives_processed += 1;

            match directive.name.as_str() {
                "listen" => {
                    if let Some(addr) = directive.args.first() {
                        listen_address = normalize_address(addr);
                        if directive.args.iter().any(|a| a == "ssl") {
                            is_ssl = true;
                        }
                        if directive.args.iter().any(|a| a == "http2") {
                            // HTTP/2 is enabled by default in Prism
                        }
                    }
                }
                "server_name" => {
                    server_name = directive.args.first().cloned();
                }
                "ssl_certificate" => {
                    ssl_cert = directive.args.first().cloned();
                    is_ssl = true;
                }
                "ssl_certificate_key" => {
                    ssl_key = directive.args.first().cloned();
                }
                "ssl" => {
                    is_ssl = directive.args.first().map(|s| s.as_str()) == Some("on");
                }
                "location" => {
                    if let Some(path) = directive.args.first() {
                        if let Some(loc_block) = &directive.block {
                            locations.push((path.clone(), loc_block.clone()));
                        }
                    }
                }
                "proxy_pass" => {
                    default_proxy_pass = directive.args.first().cloned();
                }
                "return" => {
                    // Handle return directive
                    if directive.args.len() >= 2 {
                        let status: u16 = directive.args[0].parse().unwrap_or(302);
                        let url = directive.args.get(1).cloned();

                        config.routes.push(RouteConfig {
                            match_config: MatchConfig {
                                host: server_name.clone(),
                                path: None,
                                path_prefix: Some("/".to_string()),
                                path_regex: None,
                                headers: HashMap::new(),
                                methods: Vec::new(),
                            },
                            upstream: None,
                            handler: Some(HandlerConfig {
                                handler_type: HandlerType::Redirect,
                                status,
                                body: String::new(),
                                headers: HashMap::new(),
                                redirect_url: url,
                            }),
                            middlewares: Vec::new(),
                            rewrite: None,
                            priority: 10,
                        });
                        self.stats.routes += 1;
                    }
                }
                _ => {
                    self.stats.directives_skipped += 1;
                }
            }
        }

        // Create listener
        let protocol = if is_ssl { Protocol::Https } else { Protocol::Http };
        let tls_config = if is_ssl && ssl_cert.is_some() && ssl_key.is_some() {
            Some(TlsConfig {
                cert: ssl_cert.unwrap().into(),
                key: ssl_key.unwrap().into(),
                alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                min_version: "1.2".to_string(),
                client_auth: ClientAuthMode::None,
                client_ca: None,
            })
        } else if is_ssl {
            self.warnings.push(MigrationWarning::new(
                WarningLevel::Error,
                "SSL enabled but certificate/key paths missing",
            ));
            None
        } else {
            None
        };

        // Check if listener already exists
        let listener_exists = config.listeners.iter().any(|l| l.address == listen_address);
        if !listener_exists {
            config.listeners.push(ListenerConfig {
                address: listen_address.clone(),
                protocol,
                tls: tls_config,
                max_connections: 10000,
            });
            self.stats.listeners += 1;
        }

        // Check if we have locations or need to use default proxy_pass
        let has_locations = !locations.is_empty();

        // Process locations
        for (path, loc_directives) in &locations {
            self.process_location(path, loc_directives, server_name.clone(), config)?;
        }

        // Handle default proxy_pass if no locations
        if !has_locations && default_proxy_pass.is_some() {
            let upstream_name = extract_upstream_name(default_proxy_pass.as_ref().unwrap());
            config.routes.push(RouteConfig {
                match_config: MatchConfig {
                    host: server_name,
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
                priority: 100,
            });
            self.stats.routes += 1;
        }

        Ok(())
    }

    fn process_location(
        &mut self,
        path: &str,
        directives: &[NginxDirective],
        server_name: Option<String>,
        config: &mut Config,
    ) -> Result<()> {
        let mut proxy_pass: Option<String> = None;
        let mut rewrite: Option<RewriteConfig> = None;
        let mut middlewares = Vec::new();
        let mut is_exact = false;
        let mut is_regex = false;

        // Parse location modifier
        let actual_path = if path.starts_with("= ") {
            is_exact = true;
            path[2..].trim().to_string()
        } else if path.starts_with("~ ") || path.starts_with("~* ") {
            is_regex = true;
            path.trim_start_matches("~ ")
                .trim_start_matches("~* ")
                .to_string()
        } else if path.starts_with("^~ ") {
            path[3..].trim().to_string()
        } else {
            path.to_string()
        };

        for directive in directives {
            self.stats.directives_processed += 1;

            match directive.name.as_str() {
                "proxy_pass" => {
                    proxy_pass = directive.args.first().cloned();
                }
                "rewrite" => {
                    if directive.args.len() >= 2 {
                        rewrite = Some(RewriteConfig {
                            pattern: directive.args[0].clone(),
                            replacement: directive.args[1].clone(),
                        });
                    }
                }
                "proxy_set_header" => {
                    if directive.args.len() >= 2 {
                        // Convert to headers middleware
                        let mut headers_config = HeadersConfig {
                            request_add: HashMap::new(),
                            request_remove: Vec::new(),
                            response_add: HashMap::new(),
                            response_remove: Vec::new(),
                        };
                        headers_config.request_add.insert(
                            directive.args[0].clone(),
                            directive.args[1].clone(),
                        );
                        middlewares.push(MiddlewareConfig {
                            rate_limit: None,
                            auth: None,
                            headers: Some(headers_config),
                            compression: None,
                            timeout: None,
                            circuit_breaker: None,
                            retry: None,
                            cors: None,
                            chaos: None,
                            hedging: None,
                            adaptive_concurrency: None,
                        });
                    }
                }
                "proxy_connect_timeout" | "proxy_read_timeout" | "proxy_send_timeout" => {
                    if let Some(timeout_str) = directive.args.first() {
                        if let Some(secs) = parse_duration(timeout_str) {
                            middlewares.push(MiddlewareConfig {
                                rate_limit: None,
                                auth: None,
                                headers: None,
                                compression: None,
                                timeout: Some(TimeoutConfig {
                                    connect: Duration::from_secs(secs),
                                    read: Duration::from_secs(secs),
                                    write: Duration::from_secs(secs),
                                }),
                                circuit_breaker: None,
                                retry: None,
                                cors: None,
                                chaos: None,
                                hedging: None,
                                adaptive_concurrency: None,
                            });
                        }
                    }
                }
                "limit_req" => {
                    // Rate limiting
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Warning,
                        "limit_req requires manual configuration of rate_limit middleware",
                    ).with_location(format!("line {}", directive.line)));
                }
                "auth_basic" => {
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Warning,
                        "auth_basic should be migrated to auth middleware with type: basic",
                    ));
                }
                "add_header" => {
                    if directive.args.len() >= 2 {
                        let mut headers_config = HeadersConfig {
                            request_add: HashMap::new(),
                            request_remove: Vec::new(),
                            response_add: HashMap::new(),
                            response_remove: Vec::new(),
                        };
                        headers_config.response_add.insert(
                            directive.args[0].clone(),
                            directive.args[1].clone(),
                        );
                        middlewares.push(MiddlewareConfig {
                            rate_limit: None,
                            auth: None,
                            headers: Some(headers_config),
                            compression: None,
                            timeout: None,
                            circuit_breaker: None,
                            retry: None,
                            cors: None,
                            chaos: None,
                            hedging: None,
                            adaptive_concurrency: None,
                        });
                    }
                }
                "gzip" => {
                    if directive.args.first().map(|s| s.as_str()) == Some("on") {
                        middlewares.push(MiddlewareConfig {
                            rate_limit: None,
                            auth: None,
                            headers: None,
                            compression: Some(CompressionConfig {
                                gzip: true,
                                brotli: false,
                                min_size: 1024,
                            }),
                            timeout: None,
                            circuit_breaker: None,
                            retry: None,
                            cors: None,
                            chaos: None,
                            hedging: None,
                            adaptive_concurrency: None,
                        });
                    }
                }
                "return" => {
                    if let Some(status_str) = directive.args.first() {
                        let status: u16 = status_str.parse().unwrap_or(200);
                        let body = directive.args.get(1).cloned().unwrap_or_default();

                        config.routes.push(RouteConfig {
                            match_config: MatchConfig {
                                host: server_name.clone(),
                                path: if is_exact { Some(actual_path.clone()) } else { None },
                                path_prefix: if !is_exact && !is_regex { Some(actual_path.clone()) } else { None },
                                path_regex: if is_regex { Some(actual_path.clone()) } else { None },
                                headers: HashMap::new(),
                                methods: Vec::new(),
                            },
                            upstream: None,
                            handler: Some(HandlerConfig {
                                handler_type: HandlerType::Static,
                                status,
                                body,
                                headers: HashMap::new(),
                                redirect_url: None,
                            }),
                            middlewares,
                            rewrite,
                            priority: 0,
                        });
                        self.stats.routes += 1;
                        return Ok(());
                    }
                }
                _ => {
                    self.stats.directives_skipped += 1;
                }
            }
        }

        // Create route if we have a proxy_pass
        if let Some(proxy_target) = proxy_pass {
            let upstream_name = extract_upstream_name(&proxy_target);

            // Create upstream if it doesn't exist and proxy_pass is a URL
            if proxy_target.starts_with("http://") || proxy_target.starts_with("https://") {
                if !config.upstreams.contains_key(&upstream_name) {
                    let address = proxy_target
                        .trim_start_matches("http://")
                        .trim_start_matches("https://")
                        .trim_end_matches('/');

                    config.upstreams.insert(upstream_name.clone(), UpstreamConfig {
                        servers: vec![ServerConfig {
                            address: address.to_string(),
                            weight: 1,
                            enabled: true,
                        }],
                        health_check: None,
                        load_balancing: LoadBalancingAlgorithm::RoundRobin,
                        pool: PoolConfig::default(),
                        connect_timeout: Duration::from_secs(5),
                        request_timeout: Duration::from_secs(30),
                        circuit_breaker: None,
                        retry: None,
                    });
                    self.stats.upstreams += 1;
                }
            }

            config.routes.push(RouteConfig {
                match_config: MatchConfig {
                    host: server_name,
                    path: if is_exact { Some(actual_path.clone()) } else { None },
                    path_prefix: if !is_exact && !is_regex { Some(actual_path.clone()) } else { None },
                    path_regex: if is_regex { Some(actual_path.clone()) } else { None },
                    headers: HashMap::new(),
                    methods: Vec::new(),
                },
                upstream: Some(upstream_name),
                handler: None,
                middlewares,
                rewrite,
                priority: if is_exact { 0 } else if is_regex { 5 } else { 10 },
            });
            self.stats.routes += 1;
        }

        Ok(())
    }

    fn process_upstream_block(
        &mut self,
        name: &str,
        block: &[NginxDirective],
        config: &mut Config,
    ) -> Result<()> {
        let mut servers = Vec::new();
        let mut load_balancing = LoadBalancingAlgorithm::RoundRobin;

        for directive in block {
            self.stats.directives_processed += 1;

            match directive.name.as_str() {
                "server" => {
                    if let Some(address) = directive.args.first() {
                        let mut weight = 1;
                        let mut enabled = true;

                        for arg in &directive.args[1..] {
                            if arg.starts_with("weight=") {
                                weight = arg[7..].parse().unwrap_or(1);
                            } else if arg == "down" {
                                enabled = false;
                            } else if arg == "backup" {
                                // Backup servers are not directly supported
                                self.warnings.push(MigrationWarning::new(
                                    WarningLevel::Warning,
                                    format!("backup server {} - consider using circuit breaker", address),
                                ));
                            }
                        }

                        servers.push(ServerConfig {
                            address: address.clone(),
                            weight,
                            enabled,
                        });
                    }
                }
                "least_conn" => {
                    load_balancing = LoadBalancingAlgorithm::LeastConnections;
                }
                "ip_hash" => {
                    load_balancing = LoadBalancingAlgorithm::IpHash;
                }
                "hash" => {
                    if directive.args.iter().any(|a| a == "consistent") {
                        load_balancing = LoadBalancingAlgorithm::ConsistentHash;
                    }
                }
                "random" => {
                    load_balancing = LoadBalancingAlgorithm::Random;
                }
                "keepalive" => {
                    // Pool configuration
                    self.warnings.push(MigrationWarning::new(
                        WarningLevel::Info,
                        "keepalive mapped to pool configuration",
                    ));
                }
                _ => {
                    self.stats.directives_skipped += 1;
                }
            }
        }

        config.upstreams.insert(name.to_string(), UpstreamConfig {
            servers,
            health_check: Some(HealthCheckConfig::default()),
            load_balancing,
            pool: PoolConfig::default(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            circuit_breaker: None,
            retry: None,
        });
        self.stats.upstreams += 1;

        Ok(())
    }
}

/// Nginx directive representation
#[derive(Debug, Clone)]
struct NginxDirective {
    name: String,
    args: Vec<String>,
    block: Option<Vec<NginxDirective>>,
    line: usize,
}

/// Parse size string (e.g., "10m", "1g") to bytes
fn parse_size(s: &str) -> Option<usize> {
    let s = s.to_lowercase();
    if s.ends_with('k') {
        s[..s.len()-1].parse::<usize>().ok().map(|n| n * 1024)
    } else if s.ends_with('m') {
        s[..s.len()-1].parse::<usize>().ok().map(|n| n * 1024 * 1024)
    } else if s.ends_with('g') {
        s[..s.len()-1].parse::<usize>().ok().map(|n| n * 1024 * 1024 * 1024)
    } else {
        s.parse().ok()
    }
}

/// Parse duration string (e.g., "30s", "1m") to seconds
fn parse_duration(s: &str) -> Option<u64> {
    let s = s.to_lowercase();
    if s.ends_with('s') {
        s[..s.len()-1].parse().ok()
    } else if s.ends_with('m') {
        s[..s.len()-1].parse::<u64>().ok().map(|n| n * 60)
    } else if s.ends_with('h') {
        s[..s.len()-1].parse::<u64>().ok().map(|n| n * 3600)
    } else if s.ends_with('d') {
        s[..s.len()-1].parse::<u64>().ok().map(|n| n * 86400)
    } else {
        s.parse().ok()
    }
}

/// Normalize address (add default port if missing)
fn normalize_address(addr: &str) -> String {
    if addr.contains(':') {
        addr.to_string()
    } else if let Ok(port) = addr.parse::<u16>() {
        format!("0.0.0.0:{}", port)
    } else {
        format!("{}:80", addr)
    }
}

/// Extract upstream name from proxy_pass URL
fn extract_upstream_name(proxy_pass: &str) -> String {
    let s = proxy_pass
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');

    // Check if it's a reference to an upstream (no protocol)
    if !proxy_pass.contains("://") {
        return s.to_string();
    }

    // Extract host part
    if let Some(pos) = s.find('/') {
        s[..pos].replace([':', '.', '-'], "_")
    } else {
        s.replace([':', '.', '-'], "_")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("1024"), Some(1024));
        assert_eq!(parse_size("10k"), Some(10 * 1024));
        assert_eq!(parse_size("10m"), Some(10 * 1024 * 1024));
        assert_eq!(parse_size("1g"), Some(1024 * 1024 * 1024));
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30"), Some(30));
        assert_eq!(parse_duration("30s"), Some(30));
        assert_eq!(parse_duration("5m"), Some(300));
        assert_eq!(parse_duration("1h"), Some(3600));
    }

    #[test]
    fn test_normalize_address() {
        assert_eq!(normalize_address("80"), "0.0.0.0:80");
        assert_eq!(normalize_address("8080"), "0.0.0.0:8080");
        assert_eq!(normalize_address("0.0.0.0:443"), "0.0.0.0:443");
    }

    #[test]
    fn test_extract_upstream_name() {
        assert_eq!(extract_upstream_name("http://backend:8080"), "backend_8080");
        assert_eq!(extract_upstream_name("backend"), "backend");
        assert_eq!(extract_upstream_name("http://10.0.0.1:8080/api"), "10_0_0_1_8080");
    }
}
