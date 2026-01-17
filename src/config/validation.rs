//! Configuration validation

use super::types::*;
use crate::error::{PrismError, Result};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;

/// Validate the entire configuration
pub fn validate_config(config: &Config) -> Result<()> {
    validate_listeners(&config.listeners)?;
    validate_upstreams(&config.upstreams)?;
    validate_routes(&config.routes, &config.upstreams)?;
    validate_observability(&config.observability)?;

    if let Some(admin) = &config.admin {
        validate_admin(admin)?;
    }

    Ok(())
}

/// Validate listener configurations
fn validate_listeners(listeners: &[ListenerConfig]) -> Result<()> {
    if listeners.is_empty() {
        return Err(PrismError::ConfigValidation(
            "At least one listener is required".to_string(),
        ));
    }

    let mut addresses = HashSet::new();

    for (i, listener) in listeners.iter().enumerate() {
        // Validate address format
        listener.address.parse::<SocketAddr>().map_err(|e| {
            PrismError::ConfigValidation(format!(
                "Invalid address '{}' in listener {}: {}",
                listener.address, i, e
            ))
        })?;

        // Check for duplicate addresses
        if !addresses.insert(&listener.address) {
            return Err(PrismError::ConfigValidation(format!(
                "Duplicate listener address: {}",
                listener.address
            )));
        }

        // Validate TLS configuration for HTTPS
        if listener.protocol == Protocol::Https || listener.protocol == Protocol::Http3 {
            let tls = listener.tls.as_ref().ok_or_else(|| {
                PrismError::ConfigValidation(format!(
                    "TLS configuration required for {:?} listener at {}",
                    listener.protocol, listener.address
                ))
            })?;

            validate_tls_config(tls)?;
        }

        // Validate max connections
        if listener.max_connections == 0 {
            return Err(PrismError::ConfigValidation(
                "max_connections must be greater than 0".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validate TLS configuration
fn validate_tls_config(tls: &TlsConfig) -> Result<()> {
    // Check certificate file exists
    if !Path::new(&tls.cert).exists() {
        return Err(PrismError::ConfigValidation(format!(
            "Certificate file not found: {:?}",
            tls.cert
        )));
    }

    // Check key file exists
    if !Path::new(&tls.key).exists() {
        return Err(PrismError::ConfigValidation(format!(
            "Key file not found: {:?}",
            tls.key
        )));
    }

    // Validate ALPN protocols
    for proto in &tls.alpn {
        if proto.is_empty() {
            return Err(PrismError::ConfigValidation(
                "ALPN protocol cannot be empty".to_string(),
            ));
        }
    }

    // Validate TLS version
    let valid_versions = ["1.2", "1.3"];
    if !valid_versions.contains(&tls.min_version.as_str()) {
        return Err(PrismError::ConfigValidation(format!(
            "Invalid TLS version: {}. Must be one of: {:?}",
            tls.min_version, valid_versions
        )));
    }

    Ok(())
}

/// Validate upstream configurations
fn validate_upstreams(upstreams: &std::collections::HashMap<String, UpstreamConfig>) -> Result<()> {
    for (name, upstream) in upstreams {
        if upstream.servers.is_empty() {
            return Err(PrismError::ConfigValidation(format!(
                "Upstream '{}' must have at least one server",
                name
            )));
        }

        for (i, server) in upstream.servers.iter().enumerate() {
            // Validate server address format
            if !server.address.contains(':') {
                return Err(PrismError::ConfigValidation(format!(
                    "Invalid server address '{}' in upstream '{}': missing port",
                    server.address, name
                )));
            }

            // Validate weight
            if server.weight == 0 {
                return Err(PrismError::ConfigValidation(format!(
                    "Server {} in upstream '{}' has invalid weight 0",
                    i, name
                )));
            }
        }

        // Validate health check configuration
        if let Some(health) = &upstream.health_check {
            if health.interval.is_zero() {
                return Err(PrismError::ConfigValidation(format!(
                    "Health check interval cannot be zero for upstream '{}'",
                    name
                )));
            }

            if health.timeout >= health.interval {
                return Err(PrismError::ConfigValidation(format!(
                    "Health check timeout must be less than interval for upstream '{}'",
                    name
                )));
            }
        }

        // Validate pool configuration
        if upstream.pool.max_connections == 0 {
            return Err(PrismError::ConfigValidation(format!(
                "Pool max_connections cannot be zero for upstream '{}'",
                name
            )));
        }

        if upstream.pool.min_idle > upstream.pool.max_connections {
            return Err(PrismError::ConfigValidation(format!(
                "Pool min_idle cannot exceed max_connections for upstream '{}'",
                name
            )));
        }
    }

    Ok(())
}

/// Validate route configurations
fn validate_routes(
    routes: &[RouteConfig],
    upstreams: &std::collections::HashMap<String, UpstreamConfig>,
) -> Result<()> {
    for (i, route) in routes.iter().enumerate() {
        // Validate match configuration
        let match_config = &route.match_config;

        // Must have at least one match condition
        if match_config.host.is_none()
            && match_config.path.is_none()
            && match_config.path_prefix.is_none()
            && match_config.path_regex.is_none()
            && match_config.headers.is_empty()
            && match_config.methods.is_empty()
        {
            return Err(PrismError::ConfigValidation(format!(
                "Route {} must have at least one match condition",
                i
            )));
        }

        // Validate regex patterns
        if let Some(regex) = &match_config.path_regex {
            regex::Regex::new(regex).map_err(|e| {
                PrismError::ConfigValidation(format!("Invalid path regex in route {}: {}", i, e))
            })?;
        }

        // Must have either upstream or handler
        if route.upstream.is_none() && route.handler.is_none() {
            return Err(PrismError::ConfigValidation(format!(
                "Route {} must have either 'upstream' or 'handler'",
                i
            )));
        }

        // Validate upstream reference
        if let Some(upstream_name) = &route.upstream {
            if !upstreams.contains_key(upstream_name) {
                return Err(PrismError::ConfigValidation(format!(
                    "Route {} references unknown upstream '{}'",
                    i, upstream_name
                )));
            }
        }

        // Validate handler configuration
        if let Some(handler) = &route.handler {
            if handler.handler_type == HandlerType::Redirect && handler.redirect_url.is_none() {
                return Err(PrismError::ConfigValidation(format!(
                    "Redirect handler in route {} requires 'redirect_url'",
                    i
                )));
            }
        }

        // Validate rewrite configuration
        if let Some(rewrite) = &route.rewrite {
            regex::Regex::new(&rewrite.pattern).map_err(|e| {
                PrismError::ConfigValidation(format!(
                    "Invalid rewrite pattern in route {}: {}",
                    i, e
                ))
            })?;
        }

        // Validate middlewares
        for middleware in &route.middlewares {
            validate_middleware(middleware, i)?;
        }
    }

    Ok(())
}

/// Validate middleware configuration
fn validate_middleware(middleware: &MiddlewareConfig, route_idx: usize) -> Result<()> {
    if let Some(rate_limit) = &middleware.rate_limit {
        if rate_limit.requests_per_second == 0 {
            return Err(PrismError::ConfigValidation(format!(
                "Rate limit requests_per_second must be > 0 in route {}",
                route_idx
            )));
        }
    }

    if let Some(auth) = &middleware.auth {
        match auth.auth_type {
            AuthType::Jwt => {
                if auth.jwks_url.is_none() {
                    return Err(PrismError::ConfigValidation(format!(
                        "JWT auth requires 'jwks_url' in route {}",
                        route_idx
                    )));
                }
            }
            AuthType::ApiKey => {
                if auth.api_keys.is_none() || auth.api_keys.as_ref().is_none_or(|k| k.is_empty()) {
                    return Err(PrismError::ConfigValidation(format!(
                        "API key auth requires 'api_keys' in route {}",
                        route_idx
                    )));
                }
            }
            AuthType::Basic => {}
        }
    }

    if let Some(retry) = &middleware.retry {
        if retry.max_retries == 0 {
            return Err(PrismError::ConfigValidation(format!(
                "Retry max_retries must be > 0 in route {}",
                route_idx
            )));
        }
    }

    Ok(())
}

/// Validate observability configuration
fn validate_observability(obs: &ObservabilityConfig) -> Result<()> {
    if obs.tracing.enabled && obs.tracing.endpoint.is_empty() {
        return Err(PrismError::ConfigValidation(
            "Tracing requires 'endpoint' when enabled".to_string(),
        ));
    }

    if obs.tracing.sample_rate < 0.0 || obs.tracing.sample_rate > 1.0 {
        return Err(PrismError::ConfigValidation(
            "Tracing sample_rate must be between 0.0 and 1.0".to_string(),
        ));
    }

    Ok(())
}

/// Validate admin API configuration
fn validate_admin(admin: &AdminConfig) -> Result<()> {
    admin.address.parse::<SocketAddr>().map_err(|e| {
        PrismError::ConfigValidation(format!("Invalid admin address '{}': {}", admin.address, e))
    })?;

    if admin.auth_enabled && admin.api_key.is_none() {
        return Err(PrismError::ConfigValidation(
            "Admin API key required when auth is enabled".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn minimal_config() -> Config {
        Config {
            listeners: vec![ListenerConfig {
                address: "0.0.0.0:8080".to_string(),
                protocol: Protocol::Http,
                tls: None,
                max_connections: 1000,
            }],
            upstreams: {
                let mut m = HashMap::new();
                m.insert(
                    "backend".to_string(),
                    UpstreamConfig {
                        servers: vec![ServerConfig {
                            address: "127.0.0.1:3000".to_string(),
                            weight: 1,
                            enabled: true,
                        }],
                        health_check: None,
                        load_balancing: LoadBalancingAlgorithm::RoundRobin,
                        pool: PoolConfig::default(),
                        connect_timeout: std::time::Duration::from_secs(5),
                        request_timeout: std::time::Duration::from_secs(30),
                        circuit_breaker: None,
                        retry: None,
                    },
                );
                m
            },
            routes: vec![RouteConfig {
                match_config: MatchConfig {
                    host: None,
                    path: None,
                    path_prefix: Some("/".to_string()),
                    path_regex: None,
                    headers: HashMap::new(),
                    methods: vec![],
                },
                upstream: Some("backend".to_string()),
                handler: None,
                middlewares: vec![],
                rewrite: None,
                priority: 0,
            }],
            observability: ObservabilityConfig::default(),
            admin: None,
            global: GlobalConfig::default(),
            // Next-gen features (all optional)
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
        }
    }

    #[test]
    fn test_valid_minimal_config() {
        let config = minimal_config();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_empty_listeners() {
        let mut config = minimal_config();
        config.listeners = vec![];
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_invalid_listener_address() {
        let mut config = minimal_config();
        config.listeners[0].address = "invalid".to_string();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_route_references_unknown_upstream() {
        let mut config = minimal_config();
        config.routes[0].upstream = Some("unknown".to_string());
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_route_without_match() {
        let mut config = minimal_config();
        config.routes[0].match_config = MatchConfig {
            host: None,
            path: None,
            path_prefix: None,
            path_regex: None,
            headers: HashMap::new(),
            methods: vec![],
        };
        assert!(validate_config(&config).is_err());
    }
}
