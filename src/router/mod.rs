//! Router module for request routing
//!
//! Implements efficient routing with:
//! - Host matching (exact and wildcard)
//! - Path matching (exact, prefix, regex)
//! - Header matching
//! - Method matching
//! - Traffic splitting for canary deployments
//! - GraphQL-aware routing

pub mod graphql;
mod matcher;
pub mod traffic_split;

pub use graphql::{
    extract_graphql_from_query, is_graphql_request, query_fingerprint, GraphqlAnalyzer,
    GraphqlError, GraphqlErrorExtensions, GraphqlErrorItem, GraphqlErrorResponse, GraphqlRequest,
    GraphqlRequestBody, GraphqlRoutingConfig, OperationType,
};
pub use matcher::*;
pub use traffic_split::{SplitStrategy, SplitTarget, TrafficSplitConfig, TrafficSplitter};

use crate::config::{HandlerConfig, MiddlewareConfig, RewriteConfig, RouteConfig};
use crate::error::Result;
use http::{Method, Request};
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

/// A resolved route with all necessary information for proxying
#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    /// Target upstream name
    pub upstream: Option<String>,
    /// Static handler (if no upstream)
    pub handler: Option<HandlerConfig>,
    /// Middleware configurations
    pub middlewares: Vec<MiddlewareConfig>,
    /// Path rewrite configuration
    pub rewrite: Option<CompiledRewrite>,
    /// Captured path parameters
    pub path_params: HashMap<String, String>,
}

/// Compiled rewrite rule
#[derive(Debug, Clone)]
pub struct CompiledRewrite {
    pattern: Regex,
    replacement: String,
}

impl CompiledRewrite {
    /// Create a new compiled rewrite
    pub fn new(config: &RewriteConfig) -> Result<Self> {
        let pattern = Regex::new(&config.pattern)?;
        Ok(Self {
            pattern,
            replacement: config.replacement.clone(),
        })
    }

    /// Apply the rewrite to a path
    pub fn apply(&self, path: &str) -> String {
        self.pattern.replace(path, &self.replacement).to_string()
    }
}

/// A compiled route for efficient matching
struct CompiledRoute {
    /// Original route configuration
    config: RouteConfig,
    /// Compiled host matcher
    host_matcher: Option<HostMatcher>,
    /// Compiled path matcher
    path_matcher: PathMatcher,
    /// Required headers
    required_headers: HashMap<String, String>,
    /// Allowed methods
    allowed_methods: Vec<Method>,
    /// Compiled rewrite
    rewrite: Option<CompiledRewrite>,
    /// Route priority (lower = higher priority)
    priority: i32,
}

/// The main router that matches requests to routes
pub struct Router {
    /// Compiled routes sorted by priority
    routes: Vec<CompiledRoute>,
}

impl Router {
    /// Create a new router from route configurations
    pub fn new(configs: &[RouteConfig]) -> Result<Self> {
        let mut routes: Vec<CompiledRoute> = configs
            .iter()
            .map(compile_route)
            .collect::<Result<Vec<_>>>()?;

        // Sort by priority (lower number = higher priority)
        routes.sort_by_key(|r| r.priority);

        Ok(Self { routes })
    }

    /// Resolve a request to a route
    pub fn resolve<B>(&self, request: &Request<B>) -> Option<ResolvedRoute> {
        let host = extract_host(request);
        let path = request.uri().path();
        let method = request.method();
        let headers = request.headers();

        debug!(
            "Resolving route for host={:?}, path={}, method={}",
            host, path, method
        );

        for route in &self.routes {
            // Check host match
            if let Some(host_matcher) = &route.host_matcher {
                match &host {
                    Some(h) if host_matcher.matches(h) => {}
                    Some(_) => continue,
                    None if host_matcher.allows_missing() => {}
                    None => continue,
                }
            }

            // Check path match
            let path_match = route.path_matcher.matches(path);
            if path_match.is_none() {
                continue;
            }

            // Check method match
            if !route.allowed_methods.is_empty() && !route.allowed_methods.contains(method) {
                continue;
            }

            // Check required headers
            let headers_match = route.required_headers.iter().all(|(name, value)| {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v == value)
                    .unwrap_or(false)
            });

            if !headers_match {
                continue;
            }

            // Found a match!
            debug!("Route matched for path: {}", path);

            return Some(ResolvedRoute {
                upstream: route.config.upstream.clone(),
                handler: route.config.handler.clone(),
                middlewares: route.config.middlewares.clone(),
                rewrite: route.rewrite.clone(),
                path_params: path_match.unwrap_or_default(),
            });
        }

        None
    }

    /// Get the number of routes
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Check if router has no routes
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// Compile a route configuration into a compiled route
fn compile_route(config: &RouteConfig) -> Result<CompiledRoute> {
    let match_config = &config.match_config;

    // Compile host matcher
    let host_matcher = match_config
        .host
        .as_ref()
        .map(|h| HostMatcher::new(h))
        .transpose()?;

    // Compile path matcher
    let path_matcher = PathMatcher::new(
        match_config.path.as_deref(),
        match_config.path_prefix.as_deref(),
        match_config.path_regex.as_deref(),
    )?;

    // Parse allowed methods
    let allowed_methods: Vec<Method> = match_config
        .methods
        .iter()
        .filter_map(|m| m.parse().ok())
        .collect();

    // Compile rewrite
    let rewrite = config
        .rewrite
        .as_ref()
        .map(CompiledRewrite::new)
        .transpose()?;

    Ok(CompiledRoute {
        config: config.clone(),
        host_matcher,
        path_matcher,
        required_headers: match_config.headers.clone(),
        allowed_methods,
        rewrite,
        priority: config.priority,
    })
}

/// Extract host from request
fn extract_host<B>(request: &Request<B>) -> Option<String> {
    // Try Host header first
    if let Some(host) = request.headers().get(http::header::HOST) {
        if let Ok(host_str) = host.to_str() {
            // Remove port if present
            return Some(
                host_str
                    .split(':')
                    .next()
                    .unwrap_or(host_str)
                    .to_lowercase(),
            );
        }
    }

    // Fall back to URI host
    request.uri().host().map(|h| h.to_lowercase())
}

/// Thread-safe router that can be shared across tasks
pub type SharedRouter = Arc<Router>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MatchConfig;
    use http::Request;

    fn create_route(path_prefix: &str, upstream: &str) -> RouteConfig {
        RouteConfig {
            match_config: MatchConfig {
                host: None,
                path: None,
                path_prefix: Some(path_prefix.to_string()),
                path_regex: None,
                headers: HashMap::new(),
                methods: vec![],
            },
            upstream: Some(upstream.to_string()),
            handler: None,
            middlewares: vec![],
            rewrite: None,
            priority: 0,
        }
    }

    #[test]
    fn test_simple_path_matching() {
        let routes = vec![
            create_route("/api", "api_backend"),
            create_route("/", "default_backend"),
        ];

        let router = Router::new(&routes).unwrap();

        let request = Request::builder().uri("/api/users").body(()).unwrap();

        let resolved = router.resolve(&request).unwrap();
        assert_eq!(resolved.upstream, Some("api_backend".to_string()));
    }

    #[test]
    fn test_priority_matching() {
        let mut routes = vec![
            create_route("/", "default_backend"),
            create_route("/api", "api_backend"),
        ];
        routes[0].priority = 10;
        routes[1].priority = 0;

        let router = Router::new(&routes).unwrap();

        let request = Request::builder().uri("/api/users").body(()).unwrap();

        let resolved = router.resolve(&request).unwrap();
        assert_eq!(resolved.upstream, Some("api_backend".to_string()));
    }

    #[test]
    fn test_no_match() {
        let routes = vec![create_route("/api", "api_backend")];
        let router = Router::new(&routes).unwrap();

        let request = Request::builder().uri("/other").body(()).unwrap();

        assert!(router.resolve(&request).is_none());
    }

    #[test]
    fn test_host_matching() {
        let routes = vec![RouteConfig {
            match_config: MatchConfig {
                host: Some("api.example.com".to_string()),
                path: None,
                path_prefix: Some("/".to_string()),
                path_regex: None,
                headers: HashMap::new(),
                methods: vec![],
            },
            upstream: Some("api_backend".to_string()),
            handler: None,
            middlewares: vec![],
            rewrite: None,
            priority: 0,
        }];

        let router = Router::new(&routes).unwrap();

        // Matching host
        let request = Request::builder()
            .uri("/test")
            .header("Host", "api.example.com")
            .body(())
            .unwrap();
        assert!(router.resolve(&request).is_some());

        // Non-matching host
        let request = Request::builder()
            .uri("/test")
            .header("Host", "other.example.com")
            .body(())
            .unwrap();
        assert!(router.resolve(&request).is_none());
    }
}
