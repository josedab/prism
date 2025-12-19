//! URL rewriting middleware
//!
//! Provides path manipulation, URL rewriting, and redirect capabilities.
//! Supports prefix stripping, path replacement, regex-based rewriting, and redirects.

use super::{HttpRequest, HttpResponse, Middleware, Next, RequestContext};
use crate::error::{PrismError, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http::{header, uri::PathAndQuery, Response, StatusCode, Uri};
use http_body_util::Full;
use regex::Regex;
use std::borrow::Cow;
use tracing::debug;

/// URL rewrite rule types
#[derive(Debug, Clone)]
pub enum RewriteRule {
    /// Strip a prefix from the path (e.g., "/api" -> "")
    StripPrefix(String),
    /// Add a prefix to the path
    AddPrefix(String),
    /// Replace path prefix (from, to)
    ReplacePrefix { from: String, to: String },
    /// Regex-based path rewrite
    Regex { pattern: Regex, replacement: String },
    /// Replace entire path
    SetPath(String),
    /// Redirect to a new URL
    Redirect { location: String, status: u16 },
    /// Rewrite host header
    SetHost(String),
}

impl RewriteRule {
    /// Create a strip prefix rule
    pub fn strip_prefix(prefix: impl Into<String>) -> Self {
        Self::StripPrefix(prefix.into())
    }

    /// Create an add prefix rule
    pub fn add_prefix(prefix: impl Into<String>) -> Self {
        Self::AddPrefix(prefix.into())
    }

    /// Create a replace prefix rule
    pub fn replace_prefix(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self::ReplacePrefix {
            from: from.into(),
            to: to.into(),
        }
    }

    /// Create a regex rewrite rule
    pub fn regex(pattern: &str, replacement: impl Into<String>) -> Result<Self> {
        let regex = Regex::new(pattern)?;
        Ok(Self::Regex {
            pattern: regex,
            replacement: replacement.into(),
        })
    }

    /// Create a redirect rule
    pub fn redirect(location: impl Into<String>, status: u16) -> Self {
        Self::Redirect {
            location: location.into(),
            status,
        }
    }

    /// Create a permanent redirect (301)
    pub fn permanent_redirect(location: impl Into<String>) -> Self {
        Self::redirect(location, 301)
    }

    /// Create a temporary redirect (302)
    pub fn temporary_redirect(location: impl Into<String>) -> Self {
        Self::redirect(location, 302)
    }
}

/// URL rewrite configuration
#[derive(Debug, Clone)]
pub struct RewriteConfig {
    /// List of rewrite rules to apply in order
    pub rules: Vec<RewriteRule>,
    /// Whether to preserve query string
    pub preserve_query: bool,
    /// Whether to preserve trailing slashes
    pub preserve_trailing_slash: bool,
}

impl Default for RewriteConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            preserve_query: true,
            preserve_trailing_slash: true,
        }
    }
}

/// URL rewrite middleware
pub struct RewriteMiddleware {
    config: RewriteConfig,
}

impl RewriteMiddleware {
    /// Create a new rewrite middleware
    pub fn new(config: RewriteConfig) -> Self {
        Self { config }
    }

    /// Create with a single strip prefix rule
    pub fn strip_prefix(prefix: impl Into<String>) -> Self {
        Self::new(RewriteConfig {
            rules: vec![RewriteRule::strip_prefix(prefix)],
            ..Default::default()
        })
    }

    /// Create with a single add prefix rule
    pub fn add_prefix(prefix: impl Into<String>) -> Self {
        Self::new(RewriteConfig {
            rules: vec![RewriteRule::add_prefix(prefix)],
            ..Default::default()
        })
    }

    /// Apply rewrite rules to a path
    fn rewrite_path<'a>(&self, path: &'a str) -> Cow<'a, str> {
        let mut result = Cow::Borrowed(path);

        for rule in &self.config.rules {
            result = match rule {
                RewriteRule::StripPrefix(prefix) => {
                    if result.starts_with(prefix.as_str()) {
                        let new_path = &result[prefix.len()..];
                        // Ensure path starts with /
                        if new_path.is_empty() || !new_path.starts_with('/') {
                            Cow::Owned(format!("/{}", new_path.trim_start_matches('/')))
                        } else {
                            Cow::Owned(new_path.to_string())
                        }
                    } else {
                        result
                    }
                }
                RewriteRule::AddPrefix(prefix) => {
                    let clean_prefix = prefix.trim_end_matches('/');
                    let clean_path = result.trim_start_matches('/');
                    Cow::Owned(format!("{}/{}", clean_prefix, clean_path))
                }
                RewriteRule::ReplacePrefix { from, to } => {
                    if result.starts_with(from.as_str()) {
                        let remainder = &result[from.len()..];
                        let clean_to = to.trim_end_matches('/');
                        if remainder.is_empty() || remainder.starts_with('/') {
                            Cow::Owned(format!("{}{}", clean_to, remainder))
                        } else {
                            Cow::Owned(format!("{}/{}", clean_to, remainder))
                        }
                    } else {
                        result
                    }
                }
                RewriteRule::Regex {
                    pattern,
                    replacement,
                } => Cow::Owned(
                    pattern
                        .replace_all(&result, replacement.as_str())
                        .into_owned(),
                ),
                RewriteRule::SetPath(new_path) => Cow::Owned(new_path.clone()),
                RewriteRule::Redirect { .. } | RewriteRule::SetHost(_) => {
                    // These don't modify the path
                    result
                }
            };
        }

        result
    }

    /// Check if any rule is a redirect
    fn get_redirect_rule(&self) -> Option<&RewriteRule> {
        self.config
            .rules
            .iter()
            .find(|r| matches!(r, RewriteRule::Redirect { .. }))
    }

    /// Get host rewrite if any
    fn get_host_rewrite(&self) -> Option<&str> {
        self.config.rules.iter().find_map(|r| match r {
            RewriteRule::SetHost(host) => Some(host.as_str()),
            _ => None,
        })
    }

    /// Build new URI with rewritten path
    fn build_uri(&self, original: &Uri, new_path: &str) -> Result<Uri> {
        let path_and_query = if self.config.preserve_query {
            if let Some(query) = original.query() {
                format!("{}?{}", new_path, query)
            } else {
                new_path.to_string()
            }
        } else {
            new_path.to_string()
        };

        let pq: PathAndQuery = path_and_query
            .parse()
            .map_err(|e| PrismError::Routing(format!("Invalid rewritten path: {}", e)))?;

        let mut parts = original.clone().into_parts();
        parts.path_and_query = Some(pq);

        Uri::from_parts(parts)
            .map_err(|e| PrismError::Routing(format!("Failed to build URI: {}", e)))
    }
}

#[async_trait]
impl Middleware for RewriteMiddleware {
    async fn process(
        &self,
        mut request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        // Check for redirect rule first
        if let Some(RewriteRule::Redirect { location, status }) = self.get_redirect_rule() {
            debug!("Redirecting to {} with status {}", location, status);

            let status_code = StatusCode::from_u16(*status).unwrap_or(StatusCode::FOUND);

            return Ok(Response::builder()
                .status(status_code)
                .header(header::LOCATION, location.as_str())
                .body(Full::new(Bytes::new()))
                .unwrap());
        }

        // Rewrite path
        let original_path = request.uri().path();
        let new_path = self.rewrite_path(original_path);

        if new_path != original_path {
            debug!("Rewriting path: {} -> {}", original_path, new_path);

            let new_uri = self.build_uri(request.uri(), &new_path)?;
            *request.uri_mut() = new_uri;
        }

        // Rewrite host header if configured
        if let Some(new_host) = self.get_host_rewrite() {
            if let Ok(value) = http::HeaderValue::from_str(new_host) {
                request.headers_mut().insert(header::HOST, value);
            }
        }

        next.run(request, ctx).await
    }

    fn name(&self) -> &'static str {
        "rewrite"
    }
}

/// Path manipulation utilities
pub mod path_utils {
    /// Normalize a path (remove double slashes, resolve . and ..)
    pub fn normalize(path: &str) -> String {
        let mut segments: Vec<&str> = Vec::new();

        for segment in path.split('/') {
            match segment {
                "" | "." => continue,
                ".." => {
                    segments.pop();
                }
                s => segments.push(s),
            }
        }

        let result = format!("/{}", segments.join("/"));

        // Preserve trailing slash if original had one
        if path.ends_with('/') && !result.ends_with('/') {
            format!("{}/", result)
        } else {
            result
        }
    }

    /// Join two path segments
    pub fn join(base: &str, path: &str) -> String {
        let base = base.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{}/{}", base, path)
    }

    /// Check if path matches a pattern (supports * and **)
    pub fn matches_pattern(path: &str, pattern: &str) -> bool {
        if pattern == "*" || pattern == "**" {
            return true;
        }

        if pattern.contains("**") {
            // ** matches any number of path segments
            let parts: Vec<&str> = pattern.split("**").collect();
            if parts.len() == 2 {
                let prefix = parts[0].trim_end_matches('/');
                let suffix = parts[1].trim_start_matches('/');
                return path.starts_with(prefix) && (suffix.is_empty() || path.ends_with(suffix));
            }
        }

        if pattern.contains('*') {
            // Simple glob matching (single segment)
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                return path.starts_with(parts[0]) && path.ends_with(parts[1]);
            }
        }

        path == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_prefix() {
        let middleware = RewriteMiddleware::strip_prefix("/api");

        assert_eq!(middleware.rewrite_path("/api/users"), "/users");
        assert_eq!(middleware.rewrite_path("/api"), "/");
        assert_eq!(middleware.rewrite_path("/other"), "/other");
    }

    #[test]
    fn test_add_prefix() {
        let middleware = RewriteMiddleware::add_prefix("/v1");

        assert_eq!(middleware.rewrite_path("/users"), "/v1/users");
        assert_eq!(middleware.rewrite_path("/"), "/v1/");
    }

    #[test]
    fn test_replace_prefix() {
        let config = RewriteConfig {
            rules: vec![RewriteRule::replace_prefix("/old", "/new")],
            ..Default::default()
        };
        let middleware = RewriteMiddleware::new(config);

        assert_eq!(middleware.rewrite_path("/old/path"), "/new/path");
        assert_eq!(middleware.rewrite_path("/old"), "/new");
        assert_eq!(middleware.rewrite_path("/other"), "/other");
    }

    #[test]
    fn test_regex_rewrite() {
        let config = RewriteConfig {
            rules: vec![RewriteRule::regex(r"/users/(\d+)", "/api/v1/users/$1").unwrap()],
            ..Default::default()
        };
        let middleware = RewriteMiddleware::new(config);

        assert_eq!(middleware.rewrite_path("/users/123"), "/api/v1/users/123");
        assert_eq!(middleware.rewrite_path("/users/abc"), "/users/abc");
    }

    #[test]
    fn test_chained_rules() {
        let config = RewriteConfig {
            rules: vec![
                RewriteRule::strip_prefix("/api"),
                RewriteRule::add_prefix("/v2"),
            ],
            ..Default::default()
        };
        let middleware = RewriteMiddleware::new(config);

        assert_eq!(middleware.rewrite_path("/api/users"), "/v2/users");
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(path_utils::normalize("/a/b/c"), "/a/b/c");
        assert_eq!(path_utils::normalize("/a//b/c"), "/a/b/c");
        assert_eq!(path_utils::normalize("/a/./b/c"), "/a/b/c");
        assert_eq!(path_utils::normalize("/a/b/../c"), "/a/c");
        assert_eq!(path_utils::normalize("/a/b/c/"), "/a/b/c/");
    }

    #[test]
    fn test_path_join() {
        assert_eq!(path_utils::join("/api", "/users"), "/api/users");
        assert_eq!(path_utils::join("/api/", "users"), "/api/users");
        assert_eq!(path_utils::join("/api", "users"), "/api/users");
    }

    #[test]
    fn test_pattern_matching() {
        assert!(path_utils::matches_pattern("/api/users", "/api/*"));
        assert!(path_utils::matches_pattern("/api/users/123", "/api/**"));
        assert!(path_utils::matches_pattern(
            "/api/v1/users",
            "/api/**/users"
        ));
        assert!(!path_utils::matches_pattern("/other", "/api/*"));
    }

    #[test]
    fn test_set_path() {
        let config = RewriteConfig {
            rules: vec![RewriteRule::SetPath("/fixed/path".to_string())],
            ..Default::default()
        };
        let middleware = RewriteMiddleware::new(config);

        assert_eq!(middleware.rewrite_path("/anything"), "/fixed/path");
    }
}
