//! CORS (Cross-Origin Resource Sharing) middleware

use super::{HttpRequest, HttpResponse, Middleware, Next, RequestContext};
use crate::error::Result;
use async_trait::async_trait;
use bytes::Bytes;
use http::{header, Method, Response, StatusCode};
use http_body_util::Full;
use std::collections::HashSet;

/// CORS middleware configuration
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins (use "*" for all)
    pub allowed_origins: Vec<String>,
    /// Allowed HTTP methods
    pub allowed_methods: Vec<String>,
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    /// Headers to expose to the client
    pub expose_headers: Vec<String>,
    /// Whether to allow credentials
    pub allow_credentials: bool,
    /// Max age for preflight cache (seconds)
    pub max_age: Option<u64>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
                "HEAD".to_string(),
                "PATCH".to_string(),
            ],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Requested-With".to_string(),
            ],
            expose_headers: vec![],
            allow_credentials: false,
            max_age: Some(86400), // 24 hours
        }
    }
}

impl CorsConfig {
    /// Create a permissive CORS config (allow all)
    pub fn permissive() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
                "HEAD".to_string(),
                "PATCH".to_string(),
            ],
            allowed_headers: vec!["*".to_string()],
            expose_headers: vec!["*".to_string()],
            allow_credentials: false,
            max_age: Some(86400),
        }
    }

    /// Create a restrictive CORS config
    pub fn restrictive(origins: Vec<String>) -> Self {
        Self {
            allowed_origins: origins,
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allowed_headers: vec!["Content-Type".to_string()],
            expose_headers: vec![],
            allow_credentials: true,
            max_age: Some(3600),
        }
    }
}

/// CORS middleware
pub struct CorsMiddleware {
    config: CorsConfig,
    allowed_origins_set: HashSet<String>,
    allow_all_origins: bool,
}

impl CorsMiddleware {
    /// Create a new CORS middleware
    pub fn new(config: CorsConfig) -> Self {
        let allow_all_origins = config.allowed_origins.contains(&"*".to_string());
        let allowed_origins_set: HashSet<String> = config.allowed_origins.iter().cloned().collect();

        Self {
            config,
            allowed_origins_set,
            allow_all_origins,
        }
    }

    /// Check if origin is allowed
    fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.allow_all_origins {
            return true;
        }
        self.allowed_origins_set.contains(origin)
    }

    /// Get the Access-Control-Allow-Origin header value
    fn get_allow_origin(&self, origin: Option<&str>) -> Option<String> {
        match origin {
            Some(o) if self.is_origin_allowed(o) => {
                if self.allow_all_origins && !self.config.allow_credentials {
                    Some("*".to_string())
                } else {
                    Some(o.to_string())
                }
            }
            _ if self.allow_all_origins => Some("*".to_string()),
            _ => None,
        }
    }

    /// Build preflight response
    fn preflight_response(&self, origin: Option<&str>) -> HttpResponse {
        let mut builder = Response::builder().status(StatusCode::NO_CONTENT);

        // Access-Control-Allow-Origin
        if let Some(allowed_origin) = self.get_allow_origin(origin) {
            builder = builder.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, allowed_origin);
        }

        // Access-Control-Allow-Methods
        builder = builder.header(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            self.config.allowed_methods.join(", "),
        );

        // Access-Control-Allow-Headers
        if !self.config.allowed_headers.is_empty() {
            builder = builder.header(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                self.config.allowed_headers.join(", "),
            );
        }

        // Access-Control-Allow-Credentials
        if self.config.allow_credentials {
            builder = builder.header(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        }

        // Access-Control-Max-Age
        if let Some(max_age) = self.config.max_age {
            builder = builder.header(header::ACCESS_CONTROL_MAX_AGE, max_age.to_string());
        }

        // Vary header for caching
        builder = builder.header(
            header::VARY,
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        );

        builder.body(Full::new(Bytes::new())).unwrap()
    }

    /// Add CORS headers to response
    fn add_cors_headers(&self, mut response: HttpResponse, origin: Option<&str>) -> HttpResponse {
        let headers = response.headers_mut();

        // Access-Control-Allow-Origin
        if let Some(allowed_origin) = self.get_allow_origin(origin) {
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                allowed_origin.parse().unwrap(),
            );
        }

        // Access-Control-Allow-Credentials
        if self.config.allow_credentials {
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                "true".parse().unwrap(),
            );
        }

        // Access-Control-Expose-Headers
        if !self.config.expose_headers.is_empty() {
            headers.insert(
                header::ACCESS_CONTROL_EXPOSE_HEADERS,
                self.config.expose_headers.join(", ").parse().unwrap(),
            );
        }

        // Vary header
        headers.insert(header::VARY, "Origin".parse().unwrap());

        response
    }
}

#[async_trait]
impl Middleware for CorsMiddleware {
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        let origin = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Handle preflight requests
        if request.method() == Method::OPTIONS {
            return Ok(self.preflight_response(origin.as_deref()));
        }

        // Process the actual request
        let response = next.run(request, ctx).await?;

        // Add CORS headers to response
        Ok(self.add_cors_headers(response, origin.as_deref()))
    }

    fn name(&self) -> &'static str {
        "cors"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_cors_config() {
        let config = CorsConfig::default();
        assert!(config.allowed_origins.contains(&"*".to_string()));
        assert!(config.allowed_methods.contains(&"GET".to_string()));
        assert!(!config.allow_credentials);
    }

    #[test]
    fn test_permissive_cors_config() {
        let config = CorsConfig::permissive();
        assert!(config.allowed_origins.contains(&"*".to_string()));
        assert!(config.allowed_headers.contains(&"*".to_string()));
    }

    #[test]
    fn test_restrictive_cors_config() {
        let origins = vec!["https://example.com".to_string()];
        let config = CorsConfig::restrictive(origins.clone());
        assert_eq!(config.allowed_origins, origins);
        assert!(config.allow_credentials);
    }

    #[test]
    fn test_origin_allowed() {
        let config = CorsConfig {
            allowed_origins: vec![
                "https://example.com".to_string(),
                "https://api.example.com".to_string(),
            ],
            ..Default::default()
        };
        let middleware = CorsMiddleware::new(config);

        assert!(middleware.is_origin_allowed("https://example.com"));
        assert!(middleware.is_origin_allowed("https://api.example.com"));
        assert!(!middleware.is_origin_allowed("https://evil.com"));
    }

    #[test]
    fn test_wildcard_origin() {
        let config = CorsConfig::default();
        let middleware = CorsMiddleware::new(config);

        assert!(middleware.is_origin_allowed("https://any-origin.com"));
        assert!(middleware.is_origin_allowed("http://localhost:3000"));
    }

    #[test]
    fn test_get_allow_origin_with_credentials() {
        let config = CorsConfig {
            allowed_origins: vec!["*".to_string()],
            allow_credentials: true,
            ..Default::default()
        };
        let middleware = CorsMiddleware::new(config);

        // When credentials are allowed, must return specific origin, not "*"
        let result = middleware.get_allow_origin(Some("https://example.com"));
        assert_eq!(result, Some("https://example.com".to_string()));
    }
}
