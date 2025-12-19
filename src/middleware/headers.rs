//! Header manipulation middleware

use super::{HttpRequest, HttpResponse, Middleware, Next, RequestContext};
use crate::config::HeadersConfig;
use crate::error::Result;
use async_trait::async_trait;
use http::header::HeaderName;
use std::str::FromStr;

/// Middleware for manipulating request and response headers
pub struct HeadersMiddleware {
    /// Headers to add to requests
    request_add: Vec<(HeaderName, String)>,
    /// Headers to remove from requests
    request_remove: Vec<HeaderName>,
    /// Headers to add to responses
    response_add: Vec<(HeaderName, String)>,
    /// Headers to remove from responses
    response_remove: Vec<HeaderName>,
}

impl HeadersMiddleware {
    /// Create a new headers middleware from configuration
    pub fn new(config: &HeadersConfig) -> Self {
        let request_add = config
            .request_add
            .iter()
            .filter_map(|(k, v)| HeaderName::from_str(k).ok().map(|name| (name, v.clone())))
            .collect();

        let request_remove = config
            .request_remove
            .iter()
            .filter_map(|k| HeaderName::from_str(k).ok())
            .collect();

        let response_add = config
            .response_add
            .iter()
            .filter_map(|(k, v)| HeaderName::from_str(k).ok().map(|name| (name, v.clone())))
            .collect();

        let response_remove = config
            .response_remove
            .iter()
            .filter_map(|k| HeaderName::from_str(k).ok())
            .collect();

        Self {
            request_add,
            request_remove,
            response_add,
            response_remove,
        }
    }
}

#[async_trait]
impl Middleware for HeadersMiddleware {
    async fn process(
        &self,
        mut request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        // Modify request headers
        let headers = request.headers_mut();

        // Remove specified headers
        for name in &self.request_remove {
            headers.remove(name);
        }

        // Add specified headers
        for (name, value) in &self.request_add {
            if let Ok(value) = value.parse() {
                headers.insert(name.clone(), value);
            }
        }

        // Add request ID header
        if let Ok(value) = ctx.request_id.parse() {
            headers.insert("X-Request-Id", value);
        }

        // Process request
        let mut response = next.run(request, ctx).await?;

        // Modify response headers
        let headers = response.headers_mut();

        // Remove specified headers
        for name in &self.response_remove {
            headers.remove(name);
        }

        // Add specified headers
        for (name, value) in &self.response_add {
            if let Ok(value) = value.parse() {
                headers.insert(name.clone(), value);
            }
        }

        Ok(response)
    }

    fn name(&self) -> &'static str {
        "headers"
    }
}

/// Add security headers middleware
#[allow(dead_code)]
pub struct SecurityHeadersMiddleware {
    /// Enable HSTS
    hsts: bool,
    /// Content Security Policy
    csp: Option<String>,
    /// X-Frame-Options
    frame_options: Option<String>,
    /// X-Content-Type-Options
    content_type_options: bool,
}

impl SecurityHeadersMiddleware {
    /// Create with default security headers
    #[allow(dead_code)]
    pub fn default_secure() -> Self {
        Self {
            hsts: true,
            csp: Some("default-src 'self'".to_string()),
            frame_options: Some("DENY".to_string()),
            content_type_options: true,
        }
    }
}

#[async_trait]
impl Middleware for SecurityHeadersMiddleware {
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        let mut response = next.run(request, ctx).await?;
        let headers = response.headers_mut();

        if self.hsts {
            headers.insert(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains".parse().unwrap(),
            );
        }

        if let Some(csp) = &self.csp {
            if let Ok(value) = csp.parse() {
                headers.insert("Content-Security-Policy", value);
            }
        }

        if let Some(frame_options) = &self.frame_options {
            if let Ok(value) = frame_options.parse() {
                headers.insert("X-Frame-Options", value);
            }
        }

        if self.content_type_options {
            headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
        }

        Ok(response)
    }

    fn name(&self) -> &'static str {
        "security_headers"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_headers_middleware_creation() {
        let mut request_add = HashMap::new();
        request_add.insert("X-Custom".to_string(), "value".to_string());

        let config = HeadersConfig {
            request_add,
            request_remove: vec!["X-Remove".to_string()],
            response_add: HashMap::new(),
            response_remove: vec![],
        };

        let middleware = HeadersMiddleware::new(&config);
        assert_eq!(middleware.request_add.len(), 1);
        assert_eq!(middleware.request_remove.len(), 1);
    }
}
