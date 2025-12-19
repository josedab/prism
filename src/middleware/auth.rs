//! Authentication middleware
//!
//! Supports multiple authentication methods:
//! - JWT with JWKS validation
//! - API Key authentication (header or query parameter)
//! - Basic authentication

use super::{HttpRequest, HttpResponse, Middleware, Next, RequestContext};
use crate::config::{AuthConfig, AuthType};
use crate::error::{PrismError, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http::{header, Response, StatusCode};
use http_body_util::Full;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (user ID)
    pub sub: Option<String>,
    /// Issuer
    pub iss: Option<String>,
    /// Audience
    pub aud: Option<OneOrMany>,
    /// Expiration time
    pub exp: Option<u64>,
    /// Not before
    pub nbf: Option<u64>,
    /// Issued at
    pub iat: Option<u64>,
    /// JWT ID
    pub jti: Option<String>,
    /// Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// Helper for aud claim which can be string or array
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub fn contains(&self, value: &str) -> bool {
        match self {
            OneOrMany::One(s) => s == value,
            OneOrMany::Many(v) => v.iter().any(|s| s == value),
        }
    }
}

/// JWKS (JSON Web Key Set) structure
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Individual JWK (JSON Web Key)
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    pub alg: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    // EC keys
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
}

impl Jwk {
    /// Convert JWK to DecodingKey
    pub fn to_decoding_key(&self) -> Result<DecodingKey> {
        match self.kty.as_str() {
            "RSA" => {
                let n = self
                    .n
                    .as_ref()
                    .ok_or_else(|| PrismError::Auth("RSA JWK missing 'n' parameter".to_string()))?;
                let e = self
                    .e
                    .as_ref()
                    .ok_or_else(|| PrismError::Auth("RSA JWK missing 'e' parameter".to_string()))?;
                DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| PrismError::Auth(format!("Invalid RSA key: {}", e)))
            }
            "EC" => {
                let x = self
                    .x
                    .as_ref()
                    .ok_or_else(|| PrismError::Auth("EC JWK missing 'x' parameter".to_string()))?;
                let y = self
                    .y
                    .as_ref()
                    .ok_or_else(|| PrismError::Auth("EC JWK missing 'y' parameter".to_string()))?;
                DecodingKey::from_ec_components(x, y)
                    .map_err(|e| PrismError::Auth(format!("Invalid EC key: {}", e)))
            }
            _ => Err(PrismError::Auth(format!(
                "Unsupported key type: {}",
                self.kty
            ))),
        }
    }

    /// Get algorithm for this key
    pub fn algorithm(&self) -> Algorithm {
        match self.alg.as_deref() {
            Some("RS256") => Algorithm::RS256,
            Some("RS384") => Algorithm::RS384,
            Some("RS512") => Algorithm::RS512,
            Some("ES256") => Algorithm::ES256,
            Some("ES384") => Algorithm::ES384,
            Some("PS256") => Algorithm::PS256,
            Some("PS384") => Algorithm::PS384,
            Some("PS512") => Algorithm::PS512,
            _ => {
                // Default based on key type
                match self.kty.as_str() {
                    "RSA" => Algorithm::RS256,
                    "EC" => Algorithm::ES256,
                    _ => Algorithm::RS256,
                }
            }
        }
    }
}

/// JWKS cache entry
struct JwksCacheEntry {
    jwks: Jwks,
    fetched_at: Instant,
}

/// Authentication configuration for middleware
#[derive(Debug, Clone)]
pub struct AuthMiddlewareConfig {
    /// Auth type
    pub auth_type: AuthType,
    /// JWKS URL for JWT validation
    pub jwks_url: Option<String>,
    /// Header name for API key (default: X-API-Key)
    pub api_key_header: String,
    /// Query parameter name for API key
    pub api_key_query: Option<String>,
    /// Valid API keys (hashed or plain)
    pub api_keys: HashSet<String>,
    /// Basic auth credentials (username -> password hash)
    pub basic_credentials: HashMap<String, String>,
    /// Required claims for JWT
    pub required_claims: Vec<String>,
    /// Required audience
    pub required_audience: Option<String>,
    /// Required issuer
    pub required_issuer: Option<String>,
    /// JWKS cache TTL
    pub jwks_cache_ttl: Duration,
    /// Whether to pass claims as headers
    pub pass_claims_as_headers: bool,
}

impl Default for AuthMiddlewareConfig {
    fn default() -> Self {
        Self {
            auth_type: AuthType::ApiKey,
            jwks_url: None,
            api_key_header: "X-API-Key".to_string(),
            api_key_query: None,
            api_keys: HashSet::new(),
            basic_credentials: HashMap::new(),
            required_claims: Vec::new(),
            required_audience: None,
            required_issuer: None,
            jwks_cache_ttl: Duration::from_secs(300),
            pass_claims_as_headers: false,
        }
    }
}

impl AuthMiddlewareConfig {
    /// Create from AuthConfig
    pub fn from_config(config: &AuthConfig) -> Self {
        let mut cfg = Self {
            auth_type: config.auth_type.clone(),
            jwks_url: config.jwks_url.clone(),
            ..Default::default()
        };

        if let Some(header) = &config.header {
            cfg.api_key_header = header.clone();
        }

        if let Some(keys) = &config.api_keys {
            cfg.api_keys = keys.iter().cloned().collect();
        }

        cfg
    }

    /// Add an API key
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_keys.insert(key.into());
        self
    }

    /// Add basic auth credential
    pub fn with_basic_credential(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.basic_credentials
            .insert(username.into(), password.into());
        self
    }

    /// Set JWKS URL
    pub fn with_jwks_url(mut self, url: impl Into<String>) -> Self {
        self.jwks_url = Some(url.into());
        self
    }

    /// Set required audience
    pub fn with_required_audience(mut self, audience: impl Into<String>) -> Self {
        self.required_audience = Some(audience.into());
        self
    }

    /// Set required issuer
    pub fn with_required_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.required_issuer = Some(issuer.into());
        self
    }
}

/// Authentication middleware
pub struct AuthMiddleware {
    config: AuthMiddlewareConfig,
    jwks_cache: Arc<RwLock<Option<JwksCacheEntry>>>,
    http_client: reqwest::Client,
}

impl AuthMiddleware {
    /// Create a new auth middleware
    pub fn new(config: AuthMiddlewareConfig) -> Self {
        Self {
            config,
            jwks_cache: Arc::new(RwLock::new(None)),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Create from AuthConfig
    pub fn from_config(config: &AuthConfig) -> Self {
        Self::new(AuthMiddlewareConfig::from_config(config))
    }

    /// Create JWT auth middleware
    pub fn jwt(jwks_url: impl Into<String>) -> Self {
        Self::new(AuthMiddlewareConfig {
            auth_type: AuthType::Jwt,
            jwks_url: Some(jwks_url.into()),
            ..Default::default()
        })
    }

    /// Create API key auth middleware
    pub fn api_key(keys: Vec<String>) -> Self {
        Self::new(AuthMiddlewareConfig {
            auth_type: AuthType::ApiKey,
            api_keys: keys.into_iter().collect(),
            ..Default::default()
        })
    }

    /// Create basic auth middleware
    pub fn basic(credentials: HashMap<String, String>) -> Self {
        Self::new(AuthMiddlewareConfig {
            auth_type: AuthType::Basic,
            basic_credentials: credentials,
            ..Default::default()
        })
    }

    /// Extract bearer token from Authorization header
    fn extract_bearer_token(&self, request: &HttpRequest) -> Option<String> {
        request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_string())
    }

    /// Extract API key from request
    fn extract_api_key(&self, request: &HttpRequest) -> Option<String> {
        // Try header first
        if let Some(key) = request
            .headers()
            .get(&self.config.api_key_header)
            .and_then(|v| v.to_str().ok())
        {
            return Some(key.to_string());
        }

        // Try query parameter if configured
        if let Some(param_name) = &self.config.api_key_query {
            if let Some(query) = request.uri().query() {
                for pair in query.split('&') {
                    if let Some((key, value)) = pair.split_once('=') {
                        if key == param_name {
                            return Some(value.to_string());
                        }
                    }
                }
            }
        }

        None
    }

    /// Extract basic auth credentials
    fn extract_basic_credentials(&self, request: &HttpRequest) -> Option<(String, String)> {
        request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Basic "))
            .and_then(|encoded| {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .ok()
            })
            .and_then(|decoded| String::from_utf8(decoded).ok())
            .and_then(|credentials| {
                credentials
                    .split_once(':')
                    .map(|(u, p)| (u.to_string(), p.to_string()))
            })
    }

    /// Fetch JWKS from URL
    async fn fetch_jwks(&self) -> Result<Jwks> {
        let url = self
            .config
            .jwks_url
            .as_ref()
            .ok_or_else(|| PrismError::Auth("JWKS URL not configured".to_string()))?;

        // Check cache first
        {
            let cache = self.jwks_cache.read();
            if let Some(entry) = cache.as_ref() {
                if entry.fetched_at.elapsed() < self.config.jwks_cache_ttl {
                    return Ok(entry.jwks.clone());
                }
            }
        }

        // Fetch from URL
        debug!("Fetching JWKS from {}", url);
        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| PrismError::Auth(format!("Failed to fetch JWKS: {}", e)))?;

        if !response.status().is_success() {
            return Err(PrismError::Auth(format!(
                "JWKS fetch failed with status: {}",
                response.status()
            )));
        }

        let jwks: Jwks = response
            .json()
            .await
            .map_err(|e| PrismError::Auth(format!("Failed to parse JWKS: {}", e)))?;

        // Update cache
        {
            let mut cache = self.jwks_cache.write();
            *cache = Some(JwksCacheEntry {
                jwks: jwks.clone(),
                fetched_at: Instant::now(),
            });
        }

        Ok(jwks)
    }

    /// Validate JWT token
    async fn validate_jwt(&self, token: &str) -> Result<JwtClaims> {
        // Decode header to get kid
        let header = decode_header(token)
            .map_err(|e| PrismError::Auth(format!("Invalid JWT header: {}", e)))?;

        // Fetch JWKS
        let jwks = self.fetch_jwks().await?;

        // Find matching key
        let jwk = if let Some(kid) = &header.kid {
            jwks.keys
                .iter()
                .find(|k| k.kid.as_ref() == Some(kid))
                .ok_or_else(|| PrismError::Auth(format!("No matching key for kid: {}", kid)))?
        } else {
            // Use first key if no kid specified
            jwks.keys
                .first()
                .ok_or_else(|| PrismError::Auth("No keys in JWKS".to_string()))?
        };

        // Create decoding key
        let decoding_key = jwk.to_decoding_key()?;

        // Create validation
        let mut validation = Validation::new(jwk.algorithm());

        if let Some(aud) = &self.config.required_audience {
            validation.set_audience(&[aud]);
        } else {
            validation.validate_aud = false;
        }

        if let Some(iss) = &self.config.required_issuer {
            validation.set_issuer(&[iss]);
        }

        // Decode and validate
        let token_data = decode::<JwtClaims>(token, &decoding_key, &validation)
            .map_err(|e| PrismError::Auth(format!("JWT validation failed: {}", e)))?;

        // Check required claims
        for claim in &self.config.required_claims {
            if !token_data.claims.custom.contains_key(claim) {
                return Err(PrismError::Auth(format!(
                    "Missing required claim: {}",
                    claim
                )));
            }
        }

        Ok(token_data.claims)
    }

    /// Validate API key
    fn validate_api_key(&self, key: &str) -> bool {
        self.config.api_keys.contains(key)
    }

    /// Validate basic auth credentials
    fn validate_basic(&self, username: &str, password: &str) -> bool {
        self.config
            .basic_credentials
            .get(username)
            .map(|stored| stored == password)
            .unwrap_or(false)
    }

    /// Create unauthorized response
    fn unauthorized_response(&self, message: &str) -> HttpResponse {
        let body = serde_json::json!({
            "error": "Unauthorized",
            "message": message
        });

        let mut response = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::CONTENT_TYPE, "application/json");

        // Add WWW-Authenticate header based on auth type
        response = match self.config.auth_type {
            AuthType::Jwt => response.header(header::WWW_AUTHENTICATE, "Bearer"),
            AuthType::Basic => response.header(header::WWW_AUTHENTICATE, "Basic realm=\"Prism\""),
            AuthType::ApiKey => response,
        };

        response
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap()
    }

    /// Create forbidden response
    fn forbidden_response(&self, message: &str) -> HttpResponse {
        let body = serde_json::json!({
            "error": "Forbidden",
            "message": message
        });

        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap()
    }
}

#[async_trait]
impl Middleware for AuthMiddleware {
    async fn process(
        &self,
        request: HttpRequest,
        mut ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        match self.config.auth_type {
            AuthType::Jwt => {
                let token = match self.extract_bearer_token(&request) {
                    Some(t) => t,
                    None => {
                        debug!("No bearer token found");
                        return Ok(self.unauthorized_response("Bearer token required"));
                    }
                };

                match self.validate_jwt(&token).await {
                    Ok(claims) => {
                        debug!("JWT validated successfully for sub: {:?}", claims.sub);

                        // Add user info to context
                        if let Some(sub) = &claims.sub {
                            ctx.metadata.insert("auth.subject".to_string(), sub.clone());
                        }
                        if let Some(iss) = &claims.iss {
                            ctx.metadata.insert("auth.issuer".to_string(), iss.clone());
                        }

                        next.run(request, ctx).await
                    }
                    Err(e) => {
                        warn!("JWT validation failed: {}", e);
                        Ok(self.unauthorized_response("Invalid token"))
                    }
                }
            }
            AuthType::ApiKey => {
                let key = match self.extract_api_key(&request) {
                    Some(k) => k,
                    None => {
                        debug!("No API key found");
                        return Ok(self.unauthorized_response("API key required"));
                    }
                };

                if self.validate_api_key(&key) {
                    debug!("API key validated successfully");
                    ctx.metadata
                        .insert("auth.method".to_string(), "api_key".to_string());
                    next.run(request, ctx).await
                } else {
                    warn!("Invalid API key attempted");
                    Ok(self.forbidden_response("Invalid API key"))
                }
            }
            AuthType::Basic => {
                let (username, password) = match self.extract_basic_credentials(&request) {
                    Some(creds) => creds,
                    None => {
                        debug!("No basic auth credentials found");
                        return Ok(self.unauthorized_response("Basic authentication required"));
                    }
                };

                if self.validate_basic(&username, &password) {
                    debug!("Basic auth validated for user: {}", username);
                    ctx.metadata.insert("auth.user".to_string(), username);
                    ctx.metadata
                        .insert("auth.method".to_string(), "basic".to_string());
                    next.run(request, ctx).await
                } else {
                    warn!("Invalid basic auth credentials for user: {}", username);
                    Ok(self.forbidden_response("Invalid credentials"))
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "auth"
    }
}

/// Authentication result
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authenticated with claims
    Authenticated(JwtClaims),
    /// Authenticated with API key
    ApiKeyAuthenticated,
    /// Authenticated with basic auth
    BasicAuthenticated(String),
    /// Not authenticated
    Unauthenticated,
    /// Authentication failed
    Failed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_config() {
        let config = AuthMiddlewareConfig::default()
            .with_api_key("test-key-1")
            .with_api_key("test-key-2");

        assert!(config.api_keys.contains("test-key-1"));
        assert!(config.api_keys.contains("test-key-2"));
        assert!(!config.api_keys.contains("test-key-3"));
    }

    #[test]
    fn test_basic_auth_config() {
        let config = AuthMiddlewareConfig::default()
            .with_basic_credential("admin", "password123")
            .with_basic_credential("user", "userpass");

        assert_eq!(
            config.basic_credentials.get("admin"),
            Some(&"password123".to_string())
        );
        assert_eq!(
            config.basic_credentials.get("user"),
            Some(&"userpass".to_string())
        );
    }

    #[test]
    fn test_api_key_validation() {
        let middleware =
            AuthMiddleware::api_key(vec!["valid-key-1".to_string(), "valid-key-2".to_string()]);

        assert!(middleware.validate_api_key("valid-key-1"));
        assert!(middleware.validate_api_key("valid-key-2"));
        assert!(!middleware.validate_api_key("invalid-key"));
    }

    #[test]
    fn test_basic_validation() {
        let mut credentials = HashMap::new();
        credentials.insert("admin".to_string(), "secret".to_string());

        let middleware = AuthMiddleware::basic(credentials);

        assert!(middleware.validate_basic("admin", "secret"));
        assert!(!middleware.validate_basic("admin", "wrong"));
        assert!(!middleware.validate_basic("unknown", "secret"));
    }

    #[test]
    fn test_one_or_many() {
        let one = OneOrMany::One("test".to_string());
        assert!(one.contains("test"));
        assert!(!one.contains("other"));

        let many = OneOrMany::Many(vec!["a".to_string(), "b".to_string()]);
        assert!(many.contains("a"));
        assert!(many.contains("b"));
        assert!(!many.contains("c"));
    }

    #[test]
    fn test_jwt_algorithm_mapping() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: None,
            key_use: None,
            alg: Some("RS256".to_string()),
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        assert!(matches!(jwk.algorithm(), Algorithm::RS256));

        let jwk_ec = Jwk {
            kty: "EC".to_string(),
            alg: Some("ES256".to_string()),
            ..jwk.clone()
        };
        assert!(matches!(jwk_ec.algorithm(), Algorithm::ES256));
    }
}
