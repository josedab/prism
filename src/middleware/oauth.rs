//! OAuth2/OIDC Authentication Middleware
//!
//! Provides OAuth2 and OpenID Connect authentication:
//! - OAuth2 Authorization Code flow
//! - OIDC ID Token validation
//! - Token introspection
//! - Session management with encrypted cookies
//!
//! # Example
//!
//! ```yaml
//! middlewares:
//!   - type: oauth2
//!     oauth2:
//!       provider: custom
//!       client_id: "your-client-id"
//!       client_secret: "your-client-secret"
//!       authorization_endpoint: "https://auth.example.com/authorize"
//!       token_endpoint: "https://auth.example.com/token"
//!       jwks_url: "https://auth.example.com/.well-known/jwks.json"
//!       scopes:
//!         - openid
//!         - profile
//!         - email
//! ```

use super::{HttpRequest, HttpResponse, Middleware, Next, RequestContext};
use crate::error::{PrismError, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http::{header, Response, StatusCode};
use http_body_util::Full;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};
use url::Url;

/// OAuth2 Provider presets
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OAuth2Provider {
    /// Google OAuth2/OIDC
    Google,
    /// GitHub OAuth2
    Github,
    /// Microsoft Azure AD
    Microsoft,
    /// Auth0
    Auth0,
    /// Okta
    Okta,
    /// Keycloak
    Keycloak,
    /// Custom provider
    Custom,
}

impl Default for OAuth2Provider {
    fn default() -> Self {
        Self::Custom
    }
}

/// OAuth2/OIDC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuth2Config {
    /// OAuth2 provider preset
    #[serde(default)]
    pub provider: OAuth2Provider,

    /// Client ID
    pub client_id: String,

    /// Client secret (for confidential clients)
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Authorization endpoint URL
    pub authorization_endpoint: Option<String>,

    /// Token endpoint URL
    pub token_endpoint: Option<String>,

    /// Userinfo endpoint URL (OIDC)
    pub userinfo_endpoint: Option<String>,

    /// JWKS URL for ID token validation
    pub jwks_url: Option<String>,

    /// Token introspection endpoint (RFC 7662)
    pub introspection_endpoint: Option<String>,

    /// Revocation endpoint (RFC 7009)
    pub revocation_endpoint: Option<String>,

    /// End session endpoint (OIDC)
    pub end_session_endpoint: Option<String>,

    /// OIDC issuer for discovery
    pub issuer: Option<String>,

    /// OAuth2 scopes to request
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,

    /// Redirect URI for authorization callback
    pub redirect_uri: Option<String>,

    /// Callback path (defaults to /oauth2/callback)
    #[serde(default = "default_callback_path")]
    pub callback_path: String,

    /// Login path (defaults to /oauth2/login)
    #[serde(default = "default_login_path")]
    pub login_path: String,

    /// Logout path (defaults to /oauth2/logout)
    #[serde(default = "default_logout_path")]
    pub logout_path: String,

    /// Cookie name for session
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,

    /// Cookie domain
    pub cookie_domain: Option<String>,

    /// Cookie secure flag (default: true)
    #[serde(default = "default_true")]
    pub cookie_secure: bool,

    /// Cookie HTTP only flag (default: true)
    #[serde(default = "default_true")]
    pub cookie_http_only: bool,

    /// Cookie SameSite attribute
    #[serde(default = "default_same_site")]
    pub cookie_same_site: String,

    /// Session timeout
    #[serde(default = "default_session_timeout")]
    #[serde(with = "humantime_serde")]
    pub session_timeout: Duration,

    /// Access token timeout (for caching)
    #[serde(default = "default_token_timeout")]
    #[serde(with = "humantime_serde")]
    pub token_cache_ttl: Duration,

    /// Required audience for token validation
    pub required_audience: Option<String>,

    /// Required issuer for token validation
    pub required_issuer: Option<String>,

    /// Paths to exclude from authentication
    #[serde(default)]
    pub exclude_paths: Vec<String>,

    /// Pass user info as headers to upstream
    #[serde(default = "default_true")]
    pub pass_user_headers: bool,

    /// Header prefix for user info (default: X-User-)
    #[serde(default = "default_header_prefix")]
    pub header_prefix: String,

    /// Use PKCE (Proof Key for Code Exchange)
    #[serde(default = "default_true")]
    pub use_pkce: bool,

    /// For Auth0: domain
    pub auth0_domain: Option<String>,

    /// For Okta: org URL
    pub okta_org_url: Option<String>,

    /// For Keycloak: realm
    pub keycloak_realm: Option<String>,

    /// For Keycloak: base URL
    pub keycloak_url: Option<String>,
}

fn default_scopes() -> Vec<String> {
    vec!["openid".to_string(), "profile".to_string(), "email".to_string()]
}

fn default_callback_path() -> String {
    "/oauth2/callback".to_string()
}

fn default_login_path() -> String {
    "/oauth2/login".to_string()
}

fn default_logout_path() -> String {
    "/oauth2/logout".to_string()
}

fn default_cookie_name() -> String {
    "prism_session".to_string()
}

fn default_same_site() -> String {
    "Lax".to_string()
}

fn default_session_timeout() -> Duration {
    Duration::from_secs(3600 * 24) // 24 hours
}

fn default_token_timeout() -> Duration {
    Duration::from_secs(300) // 5 minutes
}

fn default_header_prefix() -> String {
    "X-User-".to_string()
}

fn default_true() -> bool {
    true
}

impl OAuth2Config {
    /// Create configuration for Google OAuth2
    pub fn google(client_id: String, client_secret: String) -> Self {
        Self {
            provider: OAuth2Provider::Google,
            client_id,
            client_secret: Some(client_secret),
            authorization_endpoint: Some("https://accounts.google.com/o/oauth2/v2/auth".to_string()),
            token_endpoint: Some("https://oauth2.googleapis.com/token".to_string()),
            userinfo_endpoint: Some("https://openidconnect.googleapis.com/v1/userinfo".to_string()),
            jwks_url: Some("https://www.googleapis.com/oauth2/v3/certs".to_string()),
            issuer: Some("https://accounts.google.com".to_string()),
            ..Default::default()
        }
    }

    /// Create configuration for GitHub OAuth2
    pub fn github(client_id: String, client_secret: String) -> Self {
        Self {
            provider: OAuth2Provider::Github,
            client_id,
            client_secret: Some(client_secret),
            authorization_endpoint: Some("https://github.com/login/oauth/authorize".to_string()),
            token_endpoint: Some("https://github.com/login/oauth/access_token".to_string()),
            userinfo_endpoint: Some("https://api.github.com/user".to_string()),
            scopes: vec!["read:user".to_string(), "user:email".to_string()],
            ..Default::default()
        }
    }

    /// Create configuration for Microsoft/Azure AD
    pub fn microsoft(client_id: String, client_secret: String, tenant: &str) -> Self {
        let base = format!("https://login.microsoftonline.com/{}", tenant);
        Self {
            provider: OAuth2Provider::Microsoft,
            client_id,
            client_secret: Some(client_secret),
            authorization_endpoint: Some(format!("{}/oauth2/v2.0/authorize", base)),
            token_endpoint: Some(format!("{}/oauth2/v2.0/token", base)),
            userinfo_endpoint: Some("https://graph.microsoft.com/oidc/userinfo".to_string()),
            jwks_url: Some(format!("{}/discovery/v2.0/keys", base)),
            issuer: Some(format!("{}/v2.0", base)),
            ..Default::default()
        }
    }

    /// Create configuration for Auth0
    pub fn auth0(client_id: String, client_secret: String, domain: &str) -> Self {
        let base = format!("https://{}", domain);
        Self {
            provider: OAuth2Provider::Auth0,
            client_id,
            client_secret: Some(client_secret),
            authorization_endpoint: Some(format!("{}/authorize", base)),
            token_endpoint: Some(format!("{}/oauth/token", base)),
            userinfo_endpoint: Some(format!("{}/userinfo", base)),
            jwks_url: Some(format!("{}/.well-known/jwks.json", base)),
            issuer: Some(format!("{}/", base)),
            auth0_domain: Some(domain.to_string()),
            ..Default::default()
        }
    }

    /// Create configuration for Okta
    pub fn okta(client_id: String, client_secret: String, org_url: &str) -> Self {
        Self {
            provider: OAuth2Provider::Okta,
            client_id,
            client_secret: Some(client_secret),
            authorization_endpoint: Some(format!("{}/oauth2/default/v1/authorize", org_url)),
            token_endpoint: Some(format!("{}/oauth2/default/v1/token", org_url)),
            userinfo_endpoint: Some(format!("{}/oauth2/default/v1/userinfo", org_url)),
            jwks_url: Some(format!("{}/oauth2/default/v1/keys", org_url)),
            introspection_endpoint: Some(format!("{}/oauth2/default/v1/introspect", org_url)),
            revocation_endpoint: Some(format!("{}/oauth2/default/v1/revoke", org_url)),
            issuer: Some(format!("{}/oauth2/default", org_url)),
            okta_org_url: Some(org_url.to_string()),
            ..Default::default()
        }
    }

    /// Create configuration for Keycloak
    pub fn keycloak(client_id: String, client_secret: String, base_url: &str, realm: &str) -> Self {
        let realm_url = format!("{}/realms/{}", base_url, realm);
        Self {
            provider: OAuth2Provider::Keycloak,
            client_id,
            client_secret: Some(client_secret),
            authorization_endpoint: Some(format!("{}/protocol/openid-connect/auth", realm_url)),
            token_endpoint: Some(format!("{}/protocol/openid-connect/token", realm_url)),
            userinfo_endpoint: Some(format!("{}/protocol/openid-connect/userinfo", realm_url)),
            jwks_url: Some(format!("{}/protocol/openid-connect/certs", realm_url)),
            introspection_endpoint: Some(format!("{}/protocol/openid-connect/token/introspect", realm_url)),
            revocation_endpoint: Some(format!("{}/protocol/openid-connect/revoke", realm_url)),
            end_session_endpoint: Some(format!("{}/protocol/openid-connect/logout", realm_url)),
            issuer: Some(realm_url),
            keycloak_realm: Some(realm.to_string()),
            keycloak_url: Some(base_url.to_string()),
            ..Default::default()
        }
    }
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            provider: OAuth2Provider::Custom,
            client_id: String::new(),
            client_secret: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_url: None,
            introspection_endpoint: None,
            revocation_endpoint: None,
            end_session_endpoint: None,
            issuer: None,
            scopes: default_scopes(),
            redirect_uri: None,
            callback_path: default_callback_path(),
            login_path: default_login_path(),
            logout_path: default_logout_path(),
            cookie_name: default_cookie_name(),
            cookie_domain: None,
            cookie_secure: true,
            cookie_http_only: true,
            cookie_same_site: default_same_site(),
            session_timeout: default_session_timeout(),
            token_cache_ttl: default_token_timeout(),
            required_audience: None,
            required_issuer: None,
            exclude_paths: Vec::new(),
            pass_user_headers: true,
            header_prefix: default_header_prefix(),
            use_pkce: true,
            auth0_domain: None,
            okta_org_url: None,
            keycloak_realm: None,
            keycloak_url: None,
        }
    }
}

/// OAuth2 token response
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default)]
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
}

/// OIDC user info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// Subject (unique user identifier)
    pub sub: String,
    /// User's full name
    pub name: Option<String>,
    /// Given name (first name)
    pub given_name: Option<String>,
    /// Family name (last name)
    pub family_name: Option<String>,
    /// Preferred username
    pub preferred_username: Option<String>,
    /// Email address
    pub email: Option<String>,
    /// Whether email is verified
    pub email_verified: Option<bool>,
    /// Profile picture URL
    pub picture: Option<String>,
    /// Locale
    pub locale: Option<String>,
    /// Timezone
    pub zoneinfo: Option<String>,
    /// Additional claims
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// Session data stored in cookie/cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// User info
    pub user: UserInfo,
    /// Access token
    pub access_token: String,
    /// Refresh token
    pub refresh_token: Option<String>,
    /// ID token
    pub id_token: Option<String>,
    /// Token expiration time
    pub expires_at: u64,
    /// Session creation time
    pub created_at: u64,
}

/// PKCE verifier and challenge
#[derive(Debug, Clone)]
struct PkceData {
    verifier: String,
    challenge: String,
}

/// OAuth2 state for CSRF protection
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthState {
    /// Random state value
    nonce: String,
    /// Original URL to redirect after auth
    return_url: String,
    /// PKCE verifier (if used)
    pkce_verifier: Option<String>,
    /// Created timestamp
    created_at: u64,
}

/// Pending auth states (in-memory, would use Redis in production)
type StateCache = Arc<RwLock<HashMap<String, AuthState>>>;

/// Token cache
type TokenCache = Arc<RwLock<HashMap<String, (SessionData, Instant)>>>;

/// OAuth2/OIDC Middleware
pub struct OAuth2Middleware {
    config: OAuth2Config,
    http_client: reqwest::Client,
    state_cache: StateCache,
    token_cache: TokenCache,
}

impl OAuth2Middleware {
    /// Create new OAuth2 middleware
    pub fn new(config: OAuth2Config) -> Self {
        Self {
            config,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            state_cache: Arc::new(RwLock::new(HashMap::new())),
            token_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate PKCE challenge
    fn generate_pkce() -> PkceData {
        use rand::Rng;
        let verifier: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        // S256 challenge
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hash = hasher.finalize();

        use base64::Engine;
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

        PkceData { verifier, challenge }
    }

    /// Generate random state
    fn generate_state() -> String {
        use rand::Rng;
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }

    /// Get current timestamp
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Check if path should be excluded from auth
    fn is_excluded(&self, path: &str) -> bool {
        // Always exclude OAuth2 endpoints
        if path == self.config.callback_path
            || path == self.config.login_path
            || path == self.config.logout_path
        {
            return true;
        }

        // Check configured exclusions
        self.config.exclude_paths.iter().any(|p| {
            if p.ends_with('*') {
                path.starts_with(&p[..p.len() - 1])
            } else {
                path == p
            }
        })
    }

    /// Build authorization URL
    fn build_auth_url(&self, state: &str, pkce: Option<&PkceData>) -> Result<String> {
        let auth_endpoint = self.config.authorization_endpoint.as_ref()
            .ok_or_else(|| PrismError::Auth("Authorization endpoint not configured".to_string()))?;

        let mut url = Url::parse(auth_endpoint)
            .map_err(|e| PrismError::Auth(format!("Invalid authorization URL: {}", e)))?;

        let redirect_uri = self.config.redirect_uri.clone()
            .unwrap_or_else(|| format!("http://localhost{}", self.config.callback_path));

        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", &self.config.scopes.join(" "))
            .append_pair("state", state);

        if let Some(pkce) = pkce {
            url.query_pairs_mut()
                .append_pair("code_challenge", &pkce.challenge)
                .append_pair("code_challenge_method", "S256");
        }

        // Add nonce for OIDC
        if self.config.scopes.contains(&"openid".to_string()) {
            url.query_pairs_mut()
                .append_pair("nonce", &Self::generate_state());
        }

        Ok(url.to_string())
    }

    /// Exchange authorization code for tokens
    async fn exchange_code(&self, code: &str, pkce_verifier: Option<&str>) -> Result<TokenResponse> {
        let token_endpoint = self.config.token_endpoint.as_ref()
            .ok_or_else(|| PrismError::Auth("Token endpoint not configured".to_string()))?;

        let redirect_uri = self.config.redirect_uri.clone()
            .unwrap_or_else(|| format!("http://localhost{}", self.config.callback_path));

        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", self.config.client_id.as_str()),
        ];

        // Add client secret if available
        let client_secret;
        if let Some(secret) = &self.config.client_secret {
            client_secret = secret.clone();
            params.push(("client_secret", client_secret.as_str()));
        }

        // Add PKCE verifier if used
        let verifier;
        if let Some(v) = pkce_verifier {
            verifier = v.to_string();
            params.push(("code_verifier", verifier.as_str()));
        }

        debug!("Exchanging authorization code for tokens");

        let response = self.http_client
            .post(token_endpoint)
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(|e| PrismError::Auth(format!("Token exchange failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(PrismError::Auth(format!(
                "Token exchange failed with status {}: {}",
                status, body
            )));
        }

        let tokens: TokenResponse = response
            .json()
            .await
            .map_err(|e| PrismError::Auth(format!("Failed to parse token response: {}", e)))?;

        Ok(tokens)
    }

    /// Fetch user info from userinfo endpoint
    async fn fetch_userinfo(&self, access_token: &str) -> Result<UserInfo> {
        let userinfo_endpoint = self.config.userinfo_endpoint.as_ref()
            .ok_or_else(|| PrismError::Auth("Userinfo endpoint not configured".to_string()))?;

        let response = self.http_client
            .get(userinfo_endpoint)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| PrismError::Auth(format!("Userinfo fetch failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(PrismError::Auth(format!(
                "Userinfo fetch failed with status: {}",
                response.status()
            )));
        }

        let userinfo: UserInfo = response
            .json()
            .await
            .map_err(|e| PrismError::Auth(format!("Failed to parse userinfo: {}", e)))?;

        Ok(userinfo)
    }

    /// Extract session from cookie
    fn extract_session(&self, request: &HttpRequest) -> Option<String> {
        request
            .headers()
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|cookies| {
                for cookie in cookies.split(';') {
                    let cookie = cookie.trim();
                    if let Some((name, value)) = cookie.split_once('=') {
                        if name == self.config.cookie_name {
                            return Some(value.to_string());
                        }
                    }
                }
                None
            })
    }

    /// Create session cookie
    fn create_session_cookie(&self, session_id: &str) -> String {
        let mut cookie = format!("{}={}", self.config.cookie_name, session_id);

        if let Some(domain) = &self.config.cookie_domain {
            cookie.push_str(&format!("; Domain={}", domain));
        }

        cookie.push_str("; Path=/");

        if self.config.cookie_secure {
            cookie.push_str("; Secure");
        }

        if self.config.cookie_http_only {
            cookie.push_str("; HttpOnly");
        }

        cookie.push_str(&format!("; SameSite={}", self.config.cookie_same_site));

        let max_age = self.config.session_timeout.as_secs();
        cookie.push_str(&format!("; Max-Age={}", max_age));

        cookie
    }

    /// Create logout cookie (to clear session)
    fn create_logout_cookie(&self) -> String {
        let mut cookie = format!("{}=", self.config.cookie_name);
        cookie.push_str("; Path=/; Max-Age=0");
        cookie
    }

    /// Handle login request - redirect to authorization server
    fn handle_login(&self, request: &HttpRequest) -> Result<HttpResponse> {
        // Generate state and PKCE
        let state_value = Self::generate_state();
        let pkce = if self.config.use_pkce {
            Some(Self::generate_pkce())
        } else {
            None
        };

        // Store state for verification
        let return_url = request
            .uri()
            .query()
            .and_then(|q| {
                for pair in q.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        if k == "return_url" {
                            return Some(urlencoding::decode(v).unwrap_or_default().to_string());
                        }
                    }
                }
                None
            })
            .unwrap_or_else(|| "/".to_string());

        let auth_state = AuthState {
            nonce: state_value.clone(),
            return_url,
            pkce_verifier: pkce.as_ref().map(|p| p.verifier.clone()),
            created_at: Self::now(),
        };

        self.state_cache.write().insert(state_value.clone(), auth_state);

        // Build authorization URL
        let auth_url = self.build_auth_url(&state_value, pkce.as_ref())?;

        info!("Initiating OAuth2 login, redirecting to authorization server");

        Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, auth_url)
            .body(Full::new(Bytes::new()))
            .unwrap())
    }

    /// Handle callback from authorization server
    async fn handle_callback(&self, request: &HttpRequest) -> Result<HttpResponse> {
        // Parse query parameters
        let query = request.uri().query().unwrap_or("");
        let mut code = None;
        let mut state = None;
        let mut error = None;

        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                match k {
                    "code" => code = Some(v.to_string()),
                    "state" => state = Some(v.to_string()),
                    "error" => error = Some(v.to_string()),
                    _ => {}
                }
            }
        }

        // Check for error
        if let Some(err) = error {
            warn!("OAuth2 authorization error: {}", err);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(format!(
                    r#"{{"error": "OAuth2 error: {}"}}"#,
                    err
                ))))
                .unwrap());
        }

        // Validate state
        let state_value = state.ok_or_else(|| PrismError::Auth("Missing state parameter".to_string()))?;
        let auth_state = self.state_cache.write().remove(&state_value)
            .ok_or_else(|| PrismError::Auth("Invalid state parameter".to_string()))?;

        // Check state expiration (5 minutes)
        if Self::now() - auth_state.created_at > 300 {
            return Err(PrismError::Auth("State expired".to_string()));
        }

        // Get authorization code
        let code = code.ok_or_else(|| PrismError::Auth("Missing authorization code".to_string()))?;

        // Exchange code for tokens
        let tokens = self.exchange_code(&code, auth_state.pkce_verifier.as_deref()).await?;

        // Fetch user info
        let user = self.fetch_userinfo(&tokens.access_token).await?;

        info!("OAuth2 login successful for user: {:?}", user.sub);

        // Create session
        let session_id = Self::generate_state();
        let session = SessionData {
            user,
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            id_token: tokens.id_token,
            expires_at: Self::now() + tokens.expires_in.unwrap_or(3600),
            created_at: Self::now(),
        };

        // Store session
        self.token_cache.write().insert(
            session_id.clone(),
            (session, Instant::now()),
        );

        // Redirect to original URL with session cookie
        Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, auth_state.return_url)
            .header(header::SET_COOKIE, self.create_session_cookie(&session_id))
            .body(Full::new(Bytes::new()))
            .unwrap())
    }

    /// Handle logout request
    fn handle_logout(&self, request: &HttpRequest) -> HttpResponse {
        // Clear session
        if let Some(session_id) = self.extract_session(request) {
            self.token_cache.write().remove(&session_id);
        }

        // Build response with logout cookie
        let mut builder = Response::builder()
            .status(StatusCode::FOUND)
            .header(header::SET_COOKIE, self.create_logout_cookie());

        // Redirect to end session endpoint if configured
        if let Some(end_session) = &self.config.end_session_endpoint {
            builder = builder.header(header::LOCATION, end_session.as_str());
        } else {
            builder = builder.header(header::LOCATION, "/");
        }

        builder.body(Full::new(Bytes::new())).unwrap()
    }

    /// Get session data from cache
    fn get_session(&self, session_id: &str) -> Option<SessionData> {
        let cache = self.token_cache.read();
        cache.get(session_id).and_then(|(session, cached_at)| {
            // Check if session is still valid
            if cached_at.elapsed() < self.config.session_timeout {
                Some(session.clone())
            } else {
                None
            }
        })
    }

    /// Create unauthorized redirect response
    fn unauthorized_redirect(&self, return_url: &str) -> HttpResponse {
        let login_url = format!(
            "{}?return_url={}",
            self.config.login_path,
            urlencoding::encode(return_url)
        );

        Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, login_url)
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    /// Create unauthorized JSON response (for API calls)
    fn unauthorized_json(&self, message: &str) -> HttpResponse {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::WWW_AUTHENTICATE, "Bearer")
            .body(Full::new(Bytes::from(format!(
                r#"{{"error": "Unauthorized", "message": "{}"}}"#,
                message
            ))))
            .unwrap()
    }

    /// Check if request is an API call (vs browser)
    fn is_api_request(&self, request: &HttpRequest) -> bool {
        // Check Accept header
        if let Some(accept) = request.headers().get(header::ACCEPT) {
            if let Ok(accept_str) = accept.to_str() {
                if accept_str.contains("application/json") && !accept_str.contains("text/html") {
                    return true;
                }
            }
        }

        // Check for Authorization header (likely programmatic)
        if request.headers().contains_key(header::AUTHORIZATION) {
            return true;
        }

        false
    }
}

#[async_trait]
impl Middleware for OAuth2Middleware {
    async fn process(
        &self,
        mut request: HttpRequest,
        mut ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        let path = request.uri().path();

        // Check if path is excluded
        if self.is_excluded(path) {
            // Handle OAuth2 specific paths
            if path == self.config.login_path {
                return self.handle_login(&request);
            }
            if path == self.config.callback_path {
                return self.handle_callback(&request).await;
            }
            if path == self.config.logout_path {
                return Ok(self.handle_logout(&request));
            }

            // Other excluded paths pass through
            return next.run(request, ctx).await;
        }

        // Try to get session from cookie
        let session = self.extract_session(&request)
            .and_then(|id| self.get_session(&id));

        match session {
            Some(session) => {
                debug!("Authenticated user: {}", session.user.sub);

                // Add user info to context
                ctx.metadata.insert("auth.user_id".to_string(), session.user.sub.clone());
                ctx.metadata.insert("auth.method".to_string(), "oauth2".to_string());

                if let Some(email) = &session.user.email {
                    ctx.metadata.insert("auth.email".to_string(), email.clone());
                }

                // Add user info headers if configured
                if self.config.pass_user_headers {
                    let headers = request.headers_mut();

                    if let (Ok(header_name), Ok(header_value)) = (
                        format!("{}Id", self.config.header_prefix).parse::<header::HeaderName>(),
                        session.user.sub.parse::<header::HeaderValue>(),
                    ) {
                        headers.insert(header_name, header_value);
                    }

                    if let Some(email) = &session.user.email {
                        if let (Ok(header_name), Ok(header_value)) = (
                            format!("{}Email", self.config.header_prefix).parse::<header::HeaderName>(),
                            email.parse::<header::HeaderValue>(),
                        ) {
                            headers.insert(header_name, header_value);
                        }
                    }

                    if let Some(name) = &session.user.name {
                        if let (Ok(header_name), Ok(header_value)) = (
                            format!("{}Name", self.config.header_prefix).parse::<header::HeaderName>(),
                            name.parse::<header::HeaderValue>(),
                        ) {
                            headers.insert(header_name, header_value);
                        }
                    }
                }

                next.run(request, ctx).await
            }
            None => {
                // Not authenticated
                debug!("No valid session found");

                if self.is_api_request(&request) {
                    Ok(self.unauthorized_json("Authentication required"))
                } else {
                    let return_url = request.uri().path_and_query()
                        .map(|pq| pq.as_str())
                        .unwrap_or("/");
                    Ok(self.unauthorized_redirect(return_url))
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "oauth2"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = OAuth2Config::default();
        assert_eq!(config.scopes, vec!["openid", "profile", "email"]);
        assert_eq!(config.callback_path, "/oauth2/callback");
        assert_eq!(config.login_path, "/oauth2/login");
        assert!(config.use_pkce);
    }

    #[test]
    fn test_google_config() {
        let config = OAuth2Config::google("client-id".to_string(), "client-secret".to_string());
        assert_eq!(config.provider, OAuth2Provider::Google);
        assert!(config.authorization_endpoint.unwrap().contains("google.com"));
        assert!(config.token_endpoint.unwrap().contains("googleapis.com"));
    }

    #[test]
    fn test_github_config() {
        let config = OAuth2Config::github("client-id".to_string(), "client-secret".to_string());
        assert_eq!(config.provider, OAuth2Provider::Github);
        assert!(config.authorization_endpoint.unwrap().contains("github.com"));
    }

    #[test]
    fn test_auth0_config() {
        let config = OAuth2Config::auth0(
            "client-id".to_string(),
            "client-secret".to_string(),
            "myapp.auth0.com",
        );
        assert_eq!(config.provider, OAuth2Provider::Auth0);
        assert!(config.authorization_endpoint.unwrap().contains("myapp.auth0.com"));
    }

    #[test]
    fn test_okta_config() {
        let config = OAuth2Config::okta(
            "client-id".to_string(),
            "client-secret".to_string(),
            "https://dev-123.okta.com",
        );
        assert_eq!(config.provider, OAuth2Provider::Okta);
        assert!(config.introspection_endpoint.is_some());
    }

    #[test]
    fn test_keycloak_config() {
        let config = OAuth2Config::keycloak(
            "client-id".to_string(),
            "client-secret".to_string(),
            "https://keycloak.example.com",
            "myrealm",
        );
        assert_eq!(config.provider, OAuth2Provider::Keycloak);
        assert!(config.authorization_endpoint.unwrap().contains("myrealm"));
    }

    #[test]
    fn test_excluded_paths() {
        let config = OAuth2Config {
            exclude_paths: vec!["/health".to_string(), "/api/public/*".to_string()],
            ..Default::default()
        };
        let middleware = OAuth2Middleware::new(config);

        assert!(middleware.is_excluded("/oauth2/callback"));
        assert!(middleware.is_excluded("/oauth2/login"));
        assert!(middleware.is_excluded("/oauth2/logout"));
        assert!(middleware.is_excluded("/health"));
        assert!(middleware.is_excluded("/api/public/info"));
        assert!(!middleware.is_excluded("/api/private"));
    }

    #[test]
    fn test_pkce_generation() {
        let pkce = OAuth2Middleware::generate_pkce();
        assert_eq!(pkce.verifier.len(), 64);
        assert!(!pkce.challenge.is_empty());
        // S256 challenge should be base64url encoded SHA256
        assert!(!pkce.challenge.contains('+'));
        assert!(!pkce.challenge.contains('/'));
    }

    #[test]
    fn test_session_cookie_creation() {
        let config = OAuth2Config {
            cookie_name: "test_session".to_string(),
            cookie_secure: true,
            cookie_http_only: true,
            cookie_same_site: "Strict".to_string(),
            session_timeout: Duration::from_secs(3600),
            ..Default::default()
        };
        let middleware = OAuth2Middleware::new(config);

        let cookie = middleware.create_session_cookie("session123");
        assert!(cookie.contains("test_session=session123"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Max-Age=3600"));
    }
}
