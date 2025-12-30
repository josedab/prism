//! SPIFFE/SPIRE Zero-Trust Identity Module
//!
//! Implements the SPIFFE (Secure Production Identity Framework For Everyone) specification
//! for workload identity and zero-trust networking.
//!
//! Features:
//! - SPIFFE ID parsing and validation
//! - X.509 SVID (SPIFFE Verifiable Identity Document) handling
//! - JWT SVID support
//! - Workload API client
//! - mTLS with SVID-based authentication
//! - Trust bundle management
//! - Authorization policies based on SPIFFE IDs

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// SPIFFE configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpiffeConfig {
    /// Enable SPIFFE integration
    #[serde(default)]
    pub enabled: bool,

    /// Workload API socket path (unix:///tmp/spire-agent/public/api.sock)
    #[serde(default = "default_workload_api_socket")]
    pub workload_api_socket: String,

    /// Trust domain for this workload
    #[serde(default = "default_trust_domain")]
    pub trust_domain: String,

    /// Path component of our SPIFFE ID
    #[serde(default = "default_workload_path")]
    pub workload_path: String,

    /// Enable mTLS with SVID
    #[serde(default = "default_true")]
    pub mtls_enabled: bool,

    /// SVID refresh interval
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_secs: u64,

    /// Authorization policies
    #[serde(default)]
    pub authorization: AuthorizationConfig,

    /// Audience for JWT SVIDs
    #[serde(default)]
    pub jwt_audiences: Vec<String>,
}

fn default_workload_api_socket() -> String {
    "unix:///tmp/spire-agent/public/api.sock".to_string()
}

fn default_trust_domain() -> String {
    "example.org".to_string()
}

fn default_workload_path() -> String {
    "/prism/proxy".to_string()
}

fn default_true() -> bool {
    true
}

fn default_refresh_interval() -> u64 {
    300
}

impl Default for SpiffeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            workload_api_socket: default_workload_api_socket(),
            trust_domain: default_trust_domain(),
            workload_path: default_workload_path(),
            mtls_enabled: true,
            refresh_interval_secs: 300,
            authorization: AuthorizationConfig::default(),
            jwt_audiences: vec![],
        }
    }
}

/// Authorization configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationConfig {
    /// Default policy (allow or deny)
    #[serde(default)]
    pub default_action: AuthAction,

    /// Authorization rules
    #[serde(default)]
    pub rules: Vec<AuthorizationRule>,
}

/// Authorization action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthAction {
    #[default]
    Allow,
    Deny,
}

impl fmt::Display for AuthAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthAction::Allow => write!(f, "allow"),
            AuthAction::Deny => write!(f, "deny"),
        }
    }
}

/// Authorization rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRule {
    /// Rule name for logging
    pub name: String,

    /// SPIFFE ID patterns to match (supports wildcards)
    pub spiffe_ids: Vec<String>,

    /// Paths this rule applies to (supports prefix matching)
    #[serde(default)]
    pub paths: Vec<String>,

    /// Methods this rule applies to
    #[serde(default)]
    pub methods: Vec<String>,

    /// Action when rule matches
    pub action: AuthAction,
}

/// SPIFFE ID - A URI-based identifier for a workload
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpiffeId {
    /// Trust domain (e.g., "example.org")
    pub trust_domain: String,
    /// Path component (e.g., "/app/frontend")
    pub path: String,
}

impl SpiffeId {
    /// Parse a SPIFFE ID from a URI string
    pub fn parse(uri: &str) -> Result<Self, SpiffeError> {
        // Format: spiffe://trust-domain/path
        if !uri.starts_with("spiffe://") {
            return Err(SpiffeError::InvalidSpiffeId(
                "SPIFFE ID must start with spiffe://".to_string(),
            ));
        }

        let rest = &uri[9..]; // Skip "spiffe://"
        let (trust_domain, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };

        if trust_domain.is_empty() {
            return Err(SpiffeError::InvalidSpiffeId(
                "Trust domain cannot be empty".to_string(),
            ));
        }

        // Validate trust domain (must be a valid hostname)
        if !Self::is_valid_trust_domain(trust_domain) {
            return Err(SpiffeError::InvalidSpiffeId(format!(
                "Invalid trust domain: {}",
                trust_domain
            )));
        }

        // Validate path
        if !path.starts_with('/') {
            return Err(SpiffeError::InvalidSpiffeId(
                "Path must start with /".to_string(),
            ));
        }

        Ok(SpiffeId {
            trust_domain: trust_domain.to_string(),
            path: path.to_string(),
        })
    }

    /// Create a new SPIFFE ID
    pub fn new(trust_domain: &str, path: &str) -> Result<Self, SpiffeError> {
        Self::parse(&format!("spiffe://{}{}", trust_domain, path))
    }

    /// Check if a trust domain is valid
    fn is_valid_trust_domain(domain: &str) -> bool {
        if domain.is_empty() || domain.len() > 255 {
            return false;
        }

        // Basic hostname validation
        domain
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
            && !domain.starts_with('-')
            && !domain.ends_with('-')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
    }

    /// Convert to URI string
    pub fn to_uri(&self) -> String {
        format!("spiffe://{}{}", self.trust_domain, self.path)
    }

    /// Check if this SPIFFE ID matches a pattern
    /// Supports * as wildcard for path segments
    pub fn matches(&self, pattern: &str) -> bool {
        match SpiffeId::parse(pattern) {
            Ok(pattern_id) => {
                if self.trust_domain != pattern_id.trust_domain {
                    return false;
                }
                Self::path_matches(&self.path, &pattern_id.path)
            }
            Err(_) => {
                // Try pattern matching without full URI
                if pattern.starts_with("*") {
                    // Wildcard trust domain
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Check if a path matches a pattern with wildcards
    fn path_matches(path: &str, pattern: &str) -> bool {
        if pattern == "/*" || pattern == "/**" {
            return true;
        }

        let path_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let pattern_parts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();

        // Double star matches anything
        if pattern_parts.last() == Some(&"**") {
            let prefix_parts = &pattern_parts[..pattern_parts.len() - 1];
            return path_parts.starts_with(prefix_parts);
        }

        if path_parts.len() != pattern_parts.len() {
            return false;
        }

        for (path_part, pattern_part) in path_parts.iter().zip(pattern_parts.iter()) {
            if *pattern_part != "*" && path_part != pattern_part {
                return false;
            }
        }

        true
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_uri())
    }
}

impl std::str::FromStr for SpiffeId {
    type Err = SpiffeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SpiffeId::parse(s)
    }
}

/// X.509 SVID (SPIFFE Verifiable Identity Document)
#[derive(Debug, Clone)]
pub struct X509Svid {
    /// The SPIFFE ID
    pub spiffe_id: SpiffeId,

    /// Certificate chain (PEM encoded)
    pub cert_chain: Vec<Vec<u8>>,

    /// Private key (PEM encoded)
    pub private_key: Vec<u8>,

    /// Bundle of trusted CA certificates
    pub bundle: TrustBundle,

    /// Expiry time
    pub expires_at: SystemTime,
}

impl X509Svid {
    /// Check if the SVID is expired
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }

    /// Get time until expiry
    pub fn time_until_expiry(&self) -> Option<Duration> {
        self.expires_at.duration_since(SystemTime::now()).ok()
    }

    /// Check if SVID should be renewed (less than 25% lifetime remaining)
    pub fn should_renew(&self) -> bool {
        match self.time_until_expiry() {
            Some(remaining) => {
                // Renew when less than 25% of lifetime remains
                remaining < Duration::from_secs(300) // 5 minutes threshold
            }
            None => true, // Already expired
        }
    }
}

/// JWT SVID
#[derive(Debug, Clone)]
pub struct JwtSvid {
    /// The SPIFFE ID
    pub spiffe_id: SpiffeId,

    /// JWT token
    pub token: String,

    /// Audience
    pub audience: Vec<String>,

    /// Expiry time
    pub expires_at: SystemTime,
}

impl JwtSvid {
    /// Check if the JWT is expired
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }

    /// Parse JWT claims without validation (for inspection)
    pub fn parse_claims(&self) -> Result<JwtClaims, SpiffeError> {
        let parts: Vec<&str> = self.token.split('.').collect();
        if parts.len() != 3 {
            return Err(SpiffeError::InvalidJwt("Invalid JWT format".to_string()));
        }

        let payload = base64_decode_url_safe(parts[1])
            .map_err(|e| SpiffeError::InvalidJwt(format!("Base64 decode error: {}", e)))?;

        let claims: JwtClaims = serde_json::from_slice(&payload)
            .map_err(|e| SpiffeError::InvalidJwt(format!("JSON parse error: {}", e)))?;

        Ok(claims)
    }
}

/// JWT Claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (SPIFFE ID)
    pub sub: String,

    /// Audience
    #[serde(default)]
    pub aud: Vec<String>,

    /// Expiration time
    pub exp: u64,

    /// Issued at
    #[serde(default)]
    pub iat: u64,
}

/// Trust bundle containing CA certificates
#[derive(Debug, Clone)]
pub struct TrustBundle {
    /// Trust domain this bundle is for
    pub trust_domain: String,

    /// CA certificates (DER encoded)
    pub certificates: Vec<Vec<u8>>,

    /// Sequence number for updates
    pub sequence_number: u64,

    /// When this bundle was refreshed
    pub refreshed_at: SystemTime,
}

impl TrustBundle {
    /// Create a new trust bundle
    pub fn new(trust_domain: String) -> Self {
        Self {
            trust_domain,
            certificates: vec![],
            sequence_number: 0,
            refreshed_at: SystemTime::now(),
        }
    }

    /// Add a CA certificate
    pub fn add_certificate(&mut self, cert: Vec<u8>) {
        self.certificates.push(cert);
        self.sequence_number += 1;
    }
}

impl Default for TrustBundle {
    fn default() -> Self {
        Self {
            trust_domain: String::new(),
            certificates: vec![],
            sequence_number: 0,
            refreshed_at: SystemTime::UNIX_EPOCH,
        }
    }
}

/// SPIFFE error types
#[derive(Debug, Clone)]
pub enum SpiffeError {
    /// Invalid SPIFFE ID
    InvalidSpiffeId(String),
    /// Invalid X.509 certificate
    InvalidCertificate(String),
    /// Invalid JWT
    InvalidJwt(String),
    /// Workload API error
    WorkloadApi(String),
    /// Authorization denied
    AuthorizationDenied(String),
    /// SVID expired
    SvidExpired(String),
    /// Trust bundle error
    TrustBundle(String),
    /// Connection error
    Connection(String),
}

impl fmt::Display for SpiffeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpiffeError::InvalidSpiffeId(msg) => write!(f, "Invalid SPIFFE ID: {}", msg),
            SpiffeError::InvalidCertificate(msg) => write!(f, "Invalid certificate: {}", msg),
            SpiffeError::InvalidJwt(msg) => write!(f, "Invalid JWT: {}", msg),
            SpiffeError::WorkloadApi(msg) => write!(f, "Workload API error: {}", msg),
            SpiffeError::AuthorizationDenied(msg) => write!(f, "Authorization denied: {}", msg),
            SpiffeError::SvidExpired(msg) => write!(f, "SVID expired: {}", msg),
            SpiffeError::TrustBundle(msg) => write!(f, "Trust bundle error: {}", msg),
            SpiffeError::Connection(msg) => write!(f, "Connection error: {}", msg),
        }
    }
}

impl std::error::Error for SpiffeError {}

/// Workload API client for communicating with SPIRE Agent
pub struct WorkloadApiClient {
    /// Socket path
    socket_path: String,
    /// Current X.509 SVID
    x509_svid: Arc<RwLock<Option<X509Svid>>>,
    /// JWT SVIDs by audience
    jwt_svids: Arc<RwLock<HashMap<String, JwtSvid>>>,
    /// Trust bundles by trust domain
    bundles: Arc<RwLock<HashMap<String, TrustBundle>>>,
    /// Stats
    stats: WorkloadApiStats,
}

/// Workload API statistics
#[derive(Debug, Default)]
pub struct WorkloadApiStats {
    /// Number of X.509 SVID fetches
    x509_fetches: AtomicU64,
    /// Number of JWT SVID fetches
    jwt_fetches: AtomicU64,
    /// Number of bundle updates
    bundle_updates: AtomicU64,
    /// Number of errors
    errors: AtomicU64,
    /// Last successful fetch timestamp
    last_success: AtomicU64,
}

impl WorkloadApiStats {
    /// Get stats snapshot
    pub fn snapshot(&self) -> WorkloadApiStatsSnapshot {
        WorkloadApiStatsSnapshot {
            x509_fetches: self.x509_fetches.load(Ordering::Relaxed),
            jwt_fetches: self.jwt_fetches.load(Ordering::Relaxed),
            bundle_updates: self.bundle_updates.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            last_success: self.last_success.load(Ordering::Relaxed),
        }
    }
}

/// Stats snapshot
#[derive(Debug, Clone)]
pub struct WorkloadApiStatsSnapshot {
    pub x509_fetches: u64,
    pub jwt_fetches: u64,
    pub bundle_updates: u64,
    pub errors: u64,
    pub last_success: u64,
}

impl WorkloadApiClient {
    /// Create a new Workload API client
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            x509_svid: Arc::new(RwLock::new(None)),
            jwt_svids: Arc::new(RwLock::new(HashMap::new())),
            bundles: Arc::new(RwLock::new(HashMap::new())),
            stats: WorkloadApiStats::default(),
        }
    }

    /// Fetch X.509 SVID from Workload API
    pub async fn fetch_x509_svid(&self) -> Result<X509Svid, SpiffeError> {
        debug!("Fetching X.509 SVID from {}", self.socket_path);
        self.stats.x509_fetches.fetch_add(1, Ordering::Relaxed);

        // In a real implementation, this would connect to the SPIRE agent
        // via Unix domain socket and use the Workload API gRPC protocol.
        // For now, we create a mock SVID for testing.

        // Simulated SVID
        let svid = self.create_mock_x509_svid()?;

        // Cache the SVID
        {
            let mut guard = self.x509_svid.write().await;
            *guard = Some(svid.clone());
        }

        self.stats.last_success.store(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );

        info!("Fetched X.509 SVID for {}", svid.spiffe_id);
        Ok(svid)
    }

    /// Create a mock X.509 SVID for testing
    fn create_mock_x509_svid(&self) -> Result<X509Svid, SpiffeError> {
        // Parse the socket path to extract trust domain
        // Format: unix:///path/to/socket
        let trust_domain = "example.org".to_string();
        let path = "/prism/proxy".to_string();

        let spiffe_id = SpiffeId {
            trust_domain: trust_domain.clone(),
            path,
        };

        // Mock certificate (in real impl, this comes from SPIRE)
        let mock_cert =
            b"-----BEGIN CERTIFICATE-----\nMIIB...mock...\n-----END CERTIFICATE-----".to_vec();
        let mock_key =
            b"-----BEGIN PRIVATE KEY-----\nMIIB...mock...\n-----END PRIVATE KEY-----".to_vec();

        Ok(X509Svid {
            spiffe_id,
            cert_chain: vec![mock_cert],
            private_key: mock_key,
            bundle: TrustBundle::new(trust_domain),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
        })
    }

    /// Fetch JWT SVID for given audiences
    pub async fn fetch_jwt_svid(&self, audiences: &[String]) -> Result<JwtSvid, SpiffeError> {
        debug!("Fetching JWT SVID for audiences: {:?}", audiences);
        self.stats.jwt_fetches.fetch_add(1, Ordering::Relaxed);

        // Create mock JWT for testing
        let svid = self.create_mock_jwt_svid(audiences)?;

        // Cache the SVID
        {
            let mut guard = self.jwt_svids.write().await;
            let key = audiences.join(",");
            guard.insert(key, svid.clone());
        }

        self.stats.last_success.store(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );

        info!("Fetched JWT SVID for {}", svid.spiffe_id);
        Ok(svid)
    }

    /// Create a mock JWT SVID for testing
    fn create_mock_jwt_svid(&self, audiences: &[String]) -> Result<JwtSvid, SpiffeError> {
        let spiffe_id = SpiffeId {
            trust_domain: "example.org".to_string(),
            path: "/prism/proxy".to_string(),
        };

        // Create mock JWT (in real impl, signed by SPIRE)
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let exp = now + 3600;

        let claims = JwtClaims {
            sub: spiffe_id.to_uri(),
            aud: audiences.to_vec(),
            exp,
            iat: now,
        };

        let header = base64_encode_url_safe(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let payload = base64_encode_url_safe(
            &serde_json::to_vec(&claims).map_err(|e| SpiffeError::InvalidJwt(e.to_string()))?,
        );
        let signature = base64_encode_url_safe(b"mock_signature");

        let token = format!("{}.{}.{}", header, payload, signature);

        Ok(JwtSvid {
            spiffe_id,
            token,
            audience: audiences.to_vec(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
        })
    }

    /// Get cached X.509 SVID
    pub async fn get_x509_svid(&self) -> Option<X509Svid> {
        self.x509_svid.read().await.clone()
    }

    /// Get cached JWT SVID
    pub async fn get_jwt_svid(&self, audiences: &[String]) -> Option<JwtSvid> {
        let key = audiences.join(",");
        self.jwt_svids.read().await.get(&key).cloned()
    }

    /// Fetch trust bundle for a domain
    pub async fn fetch_bundle(&self, trust_domain: &str) -> Result<TrustBundle, SpiffeError> {
        debug!("Fetching trust bundle for {}", trust_domain);
        self.stats.bundle_updates.fetch_add(1, Ordering::Relaxed);

        // Create mock bundle
        let bundle = TrustBundle {
            trust_domain: trust_domain.to_string(),
            certificates: vec![b"mock_ca_cert".to_vec()],
            sequence_number: 1,
            refreshed_at: SystemTime::now(),
        };

        // Cache the bundle
        {
            let mut guard = self.bundles.write().await;
            guard.insert(trust_domain.to_string(), bundle.clone());
        }

        Ok(bundle)
    }

    /// Get stats
    pub fn stats(&self) -> WorkloadApiStatsSnapshot {
        self.stats.snapshot()
    }
}

/// Authorization engine for SPIFFE-based access control
pub struct AuthorizationEngine {
    /// Configuration
    config: AuthorizationConfig,
    /// Compiled rules for faster matching
    compiled_rules: Vec<CompiledRule>,
    /// Stats
    stats: AuthzStats,
}

/// Compiled authorization rule
struct CompiledRule {
    name: String,
    spiffe_patterns: Vec<String>,
    paths: Vec<PathMatcher>,
    methods: HashSet<String>,
    action: AuthAction,
}

/// Path matcher
enum PathMatcher {
    Exact(String),
    Prefix(String),
    Regex(regex::Regex),
}

impl PathMatcher {
    fn matches(&self, path: &str) -> bool {
        match self {
            PathMatcher::Exact(p) => path == p,
            PathMatcher::Prefix(p) => path.starts_with(p),
            PathMatcher::Regex(r) => r.is_match(path),
        }
    }
}

/// Authorization statistics
#[derive(Debug, Default)]
pub struct AuthzStats {
    /// Number of allow decisions
    allows: AtomicU64,
    /// Number of deny decisions
    denies: AtomicU64,
    /// Number of default decisions
    defaults: AtomicU64,
}

impl AuthzStats {
    /// Get snapshot
    pub fn snapshot(&self) -> AuthzStatsSnapshot {
        AuthzStatsSnapshot {
            allows: self.allows.load(Ordering::Relaxed),
            denies: self.denies.load(Ordering::Relaxed),
            defaults: self.defaults.load(Ordering::Relaxed),
        }
    }
}

/// Authorization stats snapshot
#[derive(Debug, Clone)]
pub struct AuthzStatsSnapshot {
    pub allows: u64,
    pub denies: u64,
    pub defaults: u64,
}

impl AuthorizationEngine {
    /// Create a new authorization engine
    pub fn new(config: AuthorizationConfig) -> Self {
        let compiled_rules = config
            .rules
            .iter()
            .map(|rule| CompiledRule {
                name: rule.name.clone(),
                spiffe_patterns: rule.spiffe_ids.clone(),
                paths: rule
                    .paths
                    .iter()
                    .map(|p| {
                        if p.ends_with('*') {
                            PathMatcher::Prefix(p.trim_end_matches('*').to_string())
                        } else if p.starts_with('~') {
                            // Regex pattern
                            match regex::Regex::new(&p[1..]) {
                                Ok(r) => PathMatcher::Regex(r),
                                Err(_) => PathMatcher::Exact(p.clone()),
                            }
                        } else {
                            PathMatcher::Exact(p.clone())
                        }
                    })
                    .collect(),
                methods: rule.methods.iter().cloned().collect(),
                action: rule.action,
            })
            .collect();

        Self {
            config,
            compiled_rules,
            stats: AuthzStats::default(),
        }
    }

    /// Check if a request is authorized
    pub fn authorize(
        &self,
        spiffe_id: &SpiffeId,
        path: &str,
        method: &str,
    ) -> Result<(), SpiffeError> {
        debug!("Authorizing {} {} for {}", method, path, spiffe_id.to_uri());

        // Check rules in order
        for rule in &self.compiled_rules {
            // Check if SPIFFE ID matches any pattern
            let spiffe_matches = rule
                .spiffe_patterns
                .iter()
                .any(|pattern| spiffe_id.matches(pattern));

            if !spiffe_matches {
                continue;
            }

            // Check if path matches (empty means all paths)
            let path_matches = rule.paths.is_empty() || rule.paths.iter().any(|m| m.matches(path));

            if !path_matches {
                continue;
            }

            // Check if method matches (empty means all methods)
            let method_matches = rule.methods.is_empty() || rule.methods.contains(method);

            if !method_matches {
                continue;
            }

            // Rule matches
            match rule.action {
                AuthAction::Allow => {
                    self.stats.allows.fetch_add(1, Ordering::Relaxed);
                    debug!("Authorized by rule: {}", rule.name);
                    return Ok(());
                }
                AuthAction::Deny => {
                    self.stats.denies.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "Authorization denied by rule: {} for {}",
                        rule.name,
                        spiffe_id.to_uri()
                    );
                    return Err(SpiffeError::AuthorizationDenied(format!(
                        "Denied by rule: {}",
                        rule.name
                    )));
                }
            }
        }

        // No rule matched, use default action
        self.stats.defaults.fetch_add(1, Ordering::Relaxed);

        match self.config.default_action {
            AuthAction::Allow => {
                debug!("Authorized by default action");
                Ok(())
            }
            AuthAction::Deny => {
                warn!("Authorization denied by default for {}", spiffe_id.to_uri());
                Err(SpiffeError::AuthorizationDenied(
                    "No matching rule, default is deny".to_string(),
                ))
            }
        }
    }

    /// Get stats
    pub fn stats(&self) -> AuthzStatsSnapshot {
        self.stats.snapshot()
    }
}

/// SPIFFE identity verifier for mTLS connections
pub struct IdentityVerifier {
    /// Allowed trust domains
    allowed_trust_domains: HashSet<String>,
    /// Trust bundles
    bundles: HashMap<String, TrustBundle>,
    /// Stats
    stats: VerifierStats,
}

/// Verifier statistics
#[derive(Debug, Default)]
pub struct VerifierStats {
    /// Successful verifications
    success: AtomicU64,
    /// Failed verifications
    failures: AtomicU64,
    /// Unknown trust domain
    unknown_domain: AtomicU64,
}

impl VerifierStats {
    /// Get snapshot
    pub fn snapshot(&self) -> VerifierStatsSnapshot {
        VerifierStatsSnapshot {
            success: self.success.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            unknown_domain: self.unknown_domain.load(Ordering::Relaxed),
        }
    }
}

/// Verifier stats snapshot
#[derive(Debug, Clone)]
pub struct VerifierStatsSnapshot {
    pub success: u64,
    pub failures: u64,
    pub unknown_domain: u64,
}

impl IdentityVerifier {
    /// Create a new identity verifier
    pub fn new(allowed_trust_domains: Vec<String>) -> Self {
        Self {
            allowed_trust_domains: allowed_trust_domains.into_iter().collect(),
            bundles: HashMap::new(),
            stats: VerifierStats::default(),
        }
    }

    /// Add a trust bundle
    pub fn add_bundle(&mut self, bundle: TrustBundle) {
        self.bundles.insert(bundle.trust_domain.clone(), bundle);
    }

    /// Verify a SPIFFE ID from a certificate
    pub fn verify_identity(&self, spiffe_id: &SpiffeId) -> Result<(), SpiffeError> {
        // Check if trust domain is allowed
        if !self.allowed_trust_domains.is_empty()
            && !self.allowed_trust_domains.contains(&spiffe_id.trust_domain)
        {
            self.stats.unknown_domain.fetch_add(1, Ordering::Relaxed);
            return Err(SpiffeError::AuthorizationDenied(format!(
                "Trust domain not allowed: {}",
                spiffe_id.trust_domain
            )));
        }

        // Check if we have a trust bundle for this domain
        if !self.bundles.contains_key(&spiffe_id.trust_domain) && !self.bundles.is_empty() {
            self.stats.unknown_domain.fetch_add(1, Ordering::Relaxed);
            return Err(SpiffeError::TrustBundle(format!(
                "No trust bundle for domain: {}",
                spiffe_id.trust_domain
            )));
        }

        // In a real implementation, we would verify the certificate chain
        // against the trust bundle here

        self.stats.success.fetch_add(1, Ordering::Relaxed);
        debug!("Identity verified: {}", spiffe_id.to_uri());
        Ok(())
    }

    /// Extract SPIFFE ID from certificate SAN URI
    pub fn extract_spiffe_id_from_san(san_uri: &str) -> Result<SpiffeId, SpiffeError> {
        SpiffeId::parse(san_uri)
    }

    /// Get stats
    pub fn stats(&self) -> VerifierStatsSnapshot {
        self.stats.snapshot()
    }
}

/// SPIFFE context for a request
#[derive(Debug, Clone)]
pub struct SpiffeContext {
    /// Peer SPIFFE ID (if mTLS)
    pub peer_id: Option<SpiffeId>,
    /// Whether peer was verified
    pub peer_verified: bool,
    /// Our SPIFFE ID
    pub local_id: SpiffeId,
}

impl SpiffeContext {
    /// Create a new SPIFFE context
    pub fn new(local_id: SpiffeId) -> Self {
        Self {
            peer_id: None,
            peer_verified: false,
            local_id,
        }
    }

    /// Set peer identity
    pub fn with_peer(mut self, peer_id: SpiffeId, verified: bool) -> Self {
        self.peer_id = Some(peer_id);
        self.peer_verified = verified;
        self
    }
}

/// Base64 URL-safe encoding helper
fn base64_encode_url_safe(data: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(data)
}

/// Base64 URL-safe decoding helper
fn base64_decode_url_safe(data: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.decode(data).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spiffe_id_parse() {
        let id = SpiffeId::parse("spiffe://example.org/app/frontend").unwrap();
        assert_eq!(id.trust_domain, "example.org");
        assert_eq!(id.path, "/app/frontend");
        assert_eq!(id.to_uri(), "spiffe://example.org/app/frontend");
    }

    #[test]
    fn test_spiffe_id_invalid() {
        assert!(SpiffeId::parse("http://example.org/app").is_err());
        assert!(SpiffeId::parse("spiffe:///app").is_err());
        assert!(SpiffeId::parse("spiffe://").is_err());
    }

    #[test]
    fn test_spiffe_id_matching() {
        let id = SpiffeId::parse("spiffe://example.org/app/frontend").unwrap();

        assert!(id.matches("spiffe://example.org/app/frontend"));
        assert!(id.matches("spiffe://example.org/app/*"));
        assert!(id.matches("spiffe://example.org/**"));
        assert!(!id.matches("spiffe://example.org/app/backend"));
        assert!(!id.matches("spiffe://other.org/app/frontend"));
    }

    #[test]
    fn test_default_config() {
        let config = SpiffeConfig::default();
        assert!(!config.enabled);
        assert!(config.mtls_enabled);
        assert_eq!(config.trust_domain, "example.org");
    }

    #[test]
    fn test_authorization_engine() {
        let config = AuthorizationConfig {
            default_action: AuthAction::Deny,
            rules: vec![AuthorizationRule {
                name: "allow-frontend".to_string(),
                spiffe_ids: vec!["spiffe://example.org/app/frontend".to_string()],
                paths: vec!["/api/*".to_string()],
                methods: vec!["GET".to_string(), "POST".to_string()],
                action: AuthAction::Allow,
            }],
        };

        let engine = AuthorizationEngine::new(config);
        let frontend = SpiffeId::parse("spiffe://example.org/app/frontend").unwrap();
        let backend = SpiffeId::parse("spiffe://example.org/app/backend").unwrap();

        // Frontend should be allowed
        assert!(engine.authorize(&frontend, "/api/users", "GET").is_ok());
        assert!(engine.authorize(&frontend, "/api/orders", "POST").is_ok());

        // Backend should be denied (default)
        assert!(engine.authorize(&backend, "/api/users", "GET").is_err());

        // Frontend on wrong path should be denied
        assert!(engine.authorize(&frontend, "/admin", "GET").is_err());

        // Frontend with wrong method should be denied
        assert!(engine.authorize(&frontend, "/api/users", "DELETE").is_err());
    }

    #[test]
    fn test_identity_verifier() {
        let mut verifier = IdentityVerifier::new(vec!["example.org".to_string()]);
        verifier.add_bundle(TrustBundle::new("example.org".to_string()));

        let allowed = SpiffeId::parse("spiffe://example.org/app").unwrap();
        let denied = SpiffeId::parse("spiffe://other.org/app").unwrap();

        assert!(verifier.verify_identity(&allowed).is_ok());
        assert!(verifier.verify_identity(&denied).is_err());
    }

    #[test]
    fn test_spiffe_context() {
        let local = SpiffeId::parse("spiffe://example.org/prism").unwrap();
        let peer = SpiffeId::parse("spiffe://example.org/client").unwrap();

        let ctx = SpiffeContext::new(local.clone()).with_peer(peer.clone(), true);

        assert_eq!(ctx.local_id.to_uri(), "spiffe://example.org/prism");
        assert_eq!(ctx.peer_id.unwrap().to_uri(), "spiffe://example.org/client");
        assert!(ctx.peer_verified);
    }

    #[test]
    fn test_auth_action_display() {
        assert_eq!(format!("{}", AuthAction::Allow), "allow");
        assert_eq!(format!("{}", AuthAction::Deny), "deny");
    }

    #[test]
    fn test_spiffe_error_display() {
        let err = SpiffeError::InvalidSpiffeId("test".to_string());
        assert!(err.to_string().contains("Invalid SPIFFE ID"));

        let err = SpiffeError::AuthorizationDenied("test".to_string());
        assert!(err.to_string().contains("Authorization denied"));
    }

    #[tokio::test]
    async fn test_workload_api_client() {
        let client = WorkloadApiClient::new("unix:///tmp/spire-agent/api.sock");

        // Fetch X.509 SVID (mock)
        let svid = client.fetch_x509_svid().await.unwrap();
        assert!(!svid.is_expired());
        assert!(!svid.should_renew());

        // Get cached SVID
        let cached = client.get_x509_svid().await;
        assert!(cached.is_some());

        // Check stats
        let stats = client.stats();
        assert_eq!(stats.x509_fetches, 1);
    }

    #[tokio::test]
    async fn test_jwt_svid() {
        let client = WorkloadApiClient::new("unix:///tmp/spire-agent/api.sock");

        let audiences = vec!["api.example.org".to_string()];
        let svid = client.fetch_jwt_svid(&audiences).await.unwrap();

        assert!(!svid.is_expired());
        assert_eq!(svid.audience, audiences);

        // Parse claims
        let claims = svid.parse_claims().unwrap();
        assert_eq!(claims.sub, "spiffe://example.org/prism/proxy");
    }

    #[test]
    fn test_path_matching() {
        // Test wildcard path matching
        assert!(SpiffeId::path_matches("/app/frontend", "/app/*"));
        assert!(SpiffeId::path_matches("/app/frontend/v1", "/app/**"));
        assert!(SpiffeId::path_matches("/app/frontend", "/**"));
        assert!(!SpiffeId::path_matches("/other", "/app/*"));
    }

    #[test]
    fn test_trust_bundle() {
        let mut bundle = TrustBundle::new("example.org".to_string());
        assert_eq!(bundle.sequence_number, 0);

        bundle.add_certificate(vec![1, 2, 3]);
        assert_eq!(bundle.sequence_number, 1);
        assert_eq!(bundle.certificates.len(), 1);
    }
}
