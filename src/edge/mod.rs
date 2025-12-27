//! Edge WASM Functions
//!
//! Cloudflare Workers-style edge compute at the proxy layer:
//! - Serverless function execution
//! - Request/response transformation
//! - KV storage access
//! - Fetch API for subrequests
//! - Scheduled handlers (cron triggers)
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      Edge Function Router                        │
//! │  ┌─────────────────┐    ┌─────────────────┐                     │
//! │  │  Route Matcher  │───▶│ Function Pool   │                     │
//! │  └─────────────────┘    └────────┬────────┘                     │
//! │                                   │                              │
//! │  ┌─────────────────────────────────▼───────────────────────────┐│
//! │  │                   Function Instance                          ││
//! │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          ││
//! │  │  │  Request    │  │   Worker    │  │  Response   │          ││
//! │  │  │  Context    │  │  Handler    │  │  Builder    │          ││
//! │  │  └─────────────┘  └─────────────┘  └─────────────┘          ││
//! │  │         │                │                │                  ││
//! │  │  ┌──────▼────────────────▼────────────────▼──────┐          ││
//! │  │  │                 Runtime APIs                   │          ││
//! │  │  │  • KV Storage  • Fetch  • Cache  • Crypto     │          ││
//! │  │  └───────────────────────────────────────────────┘          ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example Worker
//! ```javascript
//! export default {
//!   async fetch(request, env) {
//!     const url = new URL(request.url);
//!
//!     // Check cache first
//!     const cached = await env.KV.get(url.pathname);
//!     if (cached) {
//!       return new Response(cached);
//!     }
//!
//!     // Fetch from origin
//!     const response = await fetch(request);
//!
//!     // Cache the response
//!     await env.KV.put(url.pathname, await response.text());
//!
//!     return response;
//!   }
//! }
//! ```

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Edge function configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfig {
    /// Enable edge functions
    #[serde(default)]
    pub enabled: bool,

    /// Directory containing function scripts
    #[serde(default = "default_functions_dir")]
    pub functions_dir: PathBuf,

    /// Maximum concurrent executions per function
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_executions: usize,

    /// Maximum execution time (milliseconds)
    #[serde(default = "default_max_execution_time")]
    pub max_execution_time_ms: u64,

    /// Maximum memory per function (bytes)
    #[serde(default = "default_max_memory")]
    pub max_memory_bytes: usize,

    /// Cold start timeout (milliseconds)
    #[serde(default = "default_cold_start_timeout")]
    pub cold_start_timeout_ms: u64,

    /// Enable KV storage
    #[serde(default = "default_true")]
    pub enable_kv: bool,

    /// KV storage configuration
    #[serde(default)]
    pub kv: KvConfig,

    /// Functions
    #[serde(default)]
    pub functions: HashMap<String, FunctionConfig>,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            functions_dir: default_functions_dir(),
            max_concurrent_executions: default_max_concurrent(),
            max_execution_time_ms: default_max_execution_time(),
            max_memory_bytes: default_max_memory(),
            cold_start_timeout_ms: default_cold_start_timeout(),
            enable_kv: true,
            kv: KvConfig::default(),
            functions: HashMap::new(),
        }
    }
}

fn default_functions_dir() -> PathBuf {
    PathBuf::from("./functions")
}

fn default_max_concurrent() -> usize {
    100
}

fn default_max_execution_time() -> u64 {
    30000 // 30 seconds
}

fn default_max_memory() -> usize {
    128 * 1024 * 1024 // 128MB
}

fn default_cold_start_timeout() -> u64 {
    5000 // 5 seconds
}

fn default_true() -> bool {
    true
}

/// KV storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvConfig {
    /// Maximum key size
    #[serde(default = "default_max_key_size")]
    pub max_key_size: usize,

    /// Maximum value size
    #[serde(default = "default_max_value_size")]
    pub max_value_size: usize,

    /// Default TTL (seconds, 0 = no expiry)
    #[serde(default)]
    pub default_ttl_secs: u64,

    /// Maximum entries per namespace
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
}

impl Default for KvConfig {
    fn default() -> Self {
        Self {
            max_key_size: default_max_key_size(),
            max_value_size: default_max_value_size(),
            default_ttl_secs: 0,
            max_entries: default_max_entries(),
        }
    }
}

fn default_max_key_size() -> usize {
    512
}

fn default_max_value_size() -> usize {
    25 * 1024 * 1024 // 25MB
}

fn default_max_entries() -> usize {
    10000
}

/// Individual function configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionConfig {
    /// Function script path
    pub script: PathBuf,

    /// Route patterns this function handles
    #[serde(default)]
    pub routes: Vec<String>,

    /// Environment variables
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// KV namespace bindings
    #[serde(default)]
    pub kv_namespaces: Vec<KvBinding>,

    /// Scheduled triggers (cron expressions)
    #[serde(default)]
    pub scheduled: Vec<String>,

    /// Enable for this function
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// KV namespace binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvBinding {
    /// Binding name (how function accesses it)
    pub binding: String,
    /// Namespace ID
    pub namespace_id: String,
}

/// Request context for edge functions
#[derive(Debug, Clone)]
pub struct EdgeRequest {
    /// Request method
    pub method: String,
    /// Request URL
    pub url: String,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request body (if buffered)
    pub body: Option<Vec<u8>>,
    /// Client IP
    pub client_ip: Option<String>,
    /// Request ID
    pub request_id: String,
    /// Geo information
    pub geo: Option<GeoInfo>,
}

impl EdgeRequest {
    pub fn new(method: String, url: String) -> Self {
        Self {
            method,
            url,
            headers: HashMap::new(),
            body: None,
            client_ip: None,
            request_id: uuid::Uuid::new_v4().to_string(),
            geo: None,
        }
    }

    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }
}

/// Geo information from IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub country: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
}

/// Response from edge function
#[derive(Debug, Clone)]
pub struct EdgeResponse {
    /// HTTP status code
    pub status: u16,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body
    pub body: Vec<u8>,
    /// Pass through to origin
    pub passthrough: bool,
}

impl EdgeResponse {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: Vec::new(),
            passthrough: false,
        }
    }

    pub fn ok() -> Self {
        Self::new(200)
    }

    pub fn passthrough() -> Self {
        Self {
            status: 0,
            headers: HashMap::new(),
            body: Vec::new(),
            passthrough: true,
        }
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    pub fn with_header(mut self, key: String, value: String) -> Self {
        self.headers.insert(key, value);
        self
    }

    pub fn json(data: &impl Serialize) -> Self {
        let body = serde_json::to_vec(data).unwrap_or_default();
        Self::new(200)
            .with_header("Content-Type".to_string(), "application/json".to_string())
            .with_body(body)
    }

    pub fn text(text: &str) -> Self {
        Self::new(200)
            .with_header("Content-Type".to_string(), "text/plain".to_string())
            .with_body(text.as_bytes().to_vec())
    }

    pub fn html(html: &str) -> Self {
        Self::new(200)
            .with_header("Content-Type".to_string(), "text/html".to_string())
            .with_body(html.as_bytes().to_vec())
    }

    pub fn redirect(url: &str, permanent: bool) -> Self {
        Self::new(if permanent { 308 } else { 307 })
            .with_header("Location".to_string(), url.to_string())
    }

    pub fn not_found() -> Self {
        Self::new(404)
            .with_header("Content-Type".to_string(), "text/plain".to_string())
            .with_body(b"Not Found".to_vec())
    }

    pub fn error(status: u16, message: &str) -> Self {
        Self::new(status)
            .with_header("Content-Type".to_string(), "text/plain".to_string())
            .with_body(message.as_bytes().to_vec())
    }
}

/// KV storage entry
#[derive(Debug, Clone)]
pub struct KvEntry {
    /// Value data
    pub value: Vec<u8>,
    /// Expiration time (None = never)
    pub expires_at: Option<Instant>,
    /// Metadata
    pub metadata: Option<serde_json::Value>,
}

impl KvEntry {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            value,
            expires_at: None,
            metadata: None,
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.expires_at = Some(Instant::now() + ttl);
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|e| Instant::now() > e).unwrap_or(false)
    }
}

/// KV namespace (in-memory storage)
#[derive(Debug)]
pub struct KvNamespace {
    name: String,
    config: KvConfig,
    entries: RwLock<HashMap<String, KvEntry>>,
    stats: KvStats,
}

impl KvNamespace {
    pub fn new(name: String, config: KvConfig) -> Self {
        Self {
            name,
            config,
            entries: RwLock::new(HashMap::new()),
            stats: KvStats::new(),
        }
    }

    /// Get a value
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let entries = self.entries.read();
        if let Some(entry) = entries.get(key) {
            if entry.is_expired() {
                drop(entries);
                self.entries.write().remove(key);
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.value.clone())
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Get with metadata
    pub fn get_with_metadata(&self, key: &str) -> Option<(Vec<u8>, Option<serde_json::Value>)> {
        let entries = self.entries.read();
        if let Some(entry) = entries.get(key) {
            if entry.is_expired() {
                drop(entries);
                self.entries.write().remove(key);
                return None;
            }
            Some((entry.value.clone(), entry.metadata.clone()))
        } else {
            None
        }
    }

    /// Put a value
    pub fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        self.put_with_options(key, value, None, None)
    }

    /// Put with TTL
    pub fn put_with_ttl(&self, key: &str, value: Vec<u8>, ttl: Duration) -> Result<(), KvError> {
        self.put_with_options(key, value, Some(ttl), None)
    }

    /// Put with options
    pub fn put_with_options(
        &self,
        key: &str,
        value: Vec<u8>,
        ttl: Option<Duration>,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), KvError> {
        if key.len() > self.config.max_key_size {
            return Err(KvError::KeyTooLarge);
        }
        if value.len() > self.config.max_value_size {
            return Err(KvError::ValueTooLarge);
        }

        let mut entries = self.entries.write();
        if entries.len() >= self.config.max_entries && !entries.contains_key(key) {
            return Err(KvError::NamespaceFull);
        }

        let mut entry = KvEntry::new(value);
        if let Some(ttl) = ttl {
            entry = entry.with_ttl(ttl);
        } else if self.config.default_ttl_secs > 0 {
            entry = entry.with_ttl(Duration::from_secs(self.config.default_ttl_secs));
        }
        if let Some(meta) = metadata {
            entry = entry.with_metadata(meta);
        }

        entries.insert(key.to_string(), entry);
        self.stats.writes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Delete a key
    pub fn delete(&self, key: &str) -> bool {
        let removed = self.entries.write().remove(key).is_some();
        if removed {
            self.stats.deletes.fetch_add(1, Ordering::Relaxed);
        }
        removed
    }

    /// List keys with prefix
    pub fn list(&self, prefix: Option<&str>, limit: usize) -> Vec<String> {
        let entries = self.entries.read();
        let mut keys: Vec<_> = entries
            .keys()
            .filter(|k| {
                if let Some(p) = prefix {
                    k.starts_with(p)
                } else {
                    true
                }
            })
            .take(limit)
            .cloned()
            .collect();
        keys.sort();
        keys
    }

    /// Get statistics
    pub fn stats(&self) -> KvStatsSnapshot {
        KvStatsSnapshot {
            namespace: self.name.clone(),
            entries: self.entries.read().len(),
            hits: self.stats.hits.load(Ordering::Relaxed),
            misses: self.stats.misses.load(Ordering::Relaxed),
            writes: self.stats.writes.load(Ordering::Relaxed),
            deletes: self.stats.deletes.load(Ordering::Relaxed),
        }
    }

    /// Clean up expired entries
    pub fn gc(&self) {
        let mut entries = self.entries.write();
        entries.retain(|_, entry| !entry.is_expired());
    }
}

/// KV storage statistics
#[derive(Debug)]
struct KvStats {
    hits: AtomicU64,
    misses: AtomicU64,
    writes: AtomicU64,
    deletes: AtomicU64,
}

impl KvStats {
    fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            deletes: AtomicU64::new(0),
        }
    }
}

/// KV stats snapshot
#[derive(Debug, Clone, Serialize)]
pub struct KvStatsSnapshot {
    pub namespace: String,
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub writes: u64,
    pub deletes: u64,
}

/// KV storage errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KvError {
    KeyTooLarge,
    ValueTooLarge,
    NamespaceFull,
    NotFound,
}

impl std::fmt::Display for KvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KvError::KeyTooLarge => write!(f, "key too large"),
            KvError::ValueTooLarge => write!(f, "value too large"),
            KvError::NamespaceFull => write!(f, "namespace full"),
            KvError::NotFound => write!(f, "not found"),
        }
    }
}

impl std::error::Error for KvError {}

/// Execution result
#[derive(Debug, Clone)]
pub enum ExecutionResult {
    /// Function returned a response
    Response(EdgeResponse),
    /// Function threw an error
    Error(String),
    /// Execution timed out
    Timeout,
    /// Function not found
    NotFound,
}

/// Function execution stats
#[derive(Debug)]
pub struct FunctionStats {
    pub invocations: AtomicU64,
    pub errors: AtomicU64,
    pub timeouts: AtomicU64,
    pub total_duration_ms: AtomicU64,
    pub cold_starts: AtomicU64,
}

impl FunctionStats {
    pub fn new() -> Self {
        Self {
            invocations: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            total_duration_ms: AtomicU64::new(0),
            cold_starts: AtomicU64::new(0),
        }
    }

    pub fn record_invocation(&self, duration: Duration, is_cold_start: bool, is_error: bool) {
        self.invocations.fetch_add(1, Ordering::Relaxed);
        self.total_duration_ms
            .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
        if is_cold_start {
            self.cold_starts.fetch_add(1, Ordering::Relaxed);
        }
        if is_error {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> FunctionStatsSnapshot {
        let invocations = self.invocations.load(Ordering::Relaxed);
        FunctionStatsSnapshot {
            invocations,
            errors: self.errors.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            avg_duration_ms: if invocations > 0 {
                self.total_duration_ms.load(Ordering::Relaxed) / invocations
            } else {
                0
            },
            cold_starts: self.cold_starts.load(Ordering::Relaxed),
        }
    }
}

impl Default for FunctionStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Function stats snapshot
#[derive(Debug, Clone, Serialize)]
pub struct FunctionStatsSnapshot {
    pub invocations: u64,
    pub errors: u64,
    pub timeouts: u64,
    pub avg_duration_ms: u64,
    pub cold_starts: u64,
}

/// Edge function instance (mock implementation)
pub struct FunctionInstance {
    name: String,
    config: FunctionConfig,
    stats: Arc<FunctionStats>,
    kv_namespaces: HashMap<String, Arc<KvNamespace>>,
    created_at: Instant,
    last_used: RwLock<Instant>,
}

impl FunctionInstance {
    pub fn new(
        name: String,
        config: FunctionConfig,
        kv_namespaces: HashMap<String, Arc<KvNamespace>>,
    ) -> Self {
        Self {
            name,
            config,
            stats: Arc::new(FunctionStats::new()),
            kv_namespaces,
            created_at: Instant::now(),
            last_used: RwLock::new(Instant::now()),
        }
    }

    /// Execute the function (mock implementation)
    pub async fn execute(&self, request: EdgeRequest) -> ExecutionResult {
        let start = Instant::now();
        let is_cold_start = self.created_at.elapsed() < Duration::from_secs(1);

        *self.last_used.write() = Instant::now();

        // Mock execution: check for specific routes/patterns
        let response = self.mock_execute(&request);

        let duration = start.elapsed();
        let is_error = matches!(&response, ExecutionResult::Error(_));
        self.stats
            .record_invocation(duration, is_cold_start, is_error);

        response
    }

    fn mock_execute(&self, request: &EdgeRequest) -> ExecutionResult {
        // Check environment for behavior hints
        if let Some(mode) = self.config.env.get("MODE") {
            match mode.as_str() {
                "echo" => {
                    return ExecutionResult::Response(EdgeResponse::json(&serde_json::json!({
                        "method": request.method,
                        "url": request.url,
                        "headers": request.headers,
                    })));
                }
                "error" => {
                    return ExecutionResult::Error("Intentional error".to_string());
                }
                "passthrough" => {
                    return ExecutionResult::Response(EdgeResponse::passthrough());
                }
                _ => {}
            }
        }

        // Default: add custom header and passthrough
        let mut response = EdgeResponse::passthrough();
        response
            .headers
            .insert("X-Edge-Function".to_string(), self.name.clone());
        ExecutionResult::Response(response)
    }

    /// Get KV namespace binding
    pub fn get_kv(&self, binding: &str) -> Option<Arc<KvNamespace>> {
        self.kv_namespaces.get(binding).cloned()
    }

    /// Get stats
    pub fn stats(&self) -> Arc<FunctionStats> {
        self.stats.clone()
    }

    /// Get idle time
    pub fn idle_time(&self) -> Duration {
        self.last_used.read().elapsed()
    }
}

/// Edge function router
pub struct EdgeRouter {
    config: EdgeConfig,
    functions: RwLock<HashMap<String, Arc<FunctionInstance>>>,
    kv_namespaces: RwLock<HashMap<String, Arc<KvNamespace>>>,
    route_cache: RwLock<HashMap<String, String>>,
}

impl EdgeRouter {
    pub fn new(config: EdgeConfig) -> Self {
        Self {
            config,
            functions: RwLock::new(HashMap::new()),
            kv_namespaces: RwLock::new(HashMap::new()),
            route_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Initialize the router
    pub fn init(&self) -> Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }

        // Create KV namespaces
        for (name, func_config) in &self.config.functions {
            for binding in &func_config.kv_namespaces {
                let mut namespaces = self.kv_namespaces.write();
                if !namespaces.contains_key(&binding.namespace_id) {
                    namespaces.insert(
                        binding.namespace_id.clone(),
                        Arc::new(KvNamespace::new(
                            binding.namespace_id.clone(),
                            self.config.kv.clone(),
                        )),
                    );
                }
            }

            // Create function instance
            let kv_bindings: HashMap<_, _> = func_config
                .kv_namespaces
                .iter()
                .filter_map(|b| {
                    self.kv_namespaces
                        .read()
                        .get(&b.namespace_id)
                        .cloned()
                        .map(|ns| (b.binding.clone(), ns))
                })
                .collect();

            let instance = FunctionInstance::new(name.clone(), func_config.clone(), kv_bindings);

            self.functions
                .write()
                .insert(name.clone(), Arc::new(instance));

            // Build route cache
            for route in &func_config.routes {
                self.route_cache.write().insert(route.clone(), name.clone());
            }
        }

        Ok(())
    }

    /// Route a request to a function
    pub fn route(&self, path: &str) -> Option<Arc<FunctionInstance>> {
        // Check exact match first
        if let Some(func_name) = self.route_cache.read().get(path) {
            return self.functions.read().get(func_name).cloned();
        }

        // Check prefix matches
        let cache = self.route_cache.read();
        for (route, func_name) in cache.iter() {
            if route.ends_with('*') {
                let prefix = &route[..route.len() - 1];
                if path.starts_with(prefix) {
                    return self.functions.read().get(func_name).cloned();
                }
            }
        }

        None
    }

    /// Execute a function for a request
    pub async fn execute(&self, request: EdgeRequest) -> ExecutionResult {
        if !self.config.enabled {
            return ExecutionResult::Response(EdgeResponse::passthrough());
        }

        // Parse URL to get path
        let path = if let Ok(url) = url::Url::parse(&request.url) {
            url.path().to_string()
        } else {
            request.url.clone()
        };

        if let Some(function) = self.route(&path) {
            function.execute(request).await
        } else {
            ExecutionResult::Response(EdgeResponse::passthrough())
        }
    }

    /// Get a KV namespace
    pub fn get_kv_namespace(&self, id: &str) -> Option<Arc<KvNamespace>> {
        self.kv_namespaces.read().get(id).cloned()
    }

    /// Get function count
    pub fn function_count(&self) -> usize {
        self.functions.read().len()
    }

    /// Get KV namespace count
    pub fn kv_namespace_count(&self) -> usize {
        self.kv_namespaces.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EdgeConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_concurrent_executions, 100);
    }

    #[test]
    fn test_edge_request() {
        let request = EdgeRequest::new("GET".to_string(), "https://example.com/path".to_string())
            .with_headers([("Content-Type".to_string(), "application/json".to_string())].into())
            .with_body(b"test".to_vec());

        assert_eq!(request.method, "GET");
        assert_eq!(
            request.headers.get("Content-Type"),
            Some(&"application/json".to_string())
        );
        assert_eq!(request.body, Some(b"test".to_vec()));
    }

    #[test]
    fn test_edge_response_builders() {
        let ok = EdgeResponse::ok();
        assert_eq!(ok.status, 200);

        let text = EdgeResponse::text("hello");
        assert_eq!(text.body, b"hello".to_vec());

        let redirect = EdgeResponse::redirect("/new", true);
        assert_eq!(redirect.status, 308);
        assert_eq!(redirect.headers.get("Location"), Some(&"/new".to_string()));

        let passthrough = EdgeResponse::passthrough();
        assert!(passthrough.passthrough);
    }

    #[test]
    fn test_kv_namespace() {
        let config = KvConfig::default();
        let ns = KvNamespace::new("test".to_string(), config);

        // Put and get
        ns.put("key1", b"value1".to_vec()).unwrap();
        assert_eq!(ns.get("key1"), Some(b"value1".to_vec()));

        // Missing key
        assert_eq!(ns.get("missing"), None);

        // Delete
        assert!(ns.delete("key1"));
        assert_eq!(ns.get("key1"), None);
    }

    #[test]
    fn test_kv_namespace_with_ttl() {
        let config = KvConfig::default();
        let ns = KvNamespace::new("test".to_string(), config);

        // Put with very short TTL
        ns.put_with_ttl("expire", b"soon".to_vec(), Duration::from_millis(1))
            .unwrap();

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(10));

        // Should be expired
        assert_eq!(ns.get("expire"), None);
    }

    #[test]
    fn test_kv_limits() {
        let mut config = KvConfig::default();
        config.max_key_size = 10;
        config.max_value_size = 100;
        config.max_entries = 2;

        let ns = KvNamespace::new("test".to_string(), config);

        // Key too large
        let result = ns.put("this-key-is-too-long", b"value".to_vec());
        assert_eq!(result, Err(KvError::KeyTooLarge));

        // Value too large
        let result = ns.put("key", vec![0; 200]);
        assert_eq!(result, Err(KvError::ValueTooLarge));

        // Fill namespace
        ns.put("key1", b"v1".to_vec()).unwrap();
        ns.put("key2", b"v2".to_vec()).unwrap();

        // Namespace full
        let result = ns.put("key3", b"v3".to_vec());
        assert_eq!(result, Err(KvError::NamespaceFull));

        // But can update existing
        ns.put("key1", b"updated".to_vec()).unwrap();
        assert_eq!(ns.get("key1"), Some(b"updated".to_vec()));
    }

    #[test]
    fn test_kv_list() {
        let config = KvConfig::default();
        let ns = KvNamespace::new("test".to_string(), config);

        ns.put("user:1", b"alice".to_vec()).unwrap();
        ns.put("user:2", b"bob".to_vec()).unwrap();
        ns.put("settings:theme", b"dark".to_vec()).unwrap();

        let users = ns.list(Some("user:"), 10);
        assert_eq!(users.len(), 2);
        assert!(users.contains(&"user:1".to_string()));
        assert!(users.contains(&"user:2".to_string()));

        let all = ns.list(None, 10);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_function_stats() {
        let stats = FunctionStats::new();

        stats.record_invocation(Duration::from_millis(10), true, false);
        stats.record_invocation(Duration::from_millis(20), false, false);
        stats.record_invocation(Duration::from_millis(30), false, true);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.invocations, 3);
        assert_eq!(snapshot.errors, 1);
        assert_eq!(snapshot.cold_starts, 1);
        assert_eq!(snapshot.avg_duration_ms, 20); // (10+20+30)/3
    }

    #[tokio::test]
    async fn test_function_instance() {
        let config = FunctionConfig {
            script: PathBuf::from("test.js"),
            routes: vec!["/api/*".to_string()],
            env: [("MODE".to_string(), "echo".to_string())].into(),
            kv_namespaces: vec![],
            scheduled: vec![],
            enabled: true,
        };

        let instance = FunctionInstance::new("test-func".to_string(), config, HashMap::new());

        let request = EdgeRequest::new(
            "GET".to_string(),
            "https://example.com/api/test".to_string(),
        );
        let result = instance.execute(request).await;

        match result {
            ExecutionResult::Response(resp) => {
                assert_eq!(resp.status, 200);
                let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
                assert_eq!(body["method"], "GET");
            }
            _ => panic!("Expected response"),
        }
    }

    #[tokio::test]
    async fn test_edge_router() {
        let mut config = EdgeConfig::default();
        config.enabled = true;
        config.functions.insert(
            "api-handler".to_string(),
            FunctionConfig {
                script: PathBuf::from("api.js"),
                routes: vec!["/api/*".to_string()],
                env: [("MODE".to_string(), "echo".to_string())].into(),
                kv_namespaces: vec![],
                scheduled: vec![],
                enabled: true,
            },
        );

        let router = EdgeRouter::new(config);
        router.init().unwrap();

        assert_eq!(router.function_count(), 1);

        let request = EdgeRequest::new(
            "POST".to_string(),
            "https://example.com/api/users".to_string(),
        );
        let result = router.execute(request).await;

        match result {
            ExecutionResult::Response(resp) => {
                assert_eq!(resp.status, 200);
            }
            _ => panic!("Expected response"),
        }
    }

    #[test]
    fn test_kv_error_display() {
        assert_eq!(KvError::KeyTooLarge.to_string(), "key too large");
        assert_eq!(KvError::NamespaceFull.to_string(), "namespace full");
    }

    #[test]
    fn test_kv_entry() {
        let entry =
            KvEntry::new(b"test".to_vec()).with_metadata(serde_json::json!({"type": "test"}));

        assert!(!entry.is_expired());
        assert!(entry.metadata.is_some());
    }
}
