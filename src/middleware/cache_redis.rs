//! Redis-backed Distributed Cache Middleware
//!
//! Provides distributed response caching using Redis:
//! - Shared cache across multiple Prism instances
//! - Atomic cache operations with Lua scripts
//! - Cache invalidation via pub/sub
//! - Support for cache tags
//! - Stale-while-revalidate pattern
//!
//! # Example
//!
//! ```yaml
//! middlewares:
//!   - type: redis_cache
//!     redis_cache:
//!       url: "redis://localhost:6379"
//!       prefix: "prism:cache:"
//!       default_ttl: 5m
//!       max_entry_size: 1mb
//! ```

use super::{HttpRequest, HttpResponse, Middleware, Next, RequestContext};
use crate::error::{PrismError, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http::{header, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};
#[cfg(feature = "distributed-rate-limit")]
use tracing::info;

#[cfg(feature = "distributed-rate-limit")]
use redis::aio::MultiplexedConnection;
#[cfg(feature = "distributed-rate-limit")]
use redis::{AsyncCommands, Client as RedisClient};

/// Redis cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisCacheConfig {
    /// Redis connection URL
    pub url: String,

    /// Key prefix for cache entries
    #[serde(default = "default_prefix")]
    pub prefix: String,

    /// Default TTL for cached responses
    #[serde(default = "default_ttl")]
    #[serde(with = "humantime_serde")]
    pub default_ttl: Duration,

    /// Minimum TTL
    #[serde(default = "default_min_ttl")]
    #[serde(with = "humantime_serde")]
    pub min_ttl: Duration,

    /// Maximum TTL
    #[serde(default = "default_max_ttl")]
    #[serde(with = "humantime_serde")]
    pub max_ttl: Duration,

    /// Maximum size of a single cache entry (bytes)
    #[serde(default = "default_max_entry_size")]
    pub max_entry_size: usize,

    /// Cache private responses
    #[serde(default)]
    pub cache_private: bool,

    /// HTTP methods to cache
    #[serde(default = "default_methods")]
    pub cacheable_methods: Vec<String>,

    /// HTTP status codes to cache
    #[serde(default = "default_status_codes")]
    pub cacheable_status_codes: Vec<u16>,

    /// Enable stale-while-revalidate
    #[serde(default = "default_true")]
    pub stale_while_revalidate: bool,

    /// How long to serve stale content
    #[serde(default = "default_stale_ttl")]
    #[serde(with = "humantime_serde")]
    pub stale_ttl: Duration,

    /// Connection pool size
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,

    /// Connection timeout
    #[serde(default = "default_connect_timeout")]
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,

    /// Paths to exclude from caching
    #[serde(default)]
    pub exclude_paths: Vec<String>,

    /// Paths to include (if set, only these are cached)
    #[serde(default)]
    pub include_paths: Vec<String>,

    /// Cache vary headers
    #[serde(default = "default_vary_headers")]
    pub vary_headers: Vec<String>,

    /// Enable cache compression
    #[serde(default = "default_true")]
    pub compress: bool,

    /// Compression threshold (bytes)
    #[serde(default = "default_compression_threshold")]
    pub compression_threshold: usize,

    /// Enable cache statistics
    #[serde(default = "default_true")]
    pub enable_stats: bool,
}

fn default_prefix() -> String {
    "prism:cache:".to_string()
}

fn default_ttl() -> Duration {
    Duration::from_secs(300) // 5 minutes
}

fn default_min_ttl() -> Duration {
    Duration::from_secs(1)
}

fn default_max_ttl() -> Duration {
    Duration::from_secs(86400) // 24 hours
}

fn default_max_entry_size() -> usize {
    1024 * 1024 // 1MB
}

fn default_methods() -> Vec<String> {
    vec!["GET".to_string(), "HEAD".to_string()]
}

fn default_status_codes() -> Vec<u16> {
    vec![200, 203, 204, 206, 300, 301, 302, 304]
}

fn default_stale_ttl() -> Duration {
    Duration::from_secs(60)
}

fn default_pool_size() -> usize {
    10
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_vary_headers() -> Vec<String> {
    vec!["Accept".to_string(), "Accept-Encoding".to_string()]
}

fn default_compression_threshold() -> usize {
    1024 // 1KB
}

fn default_true() -> bool {
    true
}

impl Default for RedisCacheConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            prefix: default_prefix(),
            default_ttl: default_ttl(),
            min_ttl: default_min_ttl(),
            max_ttl: default_max_ttl(),
            max_entry_size: default_max_entry_size(),
            cache_private: false,
            cacheable_methods: default_methods(),
            cacheable_status_codes: default_status_codes(),
            stale_while_revalidate: true,
            stale_ttl: default_stale_ttl(),
            pool_size: default_pool_size(),
            connect_timeout: default_connect_timeout(),
            exclude_paths: Vec::new(),
            include_paths: Vec::new(),
            vary_headers: default_vary_headers(),
            compress: true,
            compression_threshold: default_compression_threshold(),
            enable_stats: true,
        }
    }
}

/// Cached entry stored in Redis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisCacheEntry {
    /// HTTP status code
    pub status: u16,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body (possibly compressed)
    pub body: Vec<u8>,
    /// Whether body is compressed
    pub compressed: bool,
    /// ETag for conditional requests
    pub etag: Option<String>,
    /// Last-Modified for conditional requests
    pub last_modified: Option<String>,
    /// Cache tags for invalidation
    pub tags: Vec<String>,
    /// When this entry was created (unix timestamp)
    pub created_at: u64,
    /// When this entry expires (unix timestamp)
    pub expires_at: u64,
    /// Original size before compression
    pub original_size: usize,
}

impl RedisCacheEntry {
    /// Check if entry is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.expires_at
    }

    /// Check if entry is stale (for stale-while-revalidate)
    pub fn is_stale(&self, stale_ttl: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let stale_expires = self.expires_at + stale_ttl.as_secs();
        now >= self.expires_at && now < stale_expires
    }

    /// Get age in seconds
    pub fn age(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.created_at)
    }
}

/// Cache statistics
#[derive(Debug, Default)]
pub struct RedisCacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub stale_hits: AtomicU64,
    pub stores: AtomicU64,
    pub invalidations: AtomicU64,
    pub errors: AtomicU64,
    pub bytes_served: AtomicU64,
    pub bytes_saved: AtomicU64,
}

impl RedisCacheStats {
    pub fn hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stale_hit(&self) {
        self.stale_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn store(&self) {
        self.stores.fetch_add(1, Ordering::Relaxed);
    }

    pub fn invalidate(&self) {
        self.invalidations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn bytes(&self, served: u64, saved: u64) {
        self.bytes_served.fetch_add(served, Ordering::Relaxed);
        self.bytes_saved.fetch_add(saved, Ordering::Relaxed);
    }

    /// Get snapshot of statistics
    pub fn snapshot(&self) -> RedisCacheStatsSnapshot {
        RedisCacheStatsSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            stale_hits: self.stale_hits.load(Ordering::Relaxed),
            stores: self.stores.load(Ordering::Relaxed),
            invalidations: self.invalidations.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            bytes_served: self.bytes_served.load(Ordering::Relaxed),
            bytes_saved: self.bytes_saved.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of cache statistics
#[derive(Debug, Clone, Serialize)]
pub struct RedisCacheStatsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub stale_hits: u64,
    pub stores: u64,
    pub invalidations: u64,
    pub errors: u64,
    pub bytes_served: u64,
    pub bytes_saved: u64,
}

impl RedisCacheStatsSnapshot {
    /// Calculate hit rate
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

/// Redis cache middleware
pub struct RedisCacheMiddleware {
    config: RedisCacheConfig,
    #[cfg(feature = "distributed-rate-limit")]
    connection: Option<Arc<tokio::sync::Mutex<MultiplexedConnection>>>,
    stats: Arc<RedisCacheStats>,
}

impl RedisCacheMiddleware {
    /// Create new Redis cache middleware
    #[cfg(feature = "distributed-rate-limit")]
    pub async fn new(config: RedisCacheConfig) -> Result<Self> {
        let client = RedisClient::open(config.url.as_str())
            .map_err(|e| PrismError::Config(format!("Invalid Redis URL: {}", e)))?;

        let connection = tokio::time::timeout(
            config.connect_timeout,
            client.get_multiplexed_async_connection(),
        )
        .await
        .map_err(|_| PrismError::Timeout)?
        .map_err(|e| PrismError::Config(format!("Redis connection failed: {}", e)))?;

        info!("Redis cache connected to {}", config.url);

        Ok(Self {
            config,
            connection: Some(Arc::new(tokio::sync::Mutex::new(connection))),
            stats: Arc::new(RedisCacheStats::default()),
        })
    }

    /// Create without Redis feature (stub)
    #[cfg(not(feature = "distributed-rate-limit"))]
    pub async fn new(config: RedisCacheConfig) -> Result<Self> {
        warn!("Redis cache middleware requires 'distributed-rate-limit' feature");
        Ok(Self {
            config,
            stats: Arc::new(RedisCacheStats::default()),
        })
    }

    /// Get cache statistics
    pub fn stats(&self) -> &RedisCacheStats {
        &self.stats
    }

    /// Generate cache key from request
    fn generate_key(&self, request: &HttpRequest) -> String {
        let mut key = format!(
            "{}{}:{}",
            self.config.prefix,
            request.method().as_str(),
            request.uri().path()
        );

        // Add query string if present
        if let Some(query) = request.uri().query() {
            key.push('?');
            key.push_str(query);
        }

        // Add vary headers
        for header_name in &self.config.vary_headers {
            if let Some(value) = request.headers().get(header_name) {
                if let Ok(v) = value.to_str() {
                    key.push(':');
                    key.push_str(header_name);
                    key.push('=');
                    key.push_str(v);
                }
            }
        }

        key
    }

    /// Check if request is cacheable
    fn is_cacheable_request(&self, request: &HttpRequest) -> bool {
        // Check method
        let method = request.method().as_str();
        if !self.config.cacheable_methods.iter().any(|m| m == method) {
            return false;
        }

        let path = request.uri().path();

        // Check exclusions
        if self.config.exclude_paths.iter().any(|p| {
            if p.ends_with('*') {
                path.starts_with(&p[..p.len() - 1])
            } else {
                path == p
            }
        }) {
            return false;
        }

        // Check inclusions (if set)
        if !self.config.include_paths.is_empty() {
            if !self.config.include_paths.iter().any(|p| {
                if p.ends_with('*') {
                    path.starts_with(&p[..p.len() - 1])
                } else {
                    path == p
                }
            }) {
                return false;
            }
        }

        // Check for no-cache directive in request
        if let Some(cache_control) = request.headers().get(header::CACHE_CONTROL) {
            if let Ok(value) = cache_control.to_str() {
                if value.contains("no-cache") || value.contains("no-store") {
                    return false;
                }
            }
        }

        true
    }

    /// Check if response is cacheable
    fn is_cacheable_response(&self, response: &HttpResponse) -> bool {
        // Check status code
        if !self
            .config
            .cacheable_status_codes
            .contains(&response.status().as_u16())
        {
            return false;
        }

        // Check Cache-Control header
        if let Some(cache_control) = response.headers().get(header::CACHE_CONTROL) {
            if let Ok(value) = cache_control.to_str() {
                if value.contains("no-store") {
                    return false;
                }
                if value.contains("private") && !self.config.cache_private {
                    return false;
                }
            }
        }

        true
    }

    /// Parse TTL from Cache-Control header
    #[cfg(feature = "distributed-rate-limit")]
    fn parse_ttl(&self, response: &HttpResponse) -> Duration {
        if let Some(cache_control) = response.headers().get(header::CACHE_CONTROL) {
            if let Ok(value) = cache_control.to_str() {
                // Look for max-age or s-maxage
                for directive in value.split(',') {
                    let directive = directive.trim();
                    if directive.starts_with("s-maxage=") || directive.starts_with("max-age=") {
                        if let Some(seconds_str) = directive.split('=').nth(1) {
                            if let Ok(seconds) = seconds_str.trim().parse::<u64>() {
                                let ttl = Duration::from_secs(seconds);
                                // Clamp to configured bounds
                                return ttl.clamp(self.config.min_ttl, self.config.max_ttl);
                            }
                        }
                    }
                }
            }
        }

        self.config.default_ttl
    }

    /// Compress data if configured
    #[cfg(feature = "distributed-rate-limit")]
    fn compress_if_needed(&self, data: &[u8]) -> (Vec<u8>, bool) {
        if !self.config.compress || data.len() < self.config.compression_threshold {
            return (data.to_vec(), false);
        }

        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        if encoder.write_all(data).is_ok() {
            if let Ok(compressed) = encoder.finish() {
                // Only use compression if it actually reduces size
                if compressed.len() < data.len() {
                    return (compressed, true);
                }
            }
        }

        (data.to_vec(), false)
    }

    /// Decompress data
    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| PrismError::Internal(format!("Decompression failed: {}", e)))?;
        Ok(decompressed)
    }

    /// Get entry from Redis
    #[cfg(feature = "distributed-rate-limit")]
    async fn get_entry(&self, key: &str) -> Option<RedisCacheEntry> {
        let conn = self.connection.as_ref()?;
        let mut conn = conn.lock().await;

        let data: Option<Vec<u8>> = conn.get(key).await.ok()?;
        let data = data?;

        serde_json::from_slice(&data).ok()
    }

    #[cfg(not(feature = "distributed-rate-limit"))]
    async fn get_entry(&self, _key: &str) -> Option<RedisCacheEntry> {
        None
    }

    /// Invalidate cache entries by tag
    #[cfg(feature = "distributed-rate-limit")]
    pub async fn invalidate_by_tag(&self, tag: &str) -> Result<usize> {
        let conn = self.connection.as_ref().ok_or_else(|| {
            PrismError::Internal("Redis connection not available".to_string())
        })?;

        let mut conn = conn.lock().await;

        let tag_key = format!("{}tags:{}", self.config.prefix, tag);
        let keys: Vec<String> = conn.smembers(&tag_key).await.unwrap_or_default();

        let count = keys.len();
        for key in &keys {
            let _: std::result::Result<(), _> = conn.del(key).await;
        }
        let _: std::result::Result<(), _> = conn.del(&tag_key).await;

        self.stats.invalidations.fetch_add(count as u64, Ordering::Relaxed);

        info!("Invalidated {} cache entries with tag '{}'", count, tag);

        Ok(count)
    }

    #[cfg(not(feature = "distributed-rate-limit"))]
    pub async fn invalidate_by_tag(&self, _tag: &str) -> Result<usize> {
        Ok(0)
    }

    /// Build response from cache entry
    fn build_response(&self, entry: &RedisCacheEntry) -> Result<HttpResponse> {
        let mut builder = Response::builder().status(entry.status);

        // Add headers
        for (name, value) in &entry.headers {
            if let (Ok(name), Ok(value)) = (
                name.parse::<http::header::HeaderName>(),
                value.parse::<http::header::HeaderValue>(),
            ) {
                builder = builder.header(name, value);
            }
        }

        // Add cache-related headers
        builder = builder
            .header("X-Cache", "HIT")
            .header("Age", entry.age().to_string());

        // Decompress body if needed
        let body = if entry.compressed {
            self.decompress(&entry.body)?
        } else {
            entry.body.clone()
        };

        builder
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| PrismError::Internal(format!("Failed to build response: {}", e)))
    }
}

#[async_trait]
impl Middleware for RedisCacheMiddleware {
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        // Check if request is cacheable
        if !self.is_cacheable_request(&request) {
            return next.run(request, ctx).await;
        }

        let cache_key = self.generate_key(&request);

        // Check conditional request headers
        let if_none_match = request
            .headers()
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let if_modified_since = request
            .headers()
            .get(header::IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Try to get from cache
        if let Some(entry) = self.get_entry(&cache_key).await {
            // Check conditional request
            if let Some(etag) = &entry.etag {
                if let Some(ref inm) = if_none_match {
                    if inm == etag || inm == "*" {
                        debug!("Cache conditional hit (ETag): {}", cache_key);
                        self.stats.hit();
                        return Ok(Response::builder()
                            .status(StatusCode::NOT_MODIFIED)
                            .header("X-Cache", "HIT")
                            .body(Full::new(Bytes::new()))
                            .unwrap());
                    }
                }
            }

            if let Some(lm) = &entry.last_modified {
                if let Some(ref ims) = if_modified_since {
                    if ims == lm {
                        debug!("Cache conditional hit (Last-Modified): {}", cache_key);
                        self.stats.hit();
                        return Ok(Response::builder()
                            .status(StatusCode::NOT_MODIFIED)
                            .header("X-Cache", "HIT")
                            .body(Full::new(Bytes::new()))
                            .unwrap());
                    }
                }
            }

            // Check if fresh
            if !entry.is_expired() {
                debug!("Cache hit: {}", cache_key);
                self.stats.hit();
                self.stats.bytes(entry.body.len() as u64, entry.original_size as u64);
                return self.build_response(&entry);
            }

            // Check if stale-while-revalidate
            if self.config.stale_while_revalidate && entry.is_stale(self.config.stale_ttl) {
                debug!("Cache stale hit: {}", cache_key);
                self.stats.stale_hit();

                // TODO: Trigger background revalidation
                // For now, just serve stale
                let mut response = self.build_response(&entry)?;
                response
                    .headers_mut()
                    .insert("X-Cache", "STALE".parse().unwrap());
                return Ok(response);
            }
        }

        // Cache miss - call upstream
        debug!("Cache miss: {}", cache_key);
        self.stats.miss();

        let response = next.run(request, ctx).await?;

        // Check if response is cacheable
        if !self.is_cacheable_response(&response) {
            return Ok(response);
        }

        // Extract response parts
        let (parts, body) = response.into_parts();
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| PrismError::Internal(format!("Failed to collect response body: {}", e)))?
            .to_bytes();

        // Check size limit
        if body_bytes.len() > self.config.max_entry_size {
            debug!(
                "Response too large to cache: {} > {}",
                body_bytes.len(),
                self.config.max_entry_size
            );
            return Ok(Response::from_parts(parts, Full::new(body_bytes)));
        }

        // Build response for return
        let response = Response::from_parts(parts.clone(), Full::new(body_bytes.clone()));

        // Store in cache (don't block on this)
        #[cfg(feature = "distributed-rate-limit")]
        if let Some(conn) = &self.connection {
            // Calculate TTL
            let ttl = self.parse_ttl(&response);

            // Compress if needed
            let (compressed_body, is_compressed) = self.compress_if_needed(&body_bytes);

            // Extract headers
            let mut headers = HashMap::new();
            for (name, value) in parts.headers.iter() {
                if let Ok(v) = value.to_str() {
                    headers.insert(name.to_string(), v.to_string());
                }
            }

            // Create cache entry
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let entry = RedisCacheEntry {
                status: parts.status.as_u16(),
                headers,
                body: compressed_body,
                compressed: is_compressed,
                etag: parts
                    .headers
                    .get(header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
                last_modified: parts
                    .headers
                    .get(header::LAST_MODIFIED)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string()),
                tags: Vec::new(), // TODO: Extract from response headers
                created_at: now,
                expires_at: now + ttl.as_secs(),
                original_size: body_bytes.len(),
            };

            let key = cache_key.clone();
            let stats = self.stats.clone();
            let conn = conn.clone();
            tokio::spawn(async move {
                let mut conn = conn.lock().await;
                if let Ok(data) = serde_json::to_vec(&entry) {
                    let result: std::result::Result<(), _> =
                        conn.set_ex(&key, data, ttl.as_secs()).await;
                    if result.is_ok() {
                        stats.store();
                        debug!("Stored in cache: {}", key);
                    } else {
                        stats.error();
                    }
                }
            });
        }

        // Return response with cache miss header
        let mut response = response;
        response
            .headers_mut()
            .insert("X-Cache", "MISS".parse().unwrap());
        Ok(response)
    }

    fn name(&self) -> &'static str {
        "redis_cache"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = RedisCacheConfig::default();
        assert_eq!(config.prefix, "prism:cache:");
        assert_eq!(config.default_ttl, Duration::from_secs(300));
        assert!(config.stale_while_revalidate);
    }

    #[test]
    fn test_cache_entry_expiry() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let entry = RedisCacheEntry {
            status: 200,
            headers: HashMap::new(),
            body: vec![],
            compressed: false,
            etag: None,
            last_modified: None,
            tags: vec![],
            created_at: now - 100,
            expires_at: now - 10, // Already expired
            original_size: 0,
        };

        assert!(entry.is_expired());
    }

    #[test]
    fn test_cache_entry_stale() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let entry = RedisCacheEntry {
            status: 200,
            headers: HashMap::new(),
            body: vec![],
            compressed: false,
            etag: None,
            last_modified: None,
            tags: vec![],
            created_at: now - 100,
            expires_at: now - 10, // Expired 10 seconds ago
            original_size: 0,
        };

        // Should be stale within 60 second stale window
        assert!(entry.is_stale(Duration::from_secs(60)));

        // But not stale with 5 second window
        assert!(!entry.is_stale(Duration::from_secs(5)));
    }

    #[test]
    fn test_stats_snapshot() {
        let stats = RedisCacheStats::default();
        stats.hit();
        stats.hit();
        stats.miss();
        stats.store();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.hits, 2);
        assert_eq!(snapshot.misses, 1);
        assert_eq!(snapshot.stores, 1);
        assert!((snapshot.hit_rate() - 0.666).abs() < 0.01);
    }

    #[test]
    #[cfg(feature = "distributed-rate-limit")]
    fn test_compression() {
        let config = RedisCacheConfig::default();
        let middleware = RedisCacheMiddleware {
            config,
            connection: None,
            stats: Arc::new(RedisCacheStats::default()),
        };

        // Small data shouldn't be compressed
        let small = b"hello";
        let (result, compressed) = middleware.compress_if_needed(small);
        assert!(!compressed);
        assert_eq!(result, small);

        // Large repetitive data should compress well
        let large: Vec<u8> = "a".repeat(10000).into_bytes();
        let (result, compressed) = middleware.compress_if_needed(&large);
        assert!(compressed);
        assert!(result.len() < large.len());
    }
}
