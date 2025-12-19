//! Response caching middleware
//!
//! Provides in-memory caching of HTTP responses with:
//! - Configurable TTL and max size
//! - Cache-Control header support
//! - ETag and Last-Modified conditional request handling
//! - LRU eviction policy

use bytes::Bytes;
use dashmap::DashMap;
use http::{header, Method, Request, Response, StatusCode};
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of cached entries
    pub max_entries: usize,
    /// Maximum total size in bytes
    pub max_size: usize,
    /// Default TTL for cached responses
    pub default_ttl: Duration,
    /// Minimum TTL (even if Cache-Control specifies lower)
    pub min_ttl: Duration,
    /// Maximum TTL (even if Cache-Control specifies higher)
    pub max_ttl: Duration,
    /// Whether to cache private responses
    pub cache_private: bool,
    /// Methods to cache (typically only GET)
    pub cacheable_methods: Vec<Method>,
    /// Status codes that are cacheable
    pub cacheable_status: Vec<StatusCode>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10000,
            max_size: 100 * 1024 * 1024, // 100MB
            default_ttl: Duration::from_secs(3600),
            min_ttl: Duration::from_secs(1),
            max_ttl: Duration::from_secs(86400),
            cache_private: false,
            cacheable_methods: vec![Method::GET, Method::HEAD],
            cacheable_status: vec![
                StatusCode::OK,
                StatusCode::NON_AUTHORITATIVE_INFORMATION,
                StatusCode::NO_CONTENT,
                StatusCode::PARTIAL_CONTENT,
                StatusCode::MULTIPLE_CHOICES,
                StatusCode::MOVED_PERMANENTLY,
                StatusCode::FOUND,
                StatusCode::NOT_MODIFIED,
            ],
        }
    }
}

/// A cached response entry
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Cached response status
    pub status: StatusCode,
    /// Cached response headers
    pub headers: Vec<(String, String)>,
    /// Cached response body
    pub body: Bytes,
    /// When this entry was created
    pub created_at: Instant,
    /// When this entry expires
    pub expires_at: Instant,
    /// ETag for conditional requests
    pub etag: Option<String>,
    /// Last-Modified for conditional requests
    pub last_modified: Option<String>,
    /// Size in bytes
    pub size: usize,
}

impl CacheEntry {
    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Check if this entry is still fresh
    pub fn is_fresh(&self) -> bool {
        !self.is_expired()
    }

    /// Get the age of this entry
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

/// Response cache with LRU eviction
pub struct ResponseCache {
    /// Configuration
    config: CacheConfig,
    /// Cache entries by key
    entries: DashMap<String, CacheEntry>,
    /// LRU order tracking
    lru_order: RwLock<VecDeque<String>>,
    /// Current total size
    current_size: AtomicU64,
    /// Cache statistics
    stats: CacheStats,
}

/// Cache statistics
#[derive(Debug, Default)]
pub struct CacheStats {
    /// Number of cache hits
    pub hits: AtomicU64,
    /// Number of cache misses
    pub misses: AtomicU64,
    /// Number of entries evicted
    pub evictions: AtomicU64,
    /// Number of entries expired
    pub expirations: AtomicU64,
}

impl CacheStats {
    /// Get hit rate as a percentage
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            (hits as f64 / total as f64) * 100.0
        }
    }
}

impl ResponseCache {
    /// Create a new response cache
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            entries: DashMap::new(),
            lru_order: RwLock::new(VecDeque::new()),
            current_size: AtomicU64::new(0),
            stats: CacheStats::default(),
        }
    }

    /// Generate cache key from request
    pub fn cache_key<B>(&self, request: &Request<B>) -> String {
        // Basic key: method + host + path + query
        let method = request.method().as_str();
        let uri = request.uri();
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        format!(
            "{}:{}:{}{}",
            method,
            host,
            uri.path(),
            uri.query().map(|q| format!("?{}", q)).unwrap_or_default()
        )
    }

    /// Check if a request is cacheable
    pub fn is_cacheable_request<B>(&self, request: &Request<B>) -> bool {
        // Check method
        if !self.config.cacheable_methods.contains(request.method()) {
            return false;
        }

        // Check for no-store directive
        if let Some(cache_control) = request.headers().get(header::CACHE_CONTROL) {
            if let Ok(value) = cache_control.to_str() {
                if value.contains("no-store") || value.contains("no-cache") {
                    return false;
                }
            }
        }

        // Check Authorization header (usually not cacheable)
        if request.headers().contains_key(header::AUTHORIZATION) {
            return false;
        }

        true
    }

    /// Check if a response is cacheable
    pub fn is_cacheable_response<B>(&self, response: &Response<B>) -> bool {
        // Check status code
        if !self.config.cacheable_status.contains(&response.status()) {
            return false;
        }

        // Check Cache-Control header
        if let Some(cache_control) = response.headers().get(header::CACHE_CONTROL) {
            if let Ok(value) = cache_control.to_str() {
                // Never cache no-store responses
                if value.contains("no-store") {
                    return false;
                }

                // Don't cache private responses unless configured
                if value.contains("private") && !self.config.cache_private {
                    return false;
                }

                // no-cache means validate, not don't cache
                // But we'd need conditional request support
            }
        }

        // Check Vary header - we don't support Vary: * caching
        if let Some(vary) = response.headers().get(header::VARY) {
            if let Ok(value) = vary.to_str() {
                if value == "*" {
                    return false;
                }
            }
        }

        true
    }

    /// Get a cached response
    pub fn get(&self, key: &str) -> Option<CacheEntry> {
        if let Some(entry) = self.entries.get(key) {
            if entry.is_fresh() {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                self.update_lru(key);
                trace!("Cache hit for key: {}", key);
                return Some(entry.clone());
            } else {
                // Entry expired
                drop(entry);
                self.remove(key);
                self.stats.expirations.fetch_add(1, Ordering::Relaxed);
            }
        }

        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        trace!("Cache miss for key: {}", key);
        None
    }

    /// Store a response in the cache
    pub fn put(&self, key: String, entry: CacheEntry) {
        let entry_size = entry.size as u64;

        // Check if entry is too large
        if entry.size > self.config.max_size {
            debug!("Entry too large to cache: {} bytes", entry.size);
            return;
        }

        // Evict entries if necessary
        while self.entries.len() >= self.config.max_entries
            || self.current_size.load(Ordering::Relaxed) + entry_size > self.config.max_size as u64
        {
            if !self.evict_lru() {
                break;
            }
        }

        // Remove old entry if exists
        if let Some((_, old)) = self.entries.remove(&key) {
            self.current_size
                .fetch_sub(old.size as u64, Ordering::Relaxed);
        }

        // Insert new entry
        self.entries.insert(key.clone(), entry);
        self.current_size.fetch_add(entry_size, Ordering::Relaxed);

        // Update LRU order
        let mut lru = self.lru_order.write();
        lru.push_back(key);

        debug!(
            "Cached entry, total entries: {}, total size: {}",
            self.entries.len(),
            self.current_size.load(Ordering::Relaxed)
        );
    }

    /// Remove an entry from the cache
    pub fn remove(&self, key: &str) -> Option<CacheEntry> {
        if let Some((_, entry)) = self.entries.remove(key) {
            self.current_size
                .fetch_sub(entry.size as u64, Ordering::Relaxed);

            // Remove from LRU order
            let mut lru = self.lru_order.write();
            lru.retain(|k| k != key);

            return Some(entry);
        }
        None
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.entries.clear();
        self.lru_order.write().clear();
        self.current_size.store(0, Ordering::Relaxed);
    }

    /// Get cache statistics
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Get current entry count
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get current size in bytes
    pub fn size(&self) -> u64 {
        self.current_size.load(Ordering::Relaxed)
    }

    /// Update LRU position for a key
    fn update_lru(&self, key: &str) {
        let mut lru = self.lru_order.write();
        lru.retain(|k| k != key);
        lru.push_back(key.to_string());
    }

    /// Evict the least recently used entry
    fn evict_lru(&self) -> bool {
        let key = {
            let mut lru = self.lru_order.write();
            lru.pop_front()
        };

        if let Some(key) = key {
            if self.remove(&key).is_some() {
                self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                debug!("Evicted LRU entry: {}", key);
                return true;
            }
        }
        false
    }

    /// Parse Cache-Control header to get TTL
    pub fn parse_ttl(&self, cache_control: Option<&str>) -> Duration {
        let ttl = if let Some(cc) = cache_control {
            // Look for max-age directive
            if let Some(pos) = cc.find("max-age=") {
                let start = pos + 8;
                let end = cc[start..]
                    .find(|c: char| !c.is_ascii_digit())
                    .map(|i| start + i)
                    .unwrap_or(cc.len());

                if let Ok(seconds) = cc[start..end].parse::<u64>() {
                    Duration::from_secs(seconds)
                } else {
                    self.config.default_ttl
                }
            } else if let Some(pos) = cc.find("s-maxage=") {
                // s-maxage takes precedence for shared caches
                let start = pos + 9;
                let end = cc[start..]
                    .find(|c: char| !c.is_ascii_digit())
                    .map(|i| start + i)
                    .unwrap_or(cc.len());

                if let Ok(seconds) = cc[start..end].parse::<u64>() {
                    Duration::from_secs(seconds)
                } else {
                    self.config.default_ttl
                }
            } else {
                self.config.default_ttl
            }
        } else {
            self.config.default_ttl
        };

        // Clamp TTL to configured bounds
        ttl.max(self.config.min_ttl).min(self.config.max_ttl)
    }

    /// Create a cache entry from a response
    pub fn create_entry(
        &self,
        status: StatusCode,
        headers: Vec<(String, String)>,
        body: Bytes,
        cache_control: Option<&str>,
    ) -> CacheEntry {
        let now = Instant::now();
        let ttl = self.parse_ttl(cache_control);

        // Extract ETag and Last-Modified
        let etag = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("etag"))
            .map(|(_, v)| v.clone());

        let last_modified = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("last-modified"))
            .map(|(_, v)| v.clone());

        let size = body.len()
            + headers
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>();

        CacheEntry {
            status,
            headers,
            body,
            created_at: now,
            expires_at: now + ttl,
            etag,
            last_modified,
            size,
        }
    }

    /// Handle conditional request (If-None-Match, If-Modified-Since)
    pub fn handle_conditional<B>(&self, request: &Request<B>, entry: &CacheEntry) -> bool {
        // Check If-None-Match (ETag)
        if let Some(if_none_match) = request.headers().get(header::IF_NONE_MATCH) {
            if let Ok(value) = if_none_match.to_str() {
                if let Some(ref etag) = entry.etag {
                    // Check if any of the client's ETags match
                    for client_etag in value.split(',').map(|s| s.trim()) {
                        if client_etag == "*" || client_etag == etag {
                            return true; // Return 304
                        }
                    }
                }
            }
        }

        // Check If-Modified-Since
        if let Some(if_modified_since) = request.headers().get(header::IF_MODIFIED_SINCE) {
            if let Ok(value) = if_modified_since.to_str() {
                if let Some(ref last_modified) = entry.last_modified {
                    // Simple string comparison (assumes same format)
                    if value == last_modified {
                        return true; // Return 304
                    }
                }
            }
        }

        false
    }
}

/// Cache middleware for request handling
pub struct CacheMiddleware {
    cache: Arc<ResponseCache>,
}

impl CacheMiddleware {
    /// Create a new cache middleware
    pub fn new(config: CacheConfig) -> Self {
        Self {
            cache: Arc::new(ResponseCache::new(config)),
        }
    }

    /// Get the underlying cache
    pub fn cache(&self) -> &Arc<ResponseCache> {
        &self.cache
    }

    /// Check if request can be served from cache
    pub fn get_cached_response<B>(&self, request: &Request<B>) -> Option<CacheEntry> {
        if !self.cache.is_cacheable_request(request) {
            return None;
        }

        let key = self.cache.cache_key(request);
        self.cache.get(&key)
    }

    /// Store response in cache
    pub fn store_response<B>(
        &self,
        request: &Request<B>,
        status: StatusCode,
        headers: Vec<(String, String)>,
        body: Bytes,
    ) {
        if !self.cache.is_cacheable_request(request) {
            return;
        }

        // Extract Cache-Control from headers (clone to avoid borrowing issues)
        let cache_control: Option<String> = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
            .map(|(_, v)| v.clone());

        let key = self.cache.cache_key(request);
        let entry = self
            .cache
            .create_entry(status, headers, body, cache_control.as_deref());
        self.cache.put(key, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_basic_operations() {
        let cache = ResponseCache::new(CacheConfig::default());

        let entry = CacheEntry {
            status: StatusCode::OK,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: Bytes::from("Hello, World!"),
            created_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(3600),
            etag: Some("\"abc123\"".to_string()),
            last_modified: None,
            size: 100,
        };

        cache.put("test-key".to_string(), entry.clone());

        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());

        let retrieved = cache.get("test-key").unwrap();
        assert_eq!(retrieved.status, StatusCode::OK);
        assert_eq!(retrieved.body, Bytes::from("Hello, World!"));
    }

    #[test]
    fn test_cache_expiration() {
        let config = CacheConfig {
            default_ttl: Duration::from_millis(10),
            min_ttl: Duration::from_millis(1),
            ..Default::default()
        };
        let cache = ResponseCache::new(config);

        let entry = CacheEntry {
            status: StatusCode::OK,
            headers: vec![],
            body: Bytes::from("test"),
            created_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_millis(10),
            etag: None,
            last_modified: None,
            size: 4,
        };

        cache.put("expires".to_string(), entry);

        // Should be available immediately
        assert!(cache.get("expires").is_some());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        // Should be expired now
        assert!(cache.get("expires").is_none());
    }

    #[test]
    fn test_cache_lru_eviction() {
        let config = CacheConfig {
            max_entries: 3,
            ..Default::default()
        };
        let cache = ResponseCache::new(config);

        for i in 0..4 {
            let entry = CacheEntry {
                status: StatusCode::OK,
                headers: vec![],
                body: Bytes::from(format!("entry-{}", i)),
                created_at: Instant::now(),
                expires_at: Instant::now() + Duration::from_secs(3600),
                etag: None,
                last_modified: None,
                size: 10,
            };
            cache.put(format!("key-{}", i), entry);
        }

        // Should have evicted the first entry
        assert_eq!(cache.len(), 3);
        assert!(cache.get("key-0").is_none()); // LRU entry evicted
        assert!(cache.get("key-3").is_some()); // Most recent still there
    }

    #[test]
    fn test_cache_key_generation() {
        let cache = ResponseCache::new(CacheConfig::default());

        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/test?foo=bar")
            .header(header::HOST, "example.com")
            .body(())
            .unwrap();

        let key = cache.cache_key(&request);
        assert_eq!(key, "GET:example.com:/api/test?foo=bar");
    }

    #[test]
    fn test_is_cacheable_request() {
        let cache = ResponseCache::new(CacheConfig::default());

        // GET is cacheable
        let get_request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(())
            .unwrap();
        assert!(cache.is_cacheable_request(&get_request));

        // POST is not cacheable
        let post_request = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .body(())
            .unwrap();
        assert!(!cache.is_cacheable_request(&post_request));

        // Request with Authorization is not cacheable
        let auth_request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header(header::AUTHORIZATION, "Bearer token")
            .body(())
            .unwrap();
        assert!(!cache.is_cacheable_request(&auth_request));

        // Request with no-store is not cacheable
        let no_store_request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header(header::CACHE_CONTROL, "no-store")
            .body(())
            .unwrap();
        assert!(!cache.is_cacheable_request(&no_store_request));
    }

    #[test]
    fn test_parse_ttl() {
        let cache = ResponseCache::new(CacheConfig::default());

        // max-age directive
        assert_eq!(
            cache.parse_ttl(Some("max-age=300")),
            Duration::from_secs(300)
        );

        // s-maxage directive
        assert_eq!(
            cache.parse_ttl(Some("public, s-maxage=600")),
            Duration::from_secs(600)
        );

        // No directive uses default
        let default_ttl = cache.config.default_ttl;
        assert_eq!(cache.parse_ttl(None), default_ttl);
        assert_eq!(cache.parse_ttl(Some("public")), default_ttl);
    }

    #[test]
    fn test_ttl_clamping() {
        let config = CacheConfig {
            min_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(3600),
            default_ttl: Duration::from_secs(300),
            ..Default::default()
        };
        let cache = ResponseCache::new(config);

        // Should be clamped to min
        assert_eq!(cache.parse_ttl(Some("max-age=10")), Duration::from_secs(60));

        // Should be clamped to max
        assert_eq!(
            cache.parse_ttl(Some("max-age=86400")),
            Duration::from_secs(3600)
        );

        // Should pass through
        assert_eq!(
            cache.parse_ttl(Some("max-age=1800")),
            Duration::from_secs(1800)
        );
    }

    #[test]
    fn test_conditional_requests() {
        let cache = ResponseCache::new(CacheConfig::default());

        let entry = CacheEntry {
            status: StatusCode::OK,
            headers: vec![],
            body: Bytes::new(),
            created_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(3600),
            etag: Some("\"abc123\"".to_string()),
            last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".to_string()),
            size: 0,
        };

        // Matching ETag should return true (304)
        let request_etag = Request::builder()
            .header(header::IF_NONE_MATCH, "\"abc123\"")
            .body(())
            .unwrap();
        assert!(cache.handle_conditional(&request_etag, &entry));

        // Non-matching ETag should return false
        let request_no_match = Request::builder()
            .header(header::IF_NONE_MATCH, "\"xyz789\"")
            .body(())
            .unwrap();
        assert!(!cache.handle_conditional(&request_no_match, &entry));

        // Wildcard ETag should return true
        let request_wildcard = Request::builder()
            .header(header::IF_NONE_MATCH, "*")
            .body(())
            .unwrap();
        assert!(cache.handle_conditional(&request_wildcard, &entry));

        // Matching Last-Modified should return true
        let request_modified = Request::builder()
            .header(header::IF_MODIFIED_SINCE, "Wed, 21 Oct 2015 07:28:00 GMT")
            .body(())
            .unwrap();
        assert!(cache.handle_conditional(&request_modified, &entry));
    }

    #[test]
    fn test_cache_stats() {
        let cache = ResponseCache::new(CacheConfig::default());

        let entry = CacheEntry {
            status: StatusCode::OK,
            headers: vec![],
            body: Bytes::from("test"),
            created_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(3600),
            etag: None,
            last_modified: None,
            size: 4,
        };

        cache.put("test".to_string(), entry);

        // Hit
        cache.get("test");
        // Miss
        cache.get("nonexistent");

        assert_eq!(cache.stats().hits.load(Ordering::Relaxed), 1);
        assert_eq!(cache.stats().misses.load(Ordering::Relaxed), 1);
        assert_eq!(cache.stats().hit_rate(), 50.0);
    }

    #[test]
    fn test_cache_middleware() {
        let middleware = CacheMiddleware::new(CacheConfig::default());

        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/data")
            .header(header::HOST, "example.com")
            .body(())
            .unwrap();

        // Initially no cached response
        assert!(middleware.get_cached_response(&request).is_none());

        // Store a response
        middleware.store_response(
            &request,
            StatusCode::OK,
            vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("cache-control".to_string(), "max-age=300".to_string()),
            ],
            Bytes::from("{\"data\": true}"),
        );

        // Should now have a cached response
        let cached = middleware.get_cached_response(&request);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().body, Bytes::from("{\"data\": true}"));
    }
}
