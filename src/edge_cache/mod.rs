//! Edge Caching Module
//!
//! Provides distributed edge caching with:
//! - Multi-tier cache (memory, disk, remote)
//! - Cache coherence across edge nodes
//! - Stale-while-revalidate support
//! - Vary header support
//! - Cache tags for invalidation

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::broadcast;

/// Edge cache configuration
#[derive(Debug, Clone)]
pub struct EdgeCacheConfig {
    /// Enable caching
    pub enabled: bool,
    /// Maximum memory cache size in bytes
    pub max_memory_size: usize,
    /// Maximum disk cache size in bytes
    pub max_disk_size: usize,
    /// Default TTL
    pub default_ttl: Duration,
    /// Maximum TTL
    pub max_ttl: Duration,
    /// Enable stale-while-revalidate
    pub stale_while_revalidate: bool,
    /// Stale TTL (how long to serve stale)
    pub stale_ttl: Duration,
    /// Enable cache coalescing (request coalescing during revalidation)
    pub coalesce_revalidation: bool,
    /// Node ID for distributed caching
    pub node_id: String,
    /// Enable cache sharing between nodes
    pub distributed: bool,
}

impl Default for EdgeCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_memory_size: 256 * 1024 * 1024, // 256MB
            max_disk_size: 1024 * 1024 * 1024,  // 1GB
            default_ttl: Duration::from_secs(300),
            max_ttl: Duration::from_secs(86400),
            stale_while_revalidate: true,
            stale_ttl: Duration::from_secs(60),
            coalesce_revalidation: true,
            node_id: "node-1".to_string(),
            distributed: false,
        }
    }
}

/// Cache key
#[derive(Debug, Clone, Eq)]
pub struct CacheKey {
    pub method: String,
    pub url: String,
    pub vary_headers: HashMap<String, String>,
}

impl PartialEq for CacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.method == other.method
            && self.url == other.url
            && self.vary_headers == other.vary_headers
    }
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.method.hash(state);
        self.url.hash(state);
        let mut pairs: Vec<_> = self.vary_headers.iter().collect();
        pairs.sort_by_key(|(k, _)| *k);
        for (k, v) in pairs {
            k.hash(state);
            v.hash(state);
        }
    }
}

impl CacheKey {
    pub fn new(method: &str, url: &str) -> Self {
        Self {
            method: method.to_uppercase(),
            url: url.to_string(),
            vary_headers: HashMap::new(),
        }
    }

    pub fn with_vary(mut self, name: &str, value: &str) -> Self {
        self.vary_headers
            .insert(name.to_lowercase(), value.to_string());
        self
    }

    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        let mut s = format!("{}:{}", self.method, self.url);
        if !self.vary_headers.is_empty() {
            let mut pairs: Vec<_> = self.vary_headers.iter().collect();
            pairs.sort_by_key(|(k, _)| *k);
            for (k, v) in pairs {
                s.push_str(&format!(":{}={}", k, v));
            }
        }
        s
    }
}

/// Cached entry
#[derive(Debug)]
pub struct CacheEntry {
    pub key: CacheKey,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Bytes,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub stale_at: Option<SystemTime>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub vary: Vec<String>,
    pub tags: HashSet<String>,
    pub size: usize,
    pub hit_count: AtomicU64,
}

impl Clone for CacheEntry {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            status: self.status,
            headers: self.headers.clone(),
            body: self.body.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            stale_at: self.stale_at,
            etag: self.etag.clone(),
            last_modified: self.last_modified.clone(),
            vary: self.vary.clone(),
            tags: self.tags.clone(),
            size: self.size,
            hit_count: AtomicU64::new(self.hit_count.load(Ordering::Relaxed)),
        }
    }
}

impl CacheEntry {
    pub fn is_fresh(&self) -> bool {
        SystemTime::now() < self.expires_at
    }

    pub fn is_stale(&self) -> bool {
        let now = SystemTime::now();
        now >= self.expires_at && self.stale_at.map(|s| now < s).unwrap_or(false)
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now();
        now >= self.expires_at && !self.is_stale()
    }

    pub fn age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.created_at)
            .unwrap_or(Duration::ZERO)
    }

    pub fn record_hit(&self) {
        self.hit_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Cache control directive
#[derive(Debug, Clone, Default)]
pub struct CacheControl {
    pub max_age: Option<Duration>,
    pub s_maxage: Option<Duration>,
    pub no_cache: bool,
    pub no_store: bool,
    pub private: bool,
    pub public: bool,
    pub must_revalidate: bool,
    pub stale_while_revalidate: Option<Duration>,
    pub stale_if_error: Option<Duration>,
}

impl CacheControl {
    pub fn parse(header: &str) -> Self {
        let mut cc = CacheControl::default();

        for directive in header.split(',') {
            let directive = directive.trim();
            let parts: Vec<&str> = directive.splitn(2, '=').collect();
            let name = parts[0].to_lowercase();
            let value = parts.get(1).map(|s| s.trim().trim_matches('"'));

            match name.as_str() {
                "max-age" => {
                    cc.max_age = value.and_then(|v| v.parse().ok()).map(Duration::from_secs);
                }
                "s-maxage" => {
                    cc.s_maxage = value.and_then(|v| v.parse().ok()).map(Duration::from_secs);
                }
                "no-cache" => cc.no_cache = true,
                "no-store" => cc.no_store = true,
                "private" => cc.private = true,
                "public" => cc.public = true,
                "must-revalidate" => cc.must_revalidate = true,
                "stale-while-revalidate" => {
                    cc.stale_while_revalidate =
                        value.and_then(|v| v.parse().ok()).map(Duration::from_secs);
                }
                "stale-if-error" => {
                    cc.stale_if_error = value.and_then(|v| v.parse().ok()).map(Duration::from_secs);
                }
                _ => {}
            }
        }

        cc
    }

    pub fn effective_ttl(&self, default: Duration) -> Duration {
        self.s_maxage.or(self.max_age).unwrap_or(default)
    }

    pub fn is_cacheable(&self) -> bool {
        !self.no_store && !self.private
    }
}

/// Cache lookup result
#[derive(Debug)]
pub enum CacheLookupResult {
    /// Cache hit with fresh entry
    Hit(Arc<CacheEntry>),
    /// Cache hit with stale entry (needs revalidation)
    Stale(Arc<CacheEntry>),
    /// Cache miss
    Miss,
    /// Entry is being revalidated, wait for it
    Revalidating(broadcast::Receiver<Arc<CacheEntry>>),
}

/// Cache store result
pub enum CacheStoreResult {
    Stored,
    NotCacheable,
    TooLarge,
    Evicted(Vec<CacheKey>),
}

/// Cache invalidation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidationEvent {
    pub id: String,
    pub keys: Vec<String>,
    pub tags: Vec<String>,
    pub patterns: Vec<String>,
    pub timestamp: u64,
    pub source_node: String,
}

/// Edge cache statistics
#[derive(Debug, Default)]
pub struct EdgeCacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub stale_hits: AtomicU64,
    pub stores: AtomicU64,
    pub evictions: AtomicU64,
    pub invalidations: AtomicU64,
    pub revalidations: AtomicU64,
    pub bytes_stored: AtomicU64,
    pub bytes_served: AtomicU64,
}

impl EdgeCacheStats {
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64 * 100.0
        }
    }
}

/// Memory cache tier
struct MemoryCache {
    entries: DashMap<String, Arc<CacheEntry>>,
    size: AtomicU64,
    max_size: usize,
    lru_order: RwLock<Vec<String>>,
}

impl MemoryCache {
    fn new(max_size: usize) -> Self {
        Self {
            entries: DashMap::new(),
            size: AtomicU64::new(0),
            max_size,
            lru_order: RwLock::new(Vec::new()),
        }
    }

    fn get(&self, key: &str) -> Option<Arc<CacheEntry>> {
        if let Some(entry) = self.entries.get(key) {
            // Update LRU order
            let mut order = self.lru_order.write();
            if let Some(pos) = order.iter().position(|k| k == key) {
                order.remove(pos);
            }
            order.push(key.to_string());

            Some(entry.clone())
        } else {
            None
        }
    }

    fn put(&self, entry: Arc<CacheEntry>) -> Vec<String> {
        let key = entry.key.to_string();
        let size = entry.size;
        let mut evicted = Vec::new();

        // Evict if necessary
        while self.size.load(Ordering::Relaxed) as usize + size > self.max_size {
            if let Some(evicted_key) = self.evict_one() {
                evicted.push(evicted_key);
            } else {
                break;
            }
        }

        // Store entry
        if let Some(old) = self.entries.insert(key.clone(), entry) {
            self.size.fetch_sub(old.size as u64, Ordering::Relaxed);
        }
        self.size.fetch_add(size as u64, Ordering::Relaxed);

        // Update LRU
        let mut order = self.lru_order.write();
        order.push(key);

        evicted
    }

    fn remove(&self, key: &str) -> Option<Arc<CacheEntry>> {
        if let Some((_, entry)) = self.entries.remove(key) {
            self.size.fetch_sub(entry.size as u64, Ordering::Relaxed);

            let mut order = self.lru_order.write();
            if let Some(pos) = order.iter().position(|k| k == key) {
                order.remove(pos);
            }

            Some(entry)
        } else {
            None
        }
    }

    fn evict_one(&self) -> Option<String> {
        let mut order = self.lru_order.write();
        if let Some(key) = order.first().cloned() {
            order.remove(0);
            drop(order);

            if let Some((_, entry)) = self.entries.remove(&key) {
                self.size.fetch_sub(entry.size as u64, Ordering::Relaxed);
                return Some(key);
            }
        }
        None
    }

    fn clear(&self) {
        self.entries.clear();
        self.size.store(0, Ordering::Relaxed);
        self.lru_order.write().clear();
    }
}

/// Edge cache
pub struct EdgeCache {
    config: EdgeCacheConfig,
    memory: MemoryCache,
    revalidating: DashMap<String, broadcast::Sender<Arc<CacheEntry>>>,
    tags_index: DashMap<String, HashSet<String>>,
    stats: EdgeCacheStats,
}

impl EdgeCache {
    pub fn new(config: EdgeCacheConfig) -> Self {
        Self {
            memory: MemoryCache::new(config.max_memory_size),
            config,
            revalidating: DashMap::new(),
            tags_index: DashMap::new(),
            stats: EdgeCacheStats::default(),
        }
    }

    /// Look up entry in cache
    pub fn lookup(&self, key: &CacheKey) -> CacheLookupResult {
        let key_str = key.to_string();

        // Check if revalidation is in progress
        if self.config.coalesce_revalidation {
            if let Some(sender) = self.revalidating.get(&key_str) {
                return CacheLookupResult::Revalidating(sender.subscribe());
            }
        }

        // Look up in memory cache
        if let Some(entry) = self.memory.get(&key_str) {
            entry.record_hit();
            self.stats
                .bytes_served
                .fetch_add(entry.size as u64, Ordering::Relaxed);

            if entry.is_fresh() {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return CacheLookupResult::Hit(entry);
            } else if entry.is_stale() && self.config.stale_while_revalidate {
                self.stats.stale_hits.fetch_add(1, Ordering::Relaxed);
                return CacheLookupResult::Stale(entry);
            }
        }

        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        CacheLookupResult::Miss
    }

    /// Store entry in cache
    pub fn store(&self, entry: CacheEntry) -> CacheStoreResult {
        let key_str = entry.key.to_string();

        // Check if cacheable
        if entry.size > self.config.max_memory_size {
            return CacheStoreResult::TooLarge;
        }

        let entry = Arc::new(entry);

        // Index by tags
        for tag in &entry.tags {
            self.tags_index
                .entry(tag.clone())
                .or_default()
                .insert(key_str.clone());
        }

        // Store in memory cache
        let evicted = self.memory.put(entry.clone());

        self.stats.stores.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_stored
            .fetch_add(entry.size as u64, Ordering::Relaxed);

        if !evicted.is_empty() {
            self.stats
                .evictions
                .fetch_add(evicted.len() as u64, Ordering::Relaxed);
            CacheStoreResult::Evicted(
                evicted
                    .into_iter()
                    .map(|s| CacheKey::new("GET", &s))
                    .collect(),
            )
        } else {
            CacheStoreResult::Stored
        }
    }

    /// Start revalidation for a key
    pub fn start_revalidation(&self, key: &CacheKey) -> broadcast::Sender<Arc<CacheEntry>> {
        let (tx, _) = broadcast::channel(1);
        self.revalidating.insert(key.to_string(), tx.clone());
        self.stats.revalidations.fetch_add(1, Ordering::Relaxed);
        tx
    }

    /// Complete revalidation
    pub fn complete_revalidation(&self, key: &CacheKey, entry: Arc<CacheEntry>) {
        let key_str = key.to_string();

        if let Some((_, sender)) = self.revalidating.remove(&key_str) {
            let _ = sender.send(entry.clone());
        }

        // Store the new entry
        self.memory.put(entry);
    }

    /// Cancel revalidation
    pub fn cancel_revalidation(&self, key: &CacheKey) {
        self.revalidating.remove(&key.to_string());
    }

    /// Invalidate by key
    pub fn invalidate(&self, key: &CacheKey) -> bool {
        self.stats.invalidations.fetch_add(1, Ordering::Relaxed);
        self.memory.remove(&key.to_string()).is_some()
    }

    /// Invalidate by tag
    pub fn invalidate_by_tag(&self, tag: &str) -> usize {
        let mut count = 0;

        if let Some((_, keys)) = self.tags_index.remove(tag) {
            for key in keys {
                if self.memory.remove(&key).is_some() {
                    count += 1;
                }
            }
        }

        self.stats
            .invalidations
            .fetch_add(count as u64, Ordering::Relaxed);
        count
    }

    /// Invalidate by pattern (glob)
    pub fn invalidate_by_pattern(&self, pattern: &str) -> usize {
        let mut count = 0;

        if let Ok(glob) = glob::Pattern::new(pattern) {
            let keys: Vec<_> = self
                .memory
                .entries
                .iter()
                .filter(|e| glob.matches(e.key()))
                .map(|e| e.key().clone())
                .collect();

            for key in keys {
                if self.memory.remove(&key).is_some() {
                    count += 1;
                }
            }
        }

        self.stats
            .invalidations
            .fetch_add(count as u64, Ordering::Relaxed);
        count
    }

    /// Clear entire cache
    pub fn clear(&self) {
        self.memory.clear();
        self.tags_index.clear();
        self.revalidating.clear();
    }

    /// Create cache entry from response
    pub fn create_entry(
        &self,
        key: CacheKey,
        status: u16,
        headers: HashMap<String, String>,
        body: Bytes,
        cache_control: &CacheControl,
        tags: HashSet<String>,
    ) -> CacheEntry {
        let now = SystemTime::now();
        let ttl = cache_control.effective_ttl(self.config.default_ttl);
        let ttl = ttl.min(self.config.max_ttl);

        let stale_duration = cache_control
            .stale_while_revalidate
            .unwrap_or(self.config.stale_ttl);

        let expires_at = now + ttl;
        let stale_at = if self.config.stale_while_revalidate {
            Some(expires_at + stale_duration)
        } else {
            None
        };

        let etag = headers.get("etag").cloned();
        let last_modified = headers.get("last-modified").cloned();
        let vary = headers
            .get("vary")
            .map(|v| v.split(',').map(|s| s.trim().to_lowercase()).collect())
            .unwrap_or_default();

        CacheEntry {
            key,
            status,
            headers,
            size: body.len(),
            body,
            created_at: now,
            expires_at,
            stale_at,
            etag,
            last_modified,
            vary,
            tags,
            hit_count: AtomicU64::new(0),
        }
    }

    /// Check if response is cacheable
    pub fn is_cacheable(&self, status: u16, method: &str, cache_control: &CacheControl) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Only cache GET and HEAD
        if method != "GET" && method != "HEAD" {
            return false;
        }

        // Check cache-control directives
        if !cache_control.is_cacheable() {
            return false;
        }

        // Only cache successful responses
        matches!(
            status,
            200 | 203 | 204 | 206 | 300 | 301 | 308 | 404 | 405 | 410 | 414 | 501
        )
    }

    /// Get cache statistics
    pub fn stats(&self) -> &EdgeCacheStats {
        &self.stats
    }

    /// Get current cache size
    pub fn size(&self) -> u64 {
        self.memory.size.load(Ordering::Relaxed)
    }

    /// Get entry count
    pub fn entry_count(&self) -> usize {
        self.memory.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key() {
        let key1 = CacheKey::new("GET", "/api/users");
        let key2 = CacheKey::new("GET", "/api/users").with_vary("accept", "application/json");

        assert_ne!(key1.to_string(), key2.to_string());
    }

    #[test]
    fn test_cache_control_parsing() {
        let cc = CacheControl::parse("max-age=3600, public, stale-while-revalidate=60");

        assert_eq!(cc.max_age, Some(Duration::from_secs(3600)));
        assert!(cc.public);
        assert!(!cc.private);
        assert_eq!(cc.stale_while_revalidate, Some(Duration::from_secs(60)));
    }

    #[test]
    fn test_cache_control_no_store() {
        let cc = CacheControl::parse("no-store");
        assert!(!cc.is_cacheable());
    }

    #[test]
    fn test_cache_lookup_miss() {
        let cache = EdgeCache::new(EdgeCacheConfig::default());
        let key = CacheKey::new("GET", "/api/users");

        match cache.lookup(&key) {
            CacheLookupResult::Miss => {}
            _ => panic!("Expected cache miss"),
        }
    }

    #[test]
    fn test_cache_store_and_hit() {
        let cache = EdgeCache::new(EdgeCacheConfig::default());
        let key = CacheKey::new("GET", "/api/users");

        let cc = CacheControl::parse("max-age=3600");
        let entry = cache.create_entry(
            key.clone(),
            200,
            HashMap::new(),
            Bytes::from("test body"),
            &cc,
            HashSet::new(),
        );

        cache.store(entry);

        match cache.lookup(&key) {
            CacheLookupResult::Hit(entry) => {
                assert_eq!(entry.status, 200);
                assert_eq!(entry.body, Bytes::from("test body"));
            }
            _ => panic!("Expected cache hit"),
        }
    }

    #[test]
    fn test_cache_invalidation() {
        let cache = EdgeCache::new(EdgeCacheConfig::default());
        let key = CacheKey::new("GET", "/api/users");

        let cc = CacheControl::parse("max-age=3600");
        let entry = cache.create_entry(
            key.clone(),
            200,
            HashMap::new(),
            Bytes::from("test"),
            &cc,
            HashSet::new(),
        );

        cache.store(entry);
        assert!(cache.invalidate(&key));

        match cache.lookup(&key) {
            CacheLookupResult::Miss => {}
            _ => panic!("Expected cache miss after invalidation"),
        }
    }

    #[test]
    fn test_cache_invalidation_by_tag() {
        let cache = EdgeCache::new(EdgeCacheConfig::default());
        let key = CacheKey::new("GET", "/api/users/1");

        let mut tags = HashSet::new();
        tags.insert("user:1".to_string());
        tags.insert("users".to_string());

        let cc = CacheControl::parse("max-age=3600");
        let entry = cache.create_entry(
            key.clone(),
            200,
            HashMap::new(),
            Bytes::from("test"),
            &cc,
            tags,
        );

        cache.store(entry);
        assert_eq!(cache.invalidate_by_tag("user:1"), 1);

        match cache.lookup(&key) {
            CacheLookupResult::Miss => {}
            _ => panic!("Expected cache miss after tag invalidation"),
        }
    }

    #[test]
    fn test_cache_eviction() {
        let config = EdgeCacheConfig {
            max_memory_size: 100, // Very small
            ..Default::default()
        };
        let cache = EdgeCache::new(config);

        let cc = CacheControl::parse("max-age=3600");

        // Store entries until eviction
        for i in 0..5 {
            let key = CacheKey::new("GET", &format!("/api/{}", i));
            let entry = cache.create_entry(
                key,
                200,
                HashMap::new(),
                Bytes::from("a".repeat(30)),
                &cc,
                HashSet::new(),
            );
            cache.store(entry);
        }

        // Some entries should have been evicted
        assert!(cache.stats.evictions.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_is_cacheable() {
        let cache = EdgeCache::new(EdgeCacheConfig::default());

        // GET with max-age is cacheable
        let cc = CacheControl::parse("max-age=3600");
        assert!(cache.is_cacheable(200, "GET", &cc));

        // POST is not cacheable
        assert!(!cache.is_cacheable(200, "POST", &cc));

        // no-store is not cacheable
        let cc = CacheControl::parse("no-store");
        assert!(!cache.is_cacheable(200, "GET", &cc));

        // private is not cacheable
        let cc = CacheControl::parse("private");
        assert!(!cache.is_cacheable(200, "GET", &cc));
    }

    #[test]
    fn test_cache_stats() {
        let cache = EdgeCache::new(EdgeCacheConfig::default());
        let key = CacheKey::new("GET", "/api/users");

        // Miss
        cache.lookup(&key);
        assert_eq!(cache.stats.misses.load(Ordering::Relaxed), 1);

        // Store
        let cc = CacheControl::parse("max-age=3600");
        let entry = cache.create_entry(
            key.clone(),
            200,
            HashMap::new(),
            Bytes::from("test"),
            &cc,
            HashSet::new(),
        );
        cache.store(entry);
        assert_eq!(cache.stats.stores.load(Ordering::Relaxed), 1);

        // Hit
        cache.lookup(&key);
        assert_eq!(cache.stats.hits.load(Ordering::Relaxed), 1);

        // Hit rate
        assert!(cache.stats.hit_rate() > 0.0);
    }
}
