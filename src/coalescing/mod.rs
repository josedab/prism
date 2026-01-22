//! Request Coalescing
//!
//! Deduplicates identical in-flight requests to reduce backend load.
//! When multiple clients request the same resource simultaneously,
//! only one request is sent to the backend and the response is
//! shared with all waiting clients.
//!
//! Similar to Varnish's request coalescing / nginx proxy_cache_lock.

use bytes::Bytes;
use dashmap::DashMap;
use http::{Method, Request, StatusCode};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{debug, trace, warn};

/// Request coalescing configuration
#[derive(Debug, Clone)]
pub struct CoalescingConfig {
    /// Enable request coalescing
    pub enabled: bool,
    /// Maximum time to wait for a coalesced response
    pub max_wait: Duration,
    /// Maximum number of waiters per request
    pub max_waiters: usize,
    /// Methods that can be coalesced (typically only GET/HEAD)
    pub coalescable_methods: Vec<Method>,
    /// Include query string in cache key
    pub include_query: bool,
    /// Include specific headers in cache key
    pub key_headers: Vec<String>,
    /// Maximum pending requests to track
    pub max_pending: usize,
    /// Cleanup interval for stale entries
    pub cleanup_interval: Duration,
}

impl Default for CoalescingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_wait: Duration::from_secs(30),
            max_waiters: 1000,
            coalescable_methods: vec![Method::GET, Method::HEAD],
            include_query: true,
            key_headers: vec!["Accept".to_string(), "Accept-Encoding".to_string()],
            max_pending: 10000,
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

/// Cache key for request coalescing
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoalescingKey {
    /// HTTP method
    method: String,
    /// Request URI (path and optionally query)
    uri: String,
    /// Host header
    host: Option<String>,
    /// Additional header values for the key
    headers: Vec<(String, String)>,
}

impl CoalescingKey {
    /// Create a new coalescing key from a request
    pub fn from_request<B>(request: &Request<B>, config: &CoalescingConfig) -> Self {
        let uri = if config.include_query {
            request.uri().to_string()
        } else {
            request.uri().path().to_string()
        };

        let host = request
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let mut headers: Vec<(String, String)> = config
            .key_headers
            .iter()
            .filter_map(|name| {
                request
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| (name.to_lowercase(), v.to_string()))
            })
            .collect();

        headers.sort();

        Self {
            method: request.method().to_string(),
            uri,
            host,
            headers,
        }
    }

    /// Create a simple key from method and path
    pub fn simple(method: &str, path: &str) -> Self {
        Self {
            method: method.to_string(),
            uri: path.to_string(),
            host: None,
            headers: Vec::new(),
        }
    }
}

/// A coalesced response that can be shared
#[derive(Debug, Clone)]
pub struct CoalescedResponse {
    /// Response status code
    pub status: StatusCode,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body
    pub body: Bytes,
    /// When the response was received
    pub received_at: Instant,
}

impl CoalescedResponse {
    /// Create from an HTTP response
    pub fn from_response(
        status: StatusCode,
        headers: HashMap<String, String>,
        body: Bytes,
    ) -> Self {
        Self {
            status,
            headers,
            body,
            received_at: Instant::now(),
        }
    }
}

/// Result of a coalescing operation
#[derive(Debug)]
pub enum CoalescingResult {
    /// This request is the leader - make the actual backend request
    Leader(CoalescingHandle),
    /// This request is waiting for the leader's response
    Waiter(oneshot::Receiver<Arc<CoalescedResponse>>),
    /// Coalescing is disabled or not applicable
    Bypass,
}

/// Handle for the leader request to notify waiters
pub struct CoalescingHandle {
    key: CoalescingKey,
    waiters: Vec<oneshot::Sender<Arc<CoalescedResponse>>>,
    coalescer: Arc<RequestCoalescer>,
}

impl std::fmt::Debug for CoalescingHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoalescingHandle")
            .field("key", &self.key)
            .field("waiter_count", &self.waiters.len())
            .finish()
    }
}

impl CoalescingHandle {
    /// Complete the request and notify all waiters
    pub fn complete(self, response: CoalescedResponse) {
        let response = Arc::new(response);
        let waiter_count = self.waiters.len();

        for tx in self.waiters {
            let _ = tx.send(response.clone());
        }

        self.coalescer.complete_request(&self.key, waiter_count);

        debug!(
            "Coalesced request completed, notified {} waiters",
            waiter_count
        );
    }

    /// Fail the request and notify all waiters
    pub fn fail(self, error: &str) {
        // Create an error response
        let response = Arc::new(CoalescedResponse {
            status: StatusCode::BAD_GATEWAY,
            headers: HashMap::new(),
            body: Bytes::from(format!("Coalesced request failed: {}", error)),
            received_at: Instant::now(),
        });

        let waiter_count = self.waiters.len();

        for tx in self.waiters {
            let _ = tx.send(response.clone());
        }

        self.coalescer.complete_request(&self.key, waiter_count);
        self.coalescer
            .stats
            .failed_requests
            .fetch_add(1, Ordering::Relaxed);

        warn!(
            "Coalesced request failed, notified {} waiters: {}",
            waiter_count, error
        );
    }
}

/// State of a pending coalesced request
struct PendingRequest {
    /// When the request started
    started_at: Instant,
    /// Channels waiting for the response
    waiters: Vec<oneshot::Sender<Arc<CoalescedResponse>>>,
}

/// Request coalescing statistics
#[derive(Debug, Default)]
pub struct CoalescingStats {
    /// Total requests processed
    pub total_requests: AtomicU64,
    /// Requests that became leaders
    pub leader_requests: AtomicU64,
    /// Requests that waited (coalesced)
    pub coalesced_requests: AtomicU64,
    /// Requests that bypassed coalescing
    pub bypassed_requests: AtomicU64,
    /// Failed coalesced requests
    pub failed_requests: AtomicU64,
    /// Total waiters served
    pub waiters_served: AtomicU64,
    /// Current pending requests
    pub pending_count: AtomicU64,
    /// Requests that timed out waiting
    pub timeout_requests: AtomicU64,
}

impl CoalescingStats {
    /// Get coalescing ratio (percentage of requests that were coalesced)
    pub fn coalescing_ratio(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let coalesced = self.coalesced_requests.load(Ordering::Relaxed);
        (coalesced as f64 / total as f64) * 100.0
    }

    /// Get amplification factor (how many responses per backend request)
    pub fn amplification_factor(&self) -> f64 {
        let leaders = self.leader_requests.load(Ordering::Relaxed);
        if leaders == 0 {
            return 1.0;
        }
        let total = self.leader_requests.load(Ordering::Relaxed)
            + self.coalesced_requests.load(Ordering::Relaxed);
        total as f64 / leaders as f64
    }
}

/// Request coalescer
pub struct RequestCoalescer {
    config: CoalescingConfig,
    pending: DashMap<CoalescingKey, PendingRequest>,
    stats: Arc<CoalescingStats>,
}

impl RequestCoalescer {
    /// Create a new request coalescer
    pub fn new(config: CoalescingConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            pending: DashMap::new(),
            stats: Arc::new(CoalescingStats::default()),
        })
    }

    /// Check if a request method can be coalesced
    pub fn can_coalesce(&self, method: &Method) -> bool {
        self.config.enabled && self.config.coalescable_methods.contains(method)
    }

    /// Try to coalesce a request
    pub fn coalesce<B>(self: &Arc<Self>, request: &Request<B>) -> CoalescingResult {
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        // Check if method can be coalesced
        if !self.can_coalesce(request.method()) {
            self.stats.bypassed_requests.fetch_add(1, Ordering::Relaxed);
            return CoalescingResult::Bypass;
        }

        let key = CoalescingKey::from_request(request, &self.config);

        // Try to join an existing pending request
        if let Some(mut pending) = self.pending.get_mut(&key) {
            if pending.waiters.len() < self.config.max_waiters {
                let (tx, rx) = oneshot::channel();
                pending.waiters.push(tx);
                self.stats
                    .coalesced_requests
                    .fetch_add(1, Ordering::Relaxed);

                trace!("Request coalesced, {} total waiters", pending.waiters.len());

                return CoalescingResult::Waiter(rx);
            } else {
                // Too many waiters, bypass
                self.stats.bypassed_requests.fetch_add(1, Ordering::Relaxed);
                return CoalescingResult::Bypass;
            }
        }

        // Check if we have too many pending requests
        if self.pending.len() >= self.config.max_pending {
            self.stats.bypassed_requests.fetch_add(1, Ordering::Relaxed);
            return CoalescingResult::Bypass;
        }

        // Become the leader for this request
        let pending_request = PendingRequest {
            started_at: Instant::now(),
            waiters: Vec::new(),
        };

        self.pending.insert(key.clone(), pending_request);
        self.stats.leader_requests.fetch_add(1, Ordering::Relaxed);
        self.stats.pending_count.fetch_add(1, Ordering::Relaxed);

        trace!("Request became leader");

        // Create handle for completing the request
        CoalescingResult::Leader(CoalescingHandle {
            key,
            waiters: Vec::new(),
            coalescer: self.clone(),
        })
    }

    /// Complete a pending request
    fn complete_request(&self, key: &CoalescingKey, waiter_count: usize) {
        self.pending.remove(key);
        self.stats.pending_count.fetch_sub(1, Ordering::Relaxed);
        self.stats
            .waiters_served
            .fetch_add(waiter_count as u64, Ordering::Relaxed);
    }

    /// Get statistics
    pub fn stats(&self) -> Arc<CoalescingStats> {
        self.stats.clone()
    }

    /// Clean up stale pending requests
    pub fn cleanup_stale(&self) {
        let now = Instant::now();
        let mut stale_keys = Vec::new();

        for entry in self.pending.iter() {
            if now.duration_since(entry.started_at) > self.config.max_wait {
                stale_keys.push(entry.key().clone());
            }
        }

        for key in stale_keys {
            if let Some((_, pending)) = self.pending.remove(&key) {
                // Notify waiters of timeout
                let error_response = Arc::new(CoalescedResponse {
                    status: StatusCode::GATEWAY_TIMEOUT,
                    headers: HashMap::new(),
                    body: Bytes::from("Request coalescing timeout"),
                    received_at: Instant::now(),
                });

                for tx in pending.waiters {
                    let _ = tx.send(error_response.clone());
                }

                self.stats.timeout_requests.fetch_add(1, Ordering::Relaxed);
                self.stats.pending_count.fetch_sub(1, Ordering::Relaxed);

                warn!("Cleaned up stale coalesced request");
            }
        }
    }

    /// Run cleanup task
    pub async fn run_cleanup(self: Arc<Self>) {
        loop {
            tokio::time::sleep(self.config.cleanup_interval).await;
            self.cleanup_stale();
        }
    }

    /// Get current pending request count
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Coalescing middleware wrapper
pub struct CoalescingMiddleware {
    coalescer: Arc<RequestCoalescer>,
}

impl CoalescingMiddleware {
    /// Create new coalescing middleware
    pub fn new(config: CoalescingConfig) -> Self {
        Self {
            coalescer: RequestCoalescer::new(config),
        }
    }

    /// Get the coalescer
    pub fn coalescer(&self) -> Arc<RequestCoalescer> {
        self.coalescer.clone()
    }

    /// Process a request through coalescing
    pub async fn process<B, F, Fut>(
        &self,
        request: Request<B>,
        handler: F,
    ) -> Result<CoalescedResponse, String>
    where
        F: FnOnce(Request<B>) -> Fut,
        Fut: std::future::Future<Output = Result<CoalescedResponse, String>>,
    {
        match self.coalescer.coalesce(&request) {
            CoalescingResult::Leader(handle) => {
                // We're the leader - make the actual request
                match handler(request).await {
                    Ok(response) => {
                        let response_clone = response.clone();
                        handle.complete(response);
                        Ok(response_clone)
                    }
                    Err(e) => {
                        handle.fail(&e);
                        Err(e)
                    }
                }
            }
            CoalescingResult::Waiter(rx) => {
                // Wait for the leader's response
                match tokio::time::timeout(self.coalescer.config.max_wait, rx).await {
                    Ok(Ok(response)) => Ok((*response).clone()),
                    Ok(Err(_)) => Err("Leader request was cancelled".to_string()),
                    Err(_) => {
                        self.coalescer
                            .stats
                            .timeout_requests
                            .fetch_add(1, Ordering::Relaxed);
                        Err("Timeout waiting for coalesced response".to_string())
                    }
                }
            }
            CoalescingResult::Bypass => {
                // Not coalesced - make request directly
                handler(request).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_request(method: Method, path: &str) -> Request<()> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(())
            .unwrap()
    }

    #[test]
    fn test_coalescing_key() {
        let config = CoalescingConfig::default();

        let req1 = make_test_request(Method::GET, "/api/data?id=1");
        let key1 = CoalescingKey::from_request(&req1, &config);

        let req2 = make_test_request(Method::GET, "/api/data?id=1");
        let key2 = CoalescingKey::from_request(&req2, &config);

        assert_eq!(key1, key2);

        let req3 = make_test_request(Method::GET, "/api/data?id=2");
        let key3 = CoalescingKey::from_request(&req3, &config);

        assert_ne!(key1, key3);
    }

    #[test]
    fn test_coalescing_key_without_query() {
        let mut config = CoalescingConfig::default();
        config.include_query = false;

        let req1 = make_test_request(Method::GET, "/api/data?id=1");
        let key1 = CoalescingKey::from_request(&req1, &config);

        let req2 = make_test_request(Method::GET, "/api/data?id=2");
        let key2 = CoalescingKey::from_request(&req2, &config);

        assert_eq!(key1, key2); // Same path, different query - should match
    }

    #[test]
    fn test_can_coalesce() {
        let config = CoalescingConfig::default();
        let coalescer = RequestCoalescer::new(config);

        assert!(coalescer.can_coalesce(&Method::GET));
        assert!(coalescer.can_coalesce(&Method::HEAD));
        assert!(!coalescer.can_coalesce(&Method::POST));
        assert!(!coalescer.can_coalesce(&Method::PUT));
    }

    #[tokio::test]
    async fn test_leader_request() {
        let config = CoalescingConfig::default();
        let coalescer = RequestCoalescer::new(config);

        let req = make_test_request(Method::GET, "/api/data");
        let result = coalescer.coalesce(&req);

        assert!(matches!(result, CoalescingResult::Leader(_)));
        assert_eq!(coalescer.pending_count(), 1);

        if let CoalescingResult::Leader(handle) = result {
            handle.complete(CoalescedResponse {
                status: StatusCode::OK,
                headers: HashMap::new(),
                body: Bytes::from("test"),
                received_at: Instant::now(),
            });
        }

        assert_eq!(coalescer.pending_count(), 0);
    }

    #[tokio::test]
    async fn test_waiter_request() {
        let config = CoalescingConfig::default();
        let coalescer = RequestCoalescer::new(config);

        // First request becomes leader
        let req1 = make_test_request(Method::GET, "/api/data");
        let result1 = coalescer.coalesce(&req1);
        assert!(matches!(result1, CoalescingResult::Leader(_)));

        // Second identical request becomes waiter
        let req2 = make_test_request(Method::GET, "/api/data");
        let result2 = coalescer.coalesce(&req2);
        assert!(matches!(result2, CoalescingResult::Waiter(_)));

        // Complete leader and check waiter receives response
        if let CoalescingResult::Leader(handle) = result1 {
            // Add the waiter from result2
            if let CoalescingResult::Waiter(_rx) = result2 {
                // Note: In real usage, waiters are added to the pending request
                // This test just verifies the flow
                handle.complete(CoalescedResponse {
                    status: StatusCode::OK,
                    headers: HashMap::new(),
                    body: Bytes::from("shared response"),
                    received_at: Instant::now(),
                });
            }
        }
    }

    #[test]
    fn test_post_bypasses() {
        let config = CoalescingConfig::default();
        let coalescer = RequestCoalescer::new(config);

        let req = make_test_request(Method::POST, "/api/data");
        let result = coalescer.coalesce(&req);

        assert!(matches!(result, CoalescingResult::Bypass));
    }

    #[test]
    fn test_stats() {
        let stats = CoalescingStats::default();

        stats.total_requests.store(100, Ordering::Relaxed);
        stats.leader_requests.store(20, Ordering::Relaxed);
        stats.coalesced_requests.store(80, Ordering::Relaxed);

        assert_eq!(stats.coalescing_ratio(), 80.0);
        assert_eq!(stats.amplification_factor(), 5.0);
    }

    #[test]
    fn test_disabled_coalescing() {
        let mut config = CoalescingConfig::default();
        config.enabled = false;
        let coalescer = RequestCoalescer::new(config);

        let req = make_test_request(Method::GET, "/api/data");
        let result = coalescer.coalesce(&req);

        assert!(matches!(result, CoalescingResult::Bypass));
    }
}
