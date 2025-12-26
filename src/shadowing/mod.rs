//! Traffic Shadowing (Mirroring)
//!
//! Mirror production traffic to test environments without impacting
//! the primary request flow. Useful for:
//! - Testing new service versions
//! - Load testing with real traffic patterns
//! - Debugging production issues
//! - Training ML models on real data

use bytes::Bytes;
use dashmap::DashMap;
use http::{Method, Request, StatusCode, Uri};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

/// Traffic shadowing configuration
#[derive(Debug, Clone)]
pub struct ShadowingConfig {
    /// Enable shadowing
    pub enabled: bool,
    /// Percentage of traffic to shadow (0-100)
    pub sample_rate: f64,
    /// Shadow targets
    pub targets: Vec<ShadowTarget>,
    /// Maximum queue size for shadow requests
    pub queue_size: usize,
    /// Timeout for shadow requests
    pub timeout: Duration,
    /// Retry failed shadow requests
    pub retry_enabled: bool,
    /// Maximum retries
    pub max_retries: u32,
    /// Compare responses between primary and shadow
    pub compare_responses: bool,
}

impl Default for ShadowingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sample_rate: 100.0,
            targets: Vec::new(),
            queue_size: 10000,
            timeout: Duration::from_secs(5),
            retry_enabled: false,
            max_retries: 2,
            compare_responses: false,
        }
    }
}

/// A shadow target configuration
#[derive(Debug, Clone)]
pub struct ShadowTarget {
    /// Target name/identifier
    pub name: String,
    /// Target URL
    pub url: String,
    /// Override host header
    pub host_override: Option<String>,
    /// Additional headers to add
    pub headers: HashMap<String, String>,
    /// Percentage of traffic to this target
    pub weight: f64,
    /// Whether to await response (fire-and-forget if false)
    pub await_response: bool,
    /// Path rewrite rules
    pub path_rewrites: Vec<(String, String)>,
}

/// Shadow request to be processed
#[derive(Debug)]
pub struct ShadowRequest {
    /// Original request method
    pub method: Method,
    /// Original request URI
    pub uri: Uri,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request body
    pub body: Bytes,
    /// Target for this shadow request
    pub target: ShadowTarget,
    /// Original request ID for correlation
    pub correlation_id: String,
    /// When the original request was received
    pub received_at: Instant,
    /// Retry count
    pub retry_count: u32,
}

/// Shadow response received
#[derive(Debug, Clone)]
pub struct ShadowResponse {
    /// Target name
    pub target: String,
    /// Response status code
    pub status: StatusCode,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body
    pub body: Bytes,
    /// Response latency
    pub latency: Duration,
    /// Correlation ID
    pub correlation_id: String,
}

/// Result of comparing primary and shadow responses
#[derive(Debug, Clone)]
pub struct ComparisonResult {
    /// Correlation ID
    pub correlation_id: String,
    /// Primary response status
    pub primary_status: StatusCode,
    /// Shadow response status
    pub shadow_status: StatusCode,
    /// Whether status codes match
    pub status_match: bool,
    /// Whether bodies match
    pub body_match: bool,
    /// Header differences
    pub header_differences: Vec<HeaderDiff>,
    /// Latency difference (shadow - primary)
    pub latency_diff_ms: i64,
}

/// Header difference between primary and shadow
#[derive(Debug, Clone)]
pub struct HeaderDiff {
    pub name: String,
    pub primary_value: Option<String>,
    pub shadow_value: Option<String>,
}

/// Shadowing statistics
#[derive(Debug, Default)]
pub struct ShadowingStats {
    /// Total requests received
    pub total_requests: AtomicU64,
    /// Requests selected for shadowing
    pub shadowed_requests: AtomicU64,
    /// Successful shadow requests
    pub successful_shadows: AtomicU64,
    /// Failed shadow requests
    pub failed_shadows: AtomicU64,
    /// Retried shadow requests
    pub retried_shadows: AtomicU64,
    /// Dropped due to queue full
    pub dropped_queue_full: AtomicU64,
    /// Timed out shadow requests
    pub timeout_shadows: AtomicU64,
    /// Comparisons performed
    pub comparisons: AtomicU64,
    /// Comparisons with matching results
    pub matching_comparisons: AtomicU64,
}

impl ShadowingStats {
    /// Get shadow success rate
    pub fn success_rate(&self) -> f64 {
        let shadowed = self.shadowed_requests.load(Ordering::Relaxed);
        if shadowed == 0 {
            return 100.0;
        }
        let successful = self.successful_shadows.load(Ordering::Relaxed);
        (successful as f64 / shadowed as f64) * 100.0
    }

    /// Get comparison match rate
    pub fn match_rate(&self) -> f64 {
        let compared = self.comparisons.load(Ordering::Relaxed);
        if compared == 0 {
            return 100.0;
        }
        let matching = self.matching_comparisons.load(Ordering::Relaxed);
        (matching as f64 / compared as f64) * 100.0
    }
}

/// Traffic shadowing engine
pub struct ShadowingEngine {
    config: RwLock<ShadowingConfig>,
    stats: Arc<ShadowingStats>,
    queue_tx: mpsc::Sender<ShadowRequest>,
    queue_rx: RwLock<Option<mpsc::Receiver<ShadowRequest>>>,
    comparison_results: DashMap<String, ComparisonResult>,
    primary_responses: DashMap<String, (StatusCode, HashMap<String, String>, Bytes, Duration)>,
}

impl ShadowingEngine {
    /// Create a new shadowing engine
    pub fn new(config: ShadowingConfig) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(config.queue_size);

        Arc::new(Self {
            config: RwLock::new(config),
            stats: Arc::new(ShadowingStats::default()),
            queue_tx: tx,
            queue_rx: RwLock::new(Some(rx)),
            comparison_results: DashMap::new(),
            primary_responses: DashMap::new(),
        })
    }

    /// Get statistics
    pub fn stats(&self) -> Arc<ShadowingStats> {
        self.stats.clone()
    }

    /// Check if request should be shadowed
    pub fn should_shadow(&self) -> bool {
        let config = self.config.read();
        if !config.enabled || config.targets.is_empty() {
            return false;
        }

        if config.sample_rate >= 100.0 {
            return true;
        }

        let sample: f64 = rand::random();
        sample * 100.0 < config.sample_rate
    }

    /// Shadow a request
    pub async fn shadow_request<B>(
        &self,
        request: &Request<B>,
        body: Bytes,
        correlation_id: &str,
    ) -> bool {
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        if !self.should_shadow() {
            return false;
        }

        let config = self.config.read();

        // Create shadow requests for each target
        for target in &config.targets {
            // Apply weight-based sampling
            if target.weight < 100.0 {
                let sample: f64 = rand::random();
                if sample * 100.0 >= target.weight {
                    continue;
                }
            }

            let shadow_req = ShadowRequest {
                method: request.method().clone(),
                uri: request.uri().clone(),
                headers: request
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                    .collect(),
                body: body.clone(),
                target: target.clone(),
                correlation_id: correlation_id.to_string(),
                received_at: Instant::now(),
                retry_count: 0,
            };

            // Try to queue the shadow request
            match self.queue_tx.try_send(shadow_req) {
                Ok(_) => {
                    self.stats.shadowed_requests.fetch_add(1, Ordering::Relaxed);
                    trace!(
                        "Queued shadow request to {} for {}",
                        target.name,
                        correlation_id
                    );
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.stats
                        .dropped_queue_full
                        .fetch_add(1, Ordering::Relaxed);
                    warn!("Shadow queue full, dropping request");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    error!("Shadow queue closed");
                    return false;
                }
            }
        }

        true
    }

    /// Record primary response for comparison
    pub fn record_primary_response(
        &self,
        correlation_id: &str,
        status: StatusCode,
        headers: HashMap<String, String>,
        body: Bytes,
        latency: Duration,
    ) {
        if self.config.read().compare_responses {
            self.primary_responses
                .insert(correlation_id.to_string(), (status, headers, body, latency));
        }
    }

    /// Process shadow queue (run as background task)
    pub async fn process_queue(self: Arc<Self>) {
        let mut rx = self.queue_rx.write().take().expect("Queue already taken");

        let client = reqwest::Client::builder()
            .timeout(self.config.read().timeout)
            .build()
            .expect("Failed to create HTTP client");

        while let Some(mut shadow_req) = rx.recv().await {
            let engine = self.clone();
            let client = client.clone();

            tokio::spawn(async move {
                engine
                    .execute_shadow_request(&client, &mut shadow_req)
                    .await;
            });
        }
    }

    /// Execute a single shadow request
    async fn execute_shadow_request(&self, client: &reqwest::Client, req: &mut ShadowRequest) {
        let start = Instant::now();

        // Build the shadow URL
        let mut url = req.target.url.clone();
        let path = req
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        // Apply path rewrites
        let mut rewritten_path = path.to_string();
        for (from, to) in &req.target.path_rewrites {
            rewritten_path = rewritten_path.replace(from, to);
        }

        url.push_str(&rewritten_path);

        // Build request
        let mut builder = match req.method {
            Method::GET => client.get(&url),
            Method::POST => client.post(&url),
            Method::PUT => client.put(&url),
            Method::DELETE => client.delete(&url),
            Method::PATCH => client.patch(&url),
            Method::HEAD => client.head(&url),
            _ => client.request(req.method.clone(), &url),
        };

        // Add headers
        for (name, value) in &req.headers {
            // Skip host header if we're overriding it
            if name.to_lowercase() == "host" && req.target.host_override.is_some() {
                continue;
            }
            builder = builder.header(name, value);
        }

        // Override host if specified
        if let Some(ref host) = req.target.host_override {
            builder = builder.header("Host", host);
        }

        // Add target-specific headers
        for (name, value) in &req.target.headers {
            builder = builder.header(name, value);
        }

        // Add correlation header
        builder = builder.header("X-Shadow-Correlation-Id", &req.correlation_id);
        builder = builder.header(
            "X-Shadow-Original-Time",
            req.received_at.elapsed().as_millis().to_string(),
        );

        // Add body if present
        if !req.body.is_empty() {
            builder = builder.body(req.body.clone());
        }

        // Execute request
        match builder.send().await {
            Ok(response) => {
                let status = response.status();
                let headers: HashMap<String, String> = response
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                    .collect();

                let body = response.bytes().await.unwrap_or_else(|_| Bytes::new());

                let latency = start.elapsed();

                self.stats
                    .successful_shadows
                    .fetch_add(1, Ordering::Relaxed);

                debug!(
                    "Shadow request to {} completed: {} in {:?}",
                    req.target.name, status, latency
                );

                // Compare with primary if enabled
                if self.config.read().compare_responses {
                    self.compare_responses(
                        &req.correlation_id,
                        &req.target.name,
                        status,
                        headers,
                        body,
                        latency,
                    );
                }
            }
            Err(e) => {
                self.stats.failed_shadows.fetch_add(1, Ordering::Relaxed);

                if e.is_timeout() {
                    self.stats.timeout_shadows.fetch_add(1, Ordering::Relaxed);
                    warn!("Shadow request timed out: {}", req.target.name);
                } else {
                    warn!("Shadow request failed: {} - {}", req.target.name, e);
                }

                // Retry if enabled
                let config = self.config.read();
                if config.retry_enabled && req.retry_count < config.max_retries {
                    req.retry_count += 1;
                    self.stats.retried_shadows.fetch_add(1, Ordering::Relaxed);

                    // Re-queue for retry
                    let _ = self.queue_tx.try_send(ShadowRequest {
                        method: req.method.clone(),
                        uri: req.uri.clone(),
                        headers: req.headers.clone(),
                        body: req.body.clone(),
                        target: req.target.clone(),
                        correlation_id: req.correlation_id.clone(),
                        received_at: req.received_at,
                        retry_count: req.retry_count,
                    });
                }
            }
        }
    }

    /// Compare shadow response with primary
    fn compare_responses(
        &self,
        correlation_id: &str,
        _target: &str,
        shadow_status: StatusCode,
        shadow_headers: HashMap<String, String>,
        shadow_body: Bytes,
        shadow_latency: Duration,
    ) {
        if let Some((_, (primary_status, primary_headers, primary_body, primary_latency))) =
            self.primary_responses.remove(correlation_id)
        {
            let status_match = primary_status == shadow_status;
            let body_match = primary_body == shadow_body;
            let latency_diff =
                shadow_latency.as_millis() as i64 - primary_latency.as_millis() as i64;

            // Compare headers
            let header_differences = Self::compare_headers(&primary_headers, &shadow_headers);
            let headers_match = header_differences.is_empty();

            let result = ComparisonResult {
                correlation_id: correlation_id.to_string(),
                primary_status,
                shadow_status,
                status_match,
                body_match,
                header_differences,
                latency_diff_ms: latency_diff,
            };

            self.stats.comparisons.fetch_add(1, Ordering::Relaxed);

            if status_match && body_match && headers_match {
                self.stats
                    .matching_comparisons
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                info!(
                    "Shadow comparison mismatch: status={}/{} body_match={} headers_match={}",
                    primary_status, shadow_status, body_match, headers_match
                );
            }

            self.comparison_results
                .insert(correlation_id.to_string(), result);
        }
    }

    /// Compare headers between primary and shadow responses
    fn compare_headers(
        primary: &HashMap<String, String>,
        shadow: &HashMap<String, String>,
    ) -> Vec<HeaderDiff> {
        // Headers to ignore in comparison (these commonly differ between instances)
        const IGNORED_HEADERS: &[&str] = &[
            "date",
            "x-request-id",
            "x-correlation-id",
            "x-shadow-correlation-id",
            "x-shadow-original-time",
            "server",
            "x-served-by",
            "x-cache",
            "age",
            "via",
            "set-cookie",
            "x-runtime",
            "x-response-time",
        ];

        let mut differences = Vec::new();

        // Check all primary headers
        for (name, primary_value) in primary {
            let name_lower = name.to_lowercase();

            // Skip ignored headers
            if IGNORED_HEADERS.contains(&name_lower.as_str()) {
                continue;
            }

            match shadow.get(name) {
                Some(shadow_value) => {
                    if primary_value != shadow_value {
                        differences.push(HeaderDiff {
                            name: name.clone(),
                            primary_value: Some(primary_value.clone()),
                            shadow_value: Some(shadow_value.clone()),
                        });
                    }
                }
                None => {
                    // Also check case-insensitive match
                    let shadow_value = shadow
                        .iter()
                        .find(|(k, _)| k.to_lowercase() == name_lower)
                        .map(|(_, v)| v);

                    if let Some(shadow_val) = shadow_value {
                        if primary_value != shadow_val {
                            differences.push(HeaderDiff {
                                name: name.clone(),
                                primary_value: Some(primary_value.clone()),
                                shadow_value: Some(shadow_val.clone()),
                            });
                        }
                    } else {
                        differences.push(HeaderDiff {
                            name: name.clone(),
                            primary_value: Some(primary_value.clone()),
                            shadow_value: None,
                        });
                    }
                }
            }
        }

        // Check for headers only in shadow (not in primary)
        for (name, shadow_value) in shadow {
            let name_lower = name.to_lowercase();

            // Skip ignored headers
            if IGNORED_HEADERS.contains(&name_lower.as_str()) {
                continue;
            }

            // Check if this header exists in primary (case-insensitive)
            let exists_in_primary = primary.iter().any(|(k, _)| k.to_lowercase() == name_lower);

            if !exists_in_primary {
                differences.push(HeaderDiff {
                    name: name.clone(),
                    primary_value: None,
                    shadow_value: Some(shadow_value.clone()),
                });
            }
        }

        differences
    }

    /// Get comparison results
    pub fn get_comparison(&self, correlation_id: &str) -> Option<ComparisonResult> {
        self.comparison_results
            .get(correlation_id)
            .map(|r| r.clone())
    }

    /// Get recent comparison results
    pub fn recent_comparisons(&self, limit: usize) -> Vec<ComparisonResult> {
        self.comparison_results
            .iter()
            .take(limit)
            .map(|r| r.clone())
            .collect()
    }

    /// Update configuration
    pub fn update_config(&self, config: ShadowingConfig) {
        *self.config.write() = config;
        info!("Shadowing configuration updated");
    }

    /// Add a shadow target
    pub fn add_target(&self, target: ShadowTarget) {
        self.config.write().targets.push(target);
    }

    /// Remove a shadow target
    pub fn remove_target(&self, name: &str) {
        self.config.write().targets.retain(|t| t.name != name);
    }

    /// Enable/disable shadowing
    pub fn set_enabled(&self, enabled: bool) {
        self.config.write().enabled = enabled;
        info!("Shadowing {}", if enabled { "enabled" } else { "disabled" });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ShadowingConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.sample_rate, 100.0);
    }

    #[test]
    fn test_should_shadow_disabled() {
        let config = ShadowingConfig::default();
        let engine = ShadowingEngine::new(config);
        assert!(!engine.should_shadow());
    }

    #[test]
    fn test_should_shadow_no_targets() {
        let config = ShadowingConfig {
            enabled: true,
            ..Default::default()
        };
        let engine = ShadowingEngine::new(config);
        assert!(!engine.should_shadow());
    }

    #[test]
    fn test_should_shadow_enabled() {
        let config = ShadowingConfig {
            enabled: true,
            sample_rate: 100.0,
            targets: vec![ShadowTarget {
                name: "test".to_string(),
                url: "http://localhost:8080".to_string(),
                host_override: None,
                headers: HashMap::new(),
                weight: 100.0,
                await_response: false,
                path_rewrites: Vec::new(),
            }],
            ..Default::default()
        };
        let engine = ShadowingEngine::new(config);
        assert!(engine.should_shadow());
    }

    #[test]
    fn test_stats() {
        let stats = ShadowingStats::default();
        stats.shadowed_requests.store(100, Ordering::Relaxed);
        stats.successful_shadows.store(95, Ordering::Relaxed);
        stats.failed_shadows.store(5, Ordering::Relaxed);

        assert_eq!(stats.success_rate(), 95.0);
    }

    #[test]
    fn test_comparison_result() {
        let result = ComparisonResult {
            correlation_id: "test-123".to_string(),
            primary_status: StatusCode::OK,
            shadow_status: StatusCode::OK,
            status_match: true,
            body_match: true,
            header_differences: Vec::new(),
            latency_diff_ms: 10,
        };

        assert!(result.status_match);
        assert!(result.body_match);
    }

    #[test]
    fn test_add_remove_target() {
        let config = ShadowingConfig::default();
        let engine = ShadowingEngine::new(config);

        engine.add_target(ShadowTarget {
            name: "test".to_string(),
            url: "http://localhost:8080".to_string(),
            host_override: None,
            headers: HashMap::new(),
            weight: 100.0,
            await_response: false,
            path_rewrites: Vec::new(),
        });

        assert_eq!(engine.config.read().targets.len(), 1);

        engine.remove_target("test");
        assert_eq!(engine.config.read().targets.len(), 0);
    }

    #[test]
    fn test_compare_headers_identical() {
        let primary: HashMap<String, String> = [
            ("content-type".to_string(), "application/json".to_string()),
            ("x-custom".to_string(), "value".to_string()),
        ]
        .into_iter()
        .collect();

        let shadow = primary.clone();

        let diffs = ShadowingEngine::compare_headers(&primary, &shadow);
        assert!(
            diffs.is_empty(),
            "Identical headers should have no differences"
        );
    }

    #[test]
    fn test_compare_headers_different_values() {
        let primary: HashMap<String, String> = [
            ("content-type".to_string(), "application/json".to_string()),
            ("x-custom".to_string(), "value1".to_string()),
        ]
        .into_iter()
        .collect();

        let shadow: HashMap<String, String> = [
            ("content-type".to_string(), "application/json".to_string()),
            ("x-custom".to_string(), "value2".to_string()),
        ]
        .into_iter()
        .collect();

        let diffs = ShadowingEngine::compare_headers(&primary, &shadow);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].name, "x-custom");
        assert_eq!(diffs[0].primary_value, Some("value1".to_string()));
        assert_eq!(diffs[0].shadow_value, Some("value2".to_string()));
    }

    #[test]
    fn test_compare_headers_missing_in_shadow() {
        let primary: HashMap<String, String> = [
            ("content-type".to_string(), "application/json".to_string()),
            ("x-custom".to_string(), "value".to_string()),
        ]
        .into_iter()
        .collect();

        let shadow: HashMap<String, String> =
            [("content-type".to_string(), "application/json".to_string())]
                .into_iter()
                .collect();

        let diffs = ShadowingEngine::compare_headers(&primary, &shadow);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].name, "x-custom");
        assert_eq!(diffs[0].primary_value, Some("value".to_string()));
        assert_eq!(diffs[0].shadow_value, None);
    }

    #[test]
    fn test_compare_headers_extra_in_shadow() {
        let primary: HashMap<String, String> =
            [("content-type".to_string(), "application/json".to_string())]
                .into_iter()
                .collect();

        let shadow: HashMap<String, String> = [
            ("content-type".to_string(), "application/json".to_string()),
            ("x-extra".to_string(), "extra-value".to_string()),
        ]
        .into_iter()
        .collect();

        let diffs = ShadowingEngine::compare_headers(&primary, &shadow);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].name, "x-extra");
        assert_eq!(diffs[0].primary_value, None);
        assert_eq!(diffs[0].shadow_value, Some("extra-value".to_string()));
    }

    #[test]
    fn test_compare_headers_ignores_dynamic_headers() {
        let primary: HashMap<String, String> = [
            ("content-type".to_string(), "application/json".to_string()),
            (
                "date".to_string(),
                "Mon, 01 Jan 2024 00:00:00 GMT".to_string(),
            ),
            ("x-request-id".to_string(), "abc123".to_string()),
            ("server".to_string(), "nginx/1.0".to_string()),
        ]
        .into_iter()
        .collect();

        let shadow: HashMap<String, String> = [
            ("content-type".to_string(), "application/json".to_string()),
            (
                "date".to_string(),
                "Mon, 01 Jan 2024 00:00:01 GMT".to_string(),
            ),
            ("x-request-id".to_string(), "xyz789".to_string()),
            ("server".to_string(), "nginx/2.0".to_string()),
        ]
        .into_iter()
        .collect();

        let diffs = ShadowingEngine::compare_headers(&primary, &shadow);
        assert!(
            diffs.is_empty(),
            "Dynamic headers should be ignored: {:?}",
            diffs
        );
    }

    #[test]
    fn test_compare_headers_case_insensitive() {
        let primary: HashMap<String, String> =
            [("Content-Type".to_string(), "application/json".to_string())]
                .into_iter()
                .collect();

        let shadow: HashMap<String, String> =
            [("content-type".to_string(), "application/json".to_string())]
                .into_iter()
                .collect();

        let diffs = ShadowingEngine::compare_headers(&primary, &shadow);
        assert!(
            diffs.is_empty(),
            "Case-insensitive header matching should work"
        );
    }

    #[test]
    fn test_header_diff_struct() {
        let diff = HeaderDiff {
            name: "x-test".to_string(),
            primary_value: Some("primary".to_string()),
            shadow_value: Some("shadow".to_string()),
        };

        assert_eq!(diff.name, "x-test");
        assert_eq!(diff.primary_value, Some("primary".to_string()));
        assert_eq!(diff.shadow_value, Some("shadow".to_string()));
    }
}
