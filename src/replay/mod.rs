//! Request Replay Module
//!
//! Provides request recording and replay capabilities for:
//! - Debugging production issues
//! - Performance testing with real traffic
//! - Regression testing
//! - Traffic analysis

use bytes::Bytes;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// Configuration for request recording
#[derive(Debug, Clone)]
pub struct RecordingConfig {
    /// Enable recording
    pub enabled: bool,
    /// Maximum requests to keep in memory
    pub max_memory_requests: usize,
    /// Directory to store recordings
    pub storage_dir: PathBuf,
    /// Maximum file size before rotation
    pub max_file_size: u64,
    /// Sample rate (0.0 - 1.0)
    pub sample_rate: f64,
    /// Record request bodies
    pub record_bodies: bool,
    /// Maximum body size to record
    pub max_body_size: usize,
    /// Record response bodies
    pub record_responses: bool,
    /// Filter patterns (regex)
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_memory_requests: 10000,
            storage_dir: PathBuf::from("/tmp/prism-recordings"),
            max_file_size: 100 * 1024 * 1024, // 100MB
            sample_rate: 1.0,
            record_bodies: true,
            max_body_size: 1024 * 1024, // 1MB
            record_responses: true,
            include_patterns: vec![],
            exclude_patterns: vec![],
        }
    }
}

/// Configuration for request replay
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Speed multiplier (1.0 = real time, 2.0 = 2x speed)
    pub speed_multiplier: f64,
    /// Concurrent connections
    pub concurrency: usize,
    /// Target host override
    pub target_host: Option<String>,
    /// Add headers to replayed requests
    pub additional_headers: Vec<(String, String)>,
    /// Dry run mode (don't actually send requests)
    pub dry_run: bool,
    /// Stop on first error
    pub stop_on_error: bool,
    /// Maximum requests to replay (0 = unlimited)
    pub max_requests: usize,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            speed_multiplier: 1.0,
            concurrency: 10,
            target_host: None,
            additional_headers: vec![],
            dry_run: false,
            stop_on_error: false,
            max_requests: 0,
        }
    }
}

/// Recorded HTTP request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedRequest {
    /// Unique request ID
    pub id: String,
    /// Recording timestamp
    pub timestamp: DateTime<Utc>,
    /// HTTP method
    pub method: String,
    /// Request URI
    pub uri: String,
    /// HTTP version
    pub version: String,
    /// Request headers
    pub headers: Vec<(String, String)>,
    /// Request body (if recorded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
    /// Client IP
    pub client_ip: Option<String>,
    /// Original host
    pub host: String,
    /// Time offset from start of recording (ms)
    pub offset_ms: u64,
}

/// Recorded HTTP response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedResponse {
    /// Request ID this response is for
    pub request_id: String,
    /// Response timestamp
    pub timestamp: DateTime<Utc>,
    /// Status code
    pub status: u16,
    /// Response headers
    pub headers: Vec<(String, String)>,
    /// Response body (if recorded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
    /// Response time (ms)
    pub response_time_ms: u64,
}

/// Complete recorded exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedExchange {
    pub request: RecordedRequest,
    pub response: Option<RecordedResponse>,
}

/// Recording session metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingSession {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub request_count: u64,
    pub description: Option<String>,
    pub tags: Vec<String>,
}

/// Request recorder
pub struct RequestRecorder {
    config: RecordingConfig,
    session: RwLock<Option<RecordingSession>>,
    exchanges: RwLock<VecDeque<RecordedExchange>>,
    pending_requests: DashMap<String, RecordedRequest>,
    writer: RwLock<Option<BufWriter<File>>>,
    recording_start: RwLock<Option<Instant>>,
    stats: RecordingStats,
    is_recording: AtomicBool,
}

/// Recording statistics
#[derive(Debug, Default)]
pub struct RecordingStats {
    pub requests_recorded: AtomicU64,
    pub responses_recorded: AtomicU64,
    pub bytes_recorded: AtomicU64,
    pub requests_sampled_out: AtomicU64,
    pub requests_filtered_out: AtomicU64,
    pub bodies_truncated: AtomicU64,
}

impl RequestRecorder {
    pub fn new(config: RecordingConfig) -> Self {
        Self {
            config,
            session: RwLock::new(None),
            exchanges: RwLock::new(VecDeque::new()),
            pending_requests: DashMap::new(),
            writer: RwLock::new(None),
            recording_start: RwLock::new(None),
            stats: RecordingStats::default(),
            is_recording: AtomicBool::new(false),
        }
    }

    /// Start a new recording session
    pub fn start_session(&self, description: Option<String>, tags: Vec<String>) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = RecordingSession {
            id: session_id.clone(),
            started_at: Utc::now(),
            ended_at: None,
            request_count: 0,
            description,
            tags,
        };

        // Create storage directory
        std::fs::create_dir_all(&self.config.storage_dir).ok();

        // Open file for writing
        let file_path = self
            .config
            .storage_dir
            .join(format!("{}.jsonl", session_id));
        if let Ok(file) = File::create(file_path) {
            *self.writer.write() = Some(BufWriter::new(file));
        }

        *self.session.write() = Some(session);
        *self.recording_start.write() = Some(Instant::now());
        self.is_recording.store(true, Ordering::Release);

        session_id
    }

    /// Stop the current recording session
    pub fn stop_session(&self) -> Option<RecordingSession> {
        self.is_recording.store(false, Ordering::Release);

        let mut session = self.session.write().take()?;
        session.ended_at = Some(Utc::now());
        session.request_count = self.stats.requests_recorded.load(Ordering::Relaxed);

        // Flush and close writer
        if let Some(mut writer) = self.writer.write().take() {
            writer.flush().ok();
        }

        Some(session)
    }

    /// Check if currently recording
    pub fn is_recording(&self) -> bool {
        self.is_recording.load(Ordering::Acquire)
    }

    /// Should sample this request?
    fn should_sample(&self) -> bool {
        if self.config.sample_rate >= 1.0 {
            return true;
        }
        rand::random::<f64>() < self.config.sample_rate
    }

    /// Check if URI matches filters
    fn matches_filters(&self, uri: &str) -> bool {
        // Check exclude patterns first
        for pattern in &self.config.exclude_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(uri) {
                    return false;
                }
            }
        }

        // If no include patterns, include everything
        if self.config.include_patterns.is_empty() {
            return true;
        }

        // Check include patterns
        for pattern in &self.config.include_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(uri) {
                    return true;
                }
            }
        }

        false
    }

    /// Record an incoming request
    #[allow(clippy::too_many_arguments)]
    pub fn record_request(
        &self,
        method: &str,
        uri: &str,
        version: &str,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
        client_ip: Option<String>,
        host: &str,
    ) -> Option<String> {
        if !self.is_recording() {
            return None;
        }

        if !self.should_sample() {
            self.stats
                .requests_sampled_out
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }

        if !self.matches_filters(uri) {
            self.stats
                .requests_filtered_out
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let request_id = uuid::Uuid::new_v4().to_string();
        let offset_ms = self
            .recording_start
            .read()
            .map(|start| start.elapsed().as_millis() as u64)
            .unwrap_or(0);

        let body = if self.config.record_bodies {
            body.map(|b| {
                if b.len() > self.config.max_body_size {
                    self.stats.bodies_truncated.fetch_add(1, Ordering::Relaxed);
                    b[..self.config.max_body_size].to_vec()
                } else {
                    b.to_vec()
                }
            })
        } else {
            None
        };

        let request = RecordedRequest {
            id: request_id.clone(),
            timestamp: Utc::now(),
            method: method.to_string(),
            uri: uri.to_string(),
            version: version.to_string(),
            headers,
            body,
            client_ip,
            host: host.to_string(),
            offset_ms,
        };

        // Store pending request
        self.pending_requests.insert(request_id.clone(), request);
        self.stats.requests_recorded.fetch_add(1, Ordering::Relaxed);

        Some(request_id)
    }

    /// Record a response for a request
    pub fn record_response(
        &self,
        request_id: &str,
        status: u16,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
        response_time: Duration,
    ) {
        if !self.is_recording() {
            return;
        }

        let request = match self.pending_requests.remove(request_id) {
            Some((_, req)) => req,
            None => return,
        };

        let body = if self.config.record_responses {
            body.map(|b| {
                if b.len() > self.config.max_body_size {
                    self.stats.bodies_truncated.fetch_add(1, Ordering::Relaxed);
                    b[..self.config.max_body_size].to_vec()
                } else {
                    b.to_vec()
                }
            })
        } else {
            None
        };

        let response = RecordedResponse {
            request_id: request_id.to_string(),
            timestamp: Utc::now(),
            status,
            headers,
            body,
            response_time_ms: response_time.as_millis() as u64,
        };

        let exchange = RecordedExchange {
            request,
            response: Some(response),
        };

        // Write to file
        if let Some(writer) = self.writer.write().as_mut() {
            if let Ok(json) = serde_json::to_string(&exchange) {
                writeln!(writer, "{}", json).ok();
                self.stats
                    .bytes_recorded
                    .fetch_add(json.len() as u64, Ordering::Relaxed);
            }
        }

        // Keep in memory
        let mut exchanges = self.exchanges.write();
        exchanges.push_back(exchange);
        while exchanges.len() > self.config.max_memory_requests {
            exchanges.pop_front();
        }

        self.stats
            .responses_recorded
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get recent exchanges
    pub fn recent_exchanges(&self, limit: usize) -> Vec<RecordedExchange> {
        let exchanges = self.exchanges.read();
        exchanges.iter().rev().take(limit).cloned().collect()
    }

    /// Get recording statistics
    pub fn stats(&self) -> &RecordingStats {
        &self.stats
    }
}

/// Replay result for a single request
#[derive(Debug)]
pub struct ReplayResult {
    pub request_id: String,
    pub original_status: Option<u16>,
    pub replay_status: Option<u16>,
    pub original_time_ms: Option<u64>,
    pub replay_time_ms: u64,
    pub success: bool,
    pub error: Option<String>,
    pub status_match: bool,
}

/// Aggregate replay statistics
#[derive(Debug, Default)]
pub struct ReplayStats {
    pub total_requests: AtomicU64,
    pub successful_replays: AtomicU64,
    pub failed_replays: AtomicU64,
    pub status_matches: AtomicU64,
    pub status_mismatches: AtomicU64,
    pub total_original_time_ms: AtomicU64,
    pub total_replay_time_ms: AtomicU64,
}

impl ReplayStats {
    pub fn success_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        let success = self.successful_replays.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            success as f64 / total as f64 * 100.0
        }
    }

    pub fn average_speedup(&self) -> f64 {
        let original = self.total_original_time_ms.load(Ordering::Relaxed);
        let replay = self.total_replay_time_ms.load(Ordering::Relaxed);
        if replay == 0 {
            1.0
        } else {
            original as f64 / replay as f64
        }
    }
}

/// Request replayer
pub struct RequestReplayer {
    config: ReplayConfig,
    client: reqwest::Client,
    stats: ReplayStats,
    stop_flag: AtomicBool,
}

impl RequestReplayer {
    pub fn new(config: ReplayConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            stats: ReplayStats::default(),
            stop_flag: AtomicBool::new(false),
        }
    }

    /// Stop ongoing replay
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
    }

    /// Replay a single exchange
    pub async fn replay_exchange(&self, exchange: &RecordedExchange) -> ReplayResult {
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();

        if self.config.dry_run {
            return ReplayResult {
                request_id: exchange.request.id.clone(),
                original_status: exchange.response.as_ref().map(|r| r.status),
                replay_status: None,
                original_time_ms: exchange.response.as_ref().map(|r| r.response_time_ms),
                replay_time_ms: 0,
                success: true,
                error: None,
                status_match: true,
            };
        }

        // Build target URL
        let host = self
            .config
            .target_host
            .as_ref()
            .unwrap_or(&exchange.request.host);
        let url = format!("https://{}{}", host, exchange.request.uri);

        // Build request
        let method = match exchange.request.method.as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "PATCH" => reqwest::Method::PATCH,
            "HEAD" => reqwest::Method::HEAD,
            "OPTIONS" => reqwest::Method::OPTIONS,
            _ => {
                return ReplayResult {
                    request_id: exchange.request.id.clone(),
                    original_status: exchange.response.as_ref().map(|r| r.status),
                    replay_status: None,
                    original_time_ms: exchange.response.as_ref().map(|r| r.response_time_ms),
                    replay_time_ms: start.elapsed().as_millis() as u64,
                    success: false,
                    error: Some(format!("Unknown method: {}", exchange.request.method)),
                    status_match: false,
                };
            }
        };

        let mut request = self.client.request(method, &url);

        // Add original headers
        for (name, value) in &exchange.request.headers {
            // Skip hop-by-hop headers
            if !["host", "connection", "transfer-encoding", "keep-alive"]
                .contains(&name.to_lowercase().as_str())
            {
                request = request.header(name, value);
            }
        }

        // Add additional headers
        for (name, value) in &self.config.additional_headers {
            request = request.header(name, value);
        }

        // Add body if present
        if let Some(body) = &exchange.request.body {
            request = request.body(body.clone());
        }

        // Send request
        let result = request.send().await;
        let replay_time_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(response) => {
                let replay_status = response.status().as_u16();
                let original_status = exchange.response.as_ref().map(|r| r.status);
                let status_match = original_status == Some(replay_status);

                if status_match {
                    self.stats.status_matches.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.stats.status_mismatches.fetch_add(1, Ordering::Relaxed);
                }

                self.stats
                    .successful_replays
                    .fetch_add(1, Ordering::Relaxed);
                self.stats
                    .total_replay_time_ms
                    .fetch_add(replay_time_ms, Ordering::Relaxed);

                if let Some(original_time) = exchange.response.as_ref().map(|r| r.response_time_ms)
                {
                    self.stats
                        .total_original_time_ms
                        .fetch_add(original_time, Ordering::Relaxed);
                }

                ReplayResult {
                    request_id: exchange.request.id.clone(),
                    original_status,
                    replay_status: Some(replay_status),
                    original_time_ms: exchange.response.as_ref().map(|r| r.response_time_ms),
                    replay_time_ms,
                    success: true,
                    error: None,
                    status_match,
                }
            }
            Err(e) => {
                self.stats.failed_replays.fetch_add(1, Ordering::Relaxed);
                ReplayResult {
                    request_id: exchange.request.id.clone(),
                    original_status: exchange.response.as_ref().map(|r| r.status),
                    replay_status: None,
                    original_time_ms: exchange.response.as_ref().map(|r| r.response_time_ms),
                    replay_time_ms,
                    success: false,
                    error: Some(e.to_string()),
                    status_match: false,
                }
            }
        }
    }

    /// Replay exchanges with timing preservation
    pub async fn replay_with_timing(
        &self,
        exchanges: Vec<RecordedExchange>,
        result_tx: mpsc::Sender<ReplayResult>,
    ) {
        self.stop_flag.store(false, Ordering::Release);

        let mut handles = Vec::new();
        let start = Instant::now();
        let speed = self.config.speed_multiplier;
        let max_requests = self.config.max_requests;

        for (i, exchange) in exchanges.into_iter().enumerate() {
            if self.stop_flag.load(Ordering::Acquire) {
                break;
            }

            if max_requests > 0 && i >= max_requests {
                break;
            }

            // Calculate delay based on original timing
            let target_offset =
                Duration::from_millis((exchange.request.offset_ms as f64 / speed) as u64);

            let elapsed = start.elapsed();
            if target_offset > elapsed {
                tokio::time::sleep(target_offset - elapsed).await;
            }

            let replayer = Arc::new(self.clone_stats_ref());
            let tx = result_tx.clone();

            let handle = tokio::spawn(async move {
                let result = replayer.replay_single(&exchange).await;
                tx.send(result).await.ok();
            });

            handles.push(handle);

            // Limit concurrency
            if handles.len() >= self.config.concurrency {
                let h = handles.swap_remove(0);
                let _ = h.await;
            }
        }

        // Wait for remaining
        for handle in handles {
            handle.await.ok();
        }
    }

    async fn replay_single(&self, exchange: &RecordedExchange) -> ReplayResult {
        self.replay_exchange(exchange).await
    }

    fn clone_stats_ref(&self) -> Self {
        Self {
            config: self.config.clone(),
            client: self.client.clone(),
            stats: ReplayStats::default(),
            stop_flag: AtomicBool::new(false),
        }
    }

    /// Get replay statistics
    pub fn stats(&self) -> &ReplayStats {
        &self.stats
    }
}

/// Load recorded exchanges from file
pub fn load_recording(path: &std::path::Path) -> std::io::Result<Vec<RecordedExchange>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut exchanges = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if let Ok(exchange) = serde_json::from_str::<RecordedExchange>(&line) {
            exchanges.push(exchange);
        }
    }

    Ok(exchanges)
}

/// List available recording sessions
pub fn list_sessions(storage_dir: &std::path::Path) -> std::io::Result<Vec<String>> {
    let mut sessions = Vec::new();

    for entry in std::fs::read_dir(storage_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
            if let Some(stem) = path.file_stem() {
                sessions.push(stem.to_string_lossy().to_string());
            }
        }
    }

    Ok(sessions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recording_config_default() {
        let config = RecordingConfig::default();
        assert!(config.enabled);
        assert_eq!(config.sample_rate, 1.0);
        assert!(config.record_bodies);
    }

    #[test]
    fn test_recorder_start_stop_session() {
        let config = RecordingConfig {
            storage_dir: std::env::temp_dir().join("prism-test-recordings"),
            ..Default::default()
        };
        let recorder = RequestRecorder::new(config);

        let session_id =
            recorder.start_session(Some("Test session".to_string()), vec!["test".to_string()]);
        assert!(recorder.is_recording());

        let session = recorder.stop_session().unwrap();
        assert_eq!(session.id, session_id);
        assert!(session.ended_at.is_some());
        assert!(!recorder.is_recording());
    }

    #[test]
    fn test_record_request() {
        let config = RecordingConfig {
            storage_dir: std::env::temp_dir().join("prism-test-recordings2"),
            ..Default::default()
        };
        let recorder = RequestRecorder::new(config);
        recorder.start_session(None, vec![]);

        let request_id = recorder.record_request(
            "GET",
            "/api/users",
            "HTTP/1.1",
            vec![("Content-Type".to_string(), "application/json".to_string())],
            Some(Bytes::from("test body")),
            Some("127.0.0.1".to_string()),
            "example.com",
        );

        assert!(request_id.is_some());
        assert_eq!(
            recorder.stats().requests_recorded.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_sampling() {
        let config = RecordingConfig {
            sample_rate: 0.0, // Never sample
            storage_dir: std::env::temp_dir().join("prism-test-recordings3"),
            ..Default::default()
        };
        let recorder = RequestRecorder::new(config);
        recorder.start_session(None, vec![]);

        let request_id = recorder.record_request(
            "GET",
            "/api/users",
            "HTTP/1.1",
            vec![],
            None,
            None,
            "example.com",
        );

        assert!(request_id.is_none());
        assert_eq!(
            recorder
                .stats()
                .requests_sampled_out
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_filtering() {
        let config = RecordingConfig {
            exclude_patterns: vec![r"^/health".to_string()],
            storage_dir: std::env::temp_dir().join("prism-test-recordings4"),
            ..Default::default()
        };
        let recorder = RequestRecorder::new(config);
        recorder.start_session(None, vec![]);

        // Should be filtered out
        let request_id = recorder.record_request(
            "GET",
            "/health",
            "HTTP/1.1",
            vec![],
            None,
            None,
            "example.com",
        );
        assert!(request_id.is_none());

        // Should be recorded
        let request_id = recorder.record_request(
            "GET",
            "/api/users",
            "HTTP/1.1",
            vec![],
            None,
            None,
            "example.com",
        );
        assert!(request_id.is_some());
    }

    #[test]
    fn test_replay_config_default() {
        let config = ReplayConfig::default();
        assert_eq!(config.speed_multiplier, 1.0);
        assert_eq!(config.concurrency, 10);
        assert!(!config.dry_run);
    }

    #[tokio::test]
    async fn test_replay_dry_run() {
        let config = ReplayConfig {
            dry_run: true,
            ..Default::default()
        };
        let replayer = RequestReplayer::new(config);

        let exchange = RecordedExchange {
            request: RecordedRequest {
                id: "test-1".to_string(),
                timestamp: Utc::now(),
                method: "GET".to_string(),
                uri: "/api/users".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![],
                body: None,
                client_ip: None,
                host: "example.com".to_string(),
                offset_ms: 0,
            },
            response: Some(RecordedResponse {
                request_id: "test-1".to_string(),
                timestamp: Utc::now(),
                status: 200,
                headers: vec![],
                body: None,
                response_time_ms: 50,
            }),
        };

        let result = replayer.replay_exchange(&exchange).await;
        assert!(result.success);
        assert_eq!(result.replay_time_ms, 0);
    }

    #[test]
    fn test_recorded_request_serialization() {
        let request = RecordedRequest {
            id: "test-1".to_string(),
            timestamp: Utc::now(),
            method: "POST".to_string(),
            uri: "/api/data".to_string(),
            version: "HTTP/2".to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: Some(b"{\"key\": \"value\"}".to_vec()),
            client_ip: Some("192.168.1.1".to_string()),
            host: "api.example.com".to_string(),
            offset_ms: 1000,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: RecordedRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.id, deserialized.id);
        assert_eq!(request.method, deserialized.method);
        assert_eq!(request.body, deserialized.body);
    }

    #[test]
    fn test_replay_stats() {
        let stats = ReplayStats::default();

        stats.total_requests.store(100, Ordering::Relaxed);
        stats.successful_replays.store(95, Ordering::Relaxed);
        stats.total_original_time_ms.store(10000, Ordering::Relaxed);
        stats.total_replay_time_ms.store(5000, Ordering::Relaxed);

        assert_eq!(stats.success_rate(), 95.0);
        assert_eq!(stats.average_speedup(), 2.0);
    }
}
