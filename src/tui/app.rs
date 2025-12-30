//! TUI Application State and Event Handling

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Maximum number of data points to keep in history
const MAX_HISTORY_POINTS: usize = 120;

/// Dashboard application state
pub struct DashboardApp {
    /// Whether the app should quit
    pub should_quit: bool,
    /// Current tab index
    pub current_tab: usize,
    /// Total tabs count
    pub tab_count: usize,
    /// Selected upstream index (for upstream detail view)
    pub selected_upstream: usize,
    /// Scroll offset for logs
    pub log_scroll: u16,
    /// Dashboard metrics
    pub metrics: Arc<DashboardMetrics>,
    /// Refresh rate in milliseconds
    pub refresh_rate_ms: u64,
    /// Start time
    pub start_time: Instant,
    /// Show help overlay
    pub show_help: bool,
}

impl DashboardApp {
    /// Create a new dashboard application
    pub fn new(metrics: Arc<DashboardMetrics>) -> Self {
        Self {
            should_quit: false,
            current_tab: 0,
            tab_count: 4,
            selected_upstream: 0,
            log_scroll: 0,
            metrics,
            refresh_rate_ms: 250,
            start_time: Instant::now(),
            show_help: false,
        }
    }

    /// Handle keyboard input
    pub fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Quit | KeyCode::Escape => self.should_quit = true,
            KeyCode::Tab | KeyCode::Right => {
                self.current_tab = (self.current_tab + 1) % self.tab_count;
            }
            KeyCode::BackTab | KeyCode::Left => {
                self.current_tab = self
                    .current_tab
                    .checked_sub(1)
                    .unwrap_or(self.tab_count - 1);
            }
            KeyCode::Up => {
                if self.selected_upstream > 0 {
                    self.selected_upstream -= 1;
                }
            }
            KeyCode::Down => {
                self.selected_upstream += 1;
            }
            KeyCode::Help => {
                self.show_help = !self.show_help;
            }
            KeyCode::PageUp => {
                self.log_scroll = self.log_scroll.saturating_sub(10);
            }
            KeyCode::PageDown => {
                self.log_scroll = self.log_scroll.saturating_add(10);
            }
            _ => {}
        }
    }

    /// Get uptime as human readable string
    pub fn uptime(&self) -> String {
        let elapsed = self.start_time.elapsed();
        let secs = elapsed.as_secs();
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        let secs = secs % 60;
        format!("{:02}:{:02}:{:02}", hours, mins, secs)
    }
}

/// Key codes for input handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    Quit,
    Escape,
    Tab,
    BackTab,
    Left,
    Right,
    Up,
    Down,
    Help,
    PageUp,
    PageDown,
    Enter,
    Other,
}

/// Dashboard metrics collector
pub struct DashboardMetrics {
    // Request metrics
    pub total_requests: AtomicU64,
    pub successful_requests: AtomicU64,
    pub failed_requests: AtomicU64,
    pub active_connections: AtomicU64,

    // Latency tracking
    pub latency_sum_us: AtomicU64,
    pub latency_count: AtomicU64,
    pub latency_p50_us: AtomicU64,
    pub latency_p95_us: AtomicU64,
    pub latency_p99_us: AtomicU64,

    // Rate metrics
    pub requests_per_second: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,

    // History for charts
    pub rps_history: RwLock<VecDeque<f64>>,
    pub latency_history: RwLock<VecDeque<f64>>,
    pub connections_history: RwLock<VecDeque<f64>>,
    pub error_rate_history: RwLock<VecDeque<f64>>,

    // Upstream states
    pub upstreams: RwLock<Vec<UpstreamStatus>>,

    // Recent logs
    pub recent_logs: RwLock<VecDeque<LogEntry>>,

    // Rate limiter stats
    pub rate_limited_count: AtomicU64,

    // Circuit breaker stats
    pub circuit_open_count: AtomicU64,

    // Internal tracking
    last_request_count: AtomicU64,
    last_update: RwLock<Instant>,
    running: AtomicBool,
}

impl DashboardMetrics {
    /// Create new dashboard metrics
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            latency_sum_us: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            latency_p50_us: AtomicU64::new(0),
            latency_p95_us: AtomicU64::new(0),
            latency_p99_us: AtomicU64::new(0),
            requests_per_second: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            rps_history: RwLock::new(VecDeque::with_capacity(MAX_HISTORY_POINTS)),
            latency_history: RwLock::new(VecDeque::with_capacity(MAX_HISTORY_POINTS)),
            connections_history: RwLock::new(VecDeque::with_capacity(MAX_HISTORY_POINTS)),
            error_rate_history: RwLock::new(VecDeque::with_capacity(MAX_HISTORY_POINTS)),
            upstreams: RwLock::new(Vec::new()),
            recent_logs: RwLock::new(VecDeque::with_capacity(100)),
            rate_limited_count: AtomicU64::new(0),
            circuit_open_count: AtomicU64::new(0),
            last_request_count: AtomicU64::new(0),
            last_update: RwLock::new(Instant::now()),
            running: AtomicBool::new(true),
        }
    }

    /// Record a request
    pub fn record_request(&self, success: bool, latency: Duration) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        if success {
            self.successful_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
        }

        let latency_us = latency.as_micros() as u64;
        self.latency_sum_us.fetch_add(latency_us, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record connection opened
    pub fn connection_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record connection closed
    pub fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record bytes transferred
    pub fn record_bytes(&self, bytes_in: u64, bytes_out: u64) {
        self.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
    }

    /// Record rate limited request
    pub fn record_rate_limited(&self) {
        self.rate_limited_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record circuit breaker open
    pub fn record_circuit_open(&self) {
        self.circuit_open_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Update upstream status
    pub fn update_upstream(&self, name: &str, healthy: bool, response_time: Duration) {
        let mut upstreams = self.upstreams.write();
        if let Some(upstream) = upstreams.iter_mut().find(|u| u.name == name) {
            upstream.healthy = healthy;
            upstream.last_response_time = response_time;
            upstream.total_requests += 1;
        } else {
            upstreams.push(UpstreamStatus {
                name: name.to_string(),
                healthy,
                last_response_time: response_time,
                total_requests: 1,
                active_connections: 0,
                circuit_state: CircuitState::Closed,
            });
        }
    }

    /// Add a log entry
    pub fn add_log(&self, level: LogLevel, message: String) {
        let mut logs = self.recent_logs.write();
        if logs.len() >= 100 {
            logs.pop_front();
        }
        logs.push_back(LogEntry {
            timestamp: Instant::now(),
            level,
            message,
        });
    }

    /// Update calculated metrics (should be called periodically)
    pub fn update_calculated_metrics(&self) {
        let now = Instant::now();
        let mut last_update = self.last_update.write();
        let elapsed = now.duration_since(*last_update);

        if elapsed >= Duration::from_millis(100) {
            *last_update = now;

            // Calculate RPS
            let current_count = self.total_requests.load(Ordering::Relaxed);
            let last_count = self
                .last_request_count
                .swap(current_count, Ordering::Relaxed);
            let rps = ((current_count - last_count) as f64) / elapsed.as_secs_f64();
            self.requests_per_second
                .store(rps as u64, Ordering::Relaxed);

            // Update history
            let mut rps_history = self.rps_history.write();
            if rps_history.len() >= MAX_HISTORY_POINTS {
                rps_history.pop_front();
            }
            rps_history.push_back(rps);

            // Update latency history
            let latency_count = self.latency_count.load(Ordering::Relaxed);
            let avg_latency = if latency_count > 0 {
                self.latency_sum_us.load(Ordering::Relaxed) as f64 / latency_count as f64 / 1000.0
            } else {
                0.0
            };
            let mut latency_history = self.latency_history.write();
            if latency_history.len() >= MAX_HISTORY_POINTS {
                latency_history.pop_front();
            }
            latency_history.push_back(avg_latency);

            // Update connections history
            let connections = self.active_connections.load(Ordering::Relaxed) as f64;
            let mut conn_history = self.connections_history.write();
            if conn_history.len() >= MAX_HISTORY_POINTS {
                conn_history.pop_front();
            }
            conn_history.push_back(connections);

            // Update error rate history
            let total = self.total_requests.load(Ordering::Relaxed);
            let failed = self.failed_requests.load(Ordering::Relaxed);
            let error_rate = if total > 0 {
                (failed as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let mut error_history = self.error_rate_history.write();
            if error_history.len() >= MAX_HISTORY_POINTS {
                error_history.pop_front();
            }
            error_history.push_back(error_rate);
        }
    }

    /// Check if dashboard is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Stop the dashboard
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Get RPS history as vector
    pub fn get_rps_history(&self) -> Vec<f64> {
        self.rps_history.read().iter().copied().collect()
    }

    /// Get latency history as vector
    pub fn get_latency_history(&self) -> Vec<f64> {
        self.latency_history.read().iter().copied().collect()
    }

    /// Get connections history as vector
    pub fn get_connections_history(&self) -> Vec<f64> {
        self.connections_history.read().iter().copied().collect()
    }

    /// Get error rate history as vector
    pub fn get_error_rate_history(&self) -> Vec<f64> {
        self.error_rate_history.read().iter().copied().collect()
    }

    /// Get average latency in milliseconds
    pub fn average_latency_ms(&self) -> f64 {
        let count = self.latency_count.load(Ordering::Relaxed);
        if count > 0 {
            self.latency_sum_us.load(Ordering::Relaxed) as f64 / count as f64 / 1000.0
        } else {
            0.0
        }
    }

    /// Get error rate percentage
    pub fn error_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        let failed = self.failed_requests.load(Ordering::Relaxed);
        if total > 0 {
            (failed as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }

    /// Get human readable bytes
    pub fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }
}

impl Default for DashboardMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Upstream server status
#[derive(Debug, Clone)]
pub struct UpstreamStatus {
    pub name: String,
    pub healthy: bool,
    pub last_response_time: Duration,
    pub total_requests: u64,
    pub active_connections: u32,
    pub circuit_state: CircuitState,
}

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "Closed"),
            CircuitState::Open => write!(f, "Open"),
            CircuitState::HalfOpen => write!(f, "Half-Open"),
        }
    }
}

/// Log entry for the dashboard
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: Instant,
    pub level: LogLevel,
    pub message: String,
}

/// Log level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = DashboardMetrics::new();
        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 0);
        assert!(metrics.is_running());
    }

    #[test]
    fn test_record_request() {
        let metrics = DashboardMetrics::new();
        metrics.record_request(true, Duration::from_millis(10));
        metrics.record_request(false, Duration::from_millis(20));

        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.successful_requests.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.failed_requests.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_connection_tracking() {
        let metrics = DashboardMetrics::new();
        metrics.connection_opened();
        metrics.connection_opened();
        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 2);

        metrics.connection_closed();
        assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(DashboardMetrics::format_bytes(500), "500 B");
        assert_eq!(DashboardMetrics::format_bytes(1024), "1.00 KB");
        assert_eq!(DashboardMetrics::format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(
            DashboardMetrics::format_bytes(1024 * 1024 * 1024),
            "1.00 GB"
        );
    }

    #[test]
    fn test_error_rate() {
        let metrics = DashboardMetrics::new();
        metrics.record_request(true, Duration::from_millis(10));
        metrics.record_request(true, Duration::from_millis(10));
        metrics.record_request(false, Duration::from_millis(10));
        metrics.record_request(true, Duration::from_millis(10));

        let error_rate = metrics.error_rate();
        assert!((error_rate - 25.0).abs() < 0.1);
    }

    #[test]
    fn test_upstream_status() {
        let metrics = DashboardMetrics::new();
        metrics.update_upstream("backend-1", true, Duration::from_millis(50));
        metrics.update_upstream("backend-2", false, Duration::from_millis(100));

        let upstreams = metrics.upstreams.read();
        assert_eq!(upstreams.len(), 2);
        assert!(upstreams[0].healthy);
        assert!(!upstreams[1].healthy);
    }

    #[test]
    fn test_app_key_handling() {
        let metrics = Arc::new(DashboardMetrics::new());
        let mut app = DashboardApp::new(metrics);

        assert_eq!(app.current_tab, 0);
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.current_tab, 1);
        app.handle_key(KeyCode::BackTab);
        assert_eq!(app.current_tab, 0);
    }
}
