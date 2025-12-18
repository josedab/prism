//! Prometheus metrics implementation

use crate::error::{PrismError, Result};
use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
};
use std::time::Duration;

/// Metrics collector for Prism
pub struct Metrics {
    /// Prometheus registry
    registry: Registry,

    // Request metrics
    /// Total requests
    pub requests_total: IntCounterVec,
    /// Request duration histogram
    pub request_duration_seconds: HistogramVec,
    /// Active requests gauge
    pub active_requests: IntGaugeVec,
    /// Request body size
    pub request_size_bytes: HistogramVec,
    /// Response body size
    pub response_size_bytes: HistogramVec,

    // Upstream metrics
    /// Upstream requests total
    pub upstream_requests_total: IntCounterVec,
    /// Upstream request duration
    pub upstream_request_duration_seconds: HistogramVec,
    /// Upstream connection pool size
    pub upstream_connections: IntGaugeVec,
    /// Upstream health status
    pub upstream_health: IntGaugeVec,

    // Connection metrics
    /// Total connections accepted
    pub connections_total: IntCounter,
    /// Active connections
    pub active_connections: IntGauge,
    /// TLS handshake duration
    pub tls_handshake_duration_seconds: Histogram,

    // Error metrics
    /// Error count by type
    pub errors_total: IntCounterVec,

    // Rate limiting metrics
    /// Rate limit hits
    pub rate_limit_hits: IntCounterVec,

    // Health check metrics
    /// Health check results
    pub health_check_results: IntCounterVec,
    /// Health check duration
    pub health_check_duration_seconds: HistogramVec,
}

impl Metrics {
    /// Create a new metrics instance
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        // Request metrics
        let requests_total = IntCounterVec::new(
            Opts::new("prism_requests_total", "Total number of requests"),
            &["method", "route", "status"],
        )
        .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        let request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "prism_request_duration_seconds",
                "Request duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["method", "route"],
        )
        .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        let active_requests = IntGaugeVec::new(
            Opts::new("prism_active_requests", "Number of active requests"),
            &["route"],
        )
        .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        let request_size_bytes = HistogramVec::new(
            HistogramOpts::new("prism_request_size_bytes", "Request body size in bytes").buckets(
                vec![100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0],
            ),
            &["route"],
        )
        .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        let response_size_bytes = HistogramVec::new(
            HistogramOpts::new("prism_response_size_bytes", "Response body size in bytes").buckets(
                vec![100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0],
            ),
            &["route"],
        )
        .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        // Upstream metrics
        let upstream_requests_total = IntCounterVec::new(
            Opts::new("prism_upstream_requests_total", "Total upstream requests"),
            &["upstream", "server", "status"],
        )
        .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        let upstream_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "prism_upstream_request_duration_seconds",
                "Upstream request duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["upstream"],
        )
        .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        let upstream_connections = IntGaugeVec::new(
            Opts::new(
                "prism_upstream_connections",
                "Upstream connection pool size",
            ),
            &["upstream", "state"],
        )
        .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        let upstream_health = IntGaugeVec::new(
            Opts::new(
                "prism_upstream_health",
                "Upstream health status (1=healthy, 0=unhealthy)",
            ),
            &["upstream", "server"],
        )
        .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        // Connection metrics
        let connections_total =
            IntCounter::new("prism_connections_total", "Total connections accepted")
                .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        let active_connections =
            IntGauge::new("prism_active_connections", "Number of active connections")
                .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        let tls_handshake_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "prism_tls_handshake_duration_seconds",
                "TLS handshake duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]),
        )
        .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        // Error metrics
        let errors_total = IntCounterVec::new(
            Opts::new("prism_errors_total", "Total errors by type"),
            &["type"],
        )
        .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        // Rate limiting metrics
        let rate_limit_hits = IntCounterVec::new(
            Opts::new("prism_rate_limit_hits_total", "Rate limit hits"),
            &["route", "result"],
        )
        .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        // Health check metrics
        let health_check_results = IntCounterVec::new(
            Opts::new("prism_health_check_results_total", "Health check results"),
            &["upstream", "server", "result"],
        )
        .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        let health_check_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "prism_health_check_duration_seconds",
                "Health check duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
            &["upstream"],
        )
        .map_err(|e| PrismError::Internal(format!("Failed to create metric: {}", e)))?;

        // Register all metrics
        registry.register(Box::new(requests_total.clone())).ok();
        registry
            .register(Box::new(request_duration_seconds.clone()))
            .ok();
        registry.register(Box::new(active_requests.clone())).ok();
        registry.register(Box::new(request_size_bytes.clone())).ok();
        registry
            .register(Box::new(response_size_bytes.clone()))
            .ok();
        registry
            .register(Box::new(upstream_requests_total.clone()))
            .ok();
        registry
            .register(Box::new(upstream_request_duration_seconds.clone()))
            .ok();
        registry
            .register(Box::new(upstream_connections.clone()))
            .ok();
        registry.register(Box::new(upstream_health.clone())).ok();
        registry.register(Box::new(connections_total.clone())).ok();
        registry.register(Box::new(active_connections.clone())).ok();
        registry
            .register(Box::new(tls_handshake_duration_seconds.clone()))
            .ok();
        registry.register(Box::new(errors_total.clone())).ok();
        registry.register(Box::new(rate_limit_hits.clone())).ok();
        registry
            .register(Box::new(health_check_results.clone()))
            .ok();
        registry
            .register(Box::new(health_check_duration_seconds.clone()))
            .ok();

        Ok(Self {
            registry,
            requests_total,
            request_duration_seconds,
            active_requests,
            request_size_bytes,
            response_size_bytes,
            upstream_requests_total,
            upstream_request_duration_seconds,
            upstream_connections,
            upstream_health,
            connections_total,
            active_connections,
            tls_handshake_duration_seconds,
            errors_total,
            rate_limit_hits,
            health_check_results,
            health_check_duration_seconds,
        })
    }

    /// Export metrics in Prometheus format
    pub fn export(&self) -> Result<String> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();

        encoder
            .encode(&metric_families, &mut buffer)
            .map_err(|e| PrismError::Internal(format!("Failed to encode metrics: {}", e)))?;

        String::from_utf8(buffer).map_err(|e| {
            PrismError::Internal(format!("Failed to convert metrics to string: {}", e))
        })
    }

    /// Record a request
    pub fn record_request(&self, method: &str, route: &str, status: u16, duration: Duration) {
        self.requests_total
            .with_label_values(&[method, route, &status.to_string()])
            .inc();

        self.request_duration_seconds
            .with_label_values(&[method, route])
            .observe(duration.as_secs_f64());
    }

    /// Record connection accepted
    pub fn record_connection(&self) {
        self.connections_total.inc();
        self.active_connections.inc();
    }

    /// Record connection closed
    pub fn record_connection_closed(&self) {
        self.active_connections.dec();
    }

    /// Record TLS handshake duration
    pub fn record_tls_handshake(&self, duration: Duration) {
        self.tls_handshake_duration_seconds
            .observe(duration.as_secs_f64());
    }

    /// Record an error
    pub fn record_error(&self, error_type: &str) {
        self.errors_total.with_label_values(&[error_type]).inc();
    }

    /// Record upstream request
    pub fn record_upstream_request(
        &self,
        upstream: &str,
        server: &str,
        status: u16,
        duration: Duration,
    ) {
        self.upstream_requests_total
            .with_label_values(&[upstream, server, &status.to_string()])
            .inc();

        self.upstream_request_duration_seconds
            .with_label_values(&[upstream])
            .observe(duration.as_secs_f64());
    }

    /// Update upstream health status
    pub fn update_upstream_health(&self, upstream: &str, server: &str, healthy: bool) {
        self.upstream_health
            .with_label_values(&[upstream, server])
            .set(if healthy { 1 } else { 0 });
    }

    /// Record rate limit hit
    pub fn record_rate_limit(&self, route: &str, allowed: bool) {
        let result = if allowed { "allowed" } else { "rejected" };
        self.rate_limit_hits
            .with_label_values(&[route, result])
            .inc();
    }

    /// Get a snapshot of key metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        // Sum up total requests across all labels
        let mut requests_total = 0;
        let metric_families = self.registry.gather();
        for mf in &metric_families {
            if mf.get_name() == "prism_requests_total" {
                for m in mf.get_metric() {
                    requests_total += m.get_counter().get_value() as u64;
                }
            }
        }

        MetricsSnapshot {
            requests_total,
            active_connections: self.active_connections.get(),
        }
    }
}

/// Snapshot of key metrics
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub active_connections: i64,
}

/// Helper for timing operations
pub struct Timer {
    start: std::time::Instant,
}

impl Timer {
    /// Start a new timer
    pub fn start() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = Metrics::new().unwrap();
        assert!(metrics.export().is_ok());
    }

    #[test]
    fn test_record_request() {
        let metrics = Metrics::new().unwrap();
        metrics.record_request("GET", "/api/test", 200, Duration::from_millis(50));

        let export = metrics.export().unwrap();
        assert!(export.contains("prism_requests_total"));
        assert!(export.contains("prism_request_duration_seconds"));
    }

    #[test]
    fn test_timer() {
        let timer = Timer::start();
        std::thread::sleep(Duration::from_millis(10));
        let elapsed = timer.elapsed();
        assert!(elapsed >= Duration::from_millis(10));
    }
}
