//! Observability module for metrics, logging, and tracing
//!
//! Provides:
//! - Prometheus metrics
//! - Structured access logging
//! - Distributed tracing with OpenTelemetry
//! - eBPF-based kernel-level observability (Linux only)
//! - AI/ML-based anomaly detection
//! - SLO (Service Level Objective) tracking and error budgets

pub mod anomaly;
pub mod ebpf;
mod logging;
mod metrics;
pub mod slo;
mod tracing;

pub use anomaly::{
    AnomalyAlert, AnomalyConfig, AnomalyDetector, AnomalyStats, AnomalyType, FeatureConfig,
    RequestSample, Severity,
};
pub use ebpf::{
    DropReason, EbpfCollector, EbpfConfig, EbpfError, EbpfStats, FlowStats, LatencyHistogram,
    LatencySummary, PacketDropEvent, SocketLatencyEvent, SocketOperation, TcpEvent, TcpState,
};
pub use logging::*;
pub use metrics::*;
pub use slo::{
    AlertSeverity, BurnRateWindow, LatencySampler, SloAlert, SloAlertType, SloAlertingConfig,
    SloConfig, SloSnapshot, SloState, SloStats, SloStatsSnapshot, SloTarget, SloTracker, SloType,
};
pub use tracing::*;

use crate::config::ObservabilityConfig;
use crate::error::Result;
use std::sync::Arc;

/// Observability context
pub struct Observability {
    /// Metrics registry
    pub metrics: Arc<Metrics>,
    /// Access logger
    pub access_logger: Arc<AccessLogger>,
    /// Distributed tracing
    pub tracing: Option<Arc<DistributedTracing>>,
    /// SLO tracker
    pub slo_tracker: Option<Arc<SloTracker>>,
}

impl Observability {
    /// Create observability from configuration
    pub fn new(config: &ObservabilityConfig) -> Result<Self> {
        let metrics = Arc::new(Metrics::new()?);
        let access_logger = Arc::new(AccessLogger::new(&config.access_log)?);

        // Initialize tracing if enabled
        let tracing = if config.tracing.enabled {
            Some(Arc::new(DistributedTracing::new(&config.tracing)?))
        } else {
            None
        };

        // Initialize SLO tracker if configured
        let slo_tracker = config.slo.as_ref().map(|slo_config| {
            Arc::new(SloTracker::new(slo_config.clone()))
        });

        Ok(Self {
            metrics,
            access_logger,
            tracing,
            slo_tracker,
        })
    }

    /// Shutdown observability (flush pending data)
    pub fn shutdown(&self) {
        if let Some(tracing) = &self.tracing {
            tracing.shutdown();
        }
    }

    /// Record a request for SLO tracking
    pub fn record_slo(&self, route: &str, method: &str, status: u16, latency_ms: u64) {
        if let Some(tracker) = &self.slo_tracker {
            tracker.record_request(route, method, status, latency_ms);
        }
    }

    /// Get SLO snapshots for all configured SLOs
    pub fn slo_snapshots(&self) -> Vec<SloSnapshot> {
        self.slo_tracker
            .as_ref()
            .map(|t| t.snapshot())
            .unwrap_or_default()
    }

    /// Export SLO metrics in Prometheus format
    pub fn export_slo_prometheus(&self) -> String {
        self.slo_tracker
            .as_ref()
            .map(|t| t.export_prometheus())
            .unwrap_or_default()
    }

    /// Check for SLO alerts
    pub fn check_slo_alerts(&self) -> Vec<SloAlert> {
        self.slo_tracker
            .as_ref()
            .map(|t| t.check_alerts())
            .unwrap_or_default()
    }
}
