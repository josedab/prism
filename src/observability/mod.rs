//! Observability module for metrics, logging, and tracing
//!
//! Provides:
//! - Prometheus metrics
//! - Structured access logging
//! - Distributed tracing with OpenTelemetry
//! - eBPF-based kernel-level observability (Linux only)
//! - AI/ML-based anomaly detection

pub mod anomaly;
pub mod ebpf;
mod logging;
mod metrics;
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

        Ok(Self {
            metrics,
            access_logger,
            tracing,
        })
    }

    /// Shutdown observability (flush pending data)
    pub fn shutdown(&self) {
        if let Some(tracing) = &self.tracing {
            tracing.shutdown();
        }
    }
}
