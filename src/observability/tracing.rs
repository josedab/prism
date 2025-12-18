//! Distributed tracing with OpenTelemetry
//!
//! Provides integration with OpenTelemetry for distributed tracing.
//! This module is only available when the `opentelemetry` feature is enabled.

use crate::config::TracingConfig;
use crate::error::Result;
use std::collections::HashMap;

#[cfg(feature = "opentelemetry")]
use crate::error::PrismError;
#[cfg(feature = "opentelemetry")]
use opentelemetry::{global, KeyValue};
#[cfg(feature = "opentelemetry")]
use opentelemetry_otlp::WithExportConfig;
#[cfg(feature = "opentelemetry")]
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler};
#[cfg(feature = "opentelemetry")]
use opentelemetry_sdk::Resource;
#[cfg(feature = "opentelemetry")]
use tracing::info;

/// Distributed tracing manager
pub struct DistributedTracing {
    /// Service name for tracing
    service_name: String,
    /// Whether tracing is enabled
    enabled: bool,
}

impl DistributedTracing {
    /// Create a new distributed tracing instance
    #[cfg(feature = "opentelemetry")]
    pub fn new(config: &TracingConfig) -> Result<Self> {
        if !config.enabled {
            return Ok(Self {
                service_name: config.service_name.clone(),
                enabled: false,
            });
        }

        // Initialize OpenTelemetry
        Self::init_otel(config)?;

        info!(
            "OpenTelemetry tracing initialized for service '{}' with endpoint '{}'",
            config.service_name, config.endpoint
        );

        Ok(Self {
            service_name: config.service_name.clone(),
            enabled: true,
        })
    }

    #[cfg(not(feature = "opentelemetry"))]
    pub fn new(config: &TracingConfig) -> Result<Self> {
        if config.enabled {
            tracing::warn!(
                "OpenTelemetry tracing requested but 'opentelemetry' feature is not enabled. \
                Rebuild with `cargo build --features opentelemetry`"
            );
        }
        Ok(Self {
            service_name: config.service_name.clone(),
            enabled: false,
        })
    }

    /// Initialize OpenTelemetry tracer
    #[cfg(feature = "opentelemetry")]
    fn init_otel(config: &TracingConfig) -> Result<()> {
        use opentelemetry_sdk::trace::TracerProvider;

        // Create resource with service information
        let resource = Resource::new(vec![
            KeyValue::new("service.name", config.service_name.clone()),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        ]);

        // Create OTLP exporter
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&config.endpoint)
            .build()
            .map_err(|e| PrismError::Config(format!("Failed to create OTLP exporter: {}", e)))?;

        // Create tracer provider
        let sampler = match config.sample_rate {
            rate if rate >= 1.0 => Sampler::AlwaysOn,
            rate if rate <= 0.0 => Sampler::AlwaysOff,
            rate => Sampler::TraceIdRatioBased(rate as f64),
        };

        let tracer_provider = TracerProvider::builder()
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .with_resource(resource)
            .with_sampler(sampler)
            .with_id_generator(RandomIdGenerator::default())
            .build();

        // Set as global tracer
        global::set_tracer_provider(tracer_provider);

        Ok(())
    }

    /// Check if tracing is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the service name
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Shutdown tracing (flush pending spans)
    #[cfg(feature = "opentelemetry")]
    pub fn shutdown(&self) {
        if self.enabled {
            global::shutdown_tracer_provider();
        }
    }

    #[cfg(not(feature = "opentelemetry"))]
    pub fn shutdown(&self) {
        // No-op when feature is not enabled
    }
}

/// Context for propagating trace information
#[derive(Debug, Clone, Default)]
pub struct TraceContext {
    /// Trace ID
    pub trace_id: Option<String>,
    /// Span ID
    pub span_id: Option<String>,
    /// Parent span ID
    pub parent_span_id: Option<String>,
    /// Trace flags
    pub trace_flags: Option<u8>,
    /// Baggage items
    pub baggage: HashMap<String, String>,
}

impl TraceContext {
    /// Create a new empty trace context
    pub fn new() -> Self {
        Self::default()
    }

    /// Extract trace context from HTTP headers (W3C Trace Context format)
    pub fn from_headers(headers: &http::HeaderMap) -> Self {
        let mut ctx = Self::new();

        // Extract traceparent header (W3C format)
        // Format: {version}-{trace-id}-{parent-id}-{trace-flags}
        if let Some(traceparent) = headers.get("traceparent").and_then(|v| v.to_str().ok()) {
            let parts: Vec<&str> = traceparent.split('-').collect();
            if parts.len() >= 4 {
                ctx.trace_id = Some(parts[1].to_string());
                ctx.parent_span_id = Some(parts[2].to_string());
                ctx.trace_flags = u8::from_str_radix(parts[3], 16).ok();
            }
        }

        // Extract tracestate (vendor-specific key-value pairs)
        if let Some(tracestate) = headers.get("tracestate").and_then(|v| v.to_str().ok()) {
            for pair in tracestate.split(',') {
                if let Some((key, value)) = pair.split_once('=') {
                    ctx.baggage
                        .insert(key.trim().to_string(), value.trim().to_string());
                }
            }
        }

        // Also check for Jaeger format (uber-trace-id)
        if ctx.trace_id.is_none() {
            if let Some(jaeger_ctx) = headers.get("uber-trace-id").and_then(|v| v.to_str().ok()) {
                // Jaeger format: {trace-id}:{span-id}:{parent-span-id}:{flags}
                let parts: Vec<&str> = jaeger_ctx.split(':').collect();
                if parts.len() >= 4 {
                    ctx.trace_id = Some(parts[0].to_string());
                    ctx.span_id = Some(parts[1].to_string());
                    ctx.parent_span_id = Some(parts[2].to_string());
                    ctx.trace_flags = u8::from_str_radix(parts[3], 16).ok();
                }
            }
        }

        ctx
    }

    /// Convert to HTTP headers for propagation
    pub fn to_headers(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        // Generate traceparent header
        if let (Some(trace_id), Some(span_id)) = (&self.trace_id, &self.span_id) {
            let flags = self.trace_flags.unwrap_or(0x01); // sampled by default
            let traceparent = format!("00-{}-{}-{:02x}", trace_id, span_id, flags);
            headers.push(("traceparent".to_string(), traceparent));
        }

        // Generate tracestate if we have baggage
        if !self.baggage.is_empty() {
            let tracestate: String = self
                .baggage
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(",");
            headers.push(("tracestate".to_string(), tracestate));
        }

        headers
    }

    /// Check if this context has valid trace information
    pub fn is_valid(&self) -> bool {
        self.trace_id.is_some()
    }
}

/// Span attributes for request tracing
#[derive(Debug, Clone)]
pub struct SpanAttributes {
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// HTTP host
    pub host: Option<String>,
    /// Client IP
    pub client_ip: Option<String>,
    /// Response status code
    pub status_code: Option<u16>,
    /// Upstream name
    pub upstream: Option<String>,
    /// Error message if any
    pub error: Option<String>,
}

impl SpanAttributes {
    /// Create new span attributes for a request
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_string(),
            path: path.to_string(),
            host: None,
            client_ip: None,
            status_code: None,
            upstream: None,
            error: None,
        }
    }

    /// Set host
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Set client IP
    pub fn with_client_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = Some(ip.into());
        self
    }

    /// Set response status code
    pub fn with_status(mut self, status: u16) -> Self {
        self.status_code = Some(status);
        self
    }

    /// Set upstream name
    pub fn with_upstream(mut self, upstream: impl Into<String>) -> Self {
        self.upstream = Some(upstream.into());
        self
    }

    /// Set error message
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Convert to OpenTelemetry attributes
    #[cfg(feature = "opentelemetry")]
    pub fn to_otel_attributes(&self) -> Vec<KeyValue> {
        let mut attrs = vec![
            KeyValue::new("http.method", self.method.clone()),
            KeyValue::new("http.target", self.path.clone()),
        ];

        if let Some(host) = &self.host {
            attrs.push(KeyValue::new("http.host", host.clone()));
        }
        if let Some(ip) = &self.client_ip {
            attrs.push(KeyValue::new("http.client_ip", ip.clone()));
        }
        if let Some(status) = self.status_code {
            attrs.push(KeyValue::new("http.status_code", status as i64));
        }
        if let Some(upstream) = &self.upstream {
            attrs.push(KeyValue::new("prism.upstream", upstream.clone()));
        }
        if let Some(error) = &self.error {
            attrs.push(KeyValue::new("error.message", error.clone()));
            attrs.push(KeyValue::new("error", true));
        }

        attrs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context_from_w3c_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
                .parse()
                .unwrap(),
        );

        let ctx = TraceContext::from_headers(&headers);

        assert_eq!(
            ctx.trace_id,
            Some("0af7651916cd43dd8448eb211c80319c".to_string())
        );
        assert_eq!(ctx.parent_span_id, Some("b7ad6b7169203331".to_string()));
        assert_eq!(ctx.trace_flags, Some(0x01));
    }

    #[test]
    fn test_trace_context_from_jaeger_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("uber-trace-id", "abcd1234:5678efab:0:1".parse().unwrap());

        let ctx = TraceContext::from_headers(&headers);

        assert_eq!(ctx.trace_id, Some("abcd1234".to_string()));
        assert_eq!(ctx.span_id, Some("5678efab".to_string()));
        assert_eq!(ctx.parent_span_id, Some("0".to_string()));
        assert_eq!(ctx.trace_flags, Some(0x01));
    }

    #[test]
    fn test_trace_context_to_headers() {
        let ctx = TraceContext {
            trace_id: Some("abc123".to_string()),
            span_id: Some("def456".to_string()),
            parent_span_id: None,
            trace_flags: Some(0x01),
            baggage: HashMap::new(),
        };

        let headers = ctx.to_headers();
        assert!(!headers.is_empty());

        let (name, value) = &headers[0];
        assert_eq!(name, "traceparent");
        assert!(value.contains("abc123"));
        assert!(value.contains("def456"));
    }

    #[test]
    fn test_span_attributes() {
        let attrs = SpanAttributes::new("GET", "/api/users")
            .with_host("example.com")
            .with_client_ip("192.168.1.1")
            .with_status(200);

        assert_eq!(attrs.method, "GET");
        assert_eq!(attrs.path, "/api/users");
        assert_eq!(attrs.host, Some("example.com".to_string()));
        assert_eq!(attrs.status_code, Some(200));
    }

    #[test]
    fn test_trace_context_validity() {
        let empty_ctx = TraceContext::new();
        assert!(!empty_ctx.is_valid());

        let valid_ctx = TraceContext {
            trace_id: Some("abc123".to_string()),
            ..Default::default()
        };
        assert!(valid_ctx.is_valid());
    }
}
