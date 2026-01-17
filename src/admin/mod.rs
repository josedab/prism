//! Admin API for runtime management
//!
//! Provides endpoints for:
//! - Health checks
//! - Configuration inspection
//! - Statistics and metrics
//! - Runtime control

use crate::config::{AdminConfig, Config};
use crate::error::{PrismError, Result};
use crate::observability::Observability;
use crate::upstream::UpstreamManager;
use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

/// Simple rate limiter for admin API using token bucket algorithm
struct AdminRateLimiter {
    /// Available tokens (scaled by 1000 for precision)
    tokens: AtomicU64,
    /// Last refill time (as unix millis)
    last_refill: AtomicU64,
    /// Maximum tokens (scaled by 1000)
    max_tokens: u64,
    /// Tokens added per millisecond (scaled by 1000)
    refill_rate: u64,
}

impl AdminRateLimiter {
    /// Create a new rate limiter with given rate (requests/sec) and burst
    fn new(rate: u32, burst: u32) -> Self {
        let max_tokens = (burst as u64) * 1000;
        let refill_rate = rate as u64; // rate/1000 tokens per ms

        Self {
            tokens: AtomicU64::new(max_tokens),
            last_refill: AtomicU64::new(Self::current_time_millis()),
            max_tokens,
            refill_rate,
        }
    }

    fn current_time_millis() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Try to acquire a token. Returns true if allowed, false if rate limited.
    fn try_acquire(&self) -> bool {
        let now = Self::current_time_millis();
        let last = self.last_refill.load(Ordering::Relaxed);
        let elapsed_ms = now.saturating_sub(last);

        // Refill tokens
        if elapsed_ms > 0 {
            let tokens_to_add = elapsed_ms * self.refill_rate;
            let current = self.tokens.load(Ordering::Relaxed);
            let new_tokens = (current + tokens_to_add).min(self.max_tokens);
            self.tokens.store(new_tokens, Ordering::Relaxed);
            self.last_refill.store(now, Ordering::Relaxed);
        }

        // Try to consume a token
        let mut current = self.tokens.load(Ordering::Relaxed);
        loop {
            if current < 1000 {
                return false;
            }

            match self.tokens.compare_exchange_weak(
                current,
                current - 1000,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(new) => current = new,
            }
        }
    }
}

/// Admin API server
pub struct AdminServer {
    config: AdminConfig,
    app_config: Arc<ArcSwap<Config>>,
    upstreams: Arc<UpstreamManager>,
    observability: Arc<Observability>,
    shutdown_rx: broadcast::Receiver<()>,
}

impl AdminServer {
    /// Create a new admin server
    pub fn new(
        config: AdminConfig,
        app_config: Arc<ArcSwap<Config>>,
        upstreams: Arc<UpstreamManager>,
        observability: Arc<Observability>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            config,
            app_config,
            upstreams,
            observability,
            shutdown_rx,
        }
    }

    /// Start the admin server
    pub async fn run(mut self) -> Result<()> {
        let addr: SocketAddr = self
            .config
            .address
            .parse()
            .map_err(|e| PrismError::Config(format!("Invalid admin address: {}", e)))?;

        let listener = TcpListener::bind(addr).await?;
        info!("Admin API listening on {}", addr);

        let app_config = self.app_config.clone();
        let upstreams = self.upstreams.clone();
        let observability = self.observability.clone();
        let auth_enabled = self.config.auth_enabled;
        let api_key = self.config.api_key.clone();
        // Rate limiter: 10 requests/sec with burst of 20
        let rate_limiter = Arc::new(AdminRateLimiter::new(10, 20));

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            let app_config = app_config.clone();
                            let upstreams = upstreams.clone();
                            let observability = observability.clone();
                            let api_key = api_key.clone();
                            let rate_limiter = rate_limiter.clone();

                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let service = service_fn(move |req| {
                                    let app_config = app_config.clone();
                                    let upstreams = upstreams.clone();
                                    let observability = observability.clone();
                                    let api_key = api_key.clone();
                                    let rate_limiter = rate_limiter.clone();

                                    async move {
                                        handle_admin_request(
                                            req,
                                            auth_enabled,
                                            api_key,
                                            rate_limiter,
                                            app_config,
                                            upstreams,
                                            observability,
                                        ).await
                                    }
                                });

                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await
                                {
                                    error!("Admin connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept admin connection: {}", e);
                        }
                    }
                }
                _ = self.shutdown_rx.recv() => {
                    info!("Admin API shutting down");
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Handle admin API request
async fn handle_admin_request(
    req: Request<Incoming>,
    auth_enabled: bool,
    api_key: Option<String>,
    rate_limiter: Arc<AdminRateLimiter>,
    app_config: Arc<ArcSwap<Config>>,
    upstreams: Arc<UpstreamManager>,
    observability: Arc<Observability>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    // Check rate limit first (before authentication to prevent DoS)
    if !rate_limiter.try_acquire() {
        return Ok(json_response(
            StatusCode::TOO_MANY_REQUESTS,
            &ErrorResponse {
                error: "Rate Limited".to_string(),
                message: "Too many requests to admin API".to_string(),
            },
        ));
    }

    // Check authentication if enabled
    if auth_enabled {
        if let Some(expected_key) = &api_key {
            let provided_key = req.headers().get("X-API-Key").and_then(|v| v.to_str().ok());

            // Use constant-time comparison to prevent timing attacks
            let is_valid = match provided_key {
                Some(key) if key.len() == expected_key.len() => {
                    key.as_bytes().ct_eq(expected_key.as_bytes()).into()
                }
                _ => false,
            };

            if !is_valid {
                return Ok(json_response(
                    StatusCode::UNAUTHORIZED,
                    &ErrorResponse {
                        error: "Unauthorized".to_string(),
                        message: "Invalid or missing API key".to_string(),
                    },
                ));
            }
        }
    }

    let path = req.uri().path();
    let method = req.method();

    match (method, path) {
        (&Method::GET, "/health") => Ok(handle_health()),
        (&Method::GET, "/ready") => Ok(handle_ready(&upstreams)),
        (&Method::GET, "/config") => Ok(handle_config(&app_config)),
        (&Method::GET, "/stats") => Ok(handle_stats(&upstreams, &observability)),
        (&Method::GET, "/upstreams") => Ok(handle_upstreams(&upstreams)),
        (&Method::GET, "/metrics") => Ok(handle_metrics(&observability)),
        (&Method::GET, "/slo") => Ok(handle_slo(&observability)),
        (&Method::GET, "/slo/alerts") => Ok(handle_slo_alerts(&observability)),
        _ => Ok(json_response(
            StatusCode::NOT_FOUND,
            &ErrorResponse {
                error: "Not Found".to_string(),
                message: format!("Unknown endpoint: {} {}", method, path),
            },
        )),
    }
}

/// Health check response
fn handle_health() -> Response<Full<Bytes>> {
    json_response(
        StatusCode::OK,
        &HealthResponse {
            status: "healthy".to_string(),
            version: crate::VERSION.to_string(),
        },
    )
}

/// Readiness check response
fn handle_ready(upstreams: &UpstreamManager) -> Response<Full<Bytes>> {
    let stats = upstreams.stats();
    let healthy_upstreams = stats.iter().filter(|s| s.healthy_count > 0).count();
    let total_upstreams = stats.len();

    let status = if healthy_upstreams == total_upstreams {
        "ready"
    } else if healthy_upstreams > 0 {
        "degraded"
    } else {
        "not_ready"
    };

    let status_code = if healthy_upstreams > 0 {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    json_response(
        status_code,
        &ReadyResponse {
            status: status.to_string(),
            healthy_upstreams,
            total_upstreams,
        },
    )
}

/// Configuration info response
fn handle_config(app_config: &Arc<ArcSwap<Config>>) -> Response<Full<Bytes>> {
    let config = app_config.load();

    let summary = ConfigSummary {
        listeners: config.listeners.len(),
        upstreams: config.upstreams.len(),
        routes: config.routes.len(),
        http2_enabled: config.global.http2,
        metrics_enabled: config.observability.metrics.enabled,
        access_log_enabled: config.observability.access_log.enabled,
    };

    json_response(StatusCode::OK, &summary)
}

/// Statistics response
fn handle_stats(
    upstreams: &UpstreamManager,
    observability: &Observability,
) -> Response<Full<Bytes>> {
    let upstream_stats = upstreams.stats();
    let metrics = observability.metrics.snapshot();

    let stats = StatsResponse {
        requests_total: metrics.requests_total,
        active_connections: metrics.active_connections,
        upstreams: upstream_stats
            .into_iter()
            .map(|s| UpstreamStatsResponse {
                name: s.name,
                healthy_servers: s.healthy_count,
                total_servers: s.server_count,
                active_connections: s.active_connections,
                requests_total: s.total_requests,
            })
            .collect(),
    };

    json_response(StatusCode::OK, &stats)
}

/// Upstreams info response
fn handle_upstreams(upstreams: &UpstreamManager) -> Response<Full<Bytes>> {
    let stats = upstreams.stats();

    let response: Vec<_> = stats
        .into_iter()
        .map(|s| UpstreamInfoResponse {
            name: s.name,
            servers: s
                .servers
                .into_iter()
                .map(|srv| ServerInfo {
                    address: srv.address,
                    healthy: srv.healthy,
                    weight: srv.weight,
                })
                .collect(),
            healthy_servers: s.healthy_count,
            total_servers: s.server_count,
        })
        .collect();

    json_response(StatusCode::OK, &response)
}

/// Metrics endpoint (Prometheus format)
fn handle_metrics(observability: &Observability) -> Response<Full<Bytes>> {
    match observability.metrics.export() {
        Ok(metrics) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain; version=0.0.4")
            .body(Full::new(Bytes::from(metrics)))
            .unwrap_or_else(|e| {
                error!("Failed to build metrics response: {}", e);
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "Response build failed")
            }),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &ErrorResponse {
                error: "Export Failed".to_string(),
                message: e.to_string(),
            },
        ),
    }
}

/// SLO snapshots endpoint
fn handle_slo(observability: &Observability) -> Response<Full<Bytes>> {
    let snapshots = observability.slo_snapshots();

    if snapshots.is_empty() {
        return json_response(
            StatusCode::OK,
            &SloResponse {
                enabled: observability.slo_tracker.is_some(),
                slos: vec![],
                message: if observability.slo_tracker.is_some() {
                    Some("No SLO data available yet".to_string())
                } else {
                    Some("SLO tracking is not enabled".to_string())
                },
            },
        );
    }

    let slos: Vec<SloSnapshotResponse> = snapshots
        .into_iter()
        .map(|s| SloSnapshotResponse {
            name: s.name,
            slo_type: format!("{:?}", s.slo_type),
            target: s.target,
            current_sli: s.current_sli,
            is_meeting_target: s.slo_met,
            error_budget_remaining: s.error_budget_remaining,
            burn_rate: s.burn_rate,
            total_requests: s.total_requests,
            good_requests: s.good_requests,
            window_secs: s.window_secs,
        })
        .collect();

    json_response(
        StatusCode::OK,
        &SloResponse {
            enabled: true,
            slos,
            message: None,
        },
    )
}

/// SLO alerts endpoint
fn handle_slo_alerts(observability: &Observability) -> Response<Full<Bytes>> {
    let alerts = observability.check_slo_alerts();

    let alert_responses: Vec<SloAlertResponse> = alerts
        .into_iter()
        .map(|a| SloAlertResponse {
            slo_name: a.slo_name,
            alert_type: format!("{:?}", a.alert_type),
            severity: format!("{:?}", a.severity),
            message: a.message,
            current_sli: a.current_sli,
            target_sli: a.target_sli,
            error_budget_remaining: a.error_budget_remaining,
            burn_rate: a.burn_rate,
            timestamp: a.timestamp,
        })
        .collect();

    let has_critical = alert_responses
        .iter()
        .any(|a| a.severity == "Critical");

    json_response(
        if has_critical {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::OK
        },
        &SloAlertsResponse {
            enabled: observability.slo_tracker.is_some(),
            alert_count: alert_responses.len(),
            alerts: alert_responses,
        },
    )
}

/// Create a JSON response
fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<Full<Bytes>> {
    let json = match serde_json::to_string(body) {
        Ok(j) => j,
        Err(e) => {
            warn!("Failed to serialize JSON response: {}", e);
            r#"{"error":"Serialization error"}"#.to_string()
        }
    };
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .unwrap_or_else(|e| {
            error!("Failed to build JSON response: {}", e);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Response build failed")
        })
}

/// Create a simple error response (used as fallback when other response builders fail)
fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = format!(r#"{{"error":"{}"}}"#, message);
    // Use a minimal response builder that's unlikely to fail
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("Minimal response builder should not fail")
}

// Response types

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Serialize)]
struct ReadyResponse {
    status: String,
    healthy_upstreams: usize,
    total_upstreams: usize,
}

#[derive(Serialize)]
struct ConfigSummary {
    listeners: usize,
    upstreams: usize,
    routes: usize,
    http2_enabled: bool,
    metrics_enabled: bool,
    access_log_enabled: bool,
}

#[derive(Serialize)]
struct StatsResponse {
    requests_total: u64,
    active_connections: i64,
    upstreams: Vec<UpstreamStatsResponse>,
}

#[derive(Serialize)]
struct UpstreamStatsResponse {
    name: String,
    healthy_servers: usize,
    total_servers: usize,
    active_connections: u64,
    requests_total: u64,
}

#[derive(Serialize)]
struct UpstreamInfoResponse {
    name: String,
    servers: Vec<ServerInfo>,
    healthy_servers: usize,
    total_servers: usize,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

/// Server info for upstream response
#[derive(Serialize, Clone)]
pub struct ServerInfo {
    pub address: String,
    pub healthy: bool,
    pub weight: u32,
}

#[derive(Serialize)]
struct SloResponse {
    enabled: bool,
    slos: Vec<SloSnapshotResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Serialize)]
struct SloSnapshotResponse {
    name: String,
    slo_type: String,
    target: f64,
    current_sli: f64,
    is_meeting_target: bool,
    error_budget_remaining: f64,
    burn_rate: f64,
    total_requests: u64,
    good_requests: u64,
    window_secs: u64,
}

#[derive(Serialize)]
struct SloAlertsResponse {
    enabled: bool,
    alert_count: usize,
    alerts: Vec<SloAlertResponse>,
}

#[derive(Serialize)]
struct SloAlertResponse {
    slo_name: String,
    alert_type: String,
    severity: String,
    message: String,
    current_sli: f64,
    target_sli: f64,
    error_budget_remaining: f64,
    burn_rate: f64,
    timestamp: u64,
}
