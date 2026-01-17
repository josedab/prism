//! Request handler implementation

use crate::config::HandlerType;
use crate::error::{PrismError, Result};
use crate::grpc::{
    create_grpc_trailers_only_response, is_grpc_request, is_grpc_web_request, GrpcStatus,
};
use crate::listener::Connection;
use crate::middleware::{
    build_middleware_chain, Handler, HttpRequest, MiddlewareChain, ProxyBody, RequestContext,
};
use crate::observability::{AccessLogBuilder, Observability, Timer};
use crate::router::{ResolvedRoute, Router};
use crate::upstream::{SelectionFailureReason, UpstreamManager};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
#[cfg(feature = "http3")]
use std::future::Future;
use std::net::SocketAddr;
#[cfg(feature = "http3")]
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, warn};

// HTTP/3 request handler imports
#[cfg(feature = "http3")]
use crate::listener::H3RequestHandler;

/// Request handler that processes incoming HTTP requests
pub struct RequestHandler {
    router: Arc<ArcSwap<Router>>,
    upstreams: Arc<UpstreamManager>,
    observability: Arc<Observability>,
}

impl RequestHandler {
    /// Create a new request handler
    pub fn new(
        router: Arc<ArcSwap<Router>>,
        upstreams: Arc<UpstreamManager>,
        observability: Arc<Observability>,
    ) -> Self {
        Self {
            router,
            upstreams,
            observability,
        }
    }

    /// Handle a connection
    pub async fn handle(&self, connection: Connection, addr: SocketAddr) -> Result<()> {
        match connection {
            Connection::Plain(stream) => self.handle_http(stream, addr).await,
            Connection::Tls(stream) => self.handle_http(stream, addr).await,
        }
    }

    /// Handle HTTP/1.1 connection
    async fn handle_http<S>(&self, stream: S, addr: SocketAddr) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let io = TokioIo::new(stream);
        let router = self.router.clone();
        let upstreams = self.upstreams.clone();
        let observability = self.observability.clone();

        let service = service_fn(move |req: Request<Incoming>| {
            let router = router.clone();
            let upstreams = upstreams.clone();
            let observability = observability.clone();
            let client_ip = addr.ip().to_string();

            async move {
                let ctx = RequestContext::new().with_client_ip(client_ip);
                handle_request(req, ctx, router, upstreams, observability).await
            }
        });

        // Serve HTTP/1.1
        if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
            if !e.is_incomplete_message() {
                debug!("HTTP connection error: {}", e);
            }
        }

        Ok(())
    }

    /// Handle an HTTP/3 request (called from H3 listener)
    #[cfg(feature = "http3")]
    pub async fn handle_h3_request(
        &self,
        req: Request<Bytes>,
        addr: SocketAddr,
    ) -> Response<Full<Bytes>> {
        let ctx = RequestContext::new().with_client_ip(addr.ip().to_string());

        // Convert to ProxyBody and use existing logic
        let (parts, body) = req.into_parts();
        let proxy_req: HttpRequest = Request::from_parts(parts, ProxyBody::buffered(body));

        // Use existing request handling
        match handle_request_internal(
            proxy_req,
            ctx,
            self.router.clone(),
            self.upstreams.clone(),
            self.observability.clone(),
        )
        .await
        {
            Ok(resp) => resp,
            Err(_) => Response::builder()
                .status(500)
                .body(Full::new(Bytes::from("Internal Server Error")))
                .unwrap(),
        }
    }
}

/// HTTP/3 request handler adapter
#[cfg(feature = "http3")]
pub struct H3Handler {
    router: Arc<ArcSwap<Router>>,
    upstreams: Arc<UpstreamManager>,
    observability: Arc<Observability>,
}

#[cfg(feature = "http3")]
impl H3Handler {
    /// Create a new HTTP/3 handler
    pub fn new(
        router: Arc<ArcSwap<Router>>,
        upstreams: Arc<UpstreamManager>,
        observability: Arc<Observability>,
    ) -> Self {
        Self {
            router,
            upstreams,
            observability,
        }
    }
}

#[cfg(feature = "http3")]
impl H3RequestHandler for H3Handler {
    fn handle(
        &self,
        request: Request<Bytes>,
        remote_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Response<Full<Bytes>>> + Send>> {
        let router = self.router.clone();
        let upstreams = self.upstreams.clone();
        let observability = self.observability.clone();

        Box::pin(async move {
            let ctx = RequestContext::new().with_client_ip(remote_addr.ip().to_string());

            // Convert to ProxyBody
            let (parts, body) = request.into_parts();
            let proxy_req: HttpRequest = Request::from_parts(parts, ProxyBody::buffered(body));

            // Use existing request handling
            match handle_request_internal(proxy_req, ctx, router, upstreams, observability).await {
                Ok(resp) => resp,
                Err(_) => Response::builder()
                    .status(500)
                    .body(Full::new(Bytes::from("Internal Server Error")))
                    .unwrap(),
            }
        })
    }
}

/// Handle a single HTTP request
async fn handle_request(
    req: Request<Incoming>,
    ctx: RequestContext,
    router: Arc<ArcSwap<Router>>,
    upstreams: Arc<UpstreamManager>,
    observability: Arc<Observability>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let timer = Timer::start();
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let request_id = ctx.request_id.clone();
    let client_ip = ctx.client_ip.clone().unwrap_or_else(|| "-".to_string());

    debug!(
        request_id = %request_id,
        method = %method,
        path = %path,
        "Processing request"
    );

    // Build access log entry
    let log_builder = Arc::new(Mutex::new(
        AccessLogBuilder::new(request_id.clone(), client_ip.clone())
            .request(&method, &path, &format!("{:?}", req.version()))
            .user_agent(
                req.headers()
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok()),
            )
            .referer(req.headers().get("referer").and_then(|v| v.to_str().ok()))
            .host(req.headers().get("host").and_then(|v| v.to_str().ok())),
    ));

    // Route the request - we need a reference that doesn't move req
    let router = router.load();
    let resolved = router.resolve(&req);

    // Convert Request<Incoming> to Request<ProxyBody>
    let (parts, body) = req.into_parts();
    let proxy_req: HttpRequest = Request::from_parts(parts, ProxyBody::from(body));

    let response = match resolved {
        Some(route) => process_route(proxy_req, ctx, route, upstreams, log_builder.clone()).await,
        None => {
            debug!("No route found for {} {}", method, path);
            observability.metrics.record_error("no_route");
            create_error_response(StatusCode::NOT_FOUND, "Not Found")
        }
    };

    let status = response.status().as_u16();
    let duration = timer.elapsed();

    // Record metrics
    observability
        .metrics
        .record_request(&method, &path, status, duration);

    // Record SLO metrics
    observability.record_slo(&path, &method, status, duration.as_millis() as u64);

    // Log access
    {
        let log_builder = log_builder.lock();
        let log_entry = (*log_builder).clone().response(status, 0).build();
        observability.access_logger.log(&log_entry);
    }

    debug!(
        request_id = %request_id,
        status = status,
        duration_ms = duration.as_millis(),
        "Request completed"
    );

    Ok(response)
}

/// Handle a request with pre-buffered body (for HTTP/3)
#[cfg(feature = "http3")]
async fn handle_request_internal(
    req: HttpRequest,
    ctx: RequestContext,
    router: Arc<ArcSwap<Router>>,
    upstreams: Arc<UpstreamManager>,
    observability: Arc<Observability>,
) -> Result<Response<Full<Bytes>>> {
    let timer = Timer::start();
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let request_id = ctx.request_id.clone();
    let client_ip = ctx.client_ip.clone().unwrap_or_else(|| "-".to_string());

    debug!(
        request_id = %request_id,
        method = %method,
        path = %path,
        "Processing HTTP/3 request"
    );

    // Build access log entry
    let log_builder = Arc::new(Mutex::new(
        AccessLogBuilder::new(request_id.clone(), client_ip.clone())
            .request(&method, &path, "HTTP/3")
            .user_agent(
                req.headers()
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok()),
            )
            .referer(req.headers().get("referer").and_then(|v| v.to_str().ok()))
            .host(req.headers().get("host").and_then(|v| v.to_str().ok())),
    ));

    // Route the request
    let router = router.load();
    let resolved = router.resolve(&req);

    let response = match resolved {
        Some(route) => process_route(req, ctx, route, upstreams, log_builder.clone()).await,
        None => {
            debug!("No route found for {} {}", method, path);
            observability.metrics.record_error("no_route");
            create_error_response(StatusCode::NOT_FOUND, "Not Found")
        }
    };

    let status = response.status().as_u16();
    let duration = timer.elapsed();

    // Record metrics
    observability
        .metrics
        .record_request(&method, &path, status, duration);

    // Record SLO metrics
    observability.record_slo(&path, &method, status, duration.as_millis() as u64);

    // Log access
    {
        let log_builder = log_builder.lock();
        let log_entry = (*log_builder).clone().response(status, 0).build();
        observability.access_logger.log(&log_entry);
    }

    debug!(
        request_id = %request_id,
        status = status,
        duration_ms = duration.as_millis(),
        "HTTP/3 request completed"
    );

    Ok(response)
}

/// Process a resolved route
async fn process_route(
    req: HttpRequest,
    ctx: RequestContext,
    route: ResolvedRoute,
    upstreams: Arc<UpstreamManager>,
    log_builder: Arc<Mutex<AccessLogBuilder>>,
) -> Response<Full<Bytes>> {
    // Handle static response (no middleware needed)
    if let Some(handler) = &route.handler {
        return handle_static_response(handler);
    }

    // Check if we have route-level middleware
    if !route.middlewares.is_empty() {
        // Build middleware chain from route config
        let middlewares = match build_middleware_chain(&route.middlewares) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to build middleware chain: {}", e);
                return create_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Middleware configuration error",
                );
            }
        };

        // Buffer the request body first so middleware can inspect it
        let (parts, body) = req.into_parts();
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                error!("Failed to read request body: {}", e);
                return create_error_response(
                    StatusCode::BAD_REQUEST,
                    "Failed to read request body",
                );
            }
        };

        // Create request with buffered body for middleware
        let buffered_req: HttpRequest =
            Request::from_parts(parts, ProxyBody::buffered(body_bytes.clone()));

        // Create the final handler that forwards to upstream
        let final_handler = Arc::new(BufferedUpstreamHandler {
            upstreams: upstreams.clone(),
            route: route.clone(),
            log_builder: log_builder.clone(),
            body_bytes,
        });

        // Build and execute the middleware chain
        let chain = MiddlewareChain::new(middlewares, final_handler);

        match chain.execute(buffered_req, ctx).await {
            Ok(response) => response,
            Err(e) => {
                error!("Middleware chain error: {}", e);
                let error_resp = crate::error::ErrorResponse::from(&e);
                create_error_response(
                    StatusCode::from_u16(error_resp.status)
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    &error_resp.message,
                )
            }
        }
    } else {
        // No middleware, forward directly to upstream
        if let Some(upstream_name) = &route.upstream {
            return forward_to_upstream(req, ctx, upstream_name, &upstreams, &route, log_builder)
                .await;
        }
        create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "No handler configured")
    }
}

/// Handler that forwards requests to upstream with pre-buffered body
struct BufferedUpstreamHandler {
    upstreams: Arc<UpstreamManager>,
    route: ResolvedRoute,
    log_builder: Arc<Mutex<AccessLogBuilder>>,
    body_bytes: Bytes,
}

#[async_trait]
impl Handler for BufferedUpstreamHandler {
    async fn handle(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
    ) -> Result<Response<Full<Bytes>>> {
        if let Some(upstream_name) = &self.route.upstream {
            let response = forward_to_upstream_buffered(
                request,
                ctx,
                upstream_name,
                &self.upstreams,
                &self.route,
                self.log_builder.clone(),
                &self.body_bytes,
            )
            .await;
            Ok(response)
        } else {
            Ok(create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "No upstream configured",
            ))
        }
    }
}

/// Handle static response from handler config
fn handle_static_response(handler: &crate::config::HandlerConfig) -> Response<Full<Bytes>> {
    match handler.handler_type {
        HandlerType::Static => {
            let mut builder = Response::builder().status(handler.status);

            for (name, value) in &handler.headers {
                builder = builder.header(name.as_str(), value.as_str());
            }

            builder
                .body(Full::new(Bytes::from(handler.body.clone())))
                .unwrap()
        }
        HandlerType::Redirect => {
            let location = handler.redirect_url.as_deref().unwrap_or("/");
            Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", location)
                .body(Full::new(Bytes::new()))
                .unwrap()
        }
    }
}

/// Forward request to upstream (for routes without middleware)
async fn forward_to_upstream(
    req: HttpRequest,
    ctx: RequestContext,
    upstream_name: &str,
    upstreams: &UpstreamManager,
    route: &ResolvedRoute,
    log_builder: Arc<Mutex<AccessLogBuilder>>,
) -> Response<Full<Bytes>> {
    // Check if this is a gRPC request for appropriate error responses
    let is_grpc = is_grpc_request(&req) || is_grpc_web_request(&req);

    let upstream = match upstreams.get(upstream_name) {
        Some(u) => u,
        None => {
            error!("Upstream '{}' not found", upstream_name);
            if is_grpc {
                return create_grpc_trailers_only_response(
                    GrpcStatus::Unavailable,
                    "Upstream not found",
                );
            }
            return create_error_response(StatusCode::BAD_GATEWAY, "Upstream not found");
        }
    };

    // Select a server
    let server = match upstream.select_server() {
        Some(s) => s,
        None => {
            // Determine why server selection failed
            let reason = upstream.selection_failure_reason();
            match reason {
                SelectionFailureReason::CircuitOpen => {
                    warn!(
                        "Circuit breaker open for all servers in upstream '{}'",
                        upstream_name
                    );
                    if is_grpc {
                        return create_grpc_trailers_only_response(
                            GrpcStatus::Unavailable,
                            "Circuit breaker open",
                        );
                    }
                    return create_error_response_with_header(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Service Unavailable - Circuit Breaker Open",
                        "X-Circuit-Breaker",
                        "open",
                    );
                }
                SelectionFailureReason::AllUnhealthy => {
                    warn!("No healthy servers for upstream '{}'", upstream_name);
                    if is_grpc {
                        return create_grpc_trailers_only_response(
                            GrpcStatus::Unavailable,
                            "No healthy upstreams",
                        );
                    }
                    return create_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "No healthy upstreams",
                    );
                }
                SelectionFailureReason::NoServers => {
                    error!("No servers configured for upstream '{}'", upstream_name);
                    if is_grpc {
                        return create_grpc_trailers_only_response(
                            GrpcStatus::Unavailable,
                            "No servers configured",
                        );
                    }
                    return create_error_response(StatusCode::BAD_GATEWAY, "No servers configured");
                }
            }
        }
    };

    let server_addr = server.server.address;
    server.start_request();

    // Get connection from pool
    let timer = Timer::start();
    let mut pooled = match upstream.pool().get(server_addr).await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to get connection to {}: {}", server_addr, e);
            server.end_request(false);
            if is_grpc {
                return create_grpc_trailers_only_response(
                    GrpcStatus::Unavailable,
                    "Connection failed",
                );
            }
            return create_error_response(StatusCode::BAD_GATEWAY, "Connection failed");
        }
    };

    // Forward the request (gRPC and regular HTTP use same path - gRPC over HTTP/1.1)
    let result = forward_request(req, &mut pooled, route).await;

    let duration = timer.elapsed();
    {
        let mut builder = log_builder.lock();
        *builder = std::mem::replace(
            &mut *builder,
            AccessLogBuilder::new(
                ctx.request_id.clone(),
                ctx.client_ip.clone().unwrap_or_default(),
            ),
        )
        .upstream(upstream_name, &server_addr.to_string(), duration);
    }

    match result {
        Ok(response) => {
            server.end_request(true);
            response
        }
        Err(e) => {
            error!("Failed to forward request: {}", e);
            server.end_request(false);
            server.mark_unhealthy();
            if is_grpc {
                return create_grpc_trailers_only_response(
                    GrpcStatus::Internal,
                    "Upstream request failed",
                );
            }
            create_error_response(StatusCode::BAD_GATEWAY, "Upstream request failed")
        }
    }
}

/// Forward request to upstream with pre-buffered body (for routes with middleware)
async fn forward_to_upstream_buffered(
    req: HttpRequest,
    ctx: RequestContext,
    upstream_name: &str,
    upstreams: &UpstreamManager,
    route: &ResolvedRoute,
    log_builder: Arc<Mutex<AccessLogBuilder>>,
    body_bytes: &Bytes,
) -> Response<Full<Bytes>> {
    // Check if this is a gRPC request for appropriate error responses
    let is_grpc = is_grpc_request(&req) || is_grpc_web_request(&req);

    let upstream = match upstreams.get(upstream_name) {
        Some(u) => u,
        None => {
            error!("Upstream '{}' not found", upstream_name);
            if is_grpc {
                return create_grpc_trailers_only_response(
                    GrpcStatus::Unavailable,
                    "Upstream not found",
                );
            }
            return create_error_response(StatusCode::BAD_GATEWAY, "Upstream not found");
        }
    };

    // Select a server
    let server = match upstream.select_server() {
        Some(s) => s,
        None => {
            // Determine why server selection failed
            let reason = upstream.selection_failure_reason();
            match reason {
                SelectionFailureReason::CircuitOpen => {
                    warn!(
                        "Circuit breaker open for all servers in upstream '{}'",
                        upstream_name
                    );
                    if is_grpc {
                        return create_grpc_trailers_only_response(
                            GrpcStatus::Unavailable,
                            "Circuit breaker open",
                        );
                    }
                    return create_error_response_with_header(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Service Unavailable - Circuit Breaker Open",
                        "X-Circuit-Breaker",
                        "open",
                    );
                }
                SelectionFailureReason::AllUnhealthy => {
                    warn!("No healthy servers for upstream '{}'", upstream_name);
                    if is_grpc {
                        return create_grpc_trailers_only_response(
                            GrpcStatus::Unavailable,
                            "No healthy upstreams",
                        );
                    }
                    return create_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "No healthy upstreams",
                    );
                }
                SelectionFailureReason::NoServers => {
                    error!("No servers configured for upstream '{}'", upstream_name);
                    if is_grpc {
                        return create_grpc_trailers_only_response(
                            GrpcStatus::Unavailable,
                            "No servers configured",
                        );
                    }
                    return create_error_response(StatusCode::BAD_GATEWAY, "No servers configured");
                }
            }
        }
    };

    let server_addr = server.server.address;
    server.start_request();

    // Get connection from pool
    let timer = Timer::start();
    let mut pooled = match upstream.pool().get(server_addr).await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to get connection to {}: {}", server_addr, e);
            server.end_request(false);
            if is_grpc {
                return create_grpc_trailers_only_response(
                    GrpcStatus::Unavailable,
                    "Connection failed",
                );
            }
            return create_error_response(StatusCode::BAD_GATEWAY, "Connection failed");
        }
    };

    // Forward the request with buffered body
    let result = forward_request_buffered(req, &mut pooled, route, body_bytes).await;

    let duration = timer.elapsed();
    {
        let mut builder = log_builder.lock();
        *builder = std::mem::replace(
            &mut *builder,
            AccessLogBuilder::new(
                ctx.request_id.clone(),
                ctx.client_ip.clone().unwrap_or_default(),
            ),
        )
        .upstream(upstream_name, &server_addr.to_string(), duration);
    }

    match result {
        Ok(response) => {
            server.end_request(true);
            response
        }
        Err(e) => {
            error!("Failed to forward request: {}", e);
            server.end_request(false);
            server.mark_unhealthy();
            if is_grpc {
                return create_grpc_trailers_only_response(
                    GrpcStatus::Internal,
                    "Upstream request failed",
                );
            }
            create_error_response(StatusCode::BAD_GATEWAY, "Upstream request failed")
        }
    }
}

/// Forward request to upstream server
async fn forward_request(
    req: HttpRequest,
    pooled: &mut crate::upstream::PooledConnection,
    route: &ResolvedRoute,
) -> Result<Response<Full<Bytes>>> {
    // Get address before borrowing stream
    let host = pooled.address().to_string();

    let stream = pooled
        .stream()
        .ok_or_else(|| PrismError::Upstream("Connection stream not available".to_string()))?;

    // Build the forwarded request
    let mut path = req.uri().path().to_string();
    if let Some(query) = req.uri().query() {
        path.push('?');
        path.push_str(query);
    }

    // Apply rewrite if configured
    if let Some(rewrite) = &route.rewrite {
        path = rewrite.apply(&path);
    }

    // Build HTTP request to send upstream
    let request_line = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n",
        req.method(),
        path,
        host
    );

    // Forward headers
    let mut headers = String::new();
    for (name, value) in req.headers() {
        if name == "host" || name == "connection" {
            continue;
        }
        if let Ok(v) = value.to_str() {
            headers.push_str(&format!("{}: {}\r\n", name, v));
        }
    }
    headers.push_str("\r\n");

    // Write request
    stream.write_all(request_line.as_bytes()).await?;
    stream.write_all(headers.as_bytes()).await?;

    // Write body if present
    let body = req
        .collect()
        .await
        .map_err(|e| PrismError::Http(e.to_string()))?
        .to_bytes();

    if !body.is_empty() {
        stream.write_all(&body).await?;
    }

    // Read response
    let response = read_response(stream).await?;

    Ok(response)
}

/// Forward request to upstream server with pre-buffered body
async fn forward_request_buffered(
    req: HttpRequest,
    pooled: &mut crate::upstream::PooledConnection,
    route: &ResolvedRoute,
    body_bytes: &Bytes,
) -> Result<Response<Full<Bytes>>> {
    // Get address before borrowing stream
    let host = pooled.address().to_string();

    let stream = pooled
        .stream()
        .ok_or_else(|| PrismError::Upstream("Connection stream not available".to_string()))?;

    // Build the forwarded request
    let mut path = req.uri().path().to_string();
    if let Some(query) = req.uri().query() {
        path.push('?');
        path.push_str(query);
    }

    // Apply rewrite if configured
    if let Some(rewrite) = &route.rewrite {
        path = rewrite.apply(&path);
    }

    // Build HTTP request to send upstream
    let request_line = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n",
        req.method(),
        path,
        host
    );

    // Forward headers
    let mut headers = String::new();
    for (name, value) in req.headers() {
        if name == "host" || name == "connection" {
            continue;
        }
        if let Ok(v) = value.to_str() {
            headers.push_str(&format!("{}: {}\r\n", name, v));
        }
    }
    headers.push_str("\r\n");

    // Write request
    stream.write_all(request_line.as_bytes()).await?;
    stream.write_all(headers.as_bytes()).await?;

    // Write pre-buffered body
    if !body_bytes.is_empty() {
        stream.write_all(body_bytes).await?;
    }

    // Read response
    let response = read_response(stream).await?;

    Ok(response)
}

/// Read HTTP response from stream
async fn read_response(stream: &mut TcpStream) -> Result<Response<Full<Bytes>>> {
    use tokio::io::AsyncBufReadExt;
    use tokio::io::BufReader;

    let mut reader = BufReader::new(stream);

    // Read status line
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;

    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(PrismError::Http("Invalid response status line".to_string()));
    }

    let status_code: u16 = parts[1]
        .parse()
        .map_err(|_| PrismError::Http("Invalid status code".to_string()))?;

    // Read headers
    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;

    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        if line.trim().is_empty() {
            break;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_lowercase();
            let value = value.trim();

            if name == "content-length" {
                content_length = value.parse().ok();
            } else if name == "transfer-encoding" && value.to_lowercase().contains("chunked") {
                chunked = true;
            }

            headers.push((name, value.to_string()));
        }
    }

    // Read body
    let body = if let Some(len) = content_length {
        let mut body = vec![0u8; len];
        tokio::io::AsyncReadExt::read_exact(&mut reader, &mut body).await?;
        Bytes::from(body)
    } else if chunked {
        // Simplified chunked reading
        let mut body = Vec::new();
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line).await?;
            let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);

            if size == 0 {
                break;
            }

            let mut chunk = vec![0u8; size];
            tokio::io::AsyncReadExt::read_exact(&mut reader, &mut chunk).await?;
            body.extend(chunk);

            // Read trailing \r\n
            let mut _crlf = [0u8; 2];
            tokio::io::AsyncReadExt::read_exact(&mut reader, &mut _crlf).await?;
        }
        Bytes::from(body)
    } else {
        Bytes::new()
    };

    // Build response
    let mut builder = Response::builder().status(status_code);

    for (name, value) in headers {
        builder = builder.header(name, value);
    }

    builder
        .body(Full::new(body))
        .map_err(|e| PrismError::Http(e.to_string()))
}

/// Create an error response
fn create_error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(message.to_string())))
        .unwrap()
}

/// Create an error response with a custom header
fn create_error_response_with_header(
    status: StatusCode,
    message: &str,
    header_name: &str,
    header_value: &str,
) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .header(header_name, header_value)
        .body(Full::new(Bytes::from(message.to_string())))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_response() {
        let response = create_error_response(StatusCode::NOT_FOUND, "Not Found");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
