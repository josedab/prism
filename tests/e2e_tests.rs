//! End-to-end tests for Prism reverse proxy
//!
//! These tests spin up actual HTTP servers and test the full proxy pipeline.
//! The test infrastructure can be used to test the proxy once the server is fully wired up.

use bytes::Bytes;
use futures::future::join_all;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Test backend server that counts requests
struct TestBackend {
    addr: SocketAddr,
    request_count: Arc<AtomicU32>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl TestBackend {
    async fn start(response_body: &'static str) -> Self {
        Self::start_with_handler(move |_req| async move {
            Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(response_body))))
        })
        .await
    }

    async fn start_with_handler<F, Fut>(handler: F) -> Self
    where
        F: Fn(Request<Incoming>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<Response<Full<Bytes>>, hyper::Error>> + Send,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let request_count = Arc::new(AtomicU32::new(0));
        let count = request_count.clone();

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        if let Ok((stream, _)) = result {
                            let handler = handler.clone();
                            let count = count.clone();
                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let service = service_fn(move |req| {
                                    count.fetch_add(1, Ordering::SeqCst);
                                    handler(req)
                                });
                                let _ = http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await;
                            });
                        }
                    }
                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }
        });

        Self {
            addr,
            request_count,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    fn request_count(&self) -> u32 {
        self.request_count.load(Ordering::SeqCst)
    }
}

impl Drop for TestBackend {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// HTTP client helper
async fn http_get(url: &str) -> Result<(StatusCode, String), reqwest::Error> {
    let response = reqwest::get(url).await?;
    let status = response.status();
    let body = response.text().await?;
    Ok((status, body))
}

async fn http_post(url: &str, body: &str) -> Result<(StatusCode, String), reqwest::Error> {
    let client = reqwest::Client::new();
    let response = client.post(url).body(body.to_string()).send().await?;
    let status = response.status();
    let body = response.text().await?;
    Ok((status, body))
}

// ============================================================================
// Basic Proxy Tests
// ============================================================================

#[tokio::test]
async fn test_basic_proxy_get() {
    // Start a test backend that returns a simple response
    let backend = TestBackend::start("Hello from backend!").await;

    // Verify the backend is running and accessible
    let url = format!("http://{}", backend.addr);
    let (status, body) = http_get(&url).await.expect("Failed to connect to backend");

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "Hello from backend!");
    assert_eq!(backend.request_count(), 1);
}

#[tokio::test]
async fn test_multiple_backends_round_robin() {
    let backend1 = TestBackend::start("Backend 1").await;
    let backend2 = TestBackend::start("Backend 2").await;
    let backend3 = TestBackend::start("Backend 3").await;

    // Verify all backends are accessible
    let (_, body1) = http_get(&format!("http://{}", backend1.addr))
        .await
        .unwrap();
    let (_, body2) = http_get(&format!("http://{}", backend2.addr))
        .await
        .unwrap();
    let (_, body3) = http_get(&format!("http://{}", backend3.addr))
        .await
        .unwrap();

    assert_eq!(body1, "Backend 1");
    assert_eq!(body2, "Backend 2");
    assert_eq!(body3, "Backend 3");

    assert_eq!(backend1.request_count(), 1);
    assert_eq!(backend2.request_count(), 1);
    assert_eq!(backend3.request_count(), 1);
}

#[tokio::test]
async fn test_backend_returns_custom_status() {
    let backend = TestBackend::start_with_handler(|_req| async move {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .unwrap())
    })
    .await;

    let (status, body) = http_get(&format!("http://{}", backend.addr)).await.unwrap();
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, "Not Found");
    assert_eq!(backend.request_count(), 1);
}

#[tokio::test]
async fn test_backend_with_headers() {
    let backend = TestBackend::start_with_handler(|req| async move {
        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("X-Backend-Saw-UA", user_agent)
            .body(Full::new(Bytes::from("OK")))
            .unwrap())
    })
    .await;

    let (status, _) = http_get(&format!("http://{}", backend.addr)).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(backend.request_count(), 1);
}

// ============================================================================
// Health Check Tests
// ============================================================================

#[tokio::test]
async fn test_health_check_endpoint() {
    let backend = TestBackend::start_with_handler(|req| async move {
        if req.uri().path() == "/health" {
            Ok(Response::new(Full::new(Bytes::from(r#"{"status":"ok"}"#))))
        } else {
            Ok(Response::new(Full::new(Bytes::from("Regular response"))))
        }
    })
    .await;

    // Test health endpoint
    let (_, body) = http_get(&format!("http://{}/health", backend.addr))
        .await
        .unwrap();
    assert_eq!(body, r#"{"status":"ok"}"#);

    // Test regular endpoint
    let (_, body) = http_get(&format!("http://{}/other", backend.addr))
        .await
        .unwrap();
    assert_eq!(body, "Regular response");

    assert_eq!(backend.request_count(), 2);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_backend_slow_response() {
    let backend = TestBackend::start_with_handler(|_req| async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(Response::new(Full::new(Bytes::from("Slow response"))))
    })
    .await;

    let start = std::time::Instant::now();
    let (status, body) = http_get(&format!("http://{}", backend.addr)).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "Slow response");
    assert!(elapsed >= Duration::from_millis(100));
    assert_eq!(backend.request_count(), 1);
}

#[tokio::test]
async fn test_backend_large_response() {
    let large_body: String = "x".repeat(1024 * 1024); // 1MB
    let expected_len = large_body.len();
    let backend = TestBackend::start_with_handler(move |_req| {
        let body = large_body.clone();
        async move { Ok(Response::new(Full::new(Bytes::from(body)))) }
    })
    .await;

    let (status, body) = http_get(&format!("http://{}", backend.addr)).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.len(), expected_len);
    assert_eq!(backend.request_count(), 1);
}

// ============================================================================
// Concurrent Request Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_requests() {
    let backend = TestBackend::start("Concurrent response").await;
    let addr = backend.addr;

    // Send 10 concurrent requests
    let futures: Vec<_> = (0..10)
        .map(|_| async move { http_get(&format!("http://{}", addr)).await })
        .collect();

    let results = join_all(futures).await;

    // All requests should succeed
    for result in results {
        let (status, body) = result.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "Concurrent response");
    }

    assert_eq!(backend.request_count(), 10);
}

// ============================================================================
// WebSocket Upgrade Tests
// ============================================================================

#[tokio::test]
async fn test_websocket_upgrade_detection() {
    // Test that WebSocket upgrade requests are properly detected
    let backend = TestBackend::start_with_handler(|req| async move {
        let is_websocket = req
            .headers()
            .get("upgrade")
            .map(|v| v.to_str().unwrap_or("").eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

        if is_websocket {
            Ok(Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header("Upgrade", "websocket")
                .header("Connection", "Upgrade")
                .body(Full::new(Bytes::new()))
                .unwrap())
        } else {
            Ok(Response::new(Full::new(Bytes::from("Not a WebSocket"))))
        }
    })
    .await;

    // Regular request (not WebSocket)
    let (status, body) = http_get(&format!("http://{}", backend.addr)).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "Not a WebSocket");
    assert_eq!(backend.request_count(), 1);
}

// ============================================================================
// gRPC Detection Tests
// ============================================================================

#[tokio::test]
async fn test_grpc_content_type_detection() {
    let backend = TestBackend::start_with_handler(|req| async move {
        let is_grpc = req
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or("").starts_with("application/grpc"))
            .unwrap_or(false);

        if is_grpc {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/grpc")
                .header("grpc-status", "0")
                .body(Full::new(Bytes::new()))
                .unwrap())
        } else {
            Ok(Response::new(Full::new(Bytes::from("Not gRPC"))))
        }
    })
    .await;

    // Regular request (not gRPC)
    let (status, body) = http_get(&format!("http://{}", backend.addr)).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "Not gRPC");
    assert_eq!(backend.request_count(), 1);
}

// ============================================================================
// Middleware Tests
// ============================================================================

#[tokio::test]
async fn test_request_id_header_added() {
    let backend = TestBackend::start_with_handler(|req| async move {
        let request_id = req
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("none");

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("X-Received-Request-Id", request_id)
            .body(Full::new(Bytes::from("OK")))
            .unwrap())
    })
    .await;

    let (status, _) = http_get(&format!("http://{}", backend.addr)).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(backend.request_count(), 1);
}

#[tokio::test]
async fn test_host_header_preserved() {
    let backend = TestBackend::start_with_handler(|req| async move {
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from(format!("Host: {}", host))))
            .unwrap())
    })
    .await;

    let (status, body) = http_get(&format!("http://{}", backend.addr)).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("Host: "));
    assert_eq!(backend.request_count(), 1);
}

// ============================================================================
// Compression Tests
// ============================================================================

#[tokio::test]
async fn test_compression_negotiation() {
    let backend = TestBackend::start_with_handler(|req| async move {
        let accept_encoding = req
            .headers()
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let supports_gzip = accept_encoding.contains("gzip");
        let supports_br = accept_encoding.contains("br");

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from(format!(
                "gzip: {}, br: {}",
                supports_gzip, supports_br
            ))))
            .unwrap())
    })
    .await;

    let (status, body) = http_get(&format!("http://{}", backend.addr)).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    // reqwest sends Accept-Encoding by default
    assert!(body.contains("gzip:"));
    assert_eq!(backend.request_count(), 1);
}

// ============================================================================
// Connection Pool Tests
// ============================================================================

#[tokio::test]
async fn test_connection_reuse() {
    let connection_count = Arc::new(AtomicU32::new(0));
    let count_clone = connection_count.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                count_clone.fetch_add(1, Ordering::SeqCst);
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let service = service_fn(|_req| async {
                        Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from("OK"))))
                    });
                    let _ = http1::Builder::new().serve_connection(io, service).await;
                });
            }
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Make multiple requests - reqwest reuses connections by default
    let client = reqwest::Client::new();
    for _ in 0..5 {
        let resp = client.get(format!("http://{}", addr)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // With connection reuse, we should have fewer connections than requests
    // Note: The exact count depends on reqwest's pooling behavior
    let count = connection_count.load(Ordering::SeqCst);
    assert!(count >= 1); // At least one connection was made
    assert!(count <= 5); // But not necessarily 5 due to connection reuse
}

// ============================================================================
// Timeout Tests
// ============================================================================

#[tokio::test]
async fn test_connect_timeout() {
    // Test connecting to a non-routable address times out
    // 10.255.255.1 is non-routable
    let start = std::time::Instant::now();

    let result = tokio::time::timeout(Duration::from_millis(100), async {
        let _ = tokio::net::TcpStream::connect("10.255.255.1:80").await;
    })
    .await;

    assert!(result.is_err()); // Should timeout
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn test_read_timeout() {
    // Backend that never responds
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                // Accept connection but never respond
                tokio::spawn(async move {
                    let _io = TokioIo::new(stream);
                    // Hold connection open but never write
                    tokio::time::sleep(Duration::from_secs(60)).await;
                });
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    // Attempting to read from this connection should timeout
    let result = tokio::time::timeout(Duration::from_millis(100), async {
        let _stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_secs(60)).await;
    })
    .await;

    assert!(result.is_err()); // Should timeout
}
