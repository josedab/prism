# Prism Architecture

## Overview

Prism is a high-performance, memory-safe reverse proxy written in Rust. This document describes its internal architecture and design decisions.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Clients                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Listeners                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   HTTP/1.1   │  │   HTTP/2     │  │   HTTP/3     │          │
│  │   Listener   │  │   Listener   │  │   Listener   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                      (TLS Termination via rustls)               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Request Handler                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   Middleware Chain                        │   │
│  │  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  │   │
│  │  │Auth │→ │Rate │→ │CORS │→ │Cache│→ │Comp │→ │Log  │  │   │
│  │  │     │  │Limit│  │     │  │     │  │ress │  │     │  │   │
│  │  └─────┘  └─────┘  └─────┘  └─────┘  └─────┘  └─────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Router                                    │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  Path Matcher   │  │  Host Matcher   │  │ Method Matcher  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                    Traffic Splitting                             │
│               (Canary, Blue-Green, A/B)                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Upstream Manager                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                  Load Balancer                            │  │
│  │  Round Robin │ Least Conn │ Weighted │ Consistent Hash   │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Health Checker                               │  │
│  │         Active Probes │ Passive Detection                │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Circuit Breaker                              │  │
│  │         Closed │ Open │ Half-Open States                 │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Connection Pool                              │  │
│  │    Keep-Alive │ Connection Reuse │ Pool Sizing           │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Backend Servers                              │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Listeners (`src/listener/`)

Handles incoming connections:

- **HTTP/1.1**: Standard HTTP with connection keep-alive
- **HTTP/2**: Multiplexed streams over single connection
- **HTTP/3**: QUIC-based transport (optional feature)
- **TLS**: rustls for memory-safe TLS termination

```rust
pub struct Listener {
    address: SocketAddr,
    protocol: Protocol,
    tls_config: Option<TlsConfig>,
}
```

### 2. Router (`src/router/`)

Matches requests to upstream targets:

- **Path Matchers**: Exact, prefix, regex patterns
- **Host Matchers**: Domain-based routing
- **Method Matchers**: HTTP method filtering
- **Traffic Splitting**: Canary, blue-green deployments

```rust
pub struct Router {
    routes: Vec<Route>,
    default_upstream: Option<String>,
}

pub struct Route {
    matchers: Vec<Matcher>,
    upstream: String,
    middlewares: Vec<MiddlewareRef>,
    traffic_split: Option<TrafficSplit>,
}
```

### 3. Middleware Chain (`src/middleware/`)

Extensible request/response processing:

```rust
#[async_trait]
pub trait Middleware: Send + Sync {
    async fn handle(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: Next<'_>,
    ) -> Result<Response<Full<Bytes>>>;
}
```

Built-in middleware:
- **Authentication**: JWT, API Key, Basic Auth
- **Rate Limiting**: Token bucket with Redis support
- **Caching**: Response caching with cache-control
- **Compression**: Gzip, Brotli, Zstd
- **CORS**: Cross-origin resource sharing
- **Logging**: Structured access logging

### 4. Upstream Manager (`src/upstream/`)

Manages backend server pools:

```rust
pub struct UpstreamManager {
    upstreams: DashMap<String, Upstream>,
}

pub struct Upstream {
    servers: Vec<Server>,
    load_balancer: Box<dyn LoadBalancer>,
    health_checker: HealthChecker,
    circuit_breaker: Option<CircuitBreaker>,
    connection_pool: ConnectionPool,
}
```

#### Load Balancing Algorithms

| Algorithm | Use Case |
|-----------|----------|
| Round Robin | Even distribution |
| Weighted | Heterogeneous servers |
| Least Connections | Long-lived connections |
| Consistent Hash | Session affinity |
| Random | Simple, no state |

### 5. Observability (`src/observability/`)

- **Metrics**: Prometheus format
- **Tracing**: OpenTelemetry integration
- **Logging**: Structured JSON logging

```rust
pub struct ObservabilityContext {
    metrics: PrometheusMetrics,
    tracer: Option<OpenTelemetryTracer>,
    access_logger: AccessLogger,
}
```

## Request Flow

```
1. Connection accepted by Listener
2. TLS handshake (if HTTPS)
3. HTTP parsing (hyper)
4. Request enters Handler
5. Middleware chain executes (pre-processing)
6. Router matches request to upstream
7. Load balancer selects server
8. Circuit breaker check
9. Connection from pool or new connection
10. Request forwarded to backend
11. Response received
12. Middleware chain executes (post-processing)
13. Response sent to client
```

## Concurrency Model

Prism uses Tokio's async runtime:

- **Multi-threaded**: Utilizes all CPU cores
- **Work-stealing**: Balanced task distribution
- **Cooperative scheduling**: No blocking in async code
- **Zero-copy where possible**: Efficient memory usage

```rust
#[tokio::main]
async fn main() {
    // Default: num_cpus threads
    let server = Server::new(config).await?;
    server.run().await
}
```

## Memory Safety

Rust's ownership system guarantees:

- **No buffer overflows**: Bounds checking at compile time
- **No use-after-free**: Lifetime tracking
- **No data races**: Ownership + borrowing rules
- **No null pointers**: Option<T> for optional values

## Configuration Hot Reload

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Config File  │────▶│   Watcher    │────▶│   Validator  │
└──────────────┘     └──────────────┘     └──────────────┘
                                                  │
                                                  ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Apply      │◀────│   Diff       │◀────│  New Config  │
└──────────────┘     └──────────────┘     └──────────────┘
```

Supports:
- Route changes
- Upstream changes
- Middleware configuration
- Does NOT support: Listener changes (requires restart)

## Performance Considerations

1. **Connection Pooling**: Reuse backend connections
2. **Response Caching**: Reduce backend load
3. **Compression**: Negotiate optimal algorithm
4. **Zero-Copy**: Minimize memory copying
5. **Lock-Free Structures**: DashMap for concurrent access

## Extension Points

### Custom Middleware

```rust
pub struct MyMiddleware { /* ... */ }

#[async_trait]
impl Middleware for MyMiddleware {
    async fn handle(&self, req: HttpRequest, ctx: RequestContext, next: Next<'_>)
        -> Result<Response<Full<Bytes>>> {
        // Pre-processing
        let response = next.run(req, ctx).await?;
        // Post-processing
        Ok(response)
    }
}
```

### Custom Load Balancer

```rust
pub struct MyBalancer { /* ... */ }

impl LoadBalancer for MyBalancer {
    fn select(&self, servers: &[Server], request: &Request) -> Option<&Server> {
        // Custom selection logic
    }
}
```

## Feature Modules

### Next-Gen Features (Phase 2)

| Module | Description |
|--------|-------------|
| `ml` | Smart load balancing, prediction |
| `chaos` | Fault injection testing |
| `federation` | GraphQL federation |
| `georouting` | Geographic routing |
| `edge_cache` | Distributed caching |
| `raft` | Consensus for state |
| `transform` | Request/response transformation |

## Security Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Client                            │
└─────────────────────────────────────────────────────┘
                        │
                        ▼ TLS 1.3
┌─────────────────────────────────────────────────────┐
│                Rate Limiting                         │
│            (Token Bucket / Redis)                    │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│              Authentication                          │
│         (JWT / API Key / mTLS)                      │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│              Authorization                           │
│            (Route-level ACL)                        │
└─────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│                 Backend                              │
│              (mTLS optional)                        │
└─────────────────────────────────────────────────────┘
```
