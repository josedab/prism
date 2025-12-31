# Prism - High-Performance Reverse Proxy

## Project Overview

Prism is a high-performance, memory-safe reverse proxy written in Rust. It provides HTTP/1.1, HTTP/2, and gRPC proxying with features like load balancing, health checking, rate limiting, and distributed tracing.

## Project Structure

```
src/
├── main.rs           # CLI entry point
├── lib.rs            # Library exports
├── config/           # Configuration loading & validation
│   ├── mod.rs        # Config module exports
│   ├── types.rs      # Config type definitions (YAML/TOML schema)
│   ├── validation.rs # Config validation logic
│   └── env.rs        # Environment variable expansion
├── server/           # HTTP server & request handling
│   ├── mod.rs        # Server initialization
│   ├── handler.rs    # Request handler (routing, proxying)
│   ├── reload.rs     # Hot configuration reload
│   └── shutdown.rs   # Graceful shutdown with connection draining
├── router/           # Request routing
│   ├── mod.rs        # Router implementation
│   ├── matcher.rs    # Path & host matching logic
│   └── traffic_split.rs # Traffic splitting (canary, blue-green)
├── upstream/         # Backend server management
│   ├── mod.rs        # Upstream manager, server state
│   ├── balancer.rs   # Load balancing algorithms
│   ├── health.rs     # Active & passive health checking
│   └── pool.rs       # Connection pooling
├── middleware/       # Request/response middleware
│   ├── mod.rs        # Middleware chain, types
│   ├── auth.rs       # JWT, API Key, Basic auth
│   ├── rate_limit.rs # Token bucket rate limiting
│   ├── compression.rs# Gzip/Brotli compression
│   ├── cors.rs       # CORS handling
│   ├── cache.rs      # Response caching
│   └── ...           # Other middleware
├── grpc/             # gRPC proxy support
│   ├── mod.rs        # gRPC types, detection, status codes
│   └── proxy.rs      # gRPC proxying implementation
├── observability/    # Metrics, logging, tracing
│   ├── mod.rs        # Observability context
│   ├── metrics.rs    # Prometheus metrics
│   ├── logging.rs    # Access logging
│   └── tracing.rs    # OpenTelemetry distributed tracing
├── listener/         # Connection handling
│   ├── mod.rs        # Listener manager
│   └── tls.rs        # TLS termination (rustls)
├── websocket/        # WebSocket upgrade handling
├── admin/            # Admin API endpoints
└── error.rs          # Error types (PrismError, Result)
```

## Key Technologies

- **Async Runtime**: Tokio
- **HTTP Stack**: Hyper 1.x, http-body-util
- **TLS**: rustls (memory-safe TLS)
- **Configuration**: serde, serde_yaml, toml
- **Metrics**: Prometheus
- **Tracing**: tracing crate, optional OpenTelemetry
- **Compression**: flate2 (gzip), brotli

## Common Development Tasks

### Building

```bash
# Standard build
cargo build

# With OpenTelemetry support
cargo build --features opentelemetry

# Release build
cargo build --release
```

### Testing

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test

# Run specific test
cargo test test_router_
```

### Running

```bash
# Run with config file
cargo run -- --config prism.yaml

# Run with hot reload enabled
cargo run -- --config prism.yaml --watch
```

## Feature Flags

- `default` - Core functionality
- `opentelemetry` - Enable distributed tracing with OpenTelemetry
- `distributed-rate-limit` - Redis-based distributed rate limiting
- `http3` - Future HTTP/3 support (placeholder)

## Configuration

Configuration is YAML/TOML based. Key sections:

- `listeners` - Bind addresses, TLS config, protocols
- `upstreams` - Backend servers, health checks, load balancing
- `routes` - Path/host matching, middleware, upstream targets
- `observability` - Metrics, tracing, access logging
- `admin` - Admin API configuration

## Code Patterns

### Error Handling

Uses `thiserror` for error definitions:
```rust
use crate::error::{PrismError, Result};
```

### Middleware

Implements `Middleware` trait with async handling:
```rust
#[async_trait]
impl Middleware for MyMiddleware {
    async fn handle(&self, request: HttpRequest, ctx: RequestContext, next: Next<'_>) -> Result<Response<Full<Bytes>>> {
        // Pre-processing
        let response = next.run(request, ctx).await?;
        // Post-processing
        Ok(response)
    }
}
```

### Configuration Types

All config types derive serde traits and have defaults:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MyConfig {
    #[serde(default = "default_value")]
    pub field: Type,
}
```

## Important Files

- `src/config/types.rs` - All configuration type definitions
- `src/server/handler.rs` - Main request handling logic
- `src/middleware/mod.rs` - Middleware chain and types
- `src/upstream/mod.rs` - Upstream management
- `Cargo.toml` - Dependencies and features

## Testing Guidelines

- Unit tests are in `#[cfg(test)] mod tests { }` blocks
- Integration tests are in `tests/`
- Use `tokio::test` for async tests
- Mock external dependencies where possible

## Notes for Development

1. **Body Types**: The `ProxyBody` enum handles both streaming (`Incoming`) and buffered (`Full<Bytes>`) request bodies for middleware compatibility.

2. **gRPC Detection**: Check `Content-Type: application/grpc` to detect gRPC requests and return appropriate gRPC status codes on errors.

3. **Circuit Breaker**: Integrated with server selection - check `selection_failure_reason()` to distinguish between circuit open and health check failures.

4. **Hot Reload**: Config changes are watched via `notify` crate. Listeners cannot be changed at runtime without restart.

5. **Feature Gating**: Use `#[cfg(feature = "opentelemetry")]` for optional OpenTelemetry code to avoid pulling in dependencies when not needed.
