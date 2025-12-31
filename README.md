# Prism

A high-performance, memory-safe reverse proxy written in Rust.

## Features

### Core Features

- **Memory Safety**: Zero buffer overflow vulnerabilities by design using Rust
- **High Performance**: Tokio async runtime with efficient connection pooling
- **TLS**: Memory-safe TLS termination with rustls
- **Modern Protocols**: HTTP/1.1 and HTTP/2 support
- **Load Balancing**: Round robin, least connections, weighted, consistent hash
- **Health Checking**: Active HTTP/TCP health checks with configurable thresholds
- **Configuration**: Human-readable YAML/TOML with hot reload support
- **Observability**: Prometheus metrics, structured JSON access logs, OpenTelemetry tracing
- **Middleware**: Rate limiting, header manipulation, timeouts, compression, caching
- **gRPC Proxy**: Full gRPC/gRPC-Web proxying with proper status code handling
- **WebSocket**: Full WebSocket upgrade and proxying support

### Next-Gen Features (Optional)

Enable with feature flags for production-grade capabilities:

| Feature | Flag | Description |
|---------|------|-------------|
| **HTTP/3** | `http3` | QUIC-based HTTP/3 for reduced latency |
| **io_uring** | `io_uring` | Linux 5.1+ async I/O for maximum throughput |
| **SPIFFE/SPIRE** | `spiffe` | Zero-trust workload identity and mTLS |
| **xDS API** | `xds` | Envoy-compatible control plane integration |
| **Kubernetes** | `kubernetes` | Native Gateway API controller |
| **Edge Compute** | `edge` | Cloudflare Workers-style WASM functions |
| **WASM Plugins** | `plugins` | Extensible plugin system with WebAssembly |
| **Anomaly Detection** | `anomaly-detection` | AI-powered traffic anomaly detection |
| **eBPF** | `ebpf` | Kernel-level observability (Linux 4.9+) |
| **GraphQL** | `graphql` | GraphQL-aware routing and authorization |
| **TUI Dashboard** | `tui` | Interactive terminal dashboard |

### Feature Bundles

```bash
# Enterprise features (zero-trust, service mesh)
cargo build --release --features enterprise

# Edge compute features (WASM functions, plugins)
cargo build --release --features edge-compute

# All features
cargo build --release --features full
```

## Quick Start

### Installation

```bash
cargo build --release
```

### Configuration

Create a `prism.yaml` configuration file:

```yaml
listeners:
  - address: "0.0.0.0:8080"
    protocol: http

upstreams:
  backend:
    servers:
      - address: "127.0.0.1:3000"
    load_balancing: round_robin
    health_check:
      path: /health
      interval: 10s

routes:
  - match:
      path_prefix: "/"
    upstream: backend
```

### Running

```bash
# Start the server
./target/release/prism --config prism.yaml

# Validate configuration
./target/release/prism validate --config prism.yaml

# Show parsed configuration
./target/release/prism config --config prism.yaml
```

## Configuration Reference

### Listeners

```yaml
listeners:
  - address: "0.0.0.0:443"
    protocol: https
    max_connections: 10000
    tls:
      cert: /path/to/cert.pem
      key: /path/to/key.pem
      alpn: ["h2", "http/1.1"]
```

### Upstreams

```yaml
upstreams:
  my_backend:
    servers:
      - address: "10.0.0.1:8080"
        weight: 5
      - address: "10.0.0.2:8080"
        weight: 3
    load_balancing: least_connections
    health_check:
      check_type: http
      path: /health
      interval: 10s
      timeout: 5s
      unhealthy_threshold: 3
      healthy_threshold: 2
    pool:
      max_connections: 100
      idle_timeout: 60s
```

#### Load Balancing Algorithms

- `round_robin` - Distribute requests evenly
- `least_connections` - Route to server with fewest active connections
- `random` - Random server selection
- `weighted` - Weighted distribution based on server weights
- `ip_hash` - Consistent routing based on client IP
- `consistent_hash` - Consistent hashing for session affinity

### Routes

```yaml
routes:
  - match:
      host: "api.example.com"
      path_prefix: "/v1"
      methods: ["GET", "POST"]
      headers:
        X-Api-Version: "1"
    upstream: api_backend
    middlewares:
      - rate_limit:
          requests_per_second: 100
          burst: 50
    rewrite:
      pattern: "^/v1"
      replacement: ""
    priority: 0
```

### Middlewares

```yaml
middlewares:
  - rate_limit:
      requests_per_second: 100
      burst: 50
      key_by: ip  # ip, header, or global

  - headers:
      request_add:
        X-Forwarded-Proto: "https"
      response_add:
        X-Content-Type-Options: "nosniff"
      request_remove:
        - "X-Internal-Header"

  - timeout:
      connect: 5s
      read: 30s
      write: 30s
```

### Observability

```yaml
observability:
  metrics:
    enabled: true
    path: /metrics
  access_log:
    enabled: true
    format: json  # json, combined, or common
    path: /var/log/prism/access.log
```

## CLI Commands

```bash
# Run the server
prism run --config prism.yaml

# Validate configuration
prism validate --config prism.yaml

# Show configuration
prism config --config prism.yaml

# Check health (requires admin API)
prism health --address http://127.0.0.1:9090
```

## Metrics

Prism exposes Prometheus metrics at the configured metrics path:

- `prism_requests_total` - Total requests by method, route, status
- `prism_request_duration_seconds` - Request duration histogram
- `prism_active_connections` - Current active connections
- `prism_upstream_requests_total` - Upstream requests by server
- `prism_upstream_health` - Upstream health status (1=healthy, 0=unhealthy)

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                  Prism                                   │
├─────────────────────────────────────────────────────────────────────────┤
│  Transport Layer                                                         │
│  ├── HTTP/1.1 & HTTP/2 (hyper + rustls TLS)                             │
│  ├── [http3] HTTP/3 with QUIC (quinn)                                   │
│  └── [io_uring] High-performance async I/O (Linux 5.1+)                 │
├─────────────────────────────────────────────────────────────────────────┤
│  Identity & Security                                                     │
│  ├── [spiffe] Zero-trust workload identity                              │
│  └── mTLS, JWT, API Key authentication                                  │
├─────────────────────────────────────────────────────────────────────────┤
│  Control Plane Integration                                               │
│  ├── [xds] Envoy xDS API (Istio, Consul Connect compatible)             │
│  └── [kubernetes] Gateway API controller                                │
├─────────────────────────────────────────────────────────────────────────┤
│  Request Processing                                                      │
│  ├── Router Engine (host/path/header/GraphQL matching)                  │
│  ├── Middleware Chain (rate limit, auth, compression, cache)            │
│  ├── [edge] Edge compute functions (WASM)                               │
│  └── [plugins] Extensible WASM plugins                                  │
├─────────────────────────────────────────────────────────────────────────┤
│  Upstream Management                                                     │
│  ├── Connection Pool with circuit breaker                               │
│  ├── Active & passive health checking                                   │
│  └── Load Balancing (round robin, least conn, consistent hash, P2C)    │
├─────────────────────────────────────────────────────────────────────────┤
│  Observability                                                           │
│  ├── Prometheus metrics                                                  │
│  ├── OpenTelemetry distributed tracing                                  │
│  ├── [anomaly-detection] AI traffic analysis                            │
│  └── [ebpf] Kernel-level observability (Linux)                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Example Configurations

```bash
# Basic reverse proxy
cargo run -- --config examples/basic.yaml

# High-performance with io_uring (Linux)
cargo run --features io_uring -- --config examples/high-performance.yaml

# Enterprise zero-trust setup
cargo run --features enterprise -- --config examples/enterprise.yaml

# Edge compute with WASM functions
cargo run --features edge-compute -- --config examples/edge-compute.yaml

# Full-featured deployment
cargo run --features full -- --config examples/full-featured.yaml
```

See the `examples/` directory for complete configuration samples.

## License

MIT
