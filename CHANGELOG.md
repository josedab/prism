# Changelog

All notable changes to Prism will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Property-based testing with proptest
- Fuzzing infrastructure for security testing
- Shell completions for bash, zsh, and fish
- JSON Schema for configuration validation
- Load testing scripts (k6, wrk, vegeta)
- Pre-commit hooks configuration
- Systemd service file for production deployment

### Changed
- Improved E2E test coverage with real HTTP requests

### Fixed
- Version resolution returning correct matched version

## [1.0.0] - 2024-01-15

### Added

#### Core Features
- High-performance HTTP/1.1 and HTTP/2 reverse proxy
- TLS termination with rustls (memory-safe TLS)
- Hot configuration reload without restart
- Graceful shutdown with connection draining

#### Load Balancing
- Round-robin load balancing
- Weighted load balancing
- Least connections algorithm
- Consistent hashing for session affinity
- Random selection

#### Health Checking
- Active health checks with configurable intervals
- Passive health monitoring
- Circuit breaker pattern (closed/open/half-open states)
- Automatic backend recovery

#### Routing
- Path-based routing (exact, prefix, regex)
- Host-based routing
- Method-based routing
- Header-based routing
- Query parameter routing
- Traffic splitting for canary deployments

#### Middleware
- JWT authentication
- API key authentication
- Basic authentication
- Rate limiting (token bucket algorithm)
- Response caching
- Gzip/Brotli/Zstd compression
- CORS handling
- Request/response header manipulation
- Request ID injection

#### Observability
- Prometheus metrics endpoint
- Structured JSON logging
- Access logging with customizable format
- OpenTelemetry distributed tracing (optional)
- Admin API for runtime inspection

#### Protocol Support
- HTTP/1.1 with keep-alive
- HTTP/2 with multiplexing
- gRPC proxying with proper status codes
- WebSocket upgrade handling

#### Deployment
- Docker image with multi-stage build
- Kubernetes manifests
- Helm chart
- Grafana dashboards
- Prometheus alerting rules

### Next-Gen Features (Experimental)

#### Advanced Load Balancing
- ML-based predictive load balancing
- Adaptive algorithms using request latency

#### Resilience
- Chaos engineering fault injection
- Request replay and traffic mirroring
- Live traffic migration between upstreams

#### Caching & Performance
- Distributed edge caching with TTL
- Request coalescing for duplicate requests
- Response streaming optimization

#### Routing & Discovery
- Geographic routing with latency-based selection
- API versioning with compatibility matching
- Service discovery integration

#### Security
- Automatic certificate management (ACME)
- mTLS for service mesh
- Request/response transformation

#### Protocols
- GraphQL federation gateway
- WebTransport support (experimental)
- gRPC-Web transcoding

#### Operations
- Raft consensus for distributed state
- OpenAPI schema extraction
- Configuration versioning and rollback

## [0.9.0] - 2024-01-01

### Added
- Initial beta release
- Core proxy functionality
- Basic load balancing
- Health checking
- TLS support

### Known Issues
- HTTP/3 support not yet implemented
- eBPF features require Linux kernel 4.9+

---

## Version Support

| Version | Status | Support Until |
|---------|--------|---------------|
| 1.x     | Active | Current       |
| 0.x     | EOL    | 2024-03-01    |

## Upgrade Guide

### From 0.x to 1.0

1. **Configuration format**: The `match` field in routes has been renamed to `match_config`
2. **Middleware order**: Middleware now executes in definition order
3. **Metrics names**: Some Prometheus metrics have been renamed for consistency

```yaml
# Old (0.x)
routes:
  - match:
      path_prefix: "/"

# New (1.0)
routes:
  - match_config:
      path_prefix: "/"
```

[Unreleased]: https://github.com/your-org/prism/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/your-org/prism/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/your-org/prism/releases/tag/v0.9.0
