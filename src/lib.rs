//! Prism - High-Performance Reverse Proxy
//!
//! A memory-safe reverse proxy written in Rust, providing:
//!
//! - **Memory Safety**: Zero buffer overflow vulnerabilities by design
//! - **High Performance**: Tokio async runtime with zero-copy where possible
//! - **Modern Protocols**: Native HTTP/1.1, HTTP/2 support (HTTP/3 planned)
//! - **TLS**: rustls for memory-safe TLS termination
//! - **Configuration**: Human-readable YAML/TOML with live reload
//! - **Observability**: Built-in Prometheus metrics and structured logging
//!
//! # Quick Start
//!
//! ```no_run
//! use prism::{Config, Server};
//!
//! #[tokio::main]
//! async fn main() -> prism::Result<()> {
//!     let config = prism::config::load_config("prism.yaml")?;
//!     let server = Server::new(config).await?;
//!     server.run().await
//! }
//! ```
//!
//! # Configuration
//!
//! Prism is configured via YAML or TOML files:
//!
//! ```yaml
//! listeners:
//!   - address: "0.0.0.0:8080"
//!     protocol: http
//!
//! upstreams:
//!   backend:
//!     servers:
//!       - address: "127.0.0.1:3000"
//!
//! routes:
//!   - match:
//!       path_prefix: "/"
//!     upstream: backend
//! ```

// Core modules (always available)
pub mod admin;
pub mod config;
pub mod error;
pub mod grpc;
pub mod listener;
pub mod middleware;
pub mod observability;
pub mod router;
pub mod server;
pub mod upstream;
pub mod websocket;

/// Layer 4 (TCP/UDP) proxying for databases and non-HTTP services
pub mod l4;

// Feature-gated modules

/// Edge computing / Cloudflare Workers-style functions
#[cfg(feature = "edge")]
pub mod edge;

/// io_uring high-performance async I/O (Linux 5.1+ only)
#[cfg(all(target_os = "linux", feature = "io_uring"))]
pub mod io_uring;

/// Kubernetes Gateway API support
#[cfg(feature = "kubernetes")]
pub mod k8s;

/// WebAssembly plugin system
#[cfg(feature = "plugins")]
pub mod plugin;

/// SPIFFE/SPIRE zero-trust identity
#[cfg(feature = "spiffe")]
pub mod spiffe;

/// Interactive TUI dashboard
#[cfg(feature = "tui")]
pub mod tui;

/// Envoy xDS API compatibility
#[cfg(feature = "xds")]
pub mod xds;

// Next-Gen Features (Phase 2)

/// Chaos engineering and fault injection
pub mod chaos;

/// Adaptive circuit breaker with ML-based thresholds
pub mod circuit_breaker_v2;

/// Request coalescing for deduplication
pub mod coalescing;

/// Adaptive compression with algorithm selection
pub mod compression;

/// Distributed edge caching
pub mod edge_cache;

/// GraphQL federation gateway
pub mod federation;

/// Geographic and latency-based routing
pub mod georouting;

/// Machine learning features (smart LB, classification, prediction)
pub mod ml;

/// QUIC connection migration
pub mod migration;

/// OpenAPI schema validation
pub mod openapi;

/// Raft consensus for distributed state
pub mod raft;

/// Request recording and replay
pub mod replay;

/// Traffic shadowing/mirroring
pub mod shadowing;

/// Request/response transformation engine
pub mod transform;

/// API versioning strategies
pub mod versioning;

/// WebTransport over HTTP/3
pub mod webtransport;

/// Zero-copy proxying with splice/sendfile
#[cfg(target_os = "linux")]
pub mod zerocopy;

pub use config::Config;
pub use error::{PrismError, Result};
pub use server::Server;

/// Prism version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Prism name
pub const NAME: &str = env!("CARGO_PKG_NAME");
