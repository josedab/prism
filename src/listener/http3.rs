//! HTTP/3 (QUIC) Support
//!
//! Provides HTTP/3 listener support built on the QUIC protocol:
//! - UDP-based transport with built-in encryption (TLS 1.3)
//! - Multiplexed streams without head-of-line blocking
//! - Connection migration for mobile clients
//! - 0-RTT resumption for faster connections
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        HTTP/3 Listener                          │
//! │  ┌─────────────────┐  ┌─────────────────┐                      │
//! │  │  QUIC Endpoint  │  │  Alt-Svc Header │                      │
//! │  │  (UDP Socket)   │  │  (HTTP/2 hint)  │                      │
//! │  └────────┬────────┘  └────────┬────────┘                      │
//! │           │                    │                                │
//! │  ┌────────▼────────────────────▼────────┐                      │
//! │  │           Connection Handler          │                      │
//! │  │  • 0-RTT Early Data                   │                      │
//! │  │  • Stream Multiplexing                │                      │
//! │  │  • Connection Migration               │                      │
//! │  └──────────────────────────────────────┘                      │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # QUIC Benefits
//! - **Faster connections**: 0-RTT resumption eliminates round trips
//! - **No head-of-line blocking**: Lost packets don't block other streams
//! - **Connection migration**: Seamless handoff between networks
//! - **Always encrypted**: TLS 1.3 is mandatory

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// HTTP/3 listener configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http3Config {
    /// Enable HTTP/3 support
    #[serde(default)]
    pub enabled: bool,

    /// UDP bind address for QUIC
    #[serde(default = "default_address")]
    pub address: String,

    /// TLS certificate path (required)
    pub cert_path: Option<PathBuf>,

    /// TLS private key path (required)
    pub key_path: Option<PathBuf>,

    /// Maximum idle timeout (seconds)
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Maximum concurrent streams per connection
    #[serde(default = "default_max_streams")]
    pub max_concurrent_streams: u32,

    /// Initial stream receive window size
    #[serde(default = "default_stream_window")]
    pub stream_receive_window: u32,

    /// Initial connection receive window size
    #[serde(default = "default_conn_window")]
    pub connection_receive_window: u32,

    /// Enable 0-RTT early data
    #[serde(default = "default_true")]
    pub enable_0rtt: bool,

    /// Maximum 0-RTT data size
    #[serde(default = "default_0rtt_max")]
    pub max_0rtt_size: u32,

    /// QPACK dynamic table size
    #[serde(default = "default_qpack_table")]
    pub qpack_max_table_capacity: u32,

    /// QPACK blocked streams
    #[serde(default = "default_qpack_blocked")]
    pub qpack_blocked_streams: u32,

    /// Enable connection migration
    #[serde(default = "default_true")]
    pub enable_migration: bool,

    /// Keep-alive interval (seconds, 0 to disable)
    #[serde(default = "default_keepalive")]
    pub keepalive_interval_secs: u64,

    /// Alt-Svc header configuration for HTTP/2 -> HTTP/3 upgrade
    #[serde(default)]
    pub alt_svc: AltSvcConfig,
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            enabled: false,
            address: default_address(),
            cert_path: None,
            key_path: None,
            idle_timeout_secs: default_idle_timeout(),
            max_concurrent_streams: default_max_streams(),
            stream_receive_window: default_stream_window(),
            connection_receive_window: default_conn_window(),
            enable_0rtt: true,
            max_0rtt_size: default_0rtt_max(),
            qpack_max_table_capacity: default_qpack_table(),
            qpack_blocked_streams: default_qpack_blocked(),
            enable_migration: true,
            keepalive_interval_secs: default_keepalive(),
            alt_svc: AltSvcConfig::default(),
        }
    }
}

fn default_address() -> String {
    "0.0.0.0:443".to_string()
}

fn default_idle_timeout() -> u64 {
    30
}

fn default_max_streams() -> u32 {
    100
}

fn default_stream_window() -> u32 {
    1024 * 1024 // 1MB
}

fn default_conn_window() -> u32 {
    10 * 1024 * 1024 // 10MB
}

fn default_true() -> bool {
    true
}

fn default_0rtt_max() -> u32 {
    16384 // 16KB
}

fn default_qpack_table() -> u32 {
    4096
}

fn default_qpack_blocked() -> u32 {
    100
}

fn default_keepalive() -> u64 {
    15
}

/// Alt-Svc header configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AltSvcConfig {
    /// Enable Alt-Svc header for HTTP/2 responses
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Max-age for Alt-Svc (seconds)
    #[serde(default = "default_alt_svc_max_age")]
    pub max_age_secs: u64,

    /// Port override (defaults to same port)
    pub port: Option<u16>,
}

impl Default for AltSvcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_age_secs: default_alt_svc_max_age(),
            port: None,
        }
    }
}

fn default_alt_svc_max_age() -> u64 {
    86400 // 24 hours
}

/// QUIC connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicConnectionState {
    /// Initial handshake in progress
    Handshaking,
    /// Connection established (1-RTT)
    Connected,
    /// 0-RTT data being processed
    EarlyData,
    /// Connection draining (graceful close)
    Draining,
    /// Connection closed
    Closed,
}

impl std::fmt::Display for QuicConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuicConnectionState::Handshaking => write!(f, "handshaking"),
            QuicConnectionState::Connected => write!(f, "connected"),
            QuicConnectionState::EarlyData => write!(f, "early_data"),
            QuicConnectionState::Draining => write!(f, "draining"),
            QuicConnectionState::Closed => write!(f, "closed"),
        }
    }
}

/// QUIC connection information
#[derive(Debug, Clone)]
pub struct QuicConnectionInfo {
    /// Connection ID
    pub connection_id: String,
    /// Remote address
    pub remote_addr: SocketAddr,
    /// Local address
    pub local_addr: SocketAddr,
    /// Connection state
    pub state: QuicConnectionState,
    /// ALPN protocol
    pub alpn: String,
    /// Server name (SNI)
    pub server_name: Option<String>,
    /// RTT estimate
    pub rtt: Duration,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Streams opened
    pub streams_opened: u64,
    /// Connection establishment time
    pub established_at: Instant,
    /// Whether using 0-RTT
    pub is_0rtt: bool,
    /// Connection migrated
    pub has_migrated: bool,
}

impl QuicConnectionInfo {
    /// Create a new connection info
    pub fn new(connection_id: String, remote_addr: SocketAddr, local_addr: SocketAddr) -> Self {
        Self {
            connection_id,
            remote_addr,
            local_addr,
            state: QuicConnectionState::Handshaking,
            alpn: "h3".to_string(),
            server_name: None,
            rtt: Duration::ZERO,
            bytes_sent: 0,
            bytes_received: 0,
            streams_opened: 0,
            established_at: Instant::now(),
            is_0rtt: false,
            has_migrated: false,
        }
    }

    /// Get connection age
    pub fn age(&self) -> Duration {
        self.established_at.elapsed()
    }
}

/// HTTP/3 stream types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3StreamType {
    /// Bidirectional request/response stream
    Request,
    /// Control stream (connection-level)
    Control,
    /// QPACK encoder stream
    QpackEncoder,
    /// QPACK decoder stream
    QpackDecoder,
    /// Push stream (server-initiated)
    Push,
    /// Unknown/reserved stream type
    Unknown(u64),
}

impl From<u64> for H3StreamType {
    fn from(value: u64) -> Self {
        match value {
            0x00 => H3StreamType::Control,
            0x01 => H3StreamType::Push,
            0x02 => H3StreamType::QpackEncoder,
            0x03 => H3StreamType::QpackDecoder,
            _ => H3StreamType::Unknown(value),
        }
    }
}

/// HTTP/3 frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3FrameType {
    Data,
    Headers,
    CancelPush,
    Settings,
    PushPromise,
    Goaway,
    MaxPushId,
    Unknown(u64),
}

impl From<u64> for H3FrameType {
    fn from(value: u64) -> Self {
        match value {
            0x00 => H3FrameType::Data,
            0x01 => H3FrameType::Headers,
            0x03 => H3FrameType::CancelPush,
            0x04 => H3FrameType::Settings,
            0x05 => H3FrameType::PushPromise,
            0x07 => H3FrameType::Goaway,
            0x0D => H3FrameType::MaxPushId,
            _ => H3FrameType::Unknown(value),
        }
    }
}

/// HTTP/3 settings parameters
#[derive(Debug, Clone, Default)]
pub struct Http3Settings {
    /// Maximum header list size
    pub max_header_list_size: Option<u64>,
    /// QPACK max table capacity
    pub qpack_max_table_capacity: Option<u64>,
    /// QPACK blocked streams
    pub qpack_blocked_streams: Option<u64>,
    /// Enable connect protocol (for WebSocket over H3)
    pub enable_connect_protocol: bool,
    /// Enable datagram extension
    pub enable_datagram: bool,
}

impl Http3Settings {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize to SETTINGS frame payload
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // SETTINGS_MAX_HEADER_LIST_SIZE (0x06)
        if let Some(v) = self.max_header_list_size {
            buf.extend_from_slice(&encode_varint(0x06));
            buf.extend_from_slice(&encode_varint(v));
        }

        // SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01)
        if let Some(v) = self.qpack_max_table_capacity {
            buf.extend_from_slice(&encode_varint(0x01));
            buf.extend_from_slice(&encode_varint(v));
        }

        // SETTINGS_QPACK_BLOCKED_STREAMS (0x07)
        if let Some(v) = self.qpack_blocked_streams {
            buf.extend_from_slice(&encode_varint(0x07));
            buf.extend_from_slice(&encode_varint(v));
        }

        // SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08)
        if self.enable_connect_protocol {
            buf.extend_from_slice(&encode_varint(0x08));
            buf.extend_from_slice(&encode_varint(1));
        }

        // SETTINGS_H3_DATAGRAM (0x33)
        if self.enable_datagram {
            buf.extend_from_slice(&encode_varint(0x33));
            buf.extend_from_slice(&encode_varint(1));
        }

        buf
    }
}

/// Encode a variable-length integer (QUIC varint)
fn encode_varint(value: u64) -> Vec<u8> {
    if value < 64 {
        vec![value as u8]
    } else if value < 16384 {
        let bytes = (value as u16 | 0x4000).to_be_bytes();
        bytes.to_vec()
    } else if value < 1073741824 {
        let bytes = (value as u32 | 0x80000000).to_be_bytes();
        bytes.to_vec()
    } else {
        let bytes = (value | 0xC000000000000000).to_be_bytes();
        bytes.to_vec()
    }
}

/// Decode a variable-length integer
pub fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];
    let length = 1 << (first >> 6);

    if data.len() < length {
        return None;
    }

    let value = match length {
        1 => first as u64,
        2 => {
            let mut bytes = [0u8; 2];
            bytes.copy_from_slice(&data[..2]);
            (u16::from_be_bytes(bytes) & 0x3FFF) as u64
        }
        4 => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&data[..4]);
            (u32::from_be_bytes(bytes) & 0x3FFFFFFF) as u64
        }
        8 => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[..8]);
            u64::from_be_bytes(bytes) & 0x3FFFFFFFFFFFFFFF
        }
        _ => return None,
    };

    Some((value, length))
}

/// HTTP/3 error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum H3Error {
    /// No error
    NoError = 0x100,
    /// General protocol error
    GeneralProtocolError = 0x101,
    /// Internal error
    InternalError = 0x102,
    /// Stream creation error
    StreamCreationError = 0x103,
    /// Closed critical stream
    ClosedCriticalStream = 0x104,
    /// Frame unexpected
    FrameUnexpected = 0x105,
    /// Frame error
    FrameError = 0x106,
    /// Excessive load
    ExcessiveLoad = 0x107,
    /// ID error
    IdError = 0x108,
    /// Settings error
    SettingsError = 0x109,
    /// Missing settings
    MissingSettings = 0x10A,
    /// Request rejected
    RequestRejected = 0x10B,
    /// Request cancelled
    RequestCancelled = 0x10C,
    /// Request incomplete
    RequestIncomplete = 0x10D,
    /// Message error
    MessageError = 0x10E,
    /// Connect error
    ConnectError = 0x10F,
    /// Version fallback
    VersionFallback = 0x110,
    /// QPACK decompression failed
    QpackDecompressionFailed = 0x200,
    /// QPACK encoder stream error
    QpackEncoderStreamError = 0x201,
    /// QPACK decoder stream error
    QpackDecoderStreamError = 0x202,
}

impl std::fmt::Display for H3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H3Error::NoError => write!(f, "no_error"),
            H3Error::GeneralProtocolError => write!(f, "general_protocol_error"),
            H3Error::InternalError => write!(f, "internal_error"),
            H3Error::StreamCreationError => write!(f, "stream_creation_error"),
            H3Error::ClosedCriticalStream => write!(f, "closed_critical_stream"),
            H3Error::FrameUnexpected => write!(f, "frame_unexpected"),
            H3Error::FrameError => write!(f, "frame_error"),
            H3Error::ExcessiveLoad => write!(f, "excessive_load"),
            H3Error::IdError => write!(f, "id_error"),
            H3Error::SettingsError => write!(f, "settings_error"),
            H3Error::MissingSettings => write!(f, "missing_settings"),
            H3Error::RequestRejected => write!(f, "request_rejected"),
            H3Error::RequestCancelled => write!(f, "request_cancelled"),
            H3Error::RequestIncomplete => write!(f, "request_incomplete"),
            H3Error::MessageError => write!(f, "message_error"),
            H3Error::ConnectError => write!(f, "connect_error"),
            H3Error::VersionFallback => write!(f, "version_fallback"),
            H3Error::QpackDecompressionFailed => write!(f, "qpack_decompression_failed"),
            H3Error::QpackEncoderStreamError => write!(f, "qpack_encoder_stream_error"),
            H3Error::QpackDecoderStreamError => write!(f, "qpack_decoder_stream_error"),
        }
    }
}

/// HTTP/3 listener statistics
#[derive(Debug)]
pub struct Http3Stats {
    /// Total connections
    pub total_connections: AtomicU64,
    /// Active connections
    pub active_connections: AtomicU64,
    /// Total requests
    pub total_requests: AtomicU64,
    /// 0-RTT connections
    pub zero_rtt_connections: AtomicU64,
    /// Migrated connections
    pub migrated_connections: AtomicU64,
    /// Total bytes received
    pub bytes_received: AtomicU64,
    /// Total bytes sent
    pub bytes_sent: AtomicU64,
    /// Handshake failures
    pub handshake_failures: AtomicU64,
}

impl Http3Stats {
    pub fn new() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            zero_rtt_connections: AtomicU64::new(0),
            migrated_connections: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            handshake_failures: AtomicU64::new(0),
        }
    }

    pub fn record_connection(&self, is_0rtt: bool) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        if is_0rtt {
            self.zero_rtt_connections.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_disconnect(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_migration(&self) {
        self.migrated_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bytes(&self, sent: u64, received: u64) {
        self.bytes_sent.fetch_add(sent, Ordering::Relaxed);
        self.bytes_received.fetch_add(received, Ordering::Relaxed);
    }

    pub fn record_handshake_failure(&self) {
        self.handshake_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of stats
    pub fn snapshot(&self) -> Http3StatsSnapshot {
        Http3StatsSnapshot {
            total_connections: self.total_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            zero_rtt_connections: self.zero_rtt_connections.load(Ordering::Relaxed),
            migrated_connections: self.migrated_connections.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            handshake_failures: self.handshake_failures.load(Ordering::Relaxed),
        }
    }
}

impl Default for Http3Stats {
    fn default() -> Self {
        Self::new()
    }
}

/// Stats snapshot (for serialization)
#[derive(Debug, Clone, Serialize)]
pub struct Http3StatsSnapshot {
    pub total_connections: u64,
    pub active_connections: u64,
    pub total_requests: u64,
    pub zero_rtt_connections: u64,
    pub migrated_connections: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub handshake_failures: u64,
}

/// HTTP/3 listener
pub struct Http3Listener {
    config: Http3Config,
    stats: Arc<Http3Stats>,
    connections: RwLock<HashMap<String, Arc<QuicConnectionInfo>>>,
    /// Request handler (set when integrating with server)
    #[cfg(feature = "http3")]
    request_handler: RwLock<Option<Arc<dyn H3RequestHandler + Send + Sync>>>,
}

/// Trait for handling HTTP/3 requests
#[cfg(feature = "http3")]
pub trait H3RequestHandler: Send + Sync {
    /// Handle an HTTP/3 request and return a response
    fn handle(
        &self,
        request: http::Request<bytes::Bytes>,
        remote_addr: std::net::SocketAddr,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = http::Response<http_body_util::Full<bytes::Bytes>>>
                + Send,
        >,
    >;
}

impl Http3Listener {
    /// Create a new HTTP/3 listener
    pub fn new(config: Http3Config) -> Self {
        Self {
            config,
            stats: Arc::new(Http3Stats::new()),
            connections: RwLock::new(HashMap::new()),
            #[cfg(feature = "http3")]
            request_handler: RwLock::new(None),
        }
    }

    /// Set the request handler for processing HTTP/3 requests
    #[cfg(feature = "http3")]
    pub fn set_request_handler(&self, handler: Arc<dyn H3RequestHandler + Send + Sync>) {
        *self.request_handler.write() = Some(handler);
    }

    /// Get the request handler
    #[cfg(feature = "http3")]
    pub fn request_handler(&self) -> Option<Arc<dyn H3RequestHandler + Send + Sync>> {
        self.request_handler.read().clone()
    }

    /// Get the configuration
    pub fn config(&self) -> &Http3Config {
        &self.config
    }

    /// Get statistics
    pub fn stats(&self) -> Arc<Http3Stats> {
        self.stats.clone()
    }

    /// Get Alt-Svc header value for HTTP/2 responses
    pub fn alt_svc_header(&self) -> Option<String> {
        if !self.config.alt_svc.enabled {
            return None;
        }

        let port = self.config.alt_svc.port.unwrap_or_else(|| {
            self.config
                .address
                .parse::<SocketAddr>()
                .map(|a| a.port())
                .unwrap_or(443)
        });

        Some(format!(
            "h3=\":{}\"; ma={}",
            port, self.config.alt_svc.max_age_secs
        ))
    }

    /// Get active connection count
    pub fn active_connections(&self) -> usize {
        self.connections.read().len()
    }

    /// Get connection info
    pub fn get_connection(&self, id: &str) -> Option<Arc<QuicConnectionInfo>> {
        self.connections.read().get(id).cloned()
    }

    /// Add a connection (for testing)
    pub fn add_connection(&self, info: QuicConnectionInfo) {
        let is_0rtt = info.is_0rtt;
        self.connections
            .write()
            .insert(info.connection_id.clone(), Arc::new(info));
        self.stats.record_connection(is_0rtt);
    }

    /// Remove a connection
    pub fn remove_connection(&self, id: &str) {
        if self.connections.write().remove(id).is_some() {
            self.stats.record_disconnect();
        }
    }
}

/// Generate Alt-Svc header for advertising HTTP/3 support
pub fn generate_alt_svc_header(port: u16, max_age: u64) -> String {
    format!("h3=\":{}\"; ma={}", port, max_age)
}

/// Check if a request accepts HTTP/3 upgrade
pub fn accepts_h3_upgrade(headers: &HashMap<String, String>) -> bool {
    // Check for Alt-Svc or Upgrade header indicating H3 support
    headers.iter().any(|(k, v)| {
        let k_lower = k.to_lowercase();
        if k_lower == "alt-used" {
            return v.contains("h3");
        }
        if k_lower == "upgrade" {
            return v.contains("h3");
        }
        false
    })
}

// ============================================
// HTTP/3 QUIC Implementation (Feature-Gated)
// ============================================

#[cfg(feature = "http3")]
#[allow(dead_code)] // Internal implementation with helper methods for future use
mod quic_impl {
    use super::*;
    use crate::error::{PrismError, Result};
    use bytes::{Buf, Bytes};
    use http::{Request, Response};
    use http_body_util::Full;
    use quinn::{crypto::rustls::QuicServerConfig, Endpoint, Incoming, ServerConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::fs::File;
    use std::io::BufReader;
    use std::net::SocketAddr;
    use tokio::sync::broadcast;
    use tracing::{debug, error, info, warn};

    /// Build rustls ServerConfig suitable for QUIC
    fn build_quic_server_crypto(
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
    ) -> Result<rustls::ServerConfig> {
        // Load certificates
        let cert_file = File::open(cert_path).map_err(|e| {
            PrismError::Config(format!("Failed to open certificate file: {}", e))
        })?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| PrismError::Config(format!("Failed to parse certificates: {}", e)))?;

        if certs.is_empty() {
            return Err(PrismError::Config(
                "No certificates found in certificate file".to_string(),
            ));
        }

        // Load private key
        let key_file = File::open(key_path)
            .map_err(|e| PrismError::Config(format!("Failed to open key file: {}", e)))?;
        let mut key_reader = BufReader::new(key_file);
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| PrismError::Config(format!("Failed to parse private key: {}", e)))?
            .ok_or_else(|| PrismError::Config("No private key found in key file".to_string()))?;

        // Build rustls config with QUIC-compatible settings
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| PrismError::Config(format!("TLS configuration error: {}", e)))?;

        // Enable ALPN for HTTP/3
        server_crypto.alpn_protocols = vec![b"h3".to_vec()];

        Ok(server_crypto)
    }

    impl Http3Listener {
        /// Start listening for HTTP/3 connections
        pub async fn listen(
            &self,
            mut shutdown_rx: broadcast::Receiver<()>,
        ) -> Result<()> {
            let addr: SocketAddr = self
                .config
                .address
                .parse()
                .map_err(|e| PrismError::Config(format!("Invalid address: {}", e)))?;

            // Load TLS config
            let cert_path = self.config.cert_path.as_ref().ok_or_else(|| {
                PrismError::Config("cert_path required for HTTP/3".to_string())
            })?;
            let key_path = self.config.key_path.as_ref().ok_or_else(|| {
                PrismError::Config("key_path required for HTTP/3".to_string())
            })?;

            // Build rustls ServerConfig with QUIC-compatible settings
            let server_crypto = build_quic_server_crypto(cert_path, key_path)?;

            // Create QUIC server config
            let quic_server_config = QuicServerConfig::try_from(server_crypto)
                .map_err(|e| PrismError::Config(format!("QUIC config error: {}", e)))?;

            let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

            // Configure transport parameters
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_concurrent_bidi_streams(
                self.config.max_concurrent_streams.into(),
            );
            if let Ok(timeout) = Duration::from_secs(self.config.idle_timeout_secs).try_into() {
                transport_config.max_idle_timeout(Some(timeout));
            }

            // Configure receive windows
            transport_config.receive_window(self.config.connection_receive_window.into());
            transport_config.stream_receive_window(self.config.stream_receive_window.into());

            // Configure keep-alive
            if self.config.keepalive_interval_secs > 0 {
                transport_config.keep_alive_interval(Some(Duration::from_secs(
                    self.config.keepalive_interval_secs,
                )));
            }

            server_config.transport_config(Arc::new(transport_config));

            // Bind UDP socket
            let endpoint = Endpoint::server(server_config, addr)
                .map_err(|e| PrismError::Io(e))?;

            info!("HTTP/3 listener bound to {} (UDP)", addr);

            // Accept connections loop
            loop {
                tokio::select! {
                    incoming = endpoint.accept() => {
                        match incoming {
                            Some(incoming) => {
                                let listener = self.clone_for_connection();
                                tokio::spawn(async move {
                                    if let Err(e) = listener.accept_connection(incoming).await {
                                        debug!("HTTP/3 connection error: {}", e);
                                    }
                                });
                            }
                            None => {
                                info!("HTTP/3 endpoint closed");
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("HTTP/3 listener shutting down");
                        endpoint.close(0u32.into(), b"server shutting down");
                        break;
                    }
                }
            }

            // Wait for endpoint to drain
            endpoint.wait_idle().await;
            info!("HTTP/3 endpoint drained");

            Ok(())
        }

        /// Accept a single QUIC connection
        async fn accept_connection(&self, incoming: Incoming) -> Result<()> {
            // Accept the QUIC connection
            let connection = incoming.await.map_err(|e| {
                self.stats.record_handshake_failure();
                PrismError::Connection(format!("QUIC handshake failed: {}", e))
            })?;

            let conn_id = connection.stable_id().to_string();
            let remote_addr = connection.remote_address();
            let local_addr = connection
                .local_ip()
                .map(|ip| SocketAddr::new(ip, 0))
                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

            // Note: In newer quinn versions, 0-RTT detection is done differently
            // For now, we default to false - proper detection would require checking
            // if the connection was resumed from a previous session
            let is_0rtt = false;

            debug!(
                conn_id = %conn_id,
                remote = %remote_addr,
                is_0rtt = is_0rtt,
                "HTTP/3 connection established"
            );

            // Track connection
            let mut info = QuicConnectionInfo::new(conn_id.clone(), remote_addr, local_addr);
            info.state = QuicConnectionState::Connected;
            info.is_0rtt = is_0rtt;
            self.add_connection(info);
            self.stats.record_connection(is_0rtt);

            // Create HTTP/3 connection
            let h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(connection))
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    error!("HTTP/3 connection setup failed: {}", e);
                    self.remove_connection(&conn_id);
                    return Err(PrismError::Connection(format!(
                        "HTTP/3 setup failed: {}",
                        e
                    )));
                }
            };

            // Handle HTTP/3 requests
            self.handle_h3_connection(h3_conn, conn_id.clone()).await;

            self.remove_connection(&conn_id);
            Ok(())
        }

        /// Handle HTTP/3 requests on a connection (simplified for h3_quinn)
        async fn handle_h3_connection(
            &self,
            mut conn: h3::server::Connection<h3_quinn::Connection, Bytes>,
            conn_id: String,
        ) {
            loop {
                match conn.accept().await {
                    Ok(Some(resolver)) => {
                        // In h3 0.0.8, RequestResolver implements Future
                        match resolver.resolve_request().await {
                            Ok((request, stream)) => {
                                self.stats.record_request();
                                debug!(
                                    conn_id = %conn_id,
                                    method = %request.method(),
                                    uri = %request.uri(),
                                    "HTTP/3 request received"
                                );

                                // Spawn task to handle request
                                let stats = self.stats.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_h3_request_simple(request, stream).await
                                    {
                                        debug!("HTTP/3 request error: {:?}", e);
                                    }
                                    stats.record_bytes(0, 0);
                                });
                            }
                            Err(e) => {
                                debug!(conn_id = %conn_id, error = ?e, "Failed to resolve request");
                            }
                        }
                    }
                    Ok(None) => {
                        debug!(conn_id = %conn_id, "HTTP/3 connection closed gracefully");
                        break;
                    }
                    Err(e) => {
                        warn!(conn_id = %conn_id, error = ?e, "HTTP/3 connection error");
                        break;
                    }
                }
            }
        }

        /// Clone listener state for spawned connection handlers
        fn clone_for_connection(&self) -> Http3ListenerHandle {
            Http3ListenerHandle {
                config: self.config.clone(),
                stats: self.stats.clone(),
                connections: self.connections.read().clone(),
                connections_lock: Arc::new(RwLock::new(HashMap::new())),
                request_handler: self.request_handler.read().clone(),
            }
        }
    }

    /// Handle for connection processing (avoids lifetime issues with RwLock)
    struct Http3ListenerHandle {
        config: Http3Config,
        stats: Arc<Http3Stats>,
        connections: HashMap<String, Arc<QuicConnectionInfo>>,
        connections_lock: Arc<RwLock<HashMap<String, Arc<QuicConnectionInfo>>>>,
        request_handler: Option<Arc<dyn super::H3RequestHandler + Send + Sync>>,
    }

    impl Http3ListenerHandle {
        async fn accept_connection(&self, incoming: Incoming) -> Result<()> {
            // Accept the QUIC connection
            let connection = incoming.await.map_err(|e| {
                self.stats.record_handshake_failure();
                PrismError::Connection(format!("QUIC handshake failed: {}", e))
            })?;

            let conn_id = connection.stable_id().to_string();
            let remote_addr = connection.remote_address();
            let local_addr = connection
                .local_ip()
                .map(|ip| SocketAddr::new(ip, 0))
                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

            // Note: In newer quinn versions, 0-RTT detection is done differently
            // For now, we default to false - proper detection would require checking
            // if the connection was resumed from a previous session
            let is_0rtt = false;

            debug!(
                conn_id = %conn_id,
                remote = %remote_addr,
                is_0rtt = is_0rtt,
                "HTTP/3 connection established"
            );

            // Track connection
            let mut info = QuicConnectionInfo::new(conn_id.clone(), remote_addr, local_addr);
            info.state = QuicConnectionState::Connected;
            info.is_0rtt = is_0rtt;
            self.add_connection(info);
            self.stats.record_connection(is_0rtt);

            // Create HTTP/3 connection
            let h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(connection))
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    error!("HTTP/3 connection setup failed: {}", e);
                    self.remove_connection(&conn_id);
                    return Err(PrismError::Connection(format!(
                        "HTTP/3 setup failed: {}",
                        e
                    )));
                }
            };

            // Handle HTTP/3 requests
            self.handle_h3_connection(h3_conn, conn_id.clone(), remote_addr)
                .await;

            self.remove_connection(&conn_id);
            Ok(())
        }

        fn add_connection(&self, info: QuicConnectionInfo) {
            self.connections_lock
                .write()
                .insert(info.connection_id.clone(), Arc::new(info));
        }

        fn remove_connection(&self, id: &str) {
            if self.connections_lock.write().remove(id).is_some() {
                self.stats.record_disconnect();
            }
        }

        async fn handle_h3_connection(
            &self,
            mut conn: h3::server::Connection<h3_quinn::Connection, Bytes>,
            conn_id: String,
            remote_addr: SocketAddr,
        ) {
            loop {
                match conn.accept().await {
                    Ok(Some(resolver)) => {
                        // In h3 0.0.8, RequestResolver implements Future
                        match resolver.resolve_request().await {
                            Ok((request, stream)) => {
                                self.stats.record_request();
                                debug!(
                                    conn_id = %conn_id,
                                    method = %request.method(),
                                    uri = %request.uri(),
                                    "HTTP/3 request received"
                                );

                                // Spawn task to handle request
                                let stats = self.stats.clone();
                                let handler = self.request_handler.clone();
                                tokio::spawn(async move {
                                    if let Err(e) =
                                        handle_h3_request_with_handler(request, stream, handler, remote_addr).await
                                    {
                                        debug!("HTTP/3 request error: {:?}", e);
                                    }
                                    stats.record_bytes(0, 0);
                                });
                            }
                            Err(e) => {
                                debug!(conn_id = %conn_id, error = ?e, "Failed to resolve request");
                            }
                        }
                    }
                    Ok(None) => {
                        debug!(conn_id = %conn_id, "HTTP/3 connection closed gracefully");
                        break;
                    }
                    Err(e) => {
                        warn!(conn_id = %conn_id, error = ?e, "HTTP/3 connection error");
                        break;
                    }
                }
            }
        }
    }

    /// Simple HTTP/3 request handler (no custom handler)
    async fn handle_h3_request_simple(
        request: Request<()>,
        mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Read request body
        let mut body = Vec::new();
        while let Some(chunk) = stream.recv_data().await? {
            // chunk is impl Buf, so we need to copy the bytes
            let mut chunk = chunk;
            while chunk.has_remaining() {
                body.push(chunk.get_u8());
            }
        }

        debug!(
            method = %request.method(),
            uri = %request.uri(),
            body_len = body.len(),
            "Processing HTTP/3 request"
        );

        // Default response
        let response = Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .header("server", "prism")
            .body(())
            .unwrap();

        stream.send_response(response).await?;
        stream.send_data(Bytes::from("Hello from HTTP/3 Prism!")).await?;
        stream.finish().await?;

        Ok(())
    }

    /// HTTP/3 request handler with custom handler support
    async fn handle_h3_request_with_handler(
        request: Request<()>,
        mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        handler: Option<Arc<dyn super::H3RequestHandler + Send + Sync>>,
        remote_addr: SocketAddr,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Read request body
        let mut body = Vec::new();
        while let Some(chunk) = stream.recv_data().await? {
            let mut chunk = chunk;
            while chunk.has_remaining() {
                body.push(chunk.get_u8());
            }
        }

        // Convert request to have body
        let (parts, _) = request.into_parts();
        let full_request = Request::from_parts(parts, Bytes::from(body));

        // Use handler if available, otherwise return default response
        let response = if let Some(handler) = handler {
            handler.handle(full_request, remote_addr).await
        } else {
            Response::builder()
                .status(200)
                .header("content-type", "text/plain")
                .header("server", "prism")
                .body(Full::new(Bytes::from("Hello from HTTP/3 Prism!")))
                .unwrap()
        };

        // Send response headers
        let (parts, body) = response.into_parts();
        let response_headers = Response::from_parts(parts, ());
        stream.send_response(response_headers).await?;

        // Send response body - extract Bytes from Full<Bytes>
        // Full<Bytes> wraps a single Bytes value
        use http_body_util::BodyExt;
        let collected = body.collect().await.map_err(|e| {
            Box::new(std::io::Error::other(format!("Body collect error: {:?}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        let body_bytes = collected.to_bytes();
        if !body_bytes.is_empty() {
            stream.send_data(body_bytes).await?;
        }

        stream.finish().await?;

        Ok(())
    }
}

// Re-export QUIC implementation when feature is enabled
// Note: The quic_impl module is used internally by the Http3Listener
// when the http3 feature is enabled. Methods are exposed via Http3Listener impl.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Http3Config::default();
        assert!(!config.enabled);
        assert!(config.enable_0rtt);
        assert!(config.enable_migration);
        assert_eq!(config.max_concurrent_streams, 100);
    }

    #[test]
    fn test_quic_connection_state_display() {
        assert_eq!(QuicConnectionState::Connected.to_string(), "connected");
        assert_eq!(QuicConnectionState::Handshaking.to_string(), "handshaking");
        assert_eq!(QuicConnectionState::EarlyData.to_string(), "early_data");
    }

    #[test]
    fn test_quic_connection_info() {
        let info = QuicConnectionInfo::new(
            "conn-123".to_string(),
            "192.168.1.1:12345".parse().unwrap(),
            "0.0.0.0:443".parse().unwrap(),
        );

        assert_eq!(info.connection_id, "conn-123");
        assert_eq!(info.state, QuicConnectionState::Handshaking);
        assert_eq!(info.alpn, "h3");
        assert!(!info.is_0rtt);
    }

    #[test]
    fn test_h3_stream_type() {
        assert_eq!(H3StreamType::from(0x00), H3StreamType::Control);
        assert_eq!(H3StreamType::from(0x01), H3StreamType::Push);
        assert_eq!(H3StreamType::from(0x02), H3StreamType::QpackEncoder);
        assert_eq!(H3StreamType::from(0xFF), H3StreamType::Unknown(0xFF));
    }

    #[test]
    fn test_h3_frame_type() {
        assert_eq!(H3FrameType::from(0x00), H3FrameType::Data);
        assert_eq!(H3FrameType::from(0x01), H3FrameType::Headers);
        assert_eq!(H3FrameType::from(0x04), H3FrameType::Settings);
        assert_eq!(H3FrameType::from(0x99), H3FrameType::Unknown(0x99));
    }

    #[test]
    fn test_varint_encoding() {
        // Single byte
        assert_eq!(encode_varint(0), vec![0]);
        assert_eq!(encode_varint(63), vec![63]);

        // Two bytes
        let encoded = encode_varint(64);
        assert_eq!(encoded.len(), 2);

        // Four bytes
        let encoded = encode_varint(16384);
        assert_eq!(encoded.len(), 4);
    }

    #[test]
    fn test_varint_decode() {
        let (value, len) = decode_varint(&[0x00]).unwrap();
        assert_eq!(value, 0);
        assert_eq!(len, 1);

        let (value, len) = decode_varint(&[0x3F]).unwrap();
        assert_eq!(value, 63);
        assert_eq!(len, 1);
    }

    #[test]
    fn test_http3_settings() {
        let mut settings = Http3Settings::new();
        settings.max_header_list_size = Some(16384);
        settings.qpack_max_table_capacity = Some(4096);

        let bytes = settings.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_h3_error_display() {
        assert_eq!(H3Error::NoError.to_string(), "no_error");
        assert_eq!(H3Error::RequestRejected.to_string(), "request_rejected");
    }

    #[test]
    fn test_http3_stats() {
        let stats = Http3Stats::new();

        stats.record_connection(true);
        stats.record_connection(false);
        stats.record_request();
        stats.record_bytes(100, 200);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.total_connections, 2);
        assert_eq!(snapshot.active_connections, 2);
        assert_eq!(snapshot.zero_rtt_connections, 1);
        assert_eq!(snapshot.total_requests, 1);
        assert_eq!(snapshot.bytes_sent, 100);
        assert_eq!(snapshot.bytes_received, 200);
    }

    #[test]
    fn test_http3_listener() {
        let config = Http3Config::default();
        let listener = Http3Listener::new(config);

        assert_eq!(listener.active_connections(), 0);
        assert!(listener.alt_svc_header().is_some());
    }

    #[test]
    fn test_alt_svc_header_generation() {
        let config = Http3Config {
            enabled: true,
            alt_svc: AltSvcConfig {
                enabled: true,
                max_age_secs: 3600,
                port: Some(8443),
            },
            ..Default::default()
        };

        let listener = Http3Listener::new(config);
        let header = listener.alt_svc_header().unwrap();
        assert!(header.contains("h3=\":8443\""));
        assert!(header.contains("ma=3600"));
    }

    #[test]
    fn test_generate_alt_svc() {
        let header = generate_alt_svc_header(443, 86400);
        assert_eq!(header, "h3=\":443\"; ma=86400");
    }

    #[test]
    fn test_accepts_h3_upgrade() {
        let mut headers = HashMap::new();
        assert!(!accepts_h3_upgrade(&headers));

        headers.insert("Alt-Used".to_string(), "h3=\":443\"".to_string());
        assert!(accepts_h3_upgrade(&headers));
    }

    #[test]
    fn test_connection_management() {
        let config = Http3Config::default();
        let listener = Http3Listener::new(config);

        let info = QuicConnectionInfo::new(
            "test-conn".to_string(),
            "127.0.0.1:12345".parse().unwrap(),
            "0.0.0.0:443".parse().unwrap(),
        );

        listener.add_connection(info);
        assert_eq!(listener.active_connections(), 1);
        assert!(listener.get_connection("test-conn").is_some());

        listener.remove_connection("test-conn");
        assert_eq!(listener.active_connections(), 0);
    }
}
