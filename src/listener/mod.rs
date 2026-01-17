//! Listener module for accepting incoming connections
//!
//! Supports HTTP/1.1, HTTP/2, HTTP/3 (QUIC), and TLS termination.

pub mod http3;
mod tls;

pub use http3::{
    accepts_h3_upgrade, decode_varint, generate_alt_svc_header, AltSvcConfig, H3Error, H3FrameType,
    H3StreamType, Http3Config, Http3Listener, Http3Settings, Http3Stats, Http3StatsSnapshot,
    QuicConnectionInfo, QuicConnectionState,
};
#[cfg(feature = "http3")]
pub use http3::H3RequestHandler;
pub use tls::TlsAcceptor;

use crate::config::{ListenerConfig, Protocol};
use crate::error::{PrismError, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tracing::{debug, info};

/// A listener that accepts incoming connections
pub struct Listener {
    /// TCP listener
    tcp_listener: TcpListener,
    /// TLS acceptor (if HTTPS)
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    /// Configuration
    config: ListenerConfig,
}

/// Represents an accepted connection
#[allow(clippy::large_enum_variant)]
pub enum Connection {
    /// Plain TCP connection
    Plain(TcpStream),
    /// TLS-encrypted connection
    Tls(TlsStream<TcpStream>),
}

impl Connection {
    /// Get the peer address
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Connection::Plain(stream) => stream.peer_addr(),
            Connection::Tls(stream) => stream.get_ref().0.peer_addr(),
        }
    }

    /// Check if this is a TLS connection
    pub fn is_tls(&self) -> bool {
        matches!(self, Connection::Tls(_))
    }

    /// Get the ALPN protocol if available (for TLS connections)
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Connection::Plain(_) => None,
            Connection::Tls(stream) => stream.get_ref().1.alpn_protocol(),
        }
    }
}

impl Listener {
    /// Create a new listener from configuration
    pub async fn new(config: ListenerConfig) -> Result<Self> {
        let addr: SocketAddr = config
            .address
            .parse()
            .map_err(|e| PrismError::Config(format!("Invalid listener address: {}", e)))?;

        // Create TCP listener with SO_REUSEADDR
        let tcp_listener = TcpListener::bind(addr).await.map_err(|e| {
            PrismError::Io(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("Failed to bind to {}: {}", addr, e),
            ))
        })?;

        info!("Listener bound to {}", addr);

        // Create TLS acceptor if needed
        let tls_acceptor = match config.protocol {
            Protocol::Https | Protocol::Http3 => {
                let tls_config = config.tls.as_ref().ok_or_else(|| {
                    PrismError::Config("TLS configuration required for HTTPS".to_string())
                })?;
                Some(Arc::new(TlsAcceptor::new(tls_config)?))
            }
            Protocol::Http => None,
        };

        Ok(Self {
            tcp_listener,
            tls_acceptor,
            config,
        })
    }

    /// Accept a new connection
    pub async fn accept(&self) -> Result<(Connection, SocketAddr)> {
        let (stream, addr) = self.tcp_listener.accept().await?;

        // Configure TCP socket
        stream.set_nodelay(true)?;

        debug!("Accepted connection from {}", addr);

        let connection = if let Some(tls_acceptor) = &self.tls_acceptor {
            let tls_stream = tls_acceptor.accept(stream).await?;
            Connection::Tls(tls_stream)
        } else {
            Connection::Plain(stream)
        };

        Ok((connection, addr))
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.tcp_listener.local_addr().map_err(Into::into)
    }

    /// Get the protocol
    pub fn protocol(&self) -> &Protocol {
        &self.config.protocol
    }

    /// Check if this is a TLS listener
    pub fn is_tls(&self) -> bool {
        self.tls_acceptor.is_some()
    }

    /// Get the maximum number of connections
    pub fn max_connections(&self) -> usize {
        self.config.max_connections
    }
}

/// Listener manager that handles multiple listeners
pub struct ListenerManager {
    listeners: Vec<Listener>,
}

impl ListenerManager {
    /// Create a new listener manager from configurations
    pub async fn new(configs: Vec<ListenerConfig>) -> Result<Self> {
        let mut listeners = Vec::with_capacity(configs.len());

        for config in configs {
            let listener = Listener::new(config).await?;
            listeners.push(listener);
        }

        Ok(Self { listeners })
    }

    /// Get all listeners
    pub fn listeners(&self) -> &[Listener] {
        &self.listeners
    }

    /// Get mutable reference to all listeners
    pub fn listeners_mut(&mut self) -> &mut [Listener] {
        &mut self.listeners
    }

    /// Get the number of listeners
    pub fn len(&self) -> usize {
        self.listeners.len()
    }

    /// Check if there are no listeners
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }
}
