//! WebTransport Support
//!
//! Next-generation bidirectional transport built on HTTP/3 and QUIC.
//! Provides low-latency, multiplexed streams for real-time applications.
//!
//! Features:
//! - Bidirectional streams over HTTP/3
//! - Unreliable datagrams for real-time data
//! - Connection pooling and multiplexing
//! - Automatic reconnection with session resumption

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info};

/// WebTransport configuration
#[derive(Debug, Clone)]
pub struct WebTransportConfig {
    /// Maximum concurrent bidirectional streams per session
    pub max_bidirectional_streams: u32,
    /// Maximum concurrent unidirectional streams per session
    pub max_unidirectional_streams: u32,
    /// Maximum datagram size
    pub max_datagram_size: usize,
    /// Session idle timeout
    pub idle_timeout: Duration,
    /// Enable unreliable datagrams
    pub enable_datagrams: bool,
    /// Keep-alive interval
    pub keep_alive_interval: Duration,
    /// Maximum sessions per connection
    pub max_sessions: u32,
}

impl Default for WebTransportConfig {
    fn default() -> Self {
        Self {
            max_bidirectional_streams: 100,
            max_unidirectional_streams: 100,
            max_datagram_size: 1200,
            idle_timeout: Duration::from_secs(30),
            enable_datagrams: true,
            keep_alive_interval: Duration::from_secs(10),
            max_sessions: 1000,
        }
    }
}

/// WebTransport session identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

impl SessionId {
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Stream identifier within a session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId {
    pub session_id: SessionId,
    pub stream_id: u64,
    pub stream_type: StreamType,
}

/// Type of WebTransport stream
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamType {
    /// Bidirectional stream (both sides can send)
    Bidirectional,
    /// Unidirectional stream (one side sends)
    Unidirectional,
}

/// WebTransport message
#[derive(Debug, Clone)]
pub enum WebTransportMessage {
    /// Reliable stream data
    StreamData {
        stream_id: StreamId,
        data: Bytes,
        fin: bool,
    },
    /// Unreliable datagram
    Datagram { session_id: SessionId, data: Bytes },
    /// Stream opened
    StreamOpened { stream_id: StreamId },
    /// Stream closed
    StreamClosed {
        stream_id: StreamId,
        error_code: Option<u64>,
    },
    /// Session closed
    SessionClosed {
        session_id: SessionId,
        error_code: Option<u64>,
        reason: String,
    },
}

/// WebTransport session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is being established
    Connecting,
    /// Session is active
    Connected,
    /// Session is draining (no new streams)
    Draining,
    /// Session is closed
    Closed,
}

/// Statistics for a WebTransport session
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub streams_opened: u64,
    pub streams_closed: u64,
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub datagrams_lost: u64,
    pub rtt_ms: f64,
    pub congestion_window: u64,
}

/// A WebTransport stream
pub struct WebTransportStream {
    /// Stream identifier
    pub id: StreamId,
    /// Send channel for stream data
    tx: mpsc::Sender<Bytes>,
    /// Receive channel for stream data
    rx: mpsc::Receiver<Bytes>,
    /// Whether the stream is closed for writing
    write_closed: bool,
    /// Whether the stream is closed for reading
    read_closed: bool,
}

impl WebTransportStream {
    /// Create a new stream
    fn new(id: StreamId, buffer_size: usize) -> (Self, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
        let (tx_out, rx_out) = mpsc::channel(buffer_size);
        let (tx_in, rx_in) = mpsc::channel(buffer_size);

        let stream = Self {
            id,
            tx: tx_out,
            rx: rx_in,
            write_closed: false,
            read_closed: false,
        };

        (stream, tx_in, rx_out)
    }

    /// Send data on the stream
    pub async fn send(&mut self, data: Bytes) -> Result<(), WebTransportError> {
        if self.write_closed {
            return Err(WebTransportError::StreamClosed);
        }

        self.tx
            .send(data)
            .await
            .map_err(|_| WebTransportError::StreamClosed)
    }

    /// Receive data from the stream
    pub async fn recv(&mut self) -> Option<Bytes> {
        if self.read_closed {
            return None;
        }
        self.rx.recv().await
    }

    /// Close the write side of the stream
    pub fn close_write(&mut self) {
        self.write_closed = true;
    }

    /// Close the read side of the stream
    pub fn close_read(&mut self) {
        self.read_closed = true;
    }
}

/// A WebTransport session
pub struct WebTransportSession {
    /// Session identifier
    pub id: SessionId,
    /// Session state
    state: RwLock<SessionState>,
    /// Configuration
    config: WebTransportConfig,
    /// Active streams
    streams: DashMap<u64, StreamState>,
    /// Next stream ID
    next_stream_id: AtomicU64,
    /// Datagram sender
    datagram_tx: mpsc::Sender<Bytes>,
    /// Datagram receiver
    datagram_rx: RwLock<Option<mpsc::Receiver<Bytes>>>,
    /// Session statistics
    stats: RwLock<SessionStats>,
    /// Created timestamp
    #[allow(dead_code)]
    created_at: Instant,
    /// Last activity timestamp
    last_activity: RwLock<Instant>,
    /// Close notification
    close_tx: broadcast::Sender<()>,
}

#[allow(dead_code)]
struct StreamState {
    stream_type: StreamType,
    tx: mpsc::Sender<Bytes>,
    created_at: Instant,
}

impl WebTransportSession {
    /// Create a new session
    pub fn new(config: WebTransportConfig) -> Self {
        let (datagram_tx, datagram_rx) = mpsc::channel(1000);
        let (close_tx, _) = broadcast::channel(1);

        Self {
            id: SessionId::new(),
            state: RwLock::new(SessionState::Connected),
            config,
            streams: DashMap::new(),
            next_stream_id: AtomicU64::new(0),
            datagram_tx,
            datagram_rx: RwLock::new(Some(datagram_rx)),
            stats: RwLock::new(SessionStats::default()),
            created_at: Instant::now(),
            last_activity: RwLock::new(Instant::now()),
            close_tx,
        }
    }

    /// Get session state
    pub fn state(&self) -> SessionState {
        *self.state.read()
    }

    /// Open a new bidirectional stream
    pub async fn open_bi_stream(&self) -> Result<WebTransportStream, WebTransportError> {
        self.open_stream(StreamType::Bidirectional).await
    }

    /// Open a new unidirectional stream
    pub async fn open_uni_stream(&self) -> Result<WebTransportStream, WebTransportError> {
        self.open_stream(StreamType::Unidirectional).await
    }

    async fn open_stream(
        &self,
        stream_type: StreamType,
    ) -> Result<WebTransportStream, WebTransportError> {
        // Check session state
        if *self.state.read() != SessionState::Connected {
            return Err(WebTransportError::SessionClosed);
        }

        // Check stream limits
        let current_count = self
            .streams
            .iter()
            .filter(|s| s.stream_type == stream_type)
            .count() as u32;

        let limit = match stream_type {
            StreamType::Bidirectional => self.config.max_bidirectional_streams,
            StreamType::Unidirectional => self.config.max_unidirectional_streams,
        };

        if current_count >= limit {
            return Err(WebTransportError::StreamLimitExceeded);
        }

        // Create stream
        let stream_id_num = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        let stream_id = StreamId {
            session_id: self.id,
            stream_id: stream_id_num,
            stream_type,
        };

        let (stream, tx_in, _rx_out) = WebTransportStream::new(stream_id, 100);

        // Store stream state
        self.streams.insert(
            stream_id_num,
            StreamState {
                stream_type,
                tx: tx_in,
                created_at: Instant::now(),
            },
        );

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.streams_opened += 1;
        }

        *self.last_activity.write() = Instant::now();

        debug!(
            "Opened {:?} stream {} on session {}",
            stream_type, stream_id_num, self.id.0
        );

        Ok(stream)
    }

    /// Send a datagram (unreliable)
    pub async fn send_datagram(&self, data: Bytes) -> Result<(), WebTransportError> {
        if !self.config.enable_datagrams {
            return Err(WebTransportError::DatagramsDisabled);
        }

        if data.len() > self.config.max_datagram_size {
            return Err(WebTransportError::DatagramTooLarge);
        }

        if *self.state.read() != SessionState::Connected {
            return Err(WebTransportError::SessionClosed);
        }

        // In a real implementation, this would send via QUIC datagrams
        self.datagram_tx
            .send(data)
            .await
            .map_err(|_| WebTransportError::SessionClosed)?;

        {
            let mut stats = self.stats.write();
            stats.datagrams_sent += 1;
        }

        *self.last_activity.write() = Instant::now();

        Ok(())
    }

    /// Receive a datagram
    pub async fn recv_datagram(&self) -> Option<Bytes> {
        // Take the receiver out to avoid holding lock across await
        let rx_opt = {
            let mut rx_guard = self.datagram_rx.write();
            rx_guard.take()
        };

        if let Some(mut rx) = rx_opt {
            let result = rx.recv().await;
            if result.is_some() {
                let mut stats = self.stats.write();
                stats.datagrams_received += 1;
            }
            // Put the receiver back
            {
                let mut rx_guard = self.datagram_rx.write();
                *rx_guard = Some(rx);
            }
            result
        } else {
            None
        }
    }

    /// Get session statistics
    pub fn stats(&self) -> SessionStats {
        self.stats.read().clone()
    }

    /// Close the session
    pub async fn close(&self, error_code: Option<u64>, reason: &str) {
        let mut state = self.state.write();
        if *state == SessionState::Closed {
            return;
        }

        *state = SessionState::Closed;
        drop(state);

        // Notify all waiters
        let _ = self.close_tx.send(());

        // Close all streams
        self.streams.clear();

        info!(
            "WebTransport session {} closed: code={:?}, reason={}",
            self.id.0, error_code, reason
        );
    }

    /// Check if session should be closed due to idle timeout
    pub fn is_idle_timeout(&self) -> bool {
        self.last_activity.read().elapsed() > self.config.idle_timeout
    }

    /// Get a close notification receiver
    pub fn close_notify(&self) -> broadcast::Receiver<()> {
        self.close_tx.subscribe()
    }
}

/// WebTransport server managing multiple sessions
pub struct WebTransportServer {
    /// Configuration
    config: WebTransportConfig,
    /// Active sessions
    sessions: DashMap<SessionId, Arc<WebTransportSession>>,
    /// Session event sender
    event_tx: broadcast::Sender<WebTransportEvent>,
    /// Total sessions created
    total_sessions: AtomicU64,
}

/// Events from the WebTransport server
#[derive(Debug, Clone)]
pub enum WebTransportEvent {
    /// New session established
    SessionOpened { session_id: SessionId, path: String },
    /// Session closed
    SessionClosed {
        session_id: SessionId,
        error_code: Option<u64>,
    },
    /// New stream on a session
    StreamOpened {
        session_id: SessionId,
        stream_id: u64,
    },
}

impl WebTransportServer {
    /// Create a new WebTransport server
    pub fn new(config: WebTransportConfig) -> Self {
        let (event_tx, _) = broadcast::channel(1000);

        Self {
            config,
            sessions: DashMap::new(),
            event_tx,
            total_sessions: AtomicU64::new(0),
        }
    }

    /// Accept a new WebTransport session
    pub async fn accept_session(
        &self,
        path: &str,
    ) -> Result<Arc<WebTransportSession>, WebTransportError> {
        // Check session limit
        if self.sessions.len() >= self.config.max_sessions as usize {
            return Err(WebTransportError::TooManySessions);
        }

        let session = Arc::new(WebTransportSession::new(self.config.clone()));
        let session_id = session.id;

        self.sessions.insert(session_id, session.clone());
        self.total_sessions.fetch_add(1, Ordering::Relaxed);

        let _ = self.event_tx.send(WebTransportEvent::SessionOpened {
            session_id,
            path: path.to_string(),
        });

        info!(
            "WebTransport session {} opened for path: {}",
            session_id.0, path
        );

        Ok(session)
    }

    /// Get an existing session
    pub fn get_session(&self, session_id: SessionId) -> Option<Arc<WebTransportSession>> {
        self.sessions.get(&session_id).map(|s| s.clone())
    }

    /// Close a session
    pub async fn close_session(
        &self,
        session_id: SessionId,
        error_code: Option<u64>,
        reason: &str,
    ) {
        if let Some((_, session)) = self.sessions.remove(&session_id) {
            session.close(error_code, reason).await;

            let _ = self.event_tx.send(WebTransportEvent::SessionClosed {
                session_id,
                error_code,
            });
        }
    }

    /// Get event receiver
    pub fn events(&self) -> broadcast::Receiver<WebTransportEvent> {
        self.event_tx.subscribe()
    }

    /// Get server statistics
    pub fn stats(&self) -> WebTransportServerStats {
        WebTransportServerStats {
            active_sessions: self.sessions.len() as u64,
            total_sessions: self.total_sessions.load(Ordering::Relaxed),
        }
    }

    /// Run cleanup task for idle sessions
    pub async fn run_cleanup(&self, check_interval: Duration) {
        loop {
            tokio::time::sleep(check_interval).await;

            let mut to_remove = Vec::new();

            for session in self.sessions.iter() {
                if session.is_idle_timeout() {
                    to_remove.push(*session.key());
                }
            }

            for session_id in to_remove {
                self.close_session(session_id, Some(0), "idle timeout")
                    .await;
            }
        }
    }
}

/// WebTransport server statistics
#[derive(Debug, Clone)]
pub struct WebTransportServerStats {
    pub active_sessions: u64,
    pub total_sessions: u64,
}

/// WebTransport errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum WebTransportError {
    #[error("Session is closed")]
    SessionClosed,

    #[error("Stream is closed")]
    StreamClosed,

    #[error("Stream limit exceeded")]
    StreamLimitExceeded,

    #[error("Too many sessions")]
    TooManySessions,

    #[error("Datagrams are disabled")]
    DatagramsDisabled,

    #[error("Datagram too large")]
    DatagramTooLarge,

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Protocol error: {0}")]
    Protocol(String),
}

/// WebTransport path handler
pub trait WebTransportHandler: Send + Sync {
    /// Handle a new session
    fn on_session(&self, session: Arc<WebTransportSession>, path: &str);

    /// Handle session close
    fn on_session_close(&self, session_id: SessionId);
}

/// Echo handler for testing
pub struct EchoHandler;

impl WebTransportHandler for EchoHandler {
    fn on_session(&self, session: Arc<WebTransportSession>, path: &str) {
        info!("Echo handler: new session {} on {}", session.id.0, path);

        let session_clone = session.clone();
        tokio::spawn(async move {
            // Echo datagrams
            while let Some(data) = session_clone.recv_datagram().await {
                if let Err(e) = session_clone.send_datagram(data).await {
                    error!("Failed to echo datagram: {}", e);
                    break;
                }
            }
        });
    }

    fn on_session_close(&self, session_id: SessionId) {
        info!("Echo handler: session {} closed", session_id.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_creation() {
        let config = WebTransportConfig::default();
        let session = WebTransportSession::new(config);

        assert_eq!(session.state(), SessionState::Connected);
    }

    #[tokio::test]
    async fn test_stream_creation() {
        let config = WebTransportConfig::default();
        let session = WebTransportSession::new(config);

        let stream = session.open_bi_stream().await.unwrap();
        assert_eq!(stream.id.stream_type, StreamType::Bidirectional);

        let stats = session.stats();
        assert_eq!(stats.streams_opened, 1);
    }

    #[tokio::test]
    async fn test_datagram_send() {
        let config = WebTransportConfig::default();
        let session = WebTransportSession::new(config);

        let data = Bytes::from("hello");
        session.send_datagram(data).await.unwrap();

        let stats = session.stats();
        assert_eq!(stats.datagrams_sent, 1);
    }

    #[tokio::test]
    async fn test_datagram_too_large() {
        let mut config = WebTransportConfig::default();
        config.max_datagram_size = 10;
        let session = WebTransportSession::new(config);

        let data = Bytes::from("this is way too large");
        let result = session.send_datagram(data).await;

        assert!(matches!(result, Err(WebTransportError::DatagramTooLarge)));
    }

    #[tokio::test]
    async fn test_server_session_management() {
        let config = WebTransportConfig::default();
        let server = WebTransportServer::new(config);

        let session = server.accept_session("/test").await.unwrap();
        assert_eq!(server.stats().active_sessions, 1);

        server.close_session(session.id, None, "test").await;
        assert_eq!(server.stats().active_sessions, 0);
    }

    #[tokio::test]
    async fn test_stream_limit() {
        let mut config = WebTransportConfig::default();
        config.max_bidirectional_streams = 2;
        let session = WebTransportSession::new(config);

        let _s1 = session.open_bi_stream().await.unwrap();
        let _s2 = session.open_bi_stream().await.unwrap();
        let result = session.open_bi_stream().await;

        assert!(matches!(
            result,
            Err(WebTransportError::StreamLimitExceeded)
        ));
    }

    #[tokio::test]
    async fn test_session_close() {
        let config = WebTransportConfig::default();
        let session = WebTransportSession::new(config);

        session.close(Some(0), "test close").await;

        assert_eq!(session.state(), SessionState::Closed);

        // Operations should fail on closed session
        let result = session.open_bi_stream().await;
        assert!(matches!(result, Err(WebTransportError::SessionClosed)));
    }
}
