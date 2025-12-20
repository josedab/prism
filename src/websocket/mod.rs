//! WebSocket proxying support
//!
//! Provides WebSocket upgrade detection and bidirectional proxying

use crate::error::{PrismError, Result};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use http::{header, Request, Response, StatusCode};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info, warn};
use tungstenite::Message;

/// Check if a request is a WebSocket upgrade request
pub fn is_websocket_upgrade<B>(request: &Request<B>) -> bool {
    // Check Connection header for "upgrade"
    let has_upgrade_connection = request
        .headers()
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("upgrade"))
        .unwrap_or(false);

    // Check Upgrade header for "websocket"
    let has_websocket_upgrade = request
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    // Check for Sec-WebSocket-Key
    let has_websocket_key = request.headers().contains_key("sec-websocket-key");

    has_upgrade_connection && has_websocket_upgrade && has_websocket_key
}

/// WebSocket proxy handler
pub struct WebSocketProxy {
    /// Upstream address
    upstream_addr: SocketAddr,
}

impl WebSocketProxy {
    /// Create a new WebSocket proxy
    pub fn new(upstream_addr: SocketAddr) -> Self {
        Self { upstream_addr }
    }

    /// Proxy a WebSocket connection
    ///
    /// This handles the full WebSocket lifecycle:
    /// 1. Connect to upstream
    /// 2. Perform WebSocket handshake with upstream
    /// 3. Proxy messages bidirectionally
    pub async fn proxy<S>(
        &self,
        client_stream: S,
        request: &Request<hyper::body::Incoming>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        info!("Initiating WebSocket proxy to {}", self.upstream_addr);

        // Connect to upstream
        let upstream_stream = TcpStream::connect(self.upstream_addr).await.map_err(|e| {
            PrismError::Upstream(format!(
                "Failed to connect to upstream {}: {}",
                self.upstream_addr, e
            ))
        })?;

        // Build WebSocket request for upstream
        let ws_request = build_websocket_request(request, &self.upstream_addr.to_string())?;

        // Perform WebSocket handshake with upstream
        let (upstream_ws, _response) = tokio_tungstenite::client_async(ws_request, upstream_stream)
            .await
            .map_err(|e| PrismError::WebSocket(format!("Upstream handshake failed: {}", e)))?;

        debug!("WebSocket handshake with upstream complete");

        // Wrap client stream as WebSocket
        // Note: In a full implementation, you'd complete the handshake with the client first
        let client_ws = WebSocketStream::from_raw_socket(client_stream, Role::Server, None).await;

        // Proxy messages bidirectionally
        self.proxy_messages(client_ws, upstream_ws).await
    }

    /// Proxy messages between client and upstream WebSocket connections
    async fn proxy_messages<C, U>(
        &self,
        client: WebSocketStream<C>,
        upstream: WebSocketStream<U>,
    ) -> Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (client_tx, client_rx) = client.split();
        let (upstream_tx, upstream_rx) = upstream.split();

        // Forward client -> upstream
        let client_to_upstream = forward_messages(client_rx, upstream_tx, "client->upstream");

        // Forward upstream -> client
        let upstream_to_client = forward_messages(upstream_rx, client_tx, "upstream->client");

        // Wait for either direction to complete
        tokio::select! {
            result = client_to_upstream => {
                if let Err(e) = result {
                    debug!("Client->upstream closed: {}", e);
                }
            }
            result = upstream_to_client => {
                if let Err(e) = result {
                    debug!("Upstream->client closed: {}", e);
                }
            }
        }

        info!("WebSocket proxy session ended");
        Ok(())
    }
}

/// Forward messages from source to sink
async fn forward_messages<S, T>(
    mut source: SplitStream<WebSocketStream<S>>,
    mut sink: SplitSink<WebSocketStream<T>, Message>,
    direction: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    while let Some(msg_result) = source.next().await {
        match msg_result {
            Ok(msg) => {
                match &msg {
                    Message::Close(_) => {
                        debug!("{}: Received close frame", direction);
                        let _ = sink.send(msg).await;
                        break;
                    }
                    Message::Ping(data) => {
                        debug!("{}: Forwarding ping", direction);
                        sink.send(Message::Ping(data.clone())).await.map_err(|e| {
                            PrismError::WebSocket(format!("Failed to send ping: {}", e))
                        })?;
                    }
                    Message::Pong(data) => {
                        debug!("{}: Forwarding pong", direction);
                        sink.send(Message::Pong(data.clone())).await.map_err(|e| {
                            PrismError::WebSocket(format!("Failed to send pong: {}", e))
                        })?;
                    }
                    Message::Text(_) | Message::Binary(_) => {
                        sink.send(msg).await.map_err(|e| {
                            PrismError::WebSocket(format!("Failed to forward message: {}", e))
                        })?;
                    }
                    Message::Frame(_) => {
                        // Raw frames are not typically forwarded
                        debug!("{}: Ignoring raw frame", direction);
                    }
                }
            }
            Err(e) => {
                warn!("{}: Error receiving message: {}", direction, e);
                break;
            }
        }
    }

    // Send close frame
    let _ = sink.close().await;

    Ok(())
}

/// Build a WebSocket request for upstream connection
fn build_websocket_request<B>(
    original: &Request<B>,
    host: &str,
) -> Result<tungstenite::handshake::client::Request> {
    let uri = format!(
        "ws://{}{}",
        host,
        original
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
    );

    let mut request = tungstenite::handshake::client::Request::builder()
        .uri(&uri)
        .body(())
        .map_err(|e| PrismError::WebSocket(format!("Failed to build request: {}", e)))?;

    // Copy relevant headers
    let headers = request.headers_mut();

    // Copy WebSocket-specific headers
    if let Some(key) = original.headers().get("sec-websocket-key") {
        headers.insert("sec-websocket-key", key.clone());
    }
    if let Some(version) = original.headers().get("sec-websocket-version") {
        headers.insert("sec-websocket-version", version.clone());
    }
    if let Some(protocol) = original.headers().get("sec-websocket-protocol") {
        headers.insert("sec-websocket-protocol", protocol.clone());
    }
    if let Some(extensions) = original.headers().get("sec-websocket-extensions") {
        headers.insert("sec-websocket-extensions", extensions.clone());
    }

    Ok(request)
}

/// Create a WebSocket upgrade response
pub fn create_upgrade_response(accept_key: &str) -> Response<()> {
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header("Sec-WebSocket-Accept", accept_key)
        .body(())
        .expect("Failed to build upgrade response")
}

/// Calculate the Sec-WebSocket-Accept value
pub fn calculate_accept_key(key: &str) -> String {
    // Magic GUID from RFC 6455
    const MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    // Concatenate key and magic
    let mut hasher = sha1_smol::Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(MAGIC.as_bytes());

    // Base64 encode the SHA-1 hash
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(hasher.digest().bytes())
}

// Simple SHA1 implementation for WebSocket key calculation
mod sha1_smol {
    pub struct Sha1 {
        state: [u32; 5],
        count: [u32; 2],
        buffer: [u8; 64],
    }

    impl Sha1 {
        pub fn new() -> Self {
            Self {
                state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
                count: [0, 0],
                buffer: [0; 64],
            }
        }

        pub fn update(&mut self, data: &[u8]) {
            let mut i = 0;
            let mut j = ((self.count[0] >> 3) & 63) as usize;

            self.count[0] = self.count[0].wrapping_add((data.len() as u32) << 3);
            if self.count[0] < ((data.len() as u32) << 3) {
                self.count[1] = self.count[1].wrapping_add(1);
            }
            self.count[1] = self.count[1].wrapping_add((data.len() as u32) >> 29);

            let len = data.len();
            while i < len {
                self.buffer[j] = data[i];
                j += 1;
                i += 1;
                if j == 64 {
                    self.transform();
                    j = 0;
                }
            }
        }

        pub fn digest(mut self) -> Digest {
            let mut final_count = [0u8; 8];
            for i in 0..4 {
                final_count[i] = ((self.count[1] >> ((3 - i) * 8)) & 0xFF) as u8;
                final_count[i + 4] = ((self.count[0] >> ((3 - i) * 8)) & 0xFF) as u8;
            }

            self.update(&[0x80]);
            while ((self.count[0] >> 3) & 63) != 56 {
                self.update(&[0x00]);
            }
            self.update(&final_count);

            let mut digest = [0u8; 20];
            for i in 0..5 {
                digest[i * 4] = ((self.state[i] >> 24) & 0xFF) as u8;
                digest[i * 4 + 1] = ((self.state[i] >> 16) & 0xFF) as u8;
                digest[i * 4 + 2] = ((self.state[i] >> 8) & 0xFF) as u8;
                digest[i * 4 + 3] = (self.state[i] & 0xFF) as u8;
            }

            Digest(digest)
        }

        #[allow(clippy::needless_range_loop)]
        fn transform(&mut self) {
            let mut w = [0u32; 80];

            for i in 0..16 {
                w[i] = ((self.buffer[i * 4] as u32) << 24)
                    | ((self.buffer[i * 4 + 1] as u32) << 16)
                    | ((self.buffer[i * 4 + 2] as u32) << 8)
                    | (self.buffer[i * 4 + 3] as u32);
            }

            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }

            let mut a = self.state[0];
            let mut b = self.state[1];
            let mut c = self.state[2];
            let mut d = self.state[3];
            let mut e = self.state[4];

            for i in 0..80 {
                let (f, k) = match i {
                    0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                    20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                    _ => (b ^ c ^ d, 0xCA62C1D6u32),
                };

                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(w[i]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }

            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
        }
    }

    pub struct Digest([u8; 20]);

    impl Digest {
        pub fn bytes(&self) -> [u8; 20] {
            self.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    #[test]
    fn test_is_websocket_upgrade() {
        // Valid WebSocket upgrade request
        let request = Request::builder()
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .unwrap();

        assert!(is_websocket_upgrade(&request));
    }

    #[test]
    fn test_not_websocket_upgrade() {
        // Regular HTTP request
        let request = Request::builder().body(()).unwrap();

        assert!(!is_websocket_upgrade(&request));
    }

    #[test]
    fn test_partial_websocket_headers() {
        // Missing Sec-WebSocket-Key
        let request = Request::builder()
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .body(())
            .unwrap();

        assert!(!is_websocket_upgrade(&request));
    }

    #[test]
    fn test_calculate_accept_key() {
        // Test vector from RFC 6455
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = calculate_accept_key(key);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn test_create_upgrade_response() {
        let accept_key = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        let response = create_upgrade_response(accept_key);

        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            response.headers().get(header::UPGRADE).unwrap(),
            "websocket"
        );
        assert_eq!(
            response.headers().get(header::CONNECTION).unwrap(),
            "Upgrade"
        );
        assert_eq!(
            response.headers().get("Sec-WebSocket-Accept").unwrap(),
            accept_key
        );
    }
}
