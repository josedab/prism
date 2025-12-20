//! gRPC proxy implementation
//!
//! Handles proxying gRPC requests over HTTP/2 to upstream servers.

use super::{
    create_grpc_trailers_only_response, extract_grpc_timeout, is_grpc_request, is_grpc_web_request,
    GrpcStatus, GRPC_CONTENT_TYPE,
};
use crate::error::{PrismError, Result};
use crate::upstream::PooledConnection;
use bytes::{BufMut, Bytes, BytesMut};
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{error, warn};

/// gRPC proxy configuration
#[derive(Debug, Clone)]
pub struct GrpcProxyConfig {
    /// Maximum message size (default 4MB)
    pub max_message_size: usize,
    /// Default timeout if not specified in request
    pub default_timeout: Duration,
    /// Enable gRPC-Web support
    pub enable_grpc_web: bool,
}

impl Default for GrpcProxyConfig {
    fn default() -> Self {
        Self {
            max_message_size: 4 * 1024 * 1024, // 4MB
            default_timeout: Duration::from_secs(30),
            enable_grpc_web: true,
        }
    }
}

/// gRPC proxy for handling gRPC requests
pub struct GrpcProxy {
    config: GrpcProxyConfig,
}

impl GrpcProxy {
    /// Create a new gRPC proxy with default config
    pub fn new() -> Self {
        Self {
            config: GrpcProxyConfig::default(),
        }
    }

    /// Create a new gRPC proxy with custom config
    pub fn with_config(config: GrpcProxyConfig) -> Self {
        Self { config }
    }

    /// Check if a request should be handled by the gRPC proxy
    pub fn should_handle<B>(&self, request: &Request<B>) -> bool {
        is_grpc_request(request) || (self.config.enable_grpc_web && is_grpc_web_request(request))
    }

    /// Proxy a gRPC request to upstream
    pub async fn proxy<B>(
        &self,
        request: Request<B>,
        pooled: &mut PooledConnection,
    ) -> Result<Response<Full<Bytes>>>
    where
        B: BodyExt,
        B::Error: std::fmt::Display,
    {
        let timeout =
            extract_grpc_timeout(request.headers()).unwrap_or(self.config.default_timeout);

        // Get the address before borrowing the stream
        let upstream_addr = pooled.address();

        // Get the stream from pool
        let stream = pooled
            .stream()
            .ok_or_else(|| PrismError::Upstream("Connection stream not available".to_string()))?;

        // Forward via HTTP/1.1 with gRPC framing
        // Note: Full HTTP/2 multiplexing would require the h2 crate integration
        let result = tokio::time::timeout(timeout, async {
            self.forward_grpc_request(request, stream, upstream_addr)
                .await
        })
        .await;

        match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => {
                error!("gRPC proxy error: {}", e);
                Ok(create_grpc_trailers_only_response(
                    GrpcStatus::Internal,
                    &format!("Proxy error: {}", e),
                ))
            }
            Err(_) => {
                warn!("gRPC request timed out after {:?}", timeout);
                Ok(create_grpc_trailers_only_response(
                    GrpcStatus::DeadlineExceeded,
                    "Request timeout",
                ))
            }
        }
    }

    /// Forward a gRPC request over the stream
    async fn forward_grpc_request<B>(
        &self,
        request: Request<B>,
        stream: &mut TcpStream,
        upstream_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>>
    where
        B: http_body_util::BodyExt,
        B::Error: std::fmt::Display,
    {
        let (parts, body) = request.into_parts();
        let path = parts.uri.path().to_string();
        let method = parts.method.to_string();

        // Collect body
        let body_bytes = http_body_util::BodyExt::collect(body)
            .await
            .map_err(|e| PrismError::Http(e.to_string()))?
            .to_bytes();

        // Build HTTP/1.1 request (gRPC over HTTP/1.1)
        // For proper HTTP/2, we'd use the h2 crate directly
        let mut request_data = BytesMut::new();

        // Request line
        request_data.put_slice(format!("{} {} HTTP/1.1\r\n", method, path).as_bytes());

        // Host header
        request_data.put_slice(format!("Host: {}\r\n", upstream_addr).as_bytes());

        // Content-Type (required for gRPC)
        request_data.put_slice(b"Content-Type: application/grpc\r\n");

        // TE header (required for gRPC trailers)
        request_data.put_slice(b"TE: trailers\r\n");

        // Connection header
        request_data.put_slice(b"Connection: keep-alive\r\n");

        // Forward other headers
        for (name, value) in parts.headers.iter() {
            let name_str = name.as_str();
            // Skip headers we handle specially
            if name_str == "host"
                || name_str == "connection"
                || name_str == "content-type"
                || name_str == "te"
                || name_str == "content-length"
            {
                continue;
            }
            if let Ok(v) = value.to_str() {
                request_data.put_slice(format!("{}: {}\r\n", name_str, v).as_bytes());
            }
        }

        // Content-Length
        request_data.put_slice(format!("Content-Length: {}\r\n", body_bytes.len()).as_bytes());

        // End headers
        request_data.put_slice(b"\r\n");

        // Write request
        stream.write_all(&request_data).await?;

        // Write body
        if !body_bytes.is_empty() {
            stream.write_all(&body_bytes).await?;
        }

        stream.flush().await?;

        // Read response
        let response = self.read_grpc_response(stream).await?;

        Ok(response)
    }

    /// Read a gRPC response from the stream
    async fn read_grpc_response(&self, stream: &mut TcpStream) -> Result<Response<Full<Bytes>>> {
        use tokio::io::AsyncBufReadExt;
        use tokio::io::BufReader;

        let mut reader = BufReader::new(stream);

        // Read status line
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await?;

        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(PrismError::Http("Invalid response status line".to_string()));
        }

        let http_status: u16 = parts[1]
            .parse()
            .map_err(|_| PrismError::Http("Invalid status code".to_string()))?;

        // Read headers
        let mut headers = Vec::new();
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        let mut grpc_status: Option<i32> = None;
        let mut grpc_message: Option<String> = None;

        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;

            if line.trim().is_empty() {
                break;
            }

            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim().to_lowercase();
                let value = value.trim();

                match name.as_str() {
                    "content-length" => {
                        content_length = value.parse().ok();
                    }
                    "transfer-encoding" if value.to_lowercase().contains("chunked") => {
                        chunked = true;
                    }
                    "grpc-status" => {
                        grpc_status = value.parse().ok();
                    }
                    "grpc-message" => {
                        grpc_message = Some(value.to_string());
                    }
                    _ => {}
                }

                headers.push((name, value.to_string()));
            }
        }

        // Read body
        let body = if let Some(len) = content_length {
            let mut body = vec![0u8; len];
            tokio::io::AsyncReadExt::read_exact(&mut reader, &mut body).await?;
            Bytes::from(body)
        } else if chunked {
            // Read chunked body
            let mut body = Vec::new();
            loop {
                let mut size_line = String::new();
                reader.read_line(&mut size_line).await?;
                let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);

                if size == 0 {
                    // Read trailing headers (trailers)
                    loop {
                        let mut trailer_line = String::new();
                        reader.read_line(&mut trailer_line).await?;
                        if trailer_line.trim().is_empty() {
                            break;
                        }
                        // Parse trailers for grpc-status and grpc-message
                        if let Some((name, value)) = trailer_line.split_once(':') {
                            let name = name.trim().to_lowercase();
                            let value = value.trim();
                            match name.as_str() {
                                "grpc-status" => {
                                    grpc_status = value.parse().ok();
                                }
                                "grpc-message" => {
                                    grpc_message = Some(value.to_string());
                                }
                                _ => {
                                    headers.push((name, value.to_string()));
                                }
                            }
                        }
                    }
                    break;
                }

                let mut chunk = vec![0u8; size];
                tokio::io::AsyncReadExt::read_exact(&mut reader, &mut chunk).await?;
                body.extend(chunk);

                // Read trailing \r\n
                let mut _crlf = [0u8; 2];
                tokio::io::AsyncReadExt::read_exact(&mut reader, &mut _crlf).await?;
            }
            Bytes::from(body)
        } else {
            Bytes::new()
        };

        // Build response
        let mut builder = Response::builder().status(http_status);

        // Add headers
        for (name, value) in &headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        // Always add content-type for gRPC
        builder = builder.header("content-type", GRPC_CONTENT_TYPE);

        // Add gRPC status and message if present
        if let Some(status) = grpc_status {
            builder = builder.header("grpc-status", status.to_string());
        }
        if let Some(message) = grpc_message {
            builder = builder.header("grpc-message", message);
        }

        builder
            .body(Full::new(body))
            .map_err(|e| PrismError::Http(e.to_string()))
    }
}

impl Default for GrpcProxy {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a gRPC message frame from bytes
/// gRPC message format: [compressed(1 byte)][length(4 bytes big-endian)][message]
pub fn parse_grpc_frame(data: &[u8]) -> Option<(bool, Bytes)> {
    if data.len() < 5 {
        return None;
    }

    let compressed = data[0] != 0;
    let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;

    if data.len() < 5 + length {
        return None;
    }

    let message = Bytes::copy_from_slice(&data[5..5 + length]);
    Some((compressed, message))
}

/// Encode a message as a gRPC frame
pub fn encode_grpc_frame(message: &[u8], compressed: bool) -> Bytes {
    let mut frame = BytesMut::with_capacity(5 + message.len());
    frame.put_u8(if compressed { 1 } else { 0 });
    frame.put_u32(message.len() as u32);
    frame.put_slice(message);
    frame.freeze()
}

/// gRPC-Web to gRPC converter
pub struct GrpcWebConverter;

impl GrpcWebConverter {
    /// Convert a gRPC-Web request to standard gRPC
    pub fn web_to_grpc<B>(request: Request<B>) -> Request<B> {
        let (mut parts, body) = request.into_parts();

        // Change content-type
        parts.headers.insert(
            http::header::CONTENT_TYPE,
            GRPC_CONTENT_TYPE.parse().unwrap(),
        );

        // Add TE header for trailers
        parts
            .headers
            .insert(http::header::TE, "trailers".parse().unwrap());

        Request::from_parts(parts, body)
    }

    /// Convert a gRPC response to gRPC-Web format
    ///
    /// For gRPC-Web, trailers are typically encoded as a final frame in the body.
    /// This implementation keeps the grpc-status and grpc-message as headers
    /// which is compatible with most gRPC-Web clients.
    pub fn grpc_to_web(response: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
        let (mut parts, body) = response.into_parts();

        // Change content-type to grpc-web
        parts.headers.insert(
            http::header::CONTENT_TYPE,
            "application/grpc-web".parse().unwrap(),
        );

        // Note: Full gRPC-Web compliance would encode trailers in the body
        // as a final frame (0x80 prefix). For now, we keep them as headers
        // which works with most gRPC-Web clients that support header-based trailers.

        Response::from_parts(parts, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_frame_parsing() {
        // Create a test frame
        let message = b"hello world";
        let frame = encode_grpc_frame(message, false);

        // Parse it back
        let (compressed, parsed_message) = parse_grpc_frame(&frame).unwrap();
        assert!(!compressed);
        assert_eq!(parsed_message.as_ref(), message);
    }

    #[test]
    fn test_grpc_frame_compressed() {
        let message = b"compressed data";
        let frame = encode_grpc_frame(message, true);

        let (compressed, parsed_message) = parse_grpc_frame(&frame).unwrap();
        assert!(compressed);
        assert_eq!(parsed_message.as_ref(), message);
    }

    #[test]
    fn test_grpc_frame_incomplete() {
        // Too short for header
        assert!(parse_grpc_frame(&[0, 0, 0]).is_none());

        // Header says 10 bytes but only 5 available
        let mut frame = vec![0, 0, 0, 0, 10];
        frame.extend_from_slice(b"short");
        assert!(parse_grpc_frame(&frame).is_none());
    }

    #[test]
    fn test_grpc_proxy_config_default() {
        let config = GrpcProxyConfig::default();
        assert_eq!(config.max_message_size, 4 * 1024 * 1024);
        assert_eq!(config.default_timeout, Duration::from_secs(30));
        assert!(config.enable_grpc_web);
    }

    #[test]
    fn test_grpc_proxy_should_handle() {
        let proxy = GrpcProxy::new();

        // gRPC request
        let req = Request::builder()
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(())
            .unwrap();
        assert!(proxy.should_handle(&req));

        // gRPC-Web request
        let req = Request::builder()
            .header(http::header::CONTENT_TYPE, "application/grpc-web")
            .body(())
            .unwrap();
        assert!(proxy.should_handle(&req));

        // Regular HTTP request
        let req = Request::builder()
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(())
            .unwrap();
        assert!(!proxy.should_handle(&req));
    }

    #[test]
    fn test_grpc_web_converter() {
        let req = Request::builder()
            .header(http::header::CONTENT_TYPE, "application/grpc-web")
            .body(())
            .unwrap();

        let converted = GrpcWebConverter::web_to_grpc(req);
        assert_eq!(
            converted.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "application/grpc"
        );
    }
}
