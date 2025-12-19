//! Compression middleware for response compression
//!
//! Supports gzip and brotli compression based on Accept-Encoding header

use super::{HttpRequest, HttpResponse, Middleware, Next, RequestContext};
use crate::config::CompressionConfig;
use crate::error::Result;
use async_trait::async_trait;
use brotli::enc::BrotliEncoderParams;
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use http::{header, HeaderValue, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use std::io::Write;
use tracing::debug;

/// Compression algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    Gzip,
    Brotli,
    Identity,
}

impl CompressionAlgorithm {
    /// Get the Content-Encoding header value
    fn as_header_value(&self) -> Option<&'static str> {
        match self {
            Self::Gzip => Some("gzip"),
            Self::Brotli => Some("br"),
            Self::Identity => None,
        }
    }
}

/// Compression middleware
pub struct CompressionMiddleware {
    /// Enable gzip compression
    gzip: bool,
    /// Enable brotli compression
    brotli: bool,
    /// Minimum response size to compress (bytes)
    min_size: usize,
    /// Compression level (1-9 for gzip, 0-11 for brotli)
    level: u32,
}

impl CompressionMiddleware {
    /// Create a new compression middleware
    pub fn new(config: &CompressionConfig) -> Self {
        Self {
            gzip: config.gzip,
            brotli: config.brotli,
            min_size: config.min_size,
            level: 6, // Default compression level
        }
    }

    /// Create with default settings (gzip enabled)
    pub fn default_gzip() -> Self {
        Self {
            gzip: true,
            brotli: false,
            min_size: 1024,
            level: 6,
        }
    }

    /// Create with all compression enabled
    pub fn all() -> Self {
        Self {
            gzip: true,
            brotli: true,
            min_size: 1024,
            level: 6,
        }
    }

    /// Set compression level
    pub fn with_level(mut self, level: u32) -> Self {
        self.level = level.min(11);
        self
    }

    /// Set minimum size threshold
    pub fn with_min_size(mut self, min_size: usize) -> Self {
        self.min_size = min_size;
        self
    }

    /// Parse Accept-Encoding header and determine best algorithm (public for benchmarks)
    pub fn negotiate_encoding_public(&self, accept_encoding: Option<&str>) -> CompressionAlgorithm {
        self.negotiate_encoding(accept_encoding)
    }

    /// Compress data using gzip (public for benchmarks)
    pub fn compress_gzip_public(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.compress_gzip(data)
    }

    /// Compress data using brotli (public for benchmarks)
    pub fn compress_brotli_public(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.compress_brotli(data)
    }

    /// Parse Accept-Encoding header and determine best algorithm
    fn negotiate_encoding(&self, accept_encoding: Option<&str>) -> CompressionAlgorithm {
        let accept = match accept_encoding {
            Some(ae) => ae,
            None => return CompressionAlgorithm::Identity,
        };

        // Parse quality values and sort by preference
        let mut encodings: Vec<(&str, f32)> = accept
            .split(',')
            .filter_map(|part| {
                let mut parts = part.trim().split(';');
                let encoding = parts.next()?.trim();
                let quality = parts
                    .find_map(|p| p.trim().strip_prefix("q=").and_then(|q| q.parse().ok()))
                    .unwrap_or(1.0);
                Some((encoding, quality))
            })
            .collect();

        // Sort by quality (descending)
        encodings.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Find best supported encoding
        for (encoding, quality) in encodings {
            if quality <= 0.0 {
                continue;
            }

            match encoding {
                "br" if self.brotli => return CompressionAlgorithm::Brotli,
                "gzip" if self.gzip => return CompressionAlgorithm::Gzip,
                "*" => {
                    // Wildcard - use best available
                    if self.brotli {
                        return CompressionAlgorithm::Brotli;
                    }
                    if self.gzip {
                        return CompressionAlgorithm::Gzip;
                    }
                }
                _ => continue,
            }
        }

        CompressionAlgorithm::Identity
    }

    /// Check if content type is compressible
    fn is_compressible_content_type(content_type: Option<&str>) -> bool {
        let ct = match content_type {
            Some(ct) => ct.to_lowercase(),
            None => return false,
        };

        // Text types are always compressible
        if ct.starts_with("text/") {
            return true;
        }

        // Common compressible types
        let compressible = [
            "application/json",
            "application/javascript",
            "application/xml",
            "application/xhtml+xml",
            "application/rss+xml",
            "application/atom+xml",
            "application/x-javascript",
            "application/ld+json",
            "image/svg+xml",
            "font/ttf",
            "font/otf",
        ];

        compressible.iter().any(|&c| ct.starts_with(c))
    }

    /// Compress data using gzip
    fn compress_gzip(&self, data: &[u8]) -> Result<Vec<u8>> {
        let level = Compression::new(self.level.min(9));
        let mut encoder = GzEncoder::new(Vec::new(), level);
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    /// Compress data using brotli
    fn compress_brotli(&self, data: &[u8]) -> Result<Vec<u8>> {
        let params = BrotliEncoderParams {
            quality: self.level.min(11) as i32,
            ..Default::default()
        };

        let mut output = Vec::new();
        let mut input = data;

        brotli::BrotliCompress(&mut input, &mut output, &params)?;

        Ok(output)
    }

    /// Compress response body if appropriate
    async fn maybe_compress(
        &self,
        response: HttpResponse,
        algorithm: CompressionAlgorithm,
    ) -> Result<HttpResponse> {
        // Skip if no compression requested
        if algorithm == CompressionAlgorithm::Identity {
            return Ok(response);
        }

        // Check if already compressed
        if response.headers().contains_key(header::CONTENT_ENCODING) {
            debug!("Response already compressed, skipping");
            return Ok(response);
        }

        // Check content type
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());

        if !Self::is_compressible_content_type(content_type) {
            debug!("Content type not compressible: {:?}", content_type);
            return Ok(response);
        }

        // Collect body
        let (parts, body) = response.into_parts();
        let body_bytes = body
            .collect()
            .await
            .expect("Full<Bytes> is infallible")
            .to_bytes();

        // Check minimum size
        if body_bytes.len() < self.min_size {
            debug!(
                "Body too small to compress: {} < {}",
                body_bytes.len(),
                self.min_size
            );
            return Ok(Response::from_parts(parts, Full::new(body_bytes)));
        }

        // Compress
        let compressed = match algorithm {
            CompressionAlgorithm::Gzip => self.compress_gzip(&body_bytes)?,
            CompressionAlgorithm::Brotli => self.compress_brotli(&body_bytes)?,
            CompressionAlgorithm::Identity => unreachable!(),
        };

        // Only use compressed version if smaller
        let original_size = body_bytes.len();
        let compressed_size = compressed.len();

        if compressed_size >= original_size {
            debug!(
                "Compressed size ({}) >= original ({}), skipping",
                compressed_size, original_size
            );
            return Ok(Response::from_parts(parts, Full::new(body_bytes)));
        }

        debug!(
            "Compressed {} -> {} bytes ({:.1}% reduction)",
            original_size,
            compressed_size,
            (1.0 - compressed_size as f64 / original_size as f64) * 100.0
        );

        // Build compressed response
        let mut response = Response::from_parts(parts, Full::new(Bytes::from(compressed)));

        // Update headers
        if let Some(encoding) = algorithm.as_header_value() {
            response
                .headers_mut()
                .insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
        }

        // Remove Content-Length (will be set automatically)
        response.headers_mut().remove(header::CONTENT_LENGTH);

        // Add Vary header
        if let Some(existing_vary) = response.headers().get(header::VARY).cloned() {
            let vary_str = existing_vary.to_str().unwrap_or("");
            if !vary_str.to_lowercase().contains("accept-encoding") {
                let new_vary = format!("{}, Accept-Encoding", vary_str);
                if let Ok(value) = HeaderValue::from_str(&new_vary) {
                    response.headers_mut().insert(header::VARY, value);
                }
            }
        } else {
            response
                .headers_mut()
                .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        }

        Ok(response)
    }
}

#[async_trait]
impl Middleware for CompressionMiddleware {
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        // Get Accept-Encoding before passing request
        let accept_encoding = request
            .headers()
            .get(header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Negotiate encoding
        let algorithm = self.negotiate_encoding(accept_encoding.as_deref());

        // Process request
        let response = next.run(request, ctx).await?;

        // Skip compression for certain status codes
        let status = response.status();
        if status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_MODIFIED
            || status.is_informational()
        {
            return Ok(response);
        }

        // Maybe compress response
        self.maybe_compress(response, algorithm).await
    }

    fn name(&self) -> &'static str {
        "compression"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_middleware() -> CompressionMiddleware {
        CompressionMiddleware::all().with_min_size(10)
    }

    #[test]
    fn test_negotiate_encoding_gzip() {
        let middleware = create_middleware();

        assert_eq!(
            middleware.negotiate_encoding(Some("gzip, deflate")),
            CompressionAlgorithm::Gzip
        );
    }

    #[test]
    fn test_negotiate_encoding_brotli() {
        let middleware = create_middleware();

        assert_eq!(
            middleware.negotiate_encoding(Some("br, gzip")),
            CompressionAlgorithm::Brotli
        );
    }

    #[test]
    fn test_negotiate_encoding_with_quality() {
        let middleware = create_middleware();

        // Gzip preferred over brotli
        assert_eq!(
            middleware.negotiate_encoding(Some("br;q=0.5, gzip;q=1.0")),
            CompressionAlgorithm::Gzip
        );
    }

    #[test]
    fn test_negotiate_encoding_none() {
        let middleware = create_middleware();

        assert_eq!(
            middleware.negotiate_encoding(None),
            CompressionAlgorithm::Identity
        );
    }

    #[test]
    fn test_negotiate_encoding_unsupported() {
        let middleware = create_middleware();

        assert_eq!(
            middleware.negotiate_encoding(Some("deflate")),
            CompressionAlgorithm::Identity
        );
    }

    #[test]
    fn test_negotiate_encoding_gzip_only() {
        let middleware = CompressionMiddleware::default_gzip();

        // Brotli not enabled, should fall back to gzip
        assert_eq!(
            middleware.negotiate_encoding(Some("br, gzip")),
            CompressionAlgorithm::Gzip
        );
    }

    #[test]
    fn test_is_compressible_content_type() {
        assert!(CompressionMiddleware::is_compressible_content_type(Some(
            "text/html"
        )));
        assert!(CompressionMiddleware::is_compressible_content_type(Some(
            "text/plain"
        )));
        assert!(CompressionMiddleware::is_compressible_content_type(Some(
            "application/json"
        )));
        assert!(CompressionMiddleware::is_compressible_content_type(Some(
            "application/javascript"
        )));
        assert!(CompressionMiddleware::is_compressible_content_type(Some(
            "image/svg+xml"
        )));

        assert!(!CompressionMiddleware::is_compressible_content_type(Some(
            "image/png"
        )));
        assert!(!CompressionMiddleware::is_compressible_content_type(Some(
            "video/mp4"
        )));
        assert!(!CompressionMiddleware::is_compressible_content_type(None));
    }

    #[test]
    fn test_gzip_compression() {
        let middleware = create_middleware();
        let data = b"Hello, World! This is a test string for compression.";

        let compressed = middleware.compress_gzip(data).unwrap();
        assert!(!compressed.is_empty());
    }

    #[test]
    fn test_brotli_compression() {
        let middleware = create_middleware();
        let data = b"Hello, World! This is a test string for compression.";

        let compressed = middleware.compress_brotli(data).unwrap();
        assert!(!compressed.is_empty());
    }

    #[test]
    fn test_algorithm_header_value() {
        assert_eq!(CompressionAlgorithm::Gzip.as_header_value(), Some("gzip"));
        assert_eq!(CompressionAlgorithm::Brotli.as_header_value(), Some("br"));
        assert_eq!(CompressionAlgorithm::Identity.as_header_value(), None);
    }

    #[test]
    fn test_negotiate_wildcard() {
        let middleware = create_middleware();

        // Wildcard should use best available (brotli)
        assert_eq!(
            middleware.negotiate_encoding(Some("*")),
            CompressionAlgorithm::Brotli
        );
    }

    #[test]
    fn test_negotiate_zero_quality() {
        let middleware = create_middleware();

        // Zero quality means disabled
        assert_eq!(
            middleware.negotiate_encoding(Some("gzip;q=0, br;q=0")),
            CompressionAlgorithm::Identity
        );
    }
}
