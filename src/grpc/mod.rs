//! gRPC proxy support
//!
//! Provides HTTP/2-based gRPC proxying capabilities including:
//! - gRPC request detection
//! - Bidirectional streaming
//! - gRPC trailers and status handling
//! - gRPC-Web support

mod proxy;

pub use proxy::*;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use http_body_util::Full;
use std::time::Duration;

/// gRPC content types
pub const GRPC_CONTENT_TYPE: &str = "application/grpc";
pub const GRPC_WEB_CONTENT_TYPE: &str = "application/grpc-web";
pub const GRPC_WEB_TEXT_CONTENT_TYPE: &str = "application/grpc-web-text";

/// gRPC status codes (as defined in gRPC specification)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum GrpcStatus {
    /// Not an error; returned on success
    Ok = 0,
    /// The operation was cancelled (typically by the caller)
    Cancelled = 1,
    /// Unknown error
    Unknown = 2,
    /// Client specified an invalid argument
    InvalidArgument = 3,
    /// Deadline expired before operation could complete
    DeadlineExceeded = 4,
    /// Some requested entity was not found
    NotFound = 5,
    /// Entity already exists
    AlreadyExists = 6,
    /// The caller does not have permission to execute the operation
    PermissionDenied = 7,
    /// Some resource has been exhausted
    ResourceExhausted = 8,
    /// The request does not have valid authentication credentials
    FailedPrecondition = 9,
    /// The operation was aborted
    Aborted = 10,
    /// Operation was attempted past the valid range
    OutOfRange = 11,
    /// Operation is not implemented
    Unimplemented = 12,
    /// Internal error
    Internal = 13,
    /// The service is currently unavailable
    Unavailable = 14,
    /// Unrecoverable data loss or corruption
    DataLoss = 15,
    /// The request does not have valid authentication credentials
    Unauthenticated = 16,
}

impl GrpcStatus {
    /// Create from integer value
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => GrpcStatus::Ok,
            1 => GrpcStatus::Cancelled,
            2 => GrpcStatus::Unknown,
            3 => GrpcStatus::InvalidArgument,
            4 => GrpcStatus::DeadlineExceeded,
            5 => GrpcStatus::NotFound,
            6 => GrpcStatus::AlreadyExists,
            7 => GrpcStatus::PermissionDenied,
            8 => GrpcStatus::ResourceExhausted,
            9 => GrpcStatus::FailedPrecondition,
            10 => GrpcStatus::Aborted,
            11 => GrpcStatus::OutOfRange,
            12 => GrpcStatus::Unimplemented,
            13 => GrpcStatus::Internal,
            14 => GrpcStatus::Unavailable,
            15 => GrpcStatus::DataLoss,
            16 => GrpcStatus::Unauthenticated,
            _ => GrpcStatus::Unknown,
        }
    }

    /// Convert to HTTP status code (for fallback)
    pub fn to_http_status(self) -> StatusCode {
        match self {
            GrpcStatus::Ok => StatusCode::OK,
            GrpcStatus::Cancelled => StatusCode::from_u16(499).unwrap_or(StatusCode::BAD_REQUEST),
            GrpcStatus::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
            GrpcStatus::InvalidArgument => StatusCode::BAD_REQUEST,
            GrpcStatus::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
            GrpcStatus::NotFound => StatusCode::NOT_FOUND,
            GrpcStatus::AlreadyExists => StatusCode::CONFLICT,
            GrpcStatus::PermissionDenied => StatusCode::FORBIDDEN,
            GrpcStatus::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
            GrpcStatus::FailedPrecondition => StatusCode::PRECONDITION_FAILED,
            GrpcStatus::Aborted => StatusCode::CONFLICT,
            GrpcStatus::OutOfRange => StatusCode::BAD_REQUEST,
            GrpcStatus::Unimplemented => StatusCode::NOT_IMPLEMENTED,
            GrpcStatus::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            GrpcStatus::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            GrpcStatus::DataLoss => StatusCode::INTERNAL_SERVER_ERROR,
            GrpcStatus::Unauthenticated => StatusCode::UNAUTHORIZED,
        }
    }

    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            GrpcStatus::Ok => "OK",
            GrpcStatus::Cancelled => "CANCELLED",
            GrpcStatus::Unknown => "UNKNOWN",
            GrpcStatus::InvalidArgument => "INVALID_ARGUMENT",
            GrpcStatus::DeadlineExceeded => "DEADLINE_EXCEEDED",
            GrpcStatus::NotFound => "NOT_FOUND",
            GrpcStatus::AlreadyExists => "ALREADY_EXISTS",
            GrpcStatus::PermissionDenied => "PERMISSION_DENIED",
            GrpcStatus::ResourceExhausted => "RESOURCE_EXHAUSTED",
            GrpcStatus::FailedPrecondition => "FAILED_PRECONDITION",
            GrpcStatus::Aborted => "ABORTED",
            GrpcStatus::OutOfRange => "OUT_OF_RANGE",
            GrpcStatus::Unimplemented => "UNIMPLEMENTED",
            GrpcStatus::Internal => "INTERNAL",
            GrpcStatus::Unavailable => "UNAVAILABLE",
            GrpcStatus::DataLoss => "DATA_LOSS",
            GrpcStatus::Unauthenticated => "UNAUTHENTICATED",
        }
    }
}

impl std::fmt::Display for GrpcStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Check if a request is a gRPC request
pub fn is_grpc_request<B>(request: &Request<B>) -> bool {
    request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with(GRPC_CONTENT_TYPE))
        .unwrap_or(false)
}

/// Check if a request is a gRPC-Web request
pub fn is_grpc_web_request<B>(request: &Request<B>) -> bool {
    request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            ct.starts_with(GRPC_WEB_CONTENT_TYPE) || ct.starts_with(GRPC_WEB_TEXT_CONTENT_TYPE)
        })
        .unwrap_or(false)
}

/// Extract gRPC timeout from headers (grpc-timeout header)
/// Format: `<value><unit>` where unit is H (hours), M (minutes), S (seconds),
/// m (milliseconds), u (microseconds), n (nanoseconds)
pub fn extract_grpc_timeout(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get("grpc-timeout")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_grpc_timeout)
}

/// Parse gRPC timeout string
fn parse_grpc_timeout(s: &str) -> Option<Duration> {
    if s.is_empty() {
        return None;
    }

    let (value_str, unit) = s.split_at(s.len() - 1);
    let value: u64 = value_str.parse().ok()?;

    match unit {
        "H" => Some(Duration::from_secs(value * 3600)),
        "M" => Some(Duration::from_secs(value * 60)),
        "S" => Some(Duration::from_secs(value)),
        "m" => Some(Duration::from_millis(value)),
        "u" => Some(Duration::from_micros(value)),
        "n" => Some(Duration::from_nanos(value)),
        _ => None,
    }
}

/// Format duration as gRPC timeout string
#[allow(clippy::manual_is_multiple_of)]
pub fn format_grpc_timeout(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis == 0 {
        return "0m".to_string();
    }

    // Use the most appropriate unit
    if millis >= 3600000 && millis % 3600000 == 0 {
        format!("{}H", millis / 3600000)
    } else if millis >= 60000 && millis % 60000 == 0 {
        format!("{}M", millis / 60000)
    } else if millis >= 1000 && millis % 1000 == 0 {
        format!("{}S", millis / 1000)
    } else {
        format!("{}m", millis)
    }
}

/// Create a gRPC error response with trailers
pub fn create_grpc_error_response(status: GrpcStatus, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK) // gRPC uses HTTP 200 with trailers for errors
        .header(http::header::CONTENT_TYPE, GRPC_CONTENT_TYPE)
        .header("grpc-status", (status as i32).to_string())
        .header("grpc-message", percent_encode_message(message))
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// Create a gRPC trailers-only response (for immediate errors)
pub fn create_grpc_trailers_only_response(
    status: GrpcStatus,
    message: &str,
) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, GRPC_CONTENT_TYPE)
        .header("grpc-status", (status as i32).to_string())
        .header("grpc-message", percent_encode_message(message))
        .header("trailer", "grpc-status, grpc-message")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// Percent-encode a gRPC message for the grpc-message header
fn percent_encode_message(message: &str) -> String {
    // gRPC uses percent-encoding for the message
    message
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}

/// Decode a percent-encoded gRPC message
pub fn percent_decode_message(encoded: &str) -> String {
    let mut result = String::new();
    let mut chars = encoded.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let mut hex = String::new();
            if let Some(h1) = chars.next() {
                hex.push(h1);
            }
            if let Some(h2) = chars.next() {
                hex.push(h2);
            }
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// gRPC metadata (headers and trailers)
#[derive(Debug, Clone, Default)]
pub struct GrpcMetadata {
    /// Regular headers (non-binary)
    pub headers: Vec<(String, String)>,
    /// Binary headers (base64 encoded, key ends with -bin)
    pub binary_headers: Vec<(String, Vec<u8>)>,
}

impl GrpcMetadata {
    /// Create new empty metadata
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a text header
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.headers.push((key.into(), value.into()));
    }

    /// Add a binary header (will be base64 encoded)
    pub fn insert_binary(&mut self, key: impl Into<String>, value: Vec<u8>) {
        let mut key = key.into();
        if !key.ends_with("-bin") {
            key.push_str("-bin");
        }
        self.binary_headers.push((key, value));
    }

    /// Extract metadata from HTTP headers
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let mut metadata = Self::new();

        for (name, value) in headers.iter() {
            let name_str = name.as_str();
            // Skip pseudo-headers and standard HTTP headers
            if name_str.starts_with(':')
                || name_str == "content-type"
                || name_str == "te"
                || name_str == "user-agent"
            {
                continue;
            }

            if name_str.ends_with("-bin") {
                // Binary metadata (base64 encoded)
                if let Ok(value_str) = value.to_str() {
                    if let Ok(decoded) = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        value_str,
                    ) {
                        metadata
                            .binary_headers
                            .push((name_str.to_string(), decoded));
                    }
                }
            } else if let Ok(value_str) = value.to_str() {
                metadata
                    .headers
                    .push((name_str.to_string(), value_str.to_string()));
            }
        }

        metadata
    }

    /// Convert metadata to HTTP headers
    pub fn to_header_map(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();

        for (key, value) in &self.headers {
            if let (Ok(name), Ok(val)) = (
                http::header::HeaderName::try_from(key.as_str()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(name, val);
            }
        }

        for (key, value) in &self.binary_headers {
            let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, value);
            if let (Ok(name), Ok(val)) = (
                http::header::HeaderName::try_from(key.as_str()),
                HeaderValue::from_str(&encoded),
            ) {
                headers.insert(name, val);
            }
        }

        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_grpc_request() {
        let req = Request::builder()
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(())
            .unwrap();
        assert!(is_grpc_request(&req));

        let req = Request::builder()
            .header(http::header::CONTENT_TYPE, "application/grpc+proto")
            .body(())
            .unwrap();
        assert!(is_grpc_request(&req));

        let req = Request::builder()
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(())
            .unwrap();
        assert!(!is_grpc_request(&req));
    }

    #[test]
    fn test_is_grpc_web_request() {
        let req = Request::builder()
            .header(http::header::CONTENT_TYPE, "application/grpc-web")
            .body(())
            .unwrap();
        assert!(is_grpc_web_request(&req));

        let req = Request::builder()
            .header(http::header::CONTENT_TYPE, "application/grpc-web-text")
            .body(())
            .unwrap();
        assert!(is_grpc_web_request(&req));
    }

    #[test]
    fn test_grpc_timeout_parsing() {
        assert_eq!(parse_grpc_timeout("1H"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_grpc_timeout("30M"), Some(Duration::from_secs(1800)));
        assert_eq!(parse_grpc_timeout("5S"), Some(Duration::from_secs(5)));
        assert_eq!(parse_grpc_timeout("500m"), Some(Duration::from_millis(500)));
        assert_eq!(
            parse_grpc_timeout("1000u"),
            Some(Duration::from_micros(1000))
        );
        assert_eq!(
            parse_grpc_timeout("1000000n"),
            Some(Duration::from_nanos(1000000))
        );
        assert_eq!(parse_grpc_timeout("invalid"), None);
    }

    #[test]
    fn test_grpc_timeout_formatting() {
        assert_eq!(format_grpc_timeout(Duration::from_secs(3600)), "1H");
        assert_eq!(format_grpc_timeout(Duration::from_secs(60)), "1M");
        assert_eq!(format_grpc_timeout(Duration::from_secs(5)), "5S");
        assert_eq!(format_grpc_timeout(Duration::from_millis(500)), "500m");
    }

    #[test]
    fn test_grpc_status_conversion() {
        assert_eq!(GrpcStatus::from_i32(0), GrpcStatus::Ok);
        assert_eq!(GrpcStatus::from_i32(14), GrpcStatus::Unavailable);
        assert_eq!(GrpcStatus::from_i32(999), GrpcStatus::Unknown);

        assert_eq!(GrpcStatus::Ok.to_http_status(), StatusCode::OK);
        assert_eq!(GrpcStatus::NotFound.to_http_status(), StatusCode::NOT_FOUND);
        assert_eq!(
            GrpcStatus::Unavailable.to_http_status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn test_percent_encoding() {
        let original = "Hello World!";
        let encoded = percent_encode_message(original);
        let decoded = percent_decode_message(&encoded);
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_grpc_metadata() {
        let mut metadata = GrpcMetadata::new();
        metadata.insert("x-custom-header", "value");
        metadata.insert_binary("x-binary", vec![1, 2, 3, 4]);

        assert_eq!(metadata.headers.len(), 1);
        assert_eq!(metadata.binary_headers.len(), 1);
        assert!(metadata.binary_headers[0].0.ends_with("-bin"));

        let header_map = metadata.to_header_map();
        assert!(header_map.contains_key("x-custom-header"));
        assert!(header_map.contains_key("x-binary-bin"));
    }
}
