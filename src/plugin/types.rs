//! Plugin type definitions for the WASM ABI
//!
//! Defines the interface between the host (Prism) and guest (WASM plugins).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Memory allocation request from guest
#[derive(Debug, Clone)]
pub struct MemoryRequest {
    /// Requested size in bytes
    pub size: u32,
    /// Alignment requirement
    pub align: u32,
}

/// Memory allocation response to guest
#[derive(Debug, Clone)]
pub struct MemoryResponse {
    /// Pointer to allocated memory (guest address space)
    pub ptr: u32,
    /// Actual allocated size
    pub size: u32,
}

/// String passing between host and guest
#[derive(Debug, Clone)]
pub struct GuestString {
    /// Pointer to string data
    pub ptr: u32,
    /// Length of string (not null-terminated)
    pub len: u32,
}

impl GuestString {
    pub fn new(ptr: u32, len: u32) -> Self {
        Self { ptr, len }
    }
}

/// Buffer passing between host and guest
#[derive(Debug, Clone)]
pub struct GuestBuffer {
    /// Pointer to buffer data
    pub ptr: u32,
    /// Length of buffer
    pub len: u32,
    /// Capacity of buffer
    pub cap: u32,
}

impl GuestBuffer {
    pub fn new(ptr: u32, len: u32, cap: u32) -> Self {
        Self { ptr, len, cap }
    }
}

/// Header map representation for WASM ABI
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeaderMap {
    pub headers: Vec<(String, String)>,
}

impl HeaderMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: String, value: String) {
        // Check for existing header (case-insensitive)
        let key_lower = key.to_lowercase();
        for (k, v) in &mut self.headers {
            if k.to_lowercase() == key_lower {
                *v = value;
                return;
            }
        }
        self.headers.push((key, value));
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        let key_lower = key.to_lowercase();
        for (k, v) in &self.headers {
            if k.to_lowercase() == key_lower {
                return Some(v);
            }
        }
        None
    }

    pub fn remove(&mut self, key: &str) -> Option<String> {
        let key_lower = key.to_lowercase();
        let pos = self
            .headers
            .iter()
            .position(|(k, _)| k.to_lowercase() == key_lower);
        pos.map(|i| self.headers.remove(i).1)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Serialize to bytes for WASM transfer
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

impl From<HashMap<String, String>> for HeaderMap {
    fn from(map: HashMap<String, String>) -> Self {
        Self {
            headers: map.into_iter().collect(),
        }
    }
}

impl From<HeaderMap> for HashMap<String, String> {
    fn from(map: HeaderMap) -> Self {
        map.headers.into_iter().collect()
    }
}

/// Request metadata passed to plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetadata {
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// Query string (if any)
    pub query: Option<String>,
    /// HTTP version
    pub http_version: String,
    /// Client IP address
    pub client_ip: Option<String>,
    /// Request ID
    pub request_id: Option<String>,
}

impl RequestMetadata {
    pub fn new(method: String, path: String) -> Self {
        Self {
            method,
            path,
            query: None,
            http_version: "HTTP/1.1".to_string(),
            client_ip: None,
            request_id: None,
        }
    }

    /// Serialize to bytes for WASM transfer
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// Response metadata passed to plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetadata {
    /// HTTP status code
    pub status_code: u16,
    /// Status message
    pub status_message: Option<String>,
    /// Response size in bytes
    pub body_size: Option<u64>,
    /// Response latency in milliseconds
    pub latency_ms: Option<u64>,
}

impl ResponseMetadata {
    pub fn new(status_code: u16) -> Self {
        Self {
            status_code,
            status_message: None,
            body_size: None,
            latency_ms: None,
        }
    }

    /// Serialize to bytes for WASM transfer
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// Plugin capabilities declaration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginCapabilities {
    /// Plugin name
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Required host functions
    pub required_host_functions: Vec<String>,
    /// Supported phases
    pub supported_phases: Vec<String>,
    /// Maximum memory needed
    pub max_memory_bytes: Option<u64>,
}

/// Host function IDs for the ABI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HostFunction {
    // Header operations
    GetRequestHeader = 1,
    SetRequestHeader = 2,
    RemoveRequestHeader = 3,
    GetResponseHeader = 4,
    SetResponseHeader = 5,
    RemoveResponseHeader = 6,

    // Body operations
    GetRequestBody = 10,
    SetRequestBody = 11,
    GetResponseBody = 12,
    SetResponseBody = 13,

    // Property operations
    GetProperty = 20,
    SetProperty = 21,

    // Logging
    Log = 30,

    // Configuration
    GetPluginConfig = 40,

    // Memory management
    Alloc = 50,
    Free = 51,

    // HTTP client (for subrequests)
    HttpCall = 60,

    // Shared state
    GetSharedData = 70,
    SetSharedData = 71,
}

impl From<u32> for HostFunction {
    fn from(value: u32) -> Self {
        match value {
            1 => HostFunction::GetRequestHeader,
            2 => HostFunction::SetRequestHeader,
            3 => HostFunction::RemoveRequestHeader,
            4 => HostFunction::GetResponseHeader,
            5 => HostFunction::SetResponseHeader,
            6 => HostFunction::RemoveResponseHeader,
            10 => HostFunction::GetRequestBody,
            11 => HostFunction::SetRequestBody,
            12 => HostFunction::GetResponseBody,
            13 => HostFunction::SetResponseBody,
            20 => HostFunction::GetProperty,
            21 => HostFunction::SetProperty,
            30 => HostFunction::Log,
            40 => HostFunction::GetPluginConfig,
            50 => HostFunction::Alloc,
            51 => HostFunction::Free,
            60 => HostFunction::HttpCall,
            70 => HostFunction::GetSharedData,
            71 => HostFunction::SetSharedData,
            _ => HostFunction::Log, // Default fallback
        }
    }
}

/// Error codes returned to plugins
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum PluginError {
    /// Operation succeeded
    Ok = 0,
    /// Header/property not found
    NotFound = 1,
    /// Invalid argument
    InvalidArgument = 2,
    /// Buffer too small
    BufferTooSmall = 3,
    /// Internal error
    InternalError = 4,
    /// Operation not supported
    NotSupported = 5,
    /// Permission denied
    PermissionDenied = 6,
    /// Resource exhausted
    ResourceExhausted = 7,
}

impl From<i32> for PluginError {
    fn from(value: i32) -> Self {
        match value {
            0 => PluginError::Ok,
            1 => PluginError::NotFound,
            2 => PluginError::InvalidArgument,
            3 => PluginError::BufferTooSmall,
            4 => PluginError::InternalError,
            5 => PluginError::NotSupported,
            6 => PluginError::PermissionDenied,
            7 => PluginError::ResourceExhausted,
            _ => PluginError::InternalError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_map() {
        let mut map = HeaderMap::new();
        map.insert("Content-Type".to_string(), "application/json".to_string());
        map.insert("Accept".to_string(), "*/*".to_string());

        assert_eq!(map.get("Content-Type"), Some("application/json"));
        assert_eq!(map.get("content-type"), Some("application/json")); // Case insensitive

        // Update existing
        map.insert("content-type".to_string(), "text/plain".to_string());
        assert_eq!(map.get("Content-Type"), Some("text/plain"));

        // Remove
        let removed = map.remove("Accept");
        assert_eq!(removed, Some("*/*".to_string()));
        assert_eq!(map.get("Accept"), None);
    }

    #[test]
    fn test_header_map_serialization() {
        let mut map = HeaderMap::new();
        map.insert("X-Custom".to_string(), "value".to_string());

        let bytes = map.to_bytes();
        let restored = HeaderMap::from_bytes(&bytes).unwrap();

        assert_eq!(restored.get("X-Custom"), Some("value"));
    }

    #[test]
    fn test_request_metadata() {
        let meta = RequestMetadata::new("GET".to_string(), "/api/users".to_string());

        let bytes = meta.to_bytes();
        let restored = RequestMetadata::from_bytes(&bytes).unwrap();

        assert_eq!(restored.method, "GET");
        assert_eq!(restored.path, "/api/users");
    }

    #[test]
    fn test_response_metadata() {
        let mut meta = ResponseMetadata::new(200);
        meta.latency_ms = Some(42);

        let bytes = meta.to_bytes();
        let restored = ResponseMetadata::from_bytes(&bytes).unwrap();

        assert_eq!(restored.status_code, 200);
        assert_eq!(restored.latency_ms, Some(42));
    }

    #[test]
    fn test_host_function_conversion() {
        assert_eq!(HostFunction::from(1), HostFunction::GetRequestHeader);
        assert_eq!(HostFunction::from(30), HostFunction::Log);
    }

    #[test]
    fn test_plugin_error_conversion() {
        assert_eq!(PluginError::from(0), PluginError::Ok);
        assert_eq!(PluginError::from(1), PluginError::NotFound);
        assert_eq!(PluginError::from(99), PluginError::InternalError);
    }

    #[test]
    fn test_guest_string() {
        let s = GuestString::new(0x1000, 10);
        assert_eq!(s.ptr, 0x1000);
        assert_eq!(s.len, 10);
    }

    #[test]
    fn test_guest_buffer() {
        let buf = GuestBuffer::new(0x2000, 50, 100);
        assert_eq!(buf.ptr, 0x2000);
        assert_eq!(buf.len, 50);
        assert_eq!(buf.cap, 100);
    }

    #[test]
    fn test_header_map_from_hashmap() {
        let mut hm = HashMap::new();
        hm.insert("Key1".to_string(), "Value1".to_string());
        hm.insert("Key2".to_string(), "Value2".to_string());

        let map: HeaderMap = hm.into();
        assert!(map.get("Key1").is_some());
        assert!(map.get("Key2").is_some());

        let back: HashMap<String, String> = map.into();
        assert_eq!(back.get("Key1"), Some(&"Value1".to_string()));
    }
}
