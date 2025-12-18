//! Access logging implementation

use crate::config::{AccessLogConfig, LogFormat};
use crate::error::{PrismError, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::Mutex;
use std::time::Duration;

/// Access log entry
#[derive(Debug, Clone, Serialize)]
pub struct AccessLogEntry {
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Request ID
    pub request_id: String,
    /// Client IP address
    pub client_ip: String,
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// HTTP version
    pub http_version: String,
    /// Response status code
    pub status: u16,
    /// Response body size in bytes
    pub response_size: u64,
    /// Request duration in milliseconds
    pub duration_ms: u64,
    /// Upstream name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    /// Upstream server address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_server: Option<String>,
    /// Upstream response time in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_duration_ms: Option<u64>,
    /// User agent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Referer header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referer: Option<String>,
    /// Host header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// X-Forwarded-For header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_forwarded_for: Option<String>,
    /// TLS version (if TLS)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    /// Error message (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AccessLogEntry {
    /// Create a new access log entry
    pub fn new(request_id: String, client_ip: String) -> Self {
        Self {
            timestamp: Utc::now(),
            request_id,
            client_ip,
            method: String::new(),
            path: String::new(),
            http_version: String::new(),
            status: 0,
            response_size: 0,
            duration_ms: 0,
            upstream: None,
            upstream_server: None,
            upstream_duration_ms: None,
            user_agent: None,
            referer: None,
            host: None,
            x_forwarded_for: None,
            tls_version: None,
            error: None,
        }
    }

    /// Format as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Format as combined log format
    pub fn to_combined(&self) -> String {
        format!(
            "{} - - [{}] \"{} {} {}\" {} {} \"{}\" \"{}\"",
            self.client_ip,
            self.timestamp.format("%d/%b/%Y:%H:%M:%S %z"),
            self.method,
            self.path,
            self.http_version,
            self.status,
            self.response_size,
            self.referer.as_deref().unwrap_or("-"),
            self.user_agent.as_deref().unwrap_or("-"),
        )
    }

    /// Format as common log format
    pub fn to_common(&self) -> String {
        format!(
            "{} - - [{}] \"{} {} {}\" {} {}",
            self.client_ip,
            self.timestamp.format("%d/%b/%Y:%H:%M:%S %z"),
            self.method,
            self.path,
            self.http_version,
            self.status,
            self.response_size,
        )
    }
}

/// Access logger
pub struct AccessLogger {
    /// Log format
    format: LogFormat,
    /// Output writer
    writer: Option<Mutex<BufWriter<File>>>,
    /// Whether logging is enabled
    enabled: bool,
}

impl AccessLogger {
    /// Create a new access logger
    pub fn new(config: &AccessLogConfig) -> Result<Self> {
        if !config.enabled {
            return Ok(Self {
                format: config.format.clone(),
                writer: None,
                enabled: false,
            });
        }

        let writer = if let Some(path) = &config.path {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| {
                    PrismError::Config(format!("Failed to open access log file {:?}: {}", path, e))
                })?;
            Some(Mutex::new(BufWriter::new(file)))
        } else {
            None
        };

        Ok(Self {
            format: config.format.clone(),
            writer,
            enabled: true,
        })
    }

    /// Log an access entry
    pub fn log(&self, entry: &AccessLogEntry) {
        if !self.enabled {
            return;
        }

        let line = match self.format {
            LogFormat::Json => entry.to_json(),
            LogFormat::Combined => entry.to_combined(),
            LogFormat::Common => entry.to_common(),
        };

        if let Some(writer) = &self.writer {
            if let Ok(mut writer) = writer.lock() {
                let _ = writeln!(writer, "{}", line);
                let _ = writer.flush();
            }
        } else {
            // Log to stdout
            println!("{}", line);
        }
    }

    /// Log using tracing (structured logging)
    pub fn log_structured(&self, entry: &AccessLogEntry) {
        if !self.enabled {
            return;
        }

        tracing::info!(
            request_id = %entry.request_id,
            client_ip = %entry.client_ip,
            method = %entry.method,
            path = %entry.path,
            status = entry.status,
            duration_ms = entry.duration_ms,
            response_size = entry.response_size,
            upstream = ?entry.upstream,
            "request completed"
        );
    }
}

/// Builder for access log entries
#[derive(Clone)]
pub struct AccessLogBuilder {
    entry: AccessLogEntry,
    start_time: std::time::Instant,
}

impl AccessLogBuilder {
    /// Create a new builder
    pub fn new(request_id: String, client_ip: String) -> Self {
        Self {
            entry: AccessLogEntry::new(request_id, client_ip),
            start_time: std::time::Instant::now(),
        }
    }

    /// Set request details
    pub fn request(mut self, method: &str, path: &str, http_version: &str) -> Self {
        self.entry.method = method.to_string();
        self.entry.path = path.to_string();
        self.entry.http_version = http_version.to_string();
        self
    }

    /// Set response details
    pub fn response(mut self, status: u16, size: u64) -> Self {
        self.entry.status = status;
        self.entry.response_size = size;
        self
    }

    /// Set upstream details
    pub fn upstream(mut self, name: &str, server: &str, duration: Duration) -> Self {
        self.entry.upstream = Some(name.to_string());
        self.entry.upstream_server = Some(server.to_string());
        self.entry.upstream_duration_ms = Some(duration.as_millis() as u64);
        self
    }

    /// Set user agent
    pub fn user_agent(mut self, ua: Option<&str>) -> Self {
        self.entry.user_agent = ua.map(String::from);
        self
    }

    /// Set referer
    pub fn referer(mut self, referer: Option<&str>) -> Self {
        self.entry.referer = referer.map(String::from);
        self
    }

    /// Set host
    pub fn host(mut self, host: Option<&str>) -> Self {
        self.entry.host = host.map(String::from);
        self
    }

    /// Set X-Forwarded-For
    pub fn x_forwarded_for(mut self, xff: Option<&str>) -> Self {
        self.entry.x_forwarded_for = xff.map(String::from);
        self
    }

    /// Set TLS version
    pub fn tls_version(mut self, version: Option<&str>) -> Self {
        self.entry.tls_version = version.map(String::from);
        self
    }

    /// Set error
    pub fn error(mut self, error: Option<&str>) -> Self {
        self.entry.error = error.map(String::from);
        self
    }

    /// Build the log entry
    pub fn build(mut self) -> AccessLogEntry {
        self.entry.duration_ms = self.start_time.elapsed().as_millis() as u64;
        self.entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_log_entry_json() {
        let entry = AccessLogEntry::new("req-123".to_string(), "192.168.1.1".to_string());
        let json = entry.to_json();
        assert!(json.contains("req-123"));
        assert!(json.contains("192.168.1.1"));
    }

    #[test]
    fn test_access_log_entry_combined() {
        let mut entry = AccessLogEntry::new("req-123".to_string(), "192.168.1.1".to_string());
        entry.method = "GET".to_string();
        entry.path = "/api/test".to_string();
        entry.http_version = "HTTP/1.1".to_string();
        entry.status = 200;
        entry.response_size = 1234;

        let combined = entry.to_combined();
        assert!(combined.contains("192.168.1.1"));
        assert!(combined.contains("GET /api/test HTTP/1.1"));
        assert!(combined.contains("200"));
        assert!(combined.contains("1234"));
    }

    #[test]
    fn test_access_log_builder() {
        let entry = AccessLogBuilder::new("req-456".to_string(), "10.0.0.1".to_string())
            .request("POST", "/api/users", "HTTP/2")
            .response(201, 256)
            .user_agent(Some("curl/7.64.1"))
            .build();

        assert_eq!(entry.method, "POST");
        assert_eq!(entry.path, "/api/users");
        assert_eq!(entry.status, 201);
        assert_eq!(entry.user_agent, Some("curl/7.64.1".to_string()));
    }
}
