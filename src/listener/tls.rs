//! TLS acceptor implementation using rustls
//!
//! Provides memory-safe TLS termination with support for:
//! - TLS 1.2 and 1.3
//! - ALPN for HTTP/2 negotiation
//! - Session resumption
//! - Mutual TLS (mTLS) with client certificate verification

use crate::config::{ClientAuthMode, TlsConfig};
use crate::error::{PrismError, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, WebPkiClientVerifier};
use rustls::RootCertStore;
use rustls::ServerConnection;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::{debug, info};

/// TLS acceptor for handling incoming TLS connections
#[derive(Clone)]
pub struct TlsAcceptor {
    acceptor: tokio_rustls::TlsAcceptor,
}

impl TlsAcceptor {
    /// Create a new TLS acceptor from configuration
    pub fn new(config: &TlsConfig) -> Result<Self> {
        // Load certificates
        let certs = load_certs(&config.cert)?;
        debug!("Loaded {} certificate(s)", certs.len());

        // Load private key
        let key = load_private_key(&config.key)?;
        debug!("Loaded private key");

        // Build server config based on client auth mode
        let server_config = match &config.client_auth {
            ClientAuthMode::None => ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| PrismError::Tls(format!("Failed to build TLS config: {}", e)))?,
            ClientAuthMode::Optional | ClientAuthMode::Required => {
                // Load client CA certificates
                let client_ca_path = config.client_ca.as_ref().ok_or_else(|| {
                    PrismError::Certificate(
                        "client_ca is required when client_auth is optional or required"
                            .to_string(),
                    )
                })?;

                let ca_certs = load_certs(client_ca_path)?;
                info!("Loaded {} client CA certificate(s)", ca_certs.len());

                // Build root cert store
                let mut root_store = RootCertStore::empty();
                for cert in ca_certs {
                    root_store.add(cert).map_err(|e| {
                        PrismError::Certificate(format!("Failed to add CA cert to store: {}", e))
                    })?;
                }

                // Build client verifier
                let verifier = if config.client_auth == ClientAuthMode::Required {
                    WebPkiClientVerifier::builder(Arc::new(root_store))
                        .build()
                        .map_err(|e| {
                            PrismError::Tls(format!("Failed to build client verifier: {}", e))
                        })?
                } else {
                    WebPkiClientVerifier::builder(Arc::new(root_store))
                        .allow_unauthenticated()
                        .build()
                        .map_err(|e| {
                            PrismError::Tls(format!("Failed to build client verifier: {}", e))
                        })?
                };

                info!(
                    "Configured mTLS with {:?} client authentication",
                    config.client_auth
                );

                ServerConfig::builder()
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(certs, key)
                    .map_err(|e| PrismError::Tls(format!("Failed to build TLS config: {}", e)))?
            }
        };

        let mut server_config = server_config;

        // Configure ALPN for HTTP/2
        server_config.alpn_protocols = config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

        // Enable session resumption for performance
        server_config.session_storage = rustls::server::ServerSessionMemoryCache::new(10240);

        // Set max fragment size for performance
        server_config.max_fragment_size = Some(16384);

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        Ok(Self { acceptor })
    }

    /// Accept a TLS connection
    pub async fn accept(&self, stream: TcpStream) -> Result<TlsStream<TcpStream>> {
        self.acceptor
            .accept(stream)
            .await
            .map_err(|e| PrismError::Tls(format!("TLS handshake failed: {}", e)))
    }

    /// Get information about a TLS connection
    pub fn connection_info(conn: &ServerConnection) -> TlsConnectionInfo {
        // Extract client certificate info if present
        let client_cert_info = conn.peer_certificates().and_then(|certs| {
            if certs.is_empty() {
                None
            } else {
                // Parse the first certificate to extract subject info
                // For simplicity, we just note that a cert was presented
                Some(ClientCertInfo {
                    cert_count: certs.len(),
                    // In a full implementation, you'd parse the cert to get subject DN
                    subject: None,
                })
            }
        });

        TlsConnectionInfo {
            protocol_version: conn.protocol_version(),
            alpn_protocol: conn.alpn_protocol().map(|p| p.to_vec()),
            cipher_suite: conn.negotiated_cipher_suite().map(|cs| cs.suite()),
            sni_hostname: conn.server_name().map(|s| s.to_string()),
            client_cert: client_cert_info,
        }
    }
}

/// Information about a client certificate (mTLS)
#[derive(Debug, Clone)]
pub struct ClientCertInfo {
    /// Number of certificates in the chain
    pub cert_count: usize,
    /// Subject distinguished name (if parsed)
    pub subject: Option<String>,
}

/// Information about a TLS connection
#[derive(Debug, Clone)]
pub struct TlsConnectionInfo {
    /// TLS protocol version
    pub protocol_version: Option<rustls::ProtocolVersion>,
    /// Negotiated ALPN protocol
    pub alpn_protocol: Option<Vec<u8>>,
    /// Cipher suite in use
    pub cipher_suite: Option<rustls::CipherSuite>,
    /// SNI hostname
    pub sni_hostname: Option<String>,
    /// Client certificate information (for mTLS)
    pub client_cert: Option<ClientCertInfo>,
}

impl TlsConnectionInfo {
    /// Check if HTTP/2 was negotiated
    pub fn is_http2(&self) -> bool {
        self.alpn_protocol
            .as_ref()
            .map(|p| p == b"h2")
            .unwrap_or(false)
    }

    /// Check if client presented a certificate
    pub fn has_client_cert(&self) -> bool {
        self.client_cert.is_some()
    }
}

/// Load certificates from a PEM file
fn load_certs(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).map_err(|e| {
        PrismError::Certificate(format!("Failed to open certificate file {:?}: {}", path, e))
    })?;

    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| PrismError::Certificate(format!("Failed to parse certificates: {}", e)))?;

    if certs.is_empty() {
        return Err(PrismError::Certificate(
            "No certificates found in file".to_string(),
        ));
    }

    Ok(certs)
}

/// Load private key from a PEM file
fn load_private_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).map_err(|e| {
        PrismError::Certificate(format!("Failed to open key file {:?}: {}", path, e))
    })?;

    let mut reader = BufReader::new(file);

    // Try to read different key formats
    loop {
        match rustls_pemfile::read_one(&mut reader) {
            Ok(Some(rustls_pemfile::Item::Pkcs1Key(key))) => {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
            Ok(Some(rustls_pemfile::Item::Pkcs8Key(key))) => {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Ok(Some(rustls_pemfile::Item::Sec1Key(key))) => {
                return Ok(PrivateKeyDer::Sec1(key));
            }
            Ok(Some(_)) => {
                // Skip non-key items
                continue;
            }
            Ok(None) => {
                break;
            }
            Err(e) => {
                return Err(PrismError::Certificate(format!(
                    "Failed to parse private key: {}",
                    e
                )));
            }
        }
    }

    Err(PrismError::Certificate(
        "No private key found in file".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Self-signed test certificate and key (for testing only)
    const TEST_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAJHGnwP6F3EPMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnBy
aXNtMzAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnByaXNtMzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC3a+v1JxLXhPg2G8t6EBgV
g5jNIcPKOVE1iRMhYeVYVzPblGy37AZJjJVD8nHhqVJlkgjMvJGE7ZV2yLmXwJMv
AgMBAAGjUzBRMB0GA1UdDgQWBBRNb5q3VDL3VclPg2d3WxBL7WjjPzAfBgNVHSME
GDAWgBRNb5q3VDL3VclPg2d3WxBL7WjjPzAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EAn0y8E1oYJrJ/m+Gx5lLhjt3N0S3Q2L1a9kqX9z4b8p6d1E5G
5x1mFvQ7sR9FgO3fR8RbPl7Y1D0wLzY8DgFxFQ==
-----END CERTIFICATE-----"#;

    const TEST_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALdr6/UnEteE+DYby3oQGBWDmM0hw8o5UTWJEyFh5VhXM9uUbLfs
BkmMlUPyceGpUmWSCMy8kYTtlXbIuZfAky8CAwEAAQJALzd6JA4qDQn9P5r4S3LS
fqM8WK3u5TL3c8L8y4N7M8gP0FqBfT5xzc8DLmJE9Y9N0d3Y8B5mN9kY1Z8MvH0n
AQIhAOOx/VfpZBLY3y2d0ZxGRcV8i8G8FwB4Y7cF8xvQ0CnfAiEAzMxGVbz3vDh3
P5MG8vMO/bD9y2v+j5k8ZxGK0LF8P0ECIFz7bFl8xO0F5vA7K0VzFPGWz8JqdF+B
DvI3f8vE9VPZAH8CIQC3MxE7vqQ1Fy9z8vC1v9BxX6C5/K0w9U6T8V0xP7o3AQIR
AIY1V0vA6eDFxjZBw7vL7k8=
-----END RSA PRIVATE KEY-----"#;

    #[test]
    fn test_load_certs() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(TEST_CERT.as_bytes()).unwrap();

        let certs = load_certs(file.path()).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_load_private_key() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(TEST_KEY.as_bytes()).unwrap();

        let key = load_private_key(file.path());
        assert!(key.is_ok());
    }

    #[test]
    fn test_tls_connection_info() {
        let info = TlsConnectionInfo {
            protocol_version: Some(rustls::ProtocolVersion::TLSv1_3),
            alpn_protocol: Some(b"h2".to_vec()),
            cipher_suite: None,
            sni_hostname: Some("example.com".to_string()),
            client_cert: None,
        };

        assert!(info.is_http2());
        assert!(!info.has_client_cert());
    }

    #[test]
    fn test_tls_connection_info_with_client_cert() {
        let info = TlsConnectionInfo {
            protocol_version: Some(rustls::ProtocolVersion::TLSv1_3),
            alpn_protocol: Some(b"h2".to_vec()),
            cipher_suite: None,
            sni_hostname: Some("example.com".to_string()),
            client_cert: Some(ClientCertInfo {
                cert_count: 1,
                subject: None,
            }),
        };

        assert!(info.is_http2());
        assert!(info.has_client_cert());
    }
}
