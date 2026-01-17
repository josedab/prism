//! Layer 4 Proxy Implementation

use super::{L4ListenerConfig, L4LoadBalancing, L4Protocol, L4Stats, L4UpstreamConfig};
use crate::error::{PrismError, Result};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::broadcast;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// TCP Proxy
pub struct TcpProxy {
    /// Listener configuration
    config: L4ListenerConfig,
    /// Upstream configuration
    upstream: L4UpstreamConfig,
    /// Server health status
    server_health: Arc<RwLock<HashMap<String, bool>>>,
    /// Connection counts per server
    connection_counts: Arc<RwLock<HashMap<String, AtomicUsize>>>,
    /// Round-robin counter
    rr_counter: AtomicU64,
    /// Statistics
    stats: Arc<L4Stats>,
}

impl TcpProxy {
    /// Create a new TCP proxy
    pub fn new(
        config: L4ListenerConfig,
        upstream: L4UpstreamConfig,
        stats: Arc<L4Stats>,
    ) -> Self {
        let mut server_health = HashMap::new();
        let mut connection_counts = HashMap::new();

        for server in &upstream.servers {
            server_health.insert(server.address.clone(), true);
            connection_counts.insert(server.address.clone(), AtomicUsize::new(0));
        }

        Self {
            config,
            upstream,
            server_health: Arc::new(RwLock::new(server_health)),
            connection_counts: Arc::new(RwLock::new(connection_counts)),
            rr_counter: AtomicU64::new(0),
            stats,
        }
    }

    /// Run the TCP proxy
    pub async fn run(&self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        let addr: SocketAddr = self
            .config
            .address
            .parse()
            .map_err(|e| PrismError::Config(format!("Invalid address: {}", e)))?;

        let listener = TcpListener::bind(addr).await.map_err(|e| {
            PrismError::Io(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("Failed to bind TCP listener on {}: {}", addr, e),
            ))
        })?;

        info!(
            name = %self.config.name,
            address = %addr,
            upstream = %self.config.upstream,
            "TCP proxy listening"
        );

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, client_addr)) => {
                            self.stats.record_connection(L4Protocol::Tcp);
                            debug!(
                                name = %self.config.name,
                                client = %client_addr,
                                "Accepted TCP connection"
                            );

                            // Select upstream server
                            let upstream_addr = match self.select_server(&client_addr) {
                                Some(addr) => addr,
                                None => {
                                    warn!(
                                        name = %self.config.name,
                                        "No healthy upstream servers available"
                                    );
                                    self.stats.record_error(L4Protocol::Tcp, "no_healthy_upstream");
                                    continue;
                                }
                            };

                            // Spawn connection handler
                            let config = self.config.clone();
                            let stats = self.stats.clone();
                            let connection_counts = self.connection_counts.clone();
                            let upstream_addr_clone = upstream_addr.clone();

                            tokio::spawn(async move {
                                // Increment connection count
                                if let Some(count) = connection_counts.read().get(&upstream_addr_clone) {
                                    count.fetch_add(1, Ordering::SeqCst);
                                }

                                let result = Self::handle_connection(
                                    stream,
                                    client_addr,
                                    &upstream_addr,
                                    &config,
                                    &stats,
                                ).await;

                                // Decrement connection count
                                if let Some(count) = connection_counts.read().get(&upstream_addr_clone) {
                                    count.fetch_sub(1, Ordering::SeqCst);
                                }

                                if let Err(e) = result {
                                    debug!(
                                        client = %client_addr,
                                        upstream = %upstream_addr_clone,
                                        error = %e,
                                        "TCP connection error"
                                    );
                                }

                                stats.record_disconnect(L4Protocol::Tcp);
                            });
                        }
                        Err(e) => {
                            error!(name = %self.config.name, error = %e, "Accept error");
                            self.stats.record_error(L4Protocol::Tcp, "accept_error");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!(name = %self.config.name, "TCP proxy shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single TCP connection
    async fn handle_connection(
        mut client: TcpStream,
        client_addr: SocketAddr,
        upstream_addr: &str,
        config: &L4ListenerConfig,
        stats: &L4Stats,
    ) -> Result<()> {
        // Configure client socket
        if config.tcp_nodelay {
            client.set_nodelay(true)?;
        }

        // Connect to upstream
        let upstream_socket: SocketAddr = upstream_addr
            .parse()
            .map_err(|e| PrismError::Config(format!("Invalid upstream address: {}", e)))?;

        let mut upstream = match timeout(
            config.connect_timeout,
            TcpStream::connect(upstream_socket),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                stats.record_error(L4Protocol::Tcp, "connect_failed");
                return Err(PrismError::Upstream(format!(
                    "Failed to connect to {}: {}",
                    upstream_addr, e
                )));
            }
            Err(_) => {
                stats.record_error(L4Protocol::Tcp, "connect_timeout");
                return Err(PrismError::Timeout);
            }
        };

        // Configure upstream socket
        if config.tcp_nodelay {
            upstream.set_nodelay(true)?;
        }

        debug!(
            client = %client_addr,
            upstream = %upstream_addr,
            "TCP connection established"
        );

        // Bidirectional copy
        let (mut client_read, mut client_write) = client.split();
        let (mut upstream_read, mut upstream_write) = upstream.split();

        let client_to_upstream = async {
            let mut buf = vec![0u8; config.buffer_size];
            loop {
                match timeout(config.idle_timeout, client_read.read(&mut buf)).await {
                    Ok(Ok(0)) => break, // EOF
                    Ok(Ok(n)) => {
                        stats.record_bytes(L4Protocol::Tcp, n as u64, 0);
                        if upstream_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Ok(Err(_)) | Err(_) => break,
                }
            }
            let _ = upstream_write.shutdown().await;
        };

        let upstream_to_client = async {
            let mut buf = vec![0u8; config.buffer_size];
            loop {
                match timeout(config.idle_timeout, upstream_read.read(&mut buf)).await {
                    Ok(Ok(0)) => break, // EOF
                    Ok(Ok(n)) => {
                        stats.record_bytes(L4Protocol::Tcp, 0, n as u64);
                        if client_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Ok(Err(_)) | Err(_) => break,
                }
            }
            let _ = client_write.shutdown().await;
        };

        // Run both directions concurrently
        tokio::join!(client_to_upstream, upstream_to_client);

        debug!(
            client = %client_addr,
            upstream = %upstream_addr,
            "TCP connection closed"
        );

        Ok(())
    }

    /// Select an upstream server based on load balancing algorithm
    fn select_server(&self, client_addr: &SocketAddr) -> Option<String> {
        let healthy_servers: Vec<_> = {
            let health = self.server_health.read();
            self.upstream
                .servers
                .iter()
                .filter(|s| *health.get(&s.address).unwrap_or(&false))
                .collect()
        };

        if healthy_servers.is_empty() {
            return None;
        }

        let selected = match self.upstream.load_balancing {
            L4LoadBalancing::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::SeqCst) as usize;
                &healthy_servers[idx % healthy_servers.len()]
            }
            L4LoadBalancing::LeastConnections => {
                let counts = self.connection_counts.read();
                healthy_servers
                    .iter()
                    .min_by_key(|s| {
                        counts
                            .get(&s.address)
                            .map(|c| c.load(Ordering::SeqCst))
                            .unwrap_or(0)
                    })
                    .unwrap()
            }
            L4LoadBalancing::IpHash => {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                client_addr.ip().hash(&mut hasher);
                let hash = hasher.finish();
                &healthy_servers[hash as usize % healthy_servers.len()]
            }
            L4LoadBalancing::Random => {
                use rand::Rng;
                let idx = rand::thread_rng().gen_range(0..healthy_servers.len());
                &healthy_servers[idx]
            }
            L4LoadBalancing::WeightedRoundRobin => {
                // Simple weighted selection
                let total_weight: u32 = healthy_servers.iter().map(|s| s.weight).sum();
                if total_weight == 0 {
                    return None;
                }
                let idx = self.rr_counter.fetch_add(1, Ordering::SeqCst) as u32;
                let mut target = idx % total_weight;
                for server in &healthy_servers {
                    if target < server.weight {
                        return Some(server.address.clone());
                    }
                    target -= server.weight;
                }
                &healthy_servers[0]
            }
        };

        Some(selected.address.clone())
    }

    /// Update server health status
    pub async fn set_server_health(&self, address: &str, healthy: bool) {
        let mut health = self.server_health.write();
        if let Some(status) = health.get_mut(address) {
            *status = healthy;
        }
    }

    /// Get upstream servers
    pub fn servers(&self) -> &[super::L4ServerConfig] {
        &self.upstream.servers
    }

    /// Get server addresses
    pub fn server_addresses(&self) -> Vec<String> {
        self.upstream.servers.iter().map(|s| s.address.clone()).collect()
    }

    /// Get health check config
    pub fn health_check_config(&self) -> Option<&super::L4HealthCheckConfig> {
        self.upstream.health_check.as_ref()
    }

    /// Get listener name
    pub fn name(&self) -> &str {
        &self.config.name
    }
}

/// UDP Proxy
pub struct UdpProxy {
    /// Listener configuration
    config: L4ListenerConfig,
    /// Upstream configuration
    upstream: L4UpstreamConfig,
    /// Server health status
    server_health: Arc<RwLock<HashMap<String, bool>>>,
    /// Round-robin counter
    rr_counter: AtomicU64,
    /// Statistics
    stats: Arc<L4Stats>,
    /// Client session tracking (client_addr -> upstream_addr)
    sessions: Arc<RwLock<HashMap<SocketAddr, String>>>,
}

impl UdpProxy {
    /// Create a new UDP proxy
    pub fn new(
        config: L4ListenerConfig,
        upstream: L4UpstreamConfig,
        stats: Arc<L4Stats>,
    ) -> Self {
        let mut server_health = HashMap::new();

        for server in &upstream.servers {
            server_health.insert(server.address.clone(), true);
        }

        Self {
            config,
            upstream,
            server_health: Arc::new(RwLock::new(server_health)),
            rr_counter: AtomicU64::new(0),
            stats,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Run the UDP proxy
    pub async fn run(&self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        let addr: SocketAddr = self
            .config
            .address
            .parse()
            .map_err(|e| PrismError::Config(format!("Invalid address: {}", e)))?;

        let socket = UdpSocket::bind(addr).await.map_err(|e| {
            PrismError::Io(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("Failed to bind UDP socket on {}: {}", addr, e),
            ))
        })?;

        let socket = Arc::new(socket);

        info!(
            name = %self.config.name,
            address = %addr,
            upstream = %self.config.upstream,
            "UDP proxy listening"
        );

        let mut buf = vec![0u8; self.config.buffer_size];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, client_addr)) => {
                            self.stats.record_connection(L4Protocol::Udp);
                            self.stats.record_bytes(L4Protocol::Udp, len as u64, 0);

                            debug!(
                                name = %self.config.name,
                                client = %client_addr,
                                len = len,
                                "Received UDP datagram"
                            );

                            // Get or assign upstream for this client (sticky sessions for UDP)
                            let upstream_addr = {
                                let sessions = self.sessions.read();
                                if let Some(addr) = sessions.get(&client_addr) {
                                    // Check if still healthy
                                    let health = self.server_health.read();
                                    if *health.get(addr).unwrap_or(&false) {
                                        Some(addr.clone())
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            }.or_else(|| {
                                // Select new upstream
                                let addr = self.select_server(&client_addr)?;
                                self.sessions.write().insert(client_addr, addr.clone());
                                Some(addr)
                            });

                            let upstream_addr = match upstream_addr {
                                Some(addr) => addr,
                                None => {
                                    warn!(
                                        name = %self.config.name,
                                        "No healthy upstream servers available"
                                    );
                                    self.stats.record_error(L4Protocol::Udp, "no_healthy_upstream");
                                    continue;
                                }
                            };

                            // Forward datagram
                            let upstream_socket: SocketAddr = match upstream_addr.parse() {
                                Ok(addr) => addr,
                                Err(_) => continue,
                            };

                            // Create a socket for this upstream communication
                            let upstream_sock = match UdpSocket::bind("0.0.0.0:0").await {
                                Ok(s) => s,
                                Err(e) => {
                                    error!(error = %e, "Failed to create UDP socket");
                                    continue;
                                }
                            };

                            // Send to upstream
                            if let Err(e) = upstream_sock.send_to(&buf[..len], upstream_socket).await {
                                self.stats.record_error(L4Protocol::Udp, "send_failed");
                                debug!(error = %e, "Failed to send UDP to upstream");
                                continue;
                            }

                            // Receive response with timeout
                            let listener_socket = socket.clone();
                            let stats = self.stats.clone();
                            let idle_timeout = self.config.idle_timeout;
                            let buffer_size = self.config.buffer_size;

                            tokio::spawn(async move {
                                let mut resp_buf = vec![0u8; buffer_size];
                                match timeout(idle_timeout, upstream_sock.recv(&mut resp_buf)).await {
                                    Ok(Ok(resp_len)) => {
                                        stats.record_bytes(L4Protocol::Udp, 0, resp_len as u64);
                                        if let Err(e) = listener_socket.send_to(&resp_buf[..resp_len], client_addr).await {
                                            debug!(error = %e, "Failed to send UDP response to client");
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        debug!(error = %e, "UDP upstream recv error");
                                    }
                                    Err(_) => {
                                        debug!("UDP upstream response timeout");
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            error!(name = %self.config.name, error = %e, "UDP recv error");
                            self.stats.record_error(L4Protocol::Udp, "recv_error");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!(name = %self.config.name, "UDP proxy shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Select an upstream server
    fn select_server(&self, client_addr: &SocketAddr) -> Option<String> {
        let healthy_servers: Vec<_> = {
            let health = self.server_health.read();
            self.upstream
                .servers
                .iter()
                .filter(|s| *health.get(&s.address).unwrap_or(&false))
                .collect()
        };

        if healthy_servers.is_empty() {
            return None;
        }

        let selected = match self.upstream.load_balancing {
            L4LoadBalancing::RoundRobin | L4LoadBalancing::WeightedRoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::SeqCst) as usize;
                &healthy_servers[idx % healthy_servers.len()]
            }
            L4LoadBalancing::IpHash => {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                client_addr.ip().hash(&mut hasher);
                let hash = hasher.finish();
                &healthy_servers[hash as usize % healthy_servers.len()]
            }
            _ => {
                let idx = self.rr_counter.fetch_add(1, Ordering::SeqCst) as usize;
                &healthy_servers[idx % healthy_servers.len()]
            }
        };

        Some(selected.address.clone())
    }

    /// Update server health status
    pub async fn set_server_health(&self, address: &str, healthy: bool) {
        let mut health = self.server_health.write();
        if let Some(status) = health.get_mut(address) {
            *status = healthy;
        }
    }

    /// Get upstream servers
    pub fn servers(&self) -> &[super::L4ServerConfig] {
        &self.upstream.servers
    }

    /// Get server addresses
    pub fn server_addresses(&self) -> Vec<String> {
        self.upstream.servers.iter().map(|s| s.address.clone()).collect()
    }

    /// Get health check config
    pub fn health_check_config(&self) -> Option<&super::L4HealthCheckConfig> {
        self.upstream.health_check.as_ref()
    }

    /// Get listener name
    pub fn name(&self) -> &str {
        &self.config.name
    }
}
