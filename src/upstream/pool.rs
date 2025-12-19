//! Connection pool for upstream connections

use crate::config::PoolConfig;
use crate::error::{PrismError, Result};
use dashmap::DashMap;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::debug;

/// A pooled connection
pub struct PooledConnection {
    /// The underlying TCP stream
    stream: Option<TcpStream>,
    /// The server address
    address: SocketAddr,
    /// When the connection was created
    created_at: Instant,
    /// Pool reference for returning the connection
    pool: Arc<ConnectionPool>,
}

impl PooledConnection {
    /// Get a reference to the stream
    pub fn stream(&mut self) -> Option<&mut TcpStream> {
        self.stream.as_mut()
    }

    /// Take ownership of the stream (removes from pool)
    pub fn take_stream(&mut self) -> Option<TcpStream> {
        self.stream.take()
    }

    /// Get the server address
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Check if the connection is still valid
    pub fn is_valid(&self, max_lifetime: Duration) -> bool {
        self.created_at.elapsed() < max_lifetime
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            // Return to pool if still valid
            if self.is_valid(self.pool.config.max_lifetime) {
                let pool = self.pool.clone();
                let address = self.address;
                let created_at = self.created_at;

                tokio::spawn(async move {
                    pool.return_connection(address, stream, created_at).await;
                });
            }
        }
    }
}

/// Entry in the connection pool
struct PoolEntry {
    stream: TcpStream,
    created_at: Instant,
    last_used: Instant,
}

/// Per-address connection pool
struct AddressPool {
    /// Available connections
    connections: Mutex<VecDeque<PoolEntry>>,
    /// Current connection count (including in-use)
    count: AtomicUsize,
}

impl AddressPool {
    fn new() -> Self {
        Self {
            connections: Mutex::new(VecDeque::new()),
            count: AtomicUsize::new(0),
        }
    }
}

/// Connection pool for managing upstream connections
pub struct ConnectionPool {
    /// Per-address pools
    pools: DashMap<SocketAddr, Arc<AddressPool>>,
    /// Configuration
    config: PoolConfig,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(config: &PoolConfig) -> Self {
        Self {
            pools: DashMap::new(),
            config: config.clone(),
        }
    }

    /// Get a connection to an address
    pub async fn get(self: &Arc<Self>, address: SocketAddr) -> Result<PooledConnection> {
        let pool = self
            .pools
            .entry(address)
            .or_insert_with(|| Arc::new(AddressPool::new()))
            .clone();

        // Try to get an existing connection
        {
            let mut connections = pool.connections.lock().await;

            while let Some(entry) = connections.pop_front() {
                // Check if connection is still valid
                if entry.created_at.elapsed() < self.config.max_lifetime
                    && entry.last_used.elapsed() < self.config.idle_timeout
                {
                    debug!("Reusing pooled connection to {}", address);
                    return Ok(PooledConnection {
                        stream: Some(entry.stream),
                        address,
                        created_at: entry.created_at,
                        pool: self.clone(),
                    });
                }

                // Connection expired, decrement count
                pool.count.fetch_sub(1, Ordering::Relaxed);
            }
        }

        // Check if we can create a new connection
        let current = pool.count.load(Ordering::Relaxed);
        if current >= self.config.max_connections {
            return Err(PrismError::Pool(format!(
                "Connection pool exhausted for {}",
                address
            )));
        }

        // Create new connection
        debug!("Creating new connection to {}", address);
        pool.count.fetch_add(1, Ordering::Relaxed);

        let stream = TcpStream::connect(address).await.map_err(|e| {
            pool.count.fetch_sub(1, Ordering::Relaxed);
            PrismError::Upstream(format!("Failed to connect to {}: {}", address, e))
        })?;

        // Configure the stream
        stream.set_nodelay(true)?;

        Ok(PooledConnection {
            stream: Some(stream),
            address,
            created_at: Instant::now(),
            pool: self.clone(),
        })
    }

    /// Return a connection to the pool
    async fn return_connection(&self, address: SocketAddr, stream: TcpStream, created_at: Instant) {
        let pool = match self.pools.get(&address) {
            Some(p) => p.clone(),
            None => return,
        };

        // Check if connection is still valid
        if created_at.elapsed() >= self.config.max_lifetime {
            pool.count.fetch_sub(1, Ordering::Relaxed);
            return;
        }

        let mut connections = pool.connections.lock().await;

        // Check if pool is full
        if connections.len() >= self.config.max_connections {
            pool.count.fetch_sub(1, Ordering::Relaxed);
            return;
        }

        debug!("Returning connection to pool for {}", address);
        connections.push_back(PoolEntry {
            stream,
            created_at,
            last_used: Instant::now(),
        });
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        let mut total_connections = 0;
        let _total_idle = 0;

        for entry in self.pools.iter() {
            total_connections += entry.value().count.load(Ordering::Relaxed);
            // Note: We can't easily get idle count without locking
        }

        PoolStats {
            total_connections,
            addresses: self.pools.len(),
        }
    }

    /// Clean up idle connections
    pub async fn cleanup(&self) {
        for entry in self.pools.iter() {
            let pool = entry.value();
            let mut connections = pool.connections.lock().await;

            let before = connections.len();
            connections.retain(|entry| entry.last_used.elapsed() < self.config.idle_timeout);

            let removed = before - connections.len();
            if removed > 0 {
                pool.count.fetch_sub(removed, Ordering::Relaxed);
                debug!("Cleaned up {} idle connections to {}", removed, entry.key());
            }
        }
    }
}

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub addresses: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_defaults() {
        let config = PoolConfig::default();
        assert!(config.max_connections > 0);
        assert!(config.idle_timeout.as_secs() > 0);
    }
}
