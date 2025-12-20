//! Graceful shutdown with connection draining
//!
//! Provides coordination for graceful shutdown:
//! - Tracks active connections
//! - Waits for in-flight requests to complete
//! - Forces shutdown after timeout

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, watch, Notify};
use tracing::{debug, info, warn};

/// Connection draining coordinator
#[derive(Clone)]
pub struct DrainHandle {
    inner: Arc<DrainState>,
}

struct DrainState {
    /// Whether we're currently draining
    draining: AtomicBool,
    /// Number of active connections
    active_connections: AtomicUsize,
    /// Notify when all connections are drained
    drained: Notify,
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
    /// Drain state watcher
    drain_watch_tx: watch::Sender<bool>,
    drain_watch_rx: watch::Receiver<bool>,
}

impl DrainHandle {
    /// Create a new drain handle
    pub fn new() -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        let (drain_watch_tx, drain_watch_rx) = watch::channel(false);

        Self {
            inner: Arc::new(DrainState {
                draining: AtomicBool::new(false),
                active_connections: AtomicUsize::new(0),
                drained: Notify::new(),
                shutdown_tx,
                drain_watch_tx,
                drain_watch_rx,
            }),
        }
    }

    /// Get a connection guard that tracks this connection
    pub fn connection_guard(&self) -> Option<ConnectionGuard> {
        // Don't accept new connections if we're draining
        if self.inner.draining.load(Ordering::SeqCst) {
            return None;
        }

        self.inner.active_connections.fetch_add(1, Ordering::SeqCst);
        Some(ConnectionGuard {
            state: self.inner.clone(),
        })
    }

    /// Get current active connection count
    pub fn active_connections(&self) -> usize {
        self.inner.active_connections.load(Ordering::SeqCst)
    }

    /// Check if we're currently draining
    pub fn is_draining(&self) -> bool {
        self.inner.draining.load(Ordering::SeqCst)
    }

    /// Subscribe to shutdown signal
    pub fn shutdown_rx(&self) -> broadcast::Receiver<()> {
        self.inner.shutdown_tx.subscribe()
    }

    /// Subscribe to drain state changes
    pub fn drain_watch(&self) -> watch::Receiver<bool> {
        self.inner.drain_watch_rx.clone()
    }

    /// Initiate graceful shutdown with connection draining
    ///
    /// Returns when all connections are drained or timeout is reached.
    /// Returns true if drained gracefully, false if timeout forced.
    pub async fn drain(&self, timeout: Duration) -> bool {
        info!("Initiating graceful shutdown with connection draining");

        // Mark as draining
        self.inner.draining.store(true, Ordering::SeqCst);
        let _ = self.inner.drain_watch_tx.send(true);

        // Signal all listeners to stop accepting
        let _ = self.inner.shutdown_tx.send(());

        let active = self.inner.active_connections.load(Ordering::SeqCst);
        info!("Waiting for {} active connection(s) to drain", active);

        // Wait for connections to drain with timeout
        let drain_result = tokio::time::timeout(timeout, self.wait_for_drain()).await;

        match drain_result {
            Ok(()) => {
                info!("All connections drained gracefully");
                true
            }
            Err(_) => {
                let remaining = self.inner.active_connections.load(Ordering::SeqCst);
                warn!(
                    "Drain timeout exceeded, forcing shutdown with {} connection(s) remaining",
                    remaining
                );
                false
            }
        }
    }

    /// Wait until all connections are closed
    async fn wait_for_drain(&self) {
        loop {
            let active = self.inner.active_connections.load(Ordering::SeqCst);
            if active == 0 {
                return;
            }

            debug!("Waiting for {} active connection(s)", active);

            // Wait for notification or check periodically
            tokio::select! {
                _ = self.inner.drained.notified() => {
                    // Check again
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Periodic check
                }
            }
        }
    }
}

impl Default for DrainHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard that tracks an active connection
///
/// When dropped, decrements the connection count
pub struct ConnectionGuard {
    state: Arc<DrainState>,
}

impl ConnectionGuard {
    /// Check if the server is draining (for long-lived connections)
    pub fn is_draining(&self) -> bool {
        self.state.draining.load(Ordering::SeqCst)
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let prev = self.state.active_connections.fetch_sub(1, Ordering::SeqCst);
        debug!("Connection closed, {} remaining", prev - 1);

        // Notify if this was the last connection
        if prev == 1 {
            self.state.drained.notify_waiters();
        }
    }
}

/// Shutdown coordinator for the server
pub struct ShutdownCoordinator {
    drain_handle: DrainHandle,
    shutdown_timeout: Duration,
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator
    pub fn new(shutdown_timeout: Duration) -> Self {
        Self {
            drain_handle: DrainHandle::new(),
            shutdown_timeout,
        }
    }

    /// Get the drain handle for connection tracking
    pub fn drain_handle(&self) -> &DrainHandle {
        &self.drain_handle
    }

    /// Get the shutdown timeout
    pub fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    /// Perform graceful shutdown
    pub async fn shutdown(&self) -> bool {
        self.drain_handle.drain(self.shutdown_timeout).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_drain_handle_no_connections() {
        let handle = DrainHandle::new();

        // Should drain immediately with no connections
        let result = handle.drain(Duration::from_millis(100)).await;
        assert!(result);
        assert!(handle.is_draining());
    }

    #[tokio::test]
    async fn test_drain_handle_with_connections() {
        let handle = DrainHandle::new();

        // Create some connections
        let guard1 = handle.connection_guard().unwrap();
        let guard2 = handle.connection_guard().unwrap();

        assert_eq!(handle.active_connections(), 2);

        // Start draining in background
        let handle_clone = handle.clone();
        let drain_task =
            tokio::spawn(async move { handle_clone.drain(Duration::from_secs(5)).await });

        // Give drain time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // New connections should be rejected
        assert!(handle.connection_guard().is_none());

        // Close connections
        drop(guard1);
        assert_eq!(handle.active_connections(), 1);

        drop(guard2);
        assert_eq!(handle.active_connections(), 0);

        // Drain should complete successfully
        let result = drain_task.await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_drain_timeout() {
        let handle = DrainHandle::new();

        // Create a connection that won't be closed
        let _guard = handle.connection_guard().unwrap();

        // Drain should timeout
        let result = handle.drain(Duration::from_millis(100)).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_connection_guard_draining_check() {
        let handle = DrainHandle::new();
        let guard = handle.connection_guard().unwrap();

        assert!(!guard.is_draining());

        // Start draining in background
        let handle_clone = handle.clone();
        tokio::spawn(async move { handle_clone.drain(Duration::from_secs(1)).await });

        // Wait for drain to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(guard.is_draining());

        drop(guard);
    }

    #[test]
    fn test_shutdown_coordinator() {
        let coordinator = ShutdownCoordinator::new(Duration::from_secs(30));

        assert_eq!(coordinator.shutdown_timeout(), Duration::from_secs(30));
        assert_eq!(coordinator.drain_handle().active_connections(), 0);
    }
}
