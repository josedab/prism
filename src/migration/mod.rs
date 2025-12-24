//! Connection Migration Module
//!
//! Implements QUIC-style connection migration for:
//! - Seamless network handoff (WiFi to cellular)
//! - IP address changes
//! - NAT rebinding
//! - Connection persistence across network changes

use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Connection migration configuration
#[derive(Debug, Clone)]
pub struct MigrationConfig {
    /// Enable connection migration
    pub enabled: bool,
    /// Maximum path validation retries
    pub max_path_validation_retries: u32,
    /// Path validation timeout
    pub path_validation_timeout: Duration,
    /// Maximum pending migrations
    pub max_pending_migrations: usize,
    /// Connection ID length
    pub connection_id_length: usize,
    /// Enable active path probing
    pub active_probing: bool,
    /// Probe interval
    pub probe_interval: Duration,
    /// Maximum paths per connection
    pub max_paths: usize,
    /// Path switch threshold (RTT multiple)
    pub path_switch_threshold: f64,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_path_validation_retries: 3,
            path_validation_timeout: Duration::from_secs(5),
            max_pending_migrations: 100,
            connection_id_length: 16,
            active_probing: true,
            probe_interval: Duration::from_secs(30),
            max_paths: 4,
            path_switch_threshold: 1.5,
        }
    }
}

/// Connection identifier
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ConnectionId(pub Vec<u8>);

impl ConnectionId {
    pub fn generate(length: usize) -> Self {
        use rand::Rng;
        let mut bytes = vec![0u8; length];
        rand::thread_rng().fill(&mut bytes[..]);
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Network path
#[derive(Debug, Clone)]
pub struct NetworkPath {
    pub id: u64,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub status: PathStatus,
    pub rtt: Option<Duration>,
    pub rtt_variance: Option<Duration>,
    pub congestion_window: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_lost: u64,
    pub last_packet_sent: Option<Instant>,
    pub last_packet_received: Option<Instant>,
    pub validated: bool,
    pub validation_attempts: u32,
    pub mtu: u16,
}

impl NetworkPath {
    pub fn new(id: u64, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            id,
            local_addr,
            remote_addr,
            status: PathStatus::Unknown,
            rtt: None,
            rtt_variance: None,
            congestion_window: 14720, // Initial cwnd
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_lost: 0,
            last_packet_sent: None,
            last_packet_received: None,
            validated: false,
            validation_attempts: 0,
            mtu: 1200, // Conservative default
        }
    }

    pub fn loss_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            0.0
        } else {
            self.packets_lost as f64 / self.packets_sent as f64
        }
    }

    pub fn is_usable(&self) -> bool {
        self.validated && self.status == PathStatus::Active
    }
}

/// Path status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStatus {
    /// Path status unknown
    Unknown,
    /// Path is being validated
    Validating,
    /// Path is active and usable
    Active,
    /// Path is standby (usable but not primary)
    Standby,
    /// Path validation failed
    Failed,
    /// Path is closed
    Closed,
}

/// Path validation challenge
#[derive(Debug, Clone)]
pub struct PathChallenge {
    pub data: [u8; 8],
    pub sent_at: Instant,
    pub path_id: u64,
}

/// Path validation response
#[derive(Debug, Clone)]
pub struct PathResponse {
    pub data: [u8; 8],
}

/// Migration state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationState {
    /// No migration in progress
    Idle,
    /// Probing new path
    Probing,
    /// Validating new path
    Validating,
    /// Switching to new path
    Switching,
    /// Migration complete
    Complete,
    /// Migration failed
    Failed,
}

/// Connection state
pub struct Connection {
    pub id: ConnectionId,
    pub peer_id: ConnectionId,
    pub paths: RwLock<HashMap<u64, NetworkPath>>,
    pub active_path_id: RwLock<u64>,
    pub state: RwLock<ConnectionState>,
    pub migration_state: RwLock<MigrationState>,
    pub pending_challenges: RwLock<VecDeque<PathChallenge>>,
    pub path_id_counter: AtomicU64,
    pub created_at: Instant,
    pub last_activity: RwLock<Instant>,
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Handshaking,
    Connected,
    Closing,
    Closed,
}

impl Connection {
    pub fn new(id: ConnectionId, peer_id: ConnectionId) -> Self {
        Self {
            id,
            peer_id,
            paths: RwLock::new(HashMap::new()),
            active_path_id: RwLock::new(0),
            state: RwLock::new(ConnectionState::Handshaking),
            migration_state: RwLock::new(MigrationState::Idle),
            pending_challenges: RwLock::new(VecDeque::new()),
            path_id_counter: AtomicU64::new(0),
            created_at: Instant::now(),
            last_activity: RwLock::new(Instant::now()),
        }
    }

    pub fn add_path(&self, local_addr: SocketAddr, remote_addr: SocketAddr) -> u64 {
        let path_id = self.path_id_counter.fetch_add(1, Ordering::SeqCst);
        let path = NetworkPath::new(path_id, local_addr, remote_addr);

        let mut paths = self.paths.write();
        paths.insert(path_id, path);

        // If this is the first path, make it active
        if paths.len() == 1 {
            *self.active_path_id.write() = path_id;
        }

        path_id
    }

    pub fn get_active_path(&self) -> Option<NetworkPath> {
        let path_id = *self.active_path_id.read();
        self.paths.read().get(&path_id).cloned()
    }

    pub fn set_active_path(&self, path_id: u64) -> bool {
        let paths = self.paths.read();
        if let Some(path) = paths.get(&path_id) {
            if path.is_usable() {
                *self.active_path_id.write() = path_id;
                return true;
            }
        }
        false
    }

    pub fn update_activity(&self) {
        *self.last_activity.write() = Instant::now();
    }
}

/// Migration event
#[derive(Debug, Clone)]
pub enum MigrationEvent {
    /// New path detected
    PathDetected {
        connection_id: ConnectionId,
        path_id: u64,
        new_addr: SocketAddr,
    },
    /// Path validation started
    ValidationStarted {
        connection_id: ConnectionId,
        path_id: u64,
    },
    /// Path validated successfully
    PathValidated {
        connection_id: ConnectionId,
        path_id: u64,
    },
    /// Path validation failed
    ValidationFailed {
        connection_id: ConnectionId,
        path_id: u64,
        reason: String,
    },
    /// Migrating to new path
    Migrating {
        connection_id: ConnectionId,
        old_path_id: u64,
        new_path_id: u64,
    },
    /// Migration complete
    MigrationComplete {
        connection_id: ConnectionId,
        path_id: u64,
    },
    /// Path closed
    PathClosed {
        connection_id: ConnectionId,
        path_id: u64,
    },
}

/// Migration statistics
#[derive(Debug, Default)]
pub struct MigrationStats {
    pub migrations_initiated: AtomicU64,
    pub migrations_completed: AtomicU64,
    pub migrations_failed: AtomicU64,
    pub paths_validated: AtomicU64,
    pub paths_failed: AtomicU64,
    pub challenges_sent: AtomicU64,
    pub responses_received: AtomicU64,
    pub probes_sent: AtomicU64,
}

/// Connection migration manager
pub struct MigrationManager {
    config: MigrationConfig,
    connections: DashMap<ConnectionId, Arc<Connection>>,
    connection_by_addr: DashMap<(SocketAddr, SocketAddr), ConnectionId>,
    event_tx: mpsc::Sender<MigrationEvent>,
    event_rx: RwLock<Option<mpsc::Receiver<MigrationEvent>>>,
    stats: MigrationStats,
}

impl MigrationManager {
    pub fn new(config: MigrationConfig) -> Self {
        let (event_tx, event_rx) = mpsc::channel(1000);

        Self {
            config,
            connections: DashMap::new(),
            connection_by_addr: DashMap::new(),
            event_tx,
            event_rx: RwLock::new(Some(event_rx)),
            stats: MigrationStats::default(),
        }
    }

    /// Take event receiver (can only be called once)
    pub fn take_event_receiver(&self) -> Option<mpsc::Receiver<MigrationEvent>> {
        self.event_rx.write().take()
    }

    /// Create a new connection
    pub fn create_connection(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Arc<Connection> {
        let conn_id = ConnectionId::generate(self.config.connection_id_length);
        let peer_id = ConnectionId::generate(self.config.connection_id_length);

        let connection = Arc::new(Connection::new(conn_id.clone(), peer_id));
        connection.add_path(local_addr, remote_addr);

        self.connections.insert(conn_id.clone(), connection.clone());
        self.connection_by_addr
            .insert((local_addr, remote_addr), conn_id);

        connection
    }

    /// Get connection by ID
    pub fn get_connection(&self, conn_id: &ConnectionId) -> Option<Arc<Connection>> {
        self.connections.get(conn_id).map(|c| c.clone())
    }

    /// Get connection by address pair
    pub fn get_connection_by_addr(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<Arc<Connection>> {
        self.connection_by_addr
            .get(&(local_addr, remote_addr))
            .and_then(|id| self.connections.get(&id).map(|c| c.clone()))
    }

    /// Handle packet from new address (potential migration)
    pub fn handle_address_change(
        &self,
        conn_id: &ConnectionId,
        new_local: SocketAddr,
        new_remote: SocketAddr,
    ) -> Option<u64> {
        if !self.config.enabled {
            return None;
        }

        let connection = self.get_connection(conn_id)?;

        // Check if path already exists
        {
            let paths = connection.paths.read();
            for (id, path) in paths.iter() {
                if path.local_addr == new_local && path.remote_addr == new_remote {
                    return Some(*id);
                }
            }
        }

        // Check path limit
        if connection.paths.read().len() >= self.config.max_paths {
            return None;
        }

        // Add new path
        let path_id = connection.add_path(new_local, new_remote);

        // Emit event
        let _ = self.event_tx.try_send(MigrationEvent::PathDetected {
            connection_id: conn_id.clone(),
            path_id,
            new_addr: new_remote,
        });

        // Start path validation
        self.start_path_validation(conn_id, path_id);

        Some(path_id)
    }

    /// Start path validation
    pub fn start_path_validation(&self, conn_id: &ConnectionId, path_id: u64) {
        let connection = match self.get_connection(conn_id) {
            Some(c) => c,
            None => return,
        };

        // Generate challenge
        let mut data = [0u8; 8];
        rand::Rng::fill(&mut rand::thread_rng(), &mut data);

        let challenge = PathChallenge {
            data,
            sent_at: Instant::now(),
            path_id,
        };

        connection.pending_challenges.write().push_back(challenge);

        // Update path status
        if let Some(path) = connection.paths.write().get_mut(&path_id) {
            path.status = PathStatus::Validating;
            path.validation_attempts += 1;
        }

        *connection.migration_state.write() = MigrationState::Validating;

        let _ = self.event_tx.try_send(MigrationEvent::ValidationStarted {
            connection_id: conn_id.clone(),
            path_id,
        });

        self.stats.challenges_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Handle path response (challenge answer)
    pub fn handle_path_response(&self, conn_id: &ConnectionId, response: PathResponse) -> bool {
        let connection = match self.get_connection(conn_id) {
            Some(c) => c,
            None => return false,
        };

        self.stats
            .responses_received
            .fetch_add(1, Ordering::Relaxed);

        // Find matching challenge
        let mut challenges = connection.pending_challenges.write();
        let challenge_idx = challenges.iter().position(|c| c.data == response.data);

        if let Some(idx) = challenge_idx {
            let challenge = challenges.remove(idx).unwrap();

            // Validate path
            let rtt = challenge.sent_at.elapsed();
            let path_id = challenge.path_id;

            if let Some(path) = connection.paths.write().get_mut(&path_id) {
                path.validated = true;
                path.status = PathStatus::Standby;
                path.rtt = Some(rtt);
            }

            self.stats.paths_validated.fetch_add(1, Ordering::Relaxed);

            let _ = self.event_tx.try_send(MigrationEvent::PathValidated {
                connection_id: conn_id.clone(),
                path_id,
            });

            // Consider switching to new path if it's better
            self.consider_path_switch(&connection, path_id);

            return true;
        }

        false
    }

    /// Consider switching to a better path
    fn consider_path_switch(&self, connection: &Connection, new_path_id: u64) {
        let paths = connection.paths.read();
        let active_path_id = *connection.active_path_id.read();

        let active_path = match paths.get(&active_path_id) {
            Some(p) => p,
            None => return,
        };

        let new_path = match paths.get(&new_path_id) {
            Some(p) => p,
            None => return,
        };

        // Compare RTT
        let should_switch = match (active_path.rtt, new_path.rtt) {
            (Some(active_rtt), Some(new_rtt)) => {
                let threshold = active_rtt.as_secs_f64() * self.config.path_switch_threshold;
                new_rtt.as_secs_f64() < threshold
            }
            (None, Some(_)) => true, // New path has RTT, old doesn't
            _ => false,
        };

        if should_switch && new_path.is_usable() {
            drop(paths);
            self.migrate_to_path(&connection.id, new_path_id);
        }
    }

    /// Migrate connection to a new path
    pub fn migrate_to_path(&self, conn_id: &ConnectionId, new_path_id: u64) {
        let connection = match self.get_connection(conn_id) {
            Some(c) => c,
            None => return,
        };

        let old_path_id = *connection.active_path_id.read();

        if old_path_id == new_path_id {
            return;
        }

        self.stats
            .migrations_initiated
            .fetch_add(1, Ordering::Relaxed);

        *connection.migration_state.write() = MigrationState::Switching;

        let _ = self.event_tx.try_send(MigrationEvent::Migrating {
            connection_id: conn_id.clone(),
            old_path_id,
            new_path_id,
        });

        // Update path statuses
        {
            let mut paths = connection.paths.write();

            if let Some(old_path) = paths.get_mut(&old_path_id) {
                old_path.status = PathStatus::Standby;
            }

            if let Some(new_path) = paths.get_mut(&new_path_id) {
                new_path.status = PathStatus::Active;
            }
        }

        // Switch active path
        if connection.set_active_path(new_path_id) {
            *connection.migration_state.write() = MigrationState::Complete;
            self.stats
                .migrations_completed
                .fetch_add(1, Ordering::Relaxed);

            let _ = self.event_tx.try_send(MigrationEvent::MigrationComplete {
                connection_id: conn_id.clone(),
                path_id: new_path_id,
            });
        } else {
            *connection.migration_state.write() = MigrationState::Failed;
            self.stats.migrations_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Close a path
    pub fn close_path(&self, conn_id: &ConnectionId, path_id: u64) {
        let connection = match self.get_connection(conn_id) {
            Some(c) => c,
            None => return,
        };

        let active_path_id = *connection.active_path_id.read();

        // Don't close active path
        if path_id == active_path_id {
            return;
        }

        if let Some(path) = connection.paths.write().get_mut(&path_id) {
            path.status = PathStatus::Closed;
        }

        let _ = self.event_tx.try_send(MigrationEvent::PathClosed {
            connection_id: conn_id.clone(),
            path_id,
        });
    }

    /// Close connection
    pub fn close_connection(&self, conn_id: &ConnectionId) {
        if let Some((_, connection)) = self.connections.remove(conn_id) {
            // Remove address mappings
            let paths = connection.paths.read();
            for path in paths.values() {
                self.connection_by_addr
                    .remove(&(path.local_addr, path.remote_addr));
            }
        }
    }

    /// Handle validation timeout
    pub fn handle_validation_timeout(&self, conn_id: &ConnectionId, path_id: u64) {
        let connection = match self.get_connection(conn_id) {
            Some(c) => c,
            None => return,
        };

        let should_retry = {
            let paths = connection.paths.read();
            paths
                .get(&path_id)
                .map(|p| p.validation_attempts < self.config.max_path_validation_retries)
                .unwrap_or(false)
        };

        if should_retry {
            self.start_path_validation(conn_id, path_id);
        } else {
            // Mark as failed
            if let Some(path) = connection.paths.write().get_mut(&path_id) {
                path.status = PathStatus::Failed;
            }

            self.stats.paths_failed.fetch_add(1, Ordering::Relaxed);

            let _ = self.event_tx.try_send(MigrationEvent::ValidationFailed {
                connection_id: conn_id.clone(),
                path_id,
                reason: "Timeout".to_string(),
            });
        }
    }

    /// Update path metrics
    pub fn update_path_metrics(
        &self,
        conn_id: &ConnectionId,
        path_id: u64,
        rtt: Duration,
        bytes_sent: u64,
        bytes_received: u64,
    ) {
        let connection = match self.get_connection(conn_id) {
            Some(c) => c,
            None => return,
        };

        if let Some(path) = connection.paths.write().get_mut(&path_id) {
            // Update RTT with exponential moving average
            path.rtt = Some(match path.rtt {
                Some(prev) => {
                    let alpha = 0.125;
                    Duration::from_secs_f64(
                        prev.as_secs_f64() * (1.0 - alpha) + rtt.as_secs_f64() * alpha,
                    )
                }
                None => rtt,
            });

            path.bytes_sent += bytes_sent;
            path.bytes_received += bytes_received;
            path.last_packet_received = Some(Instant::now());
        }

        connection.update_activity();
    }

    /// Get migration statistics
    pub fn stats(&self) -> &MigrationStats {
        &self.stats
    }

    /// Get active connections count
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    #[test]
    fn test_connection_id_generation() {
        let id1 = ConnectionId::generate(16);
        let id2 = ConnectionId::generate(16);

        assert_eq!(id1.as_bytes().len(), 16);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_create_connection() {
        let manager = MigrationManager::new(MigrationConfig::default());
        let conn = manager.create_connection(addr(8080), addr(9090));

        assert!(!conn.id.as_bytes().is_empty());
        assert_eq!(*conn.state.read(), ConnectionState::Handshaking);

        let path = conn.get_active_path();
        assert!(path.is_some());
    }

    #[test]
    fn test_address_change_creates_path() {
        let manager = MigrationManager::new(MigrationConfig::default());
        let conn = manager.create_connection(addr(8080), addr(9090));
        let conn_id = conn.id.clone();

        // Simulate address change
        let path_id = manager.handle_address_change(
            &conn_id,
            addr(8081), // New local
            addr(9091), // New remote
        );

        assert!(path_id.is_some());
        assert_eq!(conn.paths.read().len(), 2);
    }

    #[test]
    fn test_path_validation() {
        let manager = MigrationManager::new(MigrationConfig::default());
        let conn = manager.create_connection(addr(8080), addr(9090));
        let conn_id = conn.id.clone();

        // Add new path
        let path_id = manager
            .handle_address_change(&conn_id, addr(8081), addr(9091))
            .unwrap();

        // Get challenge data
        let challenge_data = {
            let challenges = conn.pending_challenges.read();
            assert!(!challenges.is_empty());
            challenges.front().unwrap().data
        };

        // Respond to challenge
        let result = manager.handle_path_response(
            &conn_id,
            PathResponse {
                data: challenge_data,
            },
        );

        assert!(result);

        // Check path is validated
        let paths = conn.paths.read();
        let path = paths.get(&path_id).unwrap();
        assert!(path.validated);
    }

    #[test]
    fn test_migration_to_better_path() {
        let manager = MigrationManager::new(MigrationConfig::default());
        let conn = manager.create_connection(addr(8080), addr(9090));
        let conn_id = conn.id.clone();

        // Manually set up paths with RTT
        let path1_id = *conn.active_path_id.read();
        {
            let mut paths = conn.paths.write();
            if let Some(path) = paths.get_mut(&path1_id) {
                path.validated = true;
                path.status = PathStatus::Active;
                path.rtt = Some(Duration::from_millis(100));
            }
        }

        // Add second path with better RTT
        let path2_id = conn.add_path(addr(8081), addr(9091));
        {
            let mut paths = conn.paths.write();
            if let Some(path) = paths.get_mut(&path2_id) {
                path.validated = true;
                path.status = PathStatus::Standby;
                path.rtt = Some(Duration::from_millis(20)); // Much better RTT
            }
        }

        // Migrate
        manager.migrate_to_path(&conn_id, path2_id);

        assert_eq!(*conn.active_path_id.read(), path2_id);
        assert_eq!(*conn.migration_state.read(), MigrationState::Complete);
    }

    #[test]
    fn test_close_connection() {
        let manager = MigrationManager::new(MigrationConfig::default());
        let conn = manager.create_connection(addr(8080), addr(9090));
        let conn_id = conn.id.clone();

        assert_eq!(manager.connection_count(), 1);

        manager.close_connection(&conn_id);

        assert_eq!(manager.connection_count(), 0);
        assert!(manager.get_connection(&conn_id).is_none());
    }

    #[test]
    fn test_path_metrics_update() {
        let manager = MigrationManager::new(MigrationConfig::default());
        let conn = manager.create_connection(addr(8080), addr(9090));
        let conn_id = conn.id.clone();
        let path_id = *conn.active_path_id.read();

        manager.update_path_metrics(&conn_id, path_id, Duration::from_millis(50), 1000, 500);

        let paths = conn.paths.read();
        let path = paths.get(&path_id).unwrap();
        assert!(path.rtt.is_some());
        assert_eq!(path.bytes_sent, 1000);
        assert_eq!(path.bytes_received, 500);
    }

    #[test]
    fn test_max_paths_limit() {
        let config = MigrationConfig {
            max_paths: 2,
            ..Default::default()
        };
        let manager = MigrationManager::new(config);
        let conn = manager.create_connection(addr(8080), addr(9090));
        let conn_id = conn.id.clone();

        // Add second path (should succeed)
        let result = manager.handle_address_change(&conn_id, addr(8081), addr(9091));
        assert!(result.is_some());

        // Add third path (should fail - limit reached)
        let result = manager.handle_address_change(&conn_id, addr(8082), addr(9092));
        assert!(result.is_none());
    }
}
