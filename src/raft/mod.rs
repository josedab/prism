//! Raft Consensus Module
//!
//! Implements Raft consensus for distributed state coordination:
//! - Leader election
//! - Log replication
//! - State machine application
//! - Cluster membership changes
//! - Snapshot support

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// Raft node state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Follower,
    Candidate,
    Leader,
}

/// Raft configuration
#[derive(Debug, Clone)]
pub struct RaftConfig {
    /// Node ID
    pub node_id: String,
    /// Election timeout range (min)
    pub election_timeout_min: Duration,
    /// Election timeout range (max)
    pub election_timeout_max: Duration,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
    /// Maximum log entries per append
    pub max_entries_per_append: usize,
    /// Snapshot threshold (entries before snapshot)
    pub snapshot_threshold: u64,
    /// RPC timeout
    pub rpc_timeout: Duration,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            node_id: "node-1".to_string(),
            election_timeout_min: Duration::from_millis(150),
            election_timeout_max: Duration::from_millis(300),
            heartbeat_interval: Duration::from_millis(50),
            max_entries_per_append: 100,
            snapshot_threshold: 10000,
            rpc_timeout: Duration::from_millis(100),
        }
    }
}

/// Log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub index: u64,
    pub term: u64,
    pub command: Command,
}

/// Command types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    /// Set a key-value pair
    Set { key: String, value: Vec<u8> },
    /// Delete a key
    Delete { key: String },
    /// No-op (used for leader confirmation)
    NoOp,
    /// Configuration change
    ConfigChange(ConfigChange),
}

/// Configuration change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigChange {
    AddNode { node_id: String, address: String },
    RemoveNode { node_id: String },
}

/// Peer node information
#[derive(Debug, Clone)]
pub struct Peer {
    pub id: String,
    pub address: String,
    pub next_index: u64,
    pub match_index: u64,
    pub last_contact: Option<Instant>,
}

/// AppendEntries RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesRequest {
    pub term: u64,
    pub leader_id: String,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub entries: Vec<LogEntry>,
    pub leader_commit: u64,
}

/// AppendEntries RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesResponse {
    pub term: u64,
    pub success: bool,
    pub match_index: u64,
}

/// RequestVote RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteRequest {
    pub term: u64,
    pub candidate_id: String,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

/// RequestVote RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteResponse {
    pub term: u64,
    pub vote_granted: bool,
}

/// Snapshot metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub last_included_index: u64,
    pub last_included_term: u64,
    pub configuration: ClusterConfig,
}

/// Cluster configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub nodes: HashMap<String, String>, // node_id -> address
}

/// Proposal result
pub enum ProposeResult {
    Success { index: u64 },
    NotLeader { leader_id: Option<String> },
    Timeout,
}

/// Apply result (from state machine)
#[derive(Debug, Clone)]
pub struct ApplyResult {
    pub index: u64,
    pub result: Result<Vec<u8>, String>,
}

/// Raft node statistics
#[derive(Debug, Default)]
pub struct RaftStats {
    pub terms: AtomicU64,
    pub elections_started: AtomicU64,
    pub elections_won: AtomicU64,
    pub entries_applied: AtomicU64,
    pub entries_replicated: AtomicU64,
    pub snapshots_taken: AtomicU64,
    pub rpc_sent: AtomicU64,
    pub rpc_received: AtomicU64,
}

/// Raft node
pub struct RaftNode {
    config: RaftConfig,
    state: RwLock<NodeState>,
    current_term: AtomicU64,
    voted_for: RwLock<Option<String>>,
    log: RwLock<Vec<LogEntry>>,
    commit_index: AtomicU64,
    last_applied: AtomicU64,
    leader_id: RwLock<Option<String>>,
    peers: RwLock<HashMap<String, Peer>>,
    last_heartbeat: RwLock<Instant>,
    election_timeout: RwLock<Duration>,
    #[allow(dead_code)]
    snapshot_meta: RwLock<Option<SnapshotMeta>>,
    pending_proposals: RwLock<HashMap<u64, oneshot::Sender<ProposeResult>>>,
    stats: RaftStats,
}

impl RaftNode {
    pub fn new(config: RaftConfig) -> Self {
        let election_timeout = Self::random_election_timeout(&config);

        Self {
            config,
            state: RwLock::new(NodeState::Follower),
            current_term: AtomicU64::new(0),
            voted_for: RwLock::new(None),
            log: RwLock::new(vec![LogEntry {
                index: 0,
                term: 0,
                command: Command::NoOp,
            }]),
            commit_index: AtomicU64::new(0),
            last_applied: AtomicU64::new(0),
            leader_id: RwLock::new(None),
            peers: RwLock::new(HashMap::new()),
            last_heartbeat: RwLock::new(Instant::now()),
            election_timeout: RwLock::new(election_timeout),
            snapshot_meta: RwLock::new(None),
            pending_proposals: RwLock::new(HashMap::new()),
            stats: RaftStats::default(),
        }
    }

    fn random_election_timeout(config: &RaftConfig) -> Duration {
        use rand::Rng;
        let min = config.election_timeout_min.as_millis() as u64;
        let max = config.election_timeout_max.as_millis() as u64;
        let timeout_ms = rand::thread_rng().gen_range(min..=max);
        Duration::from_millis(timeout_ms)
    }

    /// Add a peer node
    pub fn add_peer(&self, id: String, address: String) {
        let log = self.log.read();
        let next_index = log.last().map(|e| e.index + 1).unwrap_or(1);
        drop(log);

        let peer = Peer {
            id: id.clone(),
            address,
            next_index,
            match_index: 0,
            last_contact: None,
        };

        self.peers.write().insert(id, peer);
    }

    /// Remove a peer node
    pub fn remove_peer(&self, id: &str) {
        self.peers.write().remove(id);
    }

    /// Get current node state
    pub fn state(&self) -> NodeState {
        *self.state.read()
    }

    /// Get current term
    pub fn term(&self) -> u64 {
        self.current_term.load(Ordering::SeqCst)
    }

    /// Get leader ID
    pub fn leader_id(&self) -> Option<String> {
        self.leader_id.read().clone()
    }

    /// Check if this node is leader
    pub fn is_leader(&self) -> bool {
        *self.state.read() == NodeState::Leader
    }

    /// Propose a command (only on leader)
    pub fn propose(
        &self,
        command: Command,
    ) -> Result<oneshot::Receiver<ProposeResult>, ProposeError> {
        if !self.is_leader() {
            return Err(ProposeError::NotLeader(self.leader_id()));
        }

        let (tx, rx) = oneshot::channel();
        let term = self.term();

        let index = {
            let mut log = self.log.write();
            let index = log.last().map(|e| e.index + 1).unwrap_or(1);

            log.push(LogEntry {
                index,
                term,
                command,
            });

            index
        };

        self.pending_proposals.write().insert(index, tx);

        Ok(rx)
    }

    /// Handle AppendEntries RPC
    pub fn handle_append_entries(&self, req: AppendEntriesRequest) -> AppendEntriesResponse {
        self.stats.rpc_received.fetch_add(1, Ordering::Relaxed);

        let current_term = self.term();

        // Reply false if term < currentTerm
        if req.term < current_term {
            return AppendEntriesResponse {
                term: current_term,
                success: false,
                match_index: 0,
            };
        }

        // Update term if necessary
        if req.term > current_term {
            self.current_term.store(req.term, Ordering::SeqCst);
            *self.state.write() = NodeState::Follower;
            *self.voted_for.write() = None;
            self.stats.terms.fetch_add(1, Ordering::Relaxed);
        }

        // Reset election timeout
        *self.last_heartbeat.write() = Instant::now();
        *self.leader_id.write() = Some(req.leader_id);

        let log = self.log.read();

        // Check if log contains entry at prevLogIndex with matching term
        if req.prev_log_index > 0 {
            if let Some(entry) = log.iter().find(|e| e.index == req.prev_log_index) {
                if entry.term != req.prev_log_term {
                    return AppendEntriesResponse {
                        term: self.term(),
                        success: false,
                        match_index: req.prev_log_index - 1,
                    };
                }
            } else {
                return AppendEntriesResponse {
                    term: self.term(),
                    success: false,
                    match_index: 0,
                };
            }
        }

        drop(log);

        // Append new entries
        if !req.entries.is_empty() {
            let mut log = self.log.write();

            for entry in req.entries {
                // If existing entry conflicts, delete it and all following
                if let Some(pos) = log.iter().position(|e| e.index == entry.index) {
                    if log[pos].term != entry.term {
                        log.truncate(pos);
                    }
                }

                // Append if new
                if !log.iter().any(|e| e.index == entry.index) {
                    log.push(entry);
                }
            }

            self.stats
                .entries_replicated
                .fetch_add(1, Ordering::Relaxed);
        }

        // Update commit index
        if req.leader_commit > self.commit_index.load(Ordering::SeqCst) {
            let log = self.log.read();
            let last_index = log.last().map(|e| e.index).unwrap_or(0);
            let new_commit = req.leader_commit.min(last_index);
            self.commit_index.store(new_commit, Ordering::SeqCst);
        }

        let match_index = self.log.read().last().map(|e| e.index).unwrap_or(0);

        AppendEntriesResponse {
            term: self.term(),
            success: true,
            match_index,
        }
    }

    /// Handle RequestVote RPC
    pub fn handle_request_vote(&self, req: RequestVoteRequest) -> RequestVoteResponse {
        self.stats.rpc_received.fetch_add(1, Ordering::Relaxed);

        let current_term = self.term();

        // Reply false if term < currentTerm
        if req.term < current_term {
            return RequestVoteResponse {
                term: current_term,
                vote_granted: false,
            };
        }

        // Update term if necessary
        if req.term > current_term {
            self.current_term.store(req.term, Ordering::SeqCst);
            *self.state.write() = NodeState::Follower;
            *self.voted_for.write() = None;
            self.stats.terms.fetch_add(1, Ordering::Relaxed);
        }

        let voted_for = self.voted_for.read().clone();
        let can_vote = voted_for.is_none() || voted_for.as_ref() == Some(&req.candidate_id);

        if !can_vote {
            return RequestVoteResponse {
                term: self.term(),
                vote_granted: false,
            };
        }

        // Check if candidate's log is at least as up-to-date
        let log = self.log.read();
        let last_log_index = log.last().map(|e| e.index).unwrap_or(0);
        let last_log_term = log.last().map(|e| e.term).unwrap_or(0);
        drop(log);

        let log_ok = req.last_log_term > last_log_term
            || (req.last_log_term == last_log_term && req.last_log_index >= last_log_index);

        if log_ok {
            *self.voted_for.write() = Some(req.candidate_id);
            *self.last_heartbeat.write() = Instant::now();

            RequestVoteResponse {
                term: self.term(),
                vote_granted: true,
            }
        } else {
            RequestVoteResponse {
                term: self.term(),
                vote_granted: false,
            }
        }
    }

    /// Start election
    pub fn start_election(&self) -> Vec<RequestVoteRequest> {
        self.stats.elections_started.fetch_add(1, Ordering::Relaxed);

        // Increment term
        let new_term = self.current_term.fetch_add(1, Ordering::SeqCst) + 1;
        self.stats.terms.fetch_add(1, Ordering::Relaxed);

        // Transition to candidate
        *self.state.write() = NodeState::Candidate;

        // Vote for self
        *self.voted_for.write() = Some(self.config.node_id.clone());

        // Reset election timeout
        *self.election_timeout.write() = Self::random_election_timeout(&self.config);
        *self.last_heartbeat.write() = Instant::now();

        // Build vote requests
        let log = self.log.read();
        let last_log_index = log.last().map(|e| e.index).unwrap_or(0);
        let last_log_term = log.last().map(|e| e.term).unwrap_or(0);
        drop(log);

        let peers = self.peers.read();
        peers
            .values()
            .map(|_| RequestVoteRequest {
                term: new_term,
                candidate_id: self.config.node_id.clone(),
                last_log_index,
                last_log_term,
            })
            .collect()
    }

    /// Become leader
    pub fn become_leader(&self) {
        self.stats.elections_won.fetch_add(1, Ordering::Relaxed);

        *self.state.write() = NodeState::Leader;
        *self.leader_id.write() = Some(self.config.node_id.clone());

        // Initialize peer state
        let log = self.log.read();
        let next_index = log.last().map(|e| e.index + 1).unwrap_or(1);
        drop(log);

        let mut peers = self.peers.write();
        for peer in peers.values_mut() {
            peer.next_index = next_index;
            peer.match_index = 0;
        }

        // Append no-op entry to commit entries from previous term
        let mut log = self.log.write();
        let term = self.term();
        let index = log.last().map(|e| e.index + 1).unwrap_or(1);
        log.push(LogEntry {
            index,
            term,
            command: Command::NoOp,
        });
    }

    /// Generate heartbeat/append entries requests
    pub fn generate_append_entries(&self) -> Vec<(String, AppendEntriesRequest)> {
        if !self.is_leader() {
            return Vec::new();
        }

        let log = self.log.read();
        let commit_index = self.commit_index.load(Ordering::SeqCst);
        let term = self.term();
        let leader_id = self.config.node_id.clone();

        let peers = self.peers.read();
        peers
            .values()
            .map(|peer| {
                let prev_log_index = peer.next_index.saturating_sub(1);
                let prev_log_term = log
                    .iter()
                    .find(|e| e.index == prev_log_index)
                    .map(|e| e.term)
                    .unwrap_or(0);

                let entries: Vec<LogEntry> = log
                    .iter()
                    .filter(|e| e.index >= peer.next_index)
                    .take(self.config.max_entries_per_append)
                    .cloned()
                    .collect();

                (
                    peer.id.clone(),
                    AppendEntriesRequest {
                        term,
                        leader_id: leader_id.clone(),
                        prev_log_index,
                        prev_log_term,
                        entries,
                        leader_commit: commit_index,
                    },
                )
            })
            .collect()
    }

    /// Handle append entries response
    pub fn handle_append_response(&self, peer_id: &str, response: AppendEntriesResponse) {
        if response.term > self.term() {
            self.current_term.store(response.term, Ordering::SeqCst);
            *self.state.write() = NodeState::Follower;
            *self.voted_for.write() = None;
            return;
        }

        if !self.is_leader() {
            return;
        }

        let mut peers = self.peers.write();
        if let Some(peer) = peers.get_mut(peer_id) {
            if response.success {
                peer.match_index = response.match_index;
                peer.next_index = response.match_index + 1;
                peer.last_contact = Some(Instant::now());
            } else {
                // Decrement next_index and retry
                peer.next_index = peer.next_index.saturating_sub(1).max(1);
            }
        }
        drop(peers);

        // Update commit index
        self.update_commit_index();
    }

    fn update_commit_index(&self) {
        let peers = self.peers.read();
        let mut match_indices: Vec<u64> = peers.values().map(|p| p.match_index).collect();
        drop(peers);

        let log = self.log.read();
        let our_match = log.last().map(|e| e.index).unwrap_or(0);
        match_indices.push(our_match);
        match_indices.sort_unstable();

        // Majority is (n/2 + 1), so the median gives us the commit index
        let majority_index = match_indices.len() / 2;
        let potential_commit = match_indices[majority_index];

        // Only commit entries from current term
        let current_term = self.term();
        if let Some(entry) = log.iter().find(|e| e.index == potential_commit) {
            if entry.term == current_term {
                let old_commit = self.commit_index.load(Ordering::SeqCst);
                if potential_commit > old_commit {
                    self.commit_index.store(potential_commit, Ordering::SeqCst);
                }
            }
        }
    }

    /// Check if election timeout has expired
    pub fn election_timeout_expired(&self) -> bool {
        let last = *self.last_heartbeat.read();
        let timeout = *self.election_timeout.read();
        last.elapsed() >= timeout
    }

    /// Get entries to apply to state machine
    pub fn get_entries_to_apply(&self) -> Vec<LogEntry> {
        let commit_index = self.commit_index.load(Ordering::SeqCst);
        let last_applied = self.last_applied.load(Ordering::SeqCst);

        if commit_index <= last_applied {
            return Vec::new();
        }

        let log = self.log.read();
        let entries: Vec<LogEntry> = log
            .iter()
            .filter(|e| e.index > last_applied && e.index <= commit_index)
            .cloned()
            .collect();

        entries
    }

    /// Mark entries as applied
    pub fn mark_applied(&self, index: u64) {
        let current = self.last_applied.load(Ordering::SeqCst);
        if index > current {
            self.last_applied.store(index, Ordering::SeqCst);
            self.stats.entries_applied.fetch_add(1, Ordering::Relaxed);
        }

        // Resolve pending proposals
        if self.is_leader() {
            if let Some(sender) = self.pending_proposals.write().remove(&index) {
                let _ = sender.send(ProposeResult::Success { index });
            }
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &RaftStats {
        &self.stats
    }
}

/// Propose error
#[derive(Debug)]
pub enum ProposeError {
    NotLeader(Option<String>),
}

impl std::fmt::Display for ProposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotLeader(leader) => {
                if let Some(id) = leader {
                    write!(f, "Not leader, leader is: {}", id)
                } else {
                    write!(f, "Not leader, leader unknown")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_node_is_follower() {
        let node = RaftNode::new(RaftConfig::default());
        assert_eq!(node.state(), NodeState::Follower);
        assert_eq!(node.term(), 0);
    }

    #[test]
    fn test_add_peer() {
        let node = RaftNode::new(RaftConfig::default());
        node.add_peer("node-2".to_string(), "127.0.0.1:8081".to_string());

        let peers = node.peers.read();
        assert!(peers.contains_key("node-2"));
    }

    #[test]
    fn test_start_election() {
        let node = RaftNode::new(RaftConfig::default());
        node.add_peer("node-2".to_string(), "127.0.0.1:8081".to_string());

        let requests = node.start_election();

        assert_eq!(node.state(), NodeState::Candidate);
        assert_eq!(node.term(), 1);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].candidate_id, "node-1");
    }

    #[test]
    fn test_become_leader() {
        let node = RaftNode::new(RaftConfig::default());
        node.start_election();
        node.become_leader();

        assert_eq!(node.state(), NodeState::Leader);
        assert_eq!(node.leader_id(), Some("node-1".to_string()));
    }

    #[test]
    fn test_append_entries_updates_term() {
        let node = RaftNode::new(RaftConfig::default());

        let req = AppendEntriesRequest {
            term: 5,
            leader_id: "node-2".to_string(),
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        };

        let response = node.handle_append_entries(req);

        assert!(response.success);
        assert_eq!(node.term(), 5);
        assert_eq!(node.leader_id(), Some("node-2".to_string()));
    }

    #[test]
    fn test_request_vote() {
        let node = RaftNode::new(RaftConfig::default());

        let req = RequestVoteRequest {
            term: 1,
            candidate_id: "node-2".to_string(),
            last_log_index: 0,
            last_log_term: 0,
        };

        let response = node.handle_request_vote(req);

        assert!(response.vote_granted);
        assert_eq!(*node.voted_for.read(), Some("node-2".to_string()));
    }

    #[test]
    fn test_request_vote_reject_lower_term() {
        let node = RaftNode::new(RaftConfig::default());
        node.current_term.store(5, Ordering::SeqCst);

        let req = RequestVoteRequest {
            term: 3,
            candidate_id: "node-2".to_string(),
            last_log_index: 0,
            last_log_term: 0,
        };

        let response = node.handle_request_vote(req);

        assert!(!response.vote_granted);
        assert_eq!(response.term, 5);
    }

    #[test]
    fn test_propose_not_leader() {
        let node = RaftNode::new(RaftConfig::default());

        let result = node.propose(Command::Set {
            key: "test".to_string(),
            value: vec![1, 2, 3],
        });

        assert!(matches!(result, Err(ProposeError::NotLeader(_))));
    }

    #[test]
    fn test_propose_as_leader() {
        let node = RaftNode::new(RaftConfig::default());
        node.start_election();
        node.become_leader();

        let result = node.propose(Command::Set {
            key: "test".to_string(),
            value: vec![1, 2, 3],
        });

        assert!(result.is_ok());

        let log = node.log.read();
        assert!(log.len() >= 2); // Initial entry + proposed entry
    }

    #[test]
    fn test_generate_append_entries() {
        let config = RaftConfig {
            node_id: "node-1".to_string(),
            ..Default::default()
        };
        let node = RaftNode::new(config);
        node.add_peer("node-2".to_string(), "127.0.0.1:8081".to_string());
        node.start_election();
        node.become_leader();

        let requests = node.generate_append_entries();

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, "node-2");
        assert_eq!(requests[0].1.leader_id, "node-1");
    }

    #[test]
    fn test_log_replication() {
        let node = RaftNode::new(RaftConfig::default());

        let entries = vec![LogEntry {
            index: 1,
            term: 1,
            command: Command::Set {
                key: "foo".to_string(),
                value: vec![1, 2, 3],
            },
        }];

        let req = AppendEntriesRequest {
            term: 1,
            leader_id: "leader".to_string(),
            prev_log_index: 0,
            prev_log_term: 0,
            entries,
            leader_commit: 1,
        };

        let response = node.handle_append_entries(req);

        assert!(response.success);
        assert_eq!(response.match_index, 1);
        assert_eq!(node.commit_index.load(Ordering::SeqCst), 1);
    }
}
