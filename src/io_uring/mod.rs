//! io_uring High-Performance I/O Module
//!
//! Provides io_uring-based asynchronous I/O for Linux systems, offering:
//! - Submission and completion queue management
//! - Batched I/O operations
//! - Zero-copy networking where possible
//! - Kernel-bypass for reduced syscall overhead
//!
//! This module is only available on Linux systems with io_uring support.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// io_uring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IoUringConfig {
    /// Enable io_uring
    #[serde(default)]
    pub enabled: bool,

    /// Submission queue depth
    #[serde(default = "default_sq_depth")]
    pub sq_depth: u32,

    /// Completion queue depth (0 = 2x sq_depth)
    #[serde(default)]
    pub cq_depth: u32,

    /// Enable kernel polling (SQPOLL)
    #[serde(default)]
    pub kernel_poll: bool,

    /// Kernel poll idle time before sleeping (ms)
    #[serde(default = "default_sq_poll_idle")]
    pub sq_poll_idle_ms: u32,

    /// Enable fixed buffers for zero-copy
    #[serde(default = "default_true")]
    pub fixed_buffers: bool,

    /// Number of fixed buffers
    #[serde(default = "default_num_buffers")]
    pub num_buffers: usize,

    /// Size of each fixed buffer
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Enable registered file descriptors
    #[serde(default = "default_true")]
    pub registered_fds: bool,

    /// Maximum registered file descriptors
    #[serde(default = "default_max_fds")]
    pub max_registered_fds: usize,

    /// Batch submission threshold
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Submission timeout (ms)
    #[serde(default = "default_submit_timeout")]
    pub submit_timeout_ms: u64,

    /// Enable multishot accept
    #[serde(default = "default_true")]
    pub multishot_accept: bool,

    /// Enable multishot receive
    #[serde(default)]
    pub multishot_recv: bool,

    /// Enable buffer ring
    #[serde(default)]
    pub buffer_ring: bool,
}

fn default_sq_depth() -> u32 {
    4096
}

fn default_sq_poll_idle() -> u32 {
    1000
}

fn default_true() -> bool {
    true
}

fn default_num_buffers() -> usize {
    1024
}

fn default_buffer_size() -> usize {
    4096
}

fn default_max_fds() -> usize {
    1024
}

fn default_batch_size() -> usize {
    32
}

fn default_submit_timeout() -> u64 {
    100
}

impl Default for IoUringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sq_depth: default_sq_depth(),
            cq_depth: 0,
            kernel_poll: false,
            sq_poll_idle_ms: default_sq_poll_idle(),
            fixed_buffers: true,
            num_buffers: default_num_buffers(),
            buffer_size: default_buffer_size(),
            registered_fds: true,
            max_registered_fds: default_max_fds(),
            batch_size: default_batch_size(),
            submit_timeout_ms: default_submit_timeout(),
            multishot_accept: true,
            multishot_recv: false,
            buffer_ring: false,
        }
    }
}

/// io_uring operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpType {
    /// Read operation
    Read,
    /// Write operation
    Write,
    /// Accept new connection
    Accept,
    /// Connect to remote
    Connect,
    /// Close file descriptor
    Close,
    /// Timeout operation
    Timeout,
    /// Cancel operation
    Cancel,
    /// Linked timeout
    LinkTimeout,
    /// Poll for events
    Poll,
    /// Send data
    Send,
    /// Receive data
    Recv,
    /// Sendmsg
    SendMsg,
    /// Recvmsg
    RecvMsg,
    /// Splice data
    Splice,
    /// No-op (for probing)
    Nop,
    /// Provide buffers
    ProvideBuffers,
    /// Remove buffers
    RemoveBuffers,
    /// Shutdown socket
    Shutdown,
}

impl fmt::Display for OpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpType::Read => write!(f, "read"),
            OpType::Write => write!(f, "write"),
            OpType::Accept => write!(f, "accept"),
            OpType::Connect => write!(f, "connect"),
            OpType::Close => write!(f, "close"),
            OpType::Timeout => write!(f, "timeout"),
            OpType::Cancel => write!(f, "cancel"),
            OpType::LinkTimeout => write!(f, "link_timeout"),
            OpType::Poll => write!(f, "poll"),
            OpType::Send => write!(f, "send"),
            OpType::Recv => write!(f, "recv"),
            OpType::SendMsg => write!(f, "sendmsg"),
            OpType::RecvMsg => write!(f, "recvmsg"),
            OpType::Splice => write!(f, "splice"),
            OpType::Nop => write!(f, "nop"),
            OpType::ProvideBuffers => write!(f, "provide_buffers"),
            OpType::RemoveBuffers => write!(f, "remove_buffers"),
            OpType::Shutdown => write!(f, "shutdown"),
        }
    }
}

/// Completion entry result
#[derive(Debug, Clone)]
pub struct CompletionEntry {
    /// User data (for correlation)
    pub user_data: u64,
    /// Result code (negative on error)
    pub result: i32,
    /// Flags
    pub flags: u32,
    /// Operation type
    pub op_type: OpType,
}

impl CompletionEntry {
    /// Check if operation succeeded
    pub fn is_success(&self) -> bool {
        self.result >= 0
    }

    /// Get error code if failed
    pub fn error_code(&self) -> Option<i32> {
        if self.result < 0 {
            Some(-self.result)
        } else {
            None
        }
    }

    /// Check if more data available (multishot)
    pub fn has_more(&self) -> bool {
        self.flags & CQEF_MORE != 0
    }
}

/// Completion queue entry flags
const CQEF_MORE: u32 = 1 << 1;

/// io_uring error types
#[derive(Debug, Clone)]
pub enum IoUringError {
    /// Kernel doesn't support io_uring
    NotSupported(String),
    /// Ring setup failed
    SetupFailed(String),
    /// Submission queue full
    SubmissionQueueFull,
    /// Operation canceled
    Canceled,
    /// Invalid operation
    InvalidOperation(String),
    /// Buffer allocation failed
    BufferAllocation(String),
    /// File descriptor registration failed
    FdRegistration(String),
    /// Timeout
    Timeout,
    /// I/O error
    Io(i32),
}

impl fmt::Display for IoUringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IoUringError::NotSupported(msg) => write!(f, "io_uring not supported: {}", msg),
            IoUringError::SetupFailed(msg) => write!(f, "io_uring setup failed: {}", msg),
            IoUringError::SubmissionQueueFull => write!(f, "Submission queue full"),
            IoUringError::Canceled => write!(f, "Operation canceled"),
            IoUringError::InvalidOperation(msg) => write!(f, "Invalid operation: {}", msg),
            IoUringError::BufferAllocation(msg) => write!(f, "Buffer allocation failed: {}", msg),
            IoUringError::FdRegistration(msg) => write!(f, "FD registration failed: {}", msg),
            IoUringError::Timeout => write!(f, "Operation timed out"),
            IoUringError::Io(code) => write!(f, "I/O error: {}", code),
        }
    }
}

impl std::error::Error for IoUringError {}

/// Fixed buffer pool for zero-copy I/O
pub struct BufferPool {
    /// Buffer data
    buffers: Vec<Vec<u8>>,
    /// Free buffer indices
    free_list: Vec<usize>,
    /// Buffer size
    buffer_size: usize,
    /// Stats
    stats: BufferPoolStats,
}

/// Buffer pool statistics
#[derive(Debug, Default)]
struct BufferPoolStats {
    allocations: AtomicU64,
    releases: AtomicU64,
    allocation_failures: AtomicU64,
}

impl BufferPool {
    /// Create a new buffer pool
    pub fn new(num_buffers: usize, buffer_size: usize) -> Self {
        let buffers: Vec<Vec<u8>> = (0..num_buffers).map(|_| vec![0u8; buffer_size]).collect();
        let free_list: Vec<usize> = (0..num_buffers).collect();

        info!(
            "Created buffer pool with {} buffers of {} bytes each",
            num_buffers, buffer_size
        );

        Self {
            buffers,
            free_list,
            buffer_size,
            stats: BufferPoolStats::default(),
        }
    }

    /// Allocate a buffer
    pub fn alloc(&mut self) -> Option<(usize, &mut [u8])> {
        if let Some(idx) = self.free_list.pop() {
            self.stats.allocations.fetch_add(1, Ordering::Relaxed);
            Some((idx, &mut self.buffers[idx]))
        } else {
            self.stats
                .allocation_failures
                .fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Release a buffer back to the pool
    pub fn release(&mut self, idx: usize) {
        if idx < self.buffers.len() && !self.free_list.contains(&idx) {
            self.free_list.push(idx);
            self.stats.releases.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get buffer by index (immutable)
    pub fn get(&self, idx: usize) -> Option<&[u8]> {
        self.buffers.get(idx).map(|b| b.as_slice())
    }

    /// Get buffer by index (mutable)
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut [u8]> {
        self.buffers.get_mut(idx).map(|b| b.as_mut_slice())
    }

    /// Get number of free buffers
    pub fn available(&self) -> usize {
        self.free_list.len()
    }

    /// Get total number of buffers
    pub fn capacity(&self) -> usize {
        self.buffers.len()
    }

    /// Get buffer size
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// Get statistics snapshot
    pub fn stats(&self) -> BufferPoolStatsSnapshot {
        BufferPoolStatsSnapshot {
            allocations: self.stats.allocations.load(Ordering::Relaxed),
            releases: self.stats.releases.load(Ordering::Relaxed),
            allocation_failures: self.stats.allocation_failures.load(Ordering::Relaxed),
            available: self.free_list.len() as u64,
            capacity: self.buffers.len() as u64,
        }
    }
}

/// Buffer pool statistics snapshot
#[derive(Debug, Clone)]
pub struct BufferPoolStatsSnapshot {
    pub allocations: u64,
    pub releases: u64,
    pub allocation_failures: u64,
    pub available: u64,
    pub capacity: u64,
}

/// Registered file descriptor table
pub struct FdTable {
    /// File descriptors
    fds: Vec<Option<i32>>,
    /// Free slots
    free_slots: Vec<usize>,
    /// FD to index mapping
    fd_to_idx: HashMap<i32, usize>,
}

impl FdTable {
    /// Create a new FD table
    pub fn new(max_fds: usize) -> Self {
        Self {
            fds: vec![None; max_fds],
            free_slots: (0..max_fds).collect(),
            fd_to_idx: HashMap::new(),
        }
    }

    /// Register a file descriptor
    pub fn register(&mut self, fd: i32) -> Option<usize> {
        if self.fd_to_idx.contains_key(&fd) {
            return self.fd_to_idx.get(&fd).copied();
        }

        if let Some(idx) = self.free_slots.pop() {
            self.fds[idx] = Some(fd);
            self.fd_to_idx.insert(fd, idx);
            debug!("Registered fd {} at index {}", fd, idx);
            Some(idx)
        } else {
            warn!("FD table full, cannot register fd {}", fd);
            None
        }
    }

    /// Unregister a file descriptor
    pub fn unregister(&mut self, fd: i32) -> Option<usize> {
        if let Some(idx) = self.fd_to_idx.remove(&fd) {
            self.fds[idx] = None;
            self.free_slots.push(idx);
            debug!("Unregistered fd {} from index {}", fd, idx);
            Some(idx)
        } else {
            None
        }
    }

    /// Get index for a file descriptor
    pub fn get_index(&self, fd: i32) -> Option<usize> {
        self.fd_to_idx.get(&fd).copied()
    }

    /// Get FD at index
    pub fn get_fd(&self, idx: usize) -> Option<i32> {
        self.fds.get(idx).and_then(|&fd| fd)
    }

    /// Get number of registered FDs
    pub fn count(&self) -> usize {
        self.fd_to_idx.len()
    }

    /// Get capacity
    pub fn capacity(&self) -> usize {
        self.fds.len()
    }
}

/// io_uring ring instance
pub struct IoUring {
    /// Configuration
    config: IoUringConfig,
    /// Buffer pool
    buffers: Arc<RwLock<BufferPool>>,
    /// FD table
    fd_table: Arc<RwLock<FdTable>>,
    /// Running flag
    running: AtomicBool,
    /// Statistics
    stats: IoUringStats,
    /// Pending operations
    pending_ops: Arc<RwLock<HashMap<u64, PendingOp>>>,
    /// Next user data ID
    next_user_data: AtomicU64,
}

/// Pending operation
struct PendingOp {
    op_type: OpType,
    submitted_at: Instant,
    buffer_idx: Option<usize>,
}

/// io_uring statistics
#[derive(Debug, Default)]
pub struct IoUringStats {
    /// Operations submitted
    submissions: AtomicU64,
    /// Operations completed
    completions: AtomicU64,
    /// Successful operations
    successes: AtomicU64,
    /// Failed operations
    failures: AtomicU64,
    /// Submission queue overflows
    sq_overflows: AtomicU64,
    /// Completion queue overflows
    cq_overflows: AtomicU64,
    /// Total bytes read
    bytes_read: AtomicU64,
    /// Total bytes written
    bytes_written: AtomicU64,
    /// Per-operation counts
    op_counts: [AtomicU64; 18],
}

impl IoUringStats {
    /// Get snapshot
    pub fn snapshot(&self) -> IoUringStatsSnapshot {
        let mut op_counts = HashMap::new();
        let ops = [
            OpType::Read,
            OpType::Write,
            OpType::Accept,
            OpType::Connect,
            OpType::Close,
            OpType::Timeout,
            OpType::Cancel,
            OpType::LinkTimeout,
            OpType::Poll,
            OpType::Send,
            OpType::Recv,
            OpType::SendMsg,
            OpType::RecvMsg,
            OpType::Splice,
            OpType::Nop,
            OpType::ProvideBuffers,
            OpType::RemoveBuffers,
            OpType::Shutdown,
        ];

        for (i, op) in ops.iter().enumerate() {
            op_counts.insert(*op, self.op_counts[i].load(Ordering::Relaxed));
        }

        IoUringStatsSnapshot {
            submissions: self.submissions.load(Ordering::Relaxed),
            completions: self.completions.load(Ordering::Relaxed),
            successes: self.successes.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            sq_overflows: self.sq_overflows.load(Ordering::Relaxed),
            cq_overflows: self.cq_overflows.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            op_counts,
        }
    }

    fn record_op(&self, op_type: OpType) {
        let idx = match op_type {
            OpType::Read => 0,
            OpType::Write => 1,
            OpType::Accept => 2,
            OpType::Connect => 3,
            OpType::Close => 4,
            OpType::Timeout => 5,
            OpType::Cancel => 6,
            OpType::LinkTimeout => 7,
            OpType::Poll => 8,
            OpType::Send => 9,
            OpType::Recv => 10,
            OpType::SendMsg => 11,
            OpType::RecvMsg => 12,
            OpType::Splice => 13,
            OpType::Nop => 14,
            OpType::ProvideBuffers => 15,
            OpType::RemoveBuffers => 16,
            OpType::Shutdown => 17,
        };
        self.op_counts[idx].fetch_add(1, Ordering::Relaxed);
    }
}

/// Statistics snapshot
#[derive(Debug, Clone)]
pub struct IoUringStatsSnapshot {
    pub submissions: u64,
    pub completions: u64,
    pub successes: u64,
    pub failures: u64,
    pub sq_overflows: u64,
    pub cq_overflows: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub op_counts: HashMap<OpType, u64>,
}

impl IoUring {
    /// Create a new io_uring instance
    pub fn new(config: IoUringConfig) -> Result<Self, IoUringError> {
        // In a real implementation, this would call io_uring_setup()
        // For this mock, we just set up our data structures

        info!(
            "Creating io_uring with sq_depth={}, cq_depth={}",
            config.sq_depth,
            if config.cq_depth == 0 {
                config.sq_depth * 2
            } else {
                config.cq_depth
            }
        );

        let buffers = if config.fixed_buffers {
            Arc::new(RwLock::new(BufferPool::new(
                config.num_buffers,
                config.buffer_size,
            )))
        } else {
            Arc::new(RwLock::new(BufferPool::new(0, 0)))
        };

        let fd_table = if config.registered_fds {
            Arc::new(RwLock::new(FdTable::new(config.max_registered_fds)))
        } else {
            Arc::new(RwLock::new(FdTable::new(0)))
        };

        Ok(Self {
            config,
            buffers,
            fd_table,
            running: AtomicBool::new(false),
            stats: IoUringStats::default(),
            pending_ops: Arc::new(RwLock::new(HashMap::new())),
            next_user_data: AtomicU64::new(1),
        })
    }

    /// Start the io_uring instance
    pub async fn start(&self) -> Result<(), IoUringError> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(()); // Already running
        }

        info!("Starting io_uring instance");
        Ok(())
    }

    /// Stop the io_uring instance
    pub async fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Stopped io_uring instance");
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Submit a read operation
    pub async fn submit_read(&self, fd: i32, len: usize) -> Result<u64, IoUringError> {
        if !self.is_running() {
            return Err(IoUringError::InvalidOperation(
                "Ring not running".to_string(),
            ));
        }

        let user_data = self.next_user_data.fetch_add(1, Ordering::SeqCst);

        // Get buffer
        let buffer_idx = {
            let mut buffers = self.buffers.write().await;
            buffers.alloc().map(|(idx, _)| idx)
        };

        let buffer_idx = buffer_idx.ok_or(IoUringError::BufferAllocation(
            "No buffers available".to_string(),
        ))?;

        // Record pending operation
        {
            let mut pending = self.pending_ops.write().await;
            pending.insert(
                user_data,
                PendingOp {
                    op_type: OpType::Read,
                    submitted_at: Instant::now(),
                    buffer_idx: Some(buffer_idx),
                },
            );
        }

        self.stats.submissions.fetch_add(1, Ordering::Relaxed);
        self.stats.record_op(OpType::Read);

        debug!(
            "Submitted read: fd={}, len={}, user_data={}",
            fd, len, user_data
        );

        Ok(user_data)
    }

    /// Submit a write operation
    pub async fn submit_write(&self, fd: i32, data: &[u8]) -> Result<u64, IoUringError> {
        if !self.is_running() {
            return Err(IoUringError::InvalidOperation(
                "Ring not running".to_string(),
            ));
        }

        let user_data = self.next_user_data.fetch_add(1, Ordering::SeqCst);

        // Record pending operation
        {
            let mut pending = self.pending_ops.write().await;
            pending.insert(
                user_data,
                PendingOp {
                    op_type: OpType::Write,
                    submitted_at: Instant::now(),
                    buffer_idx: None,
                },
            );
        }

        self.stats.submissions.fetch_add(1, Ordering::Relaxed);
        self.stats.record_op(OpType::Write);
        self.stats
            .bytes_written
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        debug!(
            "Submitted write: fd={}, len={}, user_data={}",
            fd,
            data.len(),
            user_data
        );

        Ok(user_data)
    }

    /// Submit an accept operation
    pub async fn submit_accept(&self, fd: i32) -> Result<u64, IoUringError> {
        if !self.is_running() {
            return Err(IoUringError::InvalidOperation(
                "Ring not running".to_string(),
            ));
        }

        let user_data = self.next_user_data.fetch_add(1, Ordering::SeqCst);

        // Record pending operation
        {
            let mut pending = self.pending_ops.write().await;
            pending.insert(
                user_data,
                PendingOp {
                    op_type: OpType::Accept,
                    submitted_at: Instant::now(),
                    buffer_idx: None,
                },
            );
        }

        self.stats.submissions.fetch_add(1, Ordering::Relaxed);
        self.stats.record_op(OpType::Accept);

        debug!("Submitted accept: fd={}, user_data={}", fd, user_data);

        Ok(user_data)
    }

    /// Submit a connect operation
    pub async fn submit_connect(&self, fd: i32, addr: &str) -> Result<u64, IoUringError> {
        if !self.is_running() {
            return Err(IoUringError::InvalidOperation(
                "Ring not running".to_string(),
            ));
        }

        let user_data = self.next_user_data.fetch_add(1, Ordering::SeqCst);

        // Record pending operation
        {
            let mut pending = self.pending_ops.write().await;
            pending.insert(
                user_data,
                PendingOp {
                    op_type: OpType::Connect,
                    submitted_at: Instant::now(),
                    buffer_idx: None,
                },
            );
        }

        self.stats.submissions.fetch_add(1, Ordering::Relaxed);
        self.stats.record_op(OpType::Connect);

        debug!(
            "Submitted connect: fd={}, addr={}, user_data={}",
            fd, addr, user_data
        );

        Ok(user_data)
    }

    /// Submit a close operation
    pub async fn submit_close(&self, fd: i32) -> Result<u64, IoUringError> {
        if !self.is_running() {
            return Err(IoUringError::InvalidOperation(
                "Ring not running".to_string(),
            ));
        }

        let user_data = self.next_user_data.fetch_add(1, Ordering::SeqCst);

        // Record pending operation
        {
            let mut pending = self.pending_ops.write().await;
            pending.insert(
                user_data,
                PendingOp {
                    op_type: OpType::Close,
                    submitted_at: Instant::now(),
                    buffer_idx: None,
                },
            );
        }

        self.stats.submissions.fetch_add(1, Ordering::Relaxed);
        self.stats.record_op(OpType::Close);

        debug!("Submitted close: fd={}, user_data={}", fd, user_data);

        Ok(user_data)
    }

    /// Poll for completions (mock implementation)
    pub async fn poll_completions(&self) -> Vec<CompletionEntry> {
        // In real implementation, this would call io_uring_peek_batch_cqe()
        // For mock, we simulate completion of pending operations

        let mut completions = Vec::new();
        let mut to_remove = Vec::new();

        {
            let pending = self.pending_ops.read().await;
            for (&user_data, op) in pending.iter() {
                // Simulate completion after a short delay
                if op.submitted_at.elapsed() > Duration::from_micros(100) {
                    completions.push(CompletionEntry {
                        user_data,
                        result: 0, // Success
                        flags: 0,
                        op_type: op.op_type,
                    });
                    to_remove.push(user_data);
                }
            }
        }

        // Remove completed operations
        if !to_remove.is_empty() {
            let mut pending = self.pending_ops.write().await;
            let mut buffers = self.buffers.write().await;

            for user_data in &to_remove {
                if let Some(op) = pending.remove(user_data) {
                    if let Some(idx) = op.buffer_idx {
                        buffers.release(idx);
                    }
                }
            }
        }

        // Update stats
        for entry in &completions {
            self.stats.completions.fetch_add(1, Ordering::Relaxed);
            if entry.is_success() {
                self.stats.successes.fetch_add(1, Ordering::Relaxed);
            } else {
                self.stats.failures.fetch_add(1, Ordering::Relaxed);
            }
        }

        completions
    }

    /// Register a file descriptor
    pub async fn register_fd(&self, fd: i32) -> Result<usize, IoUringError> {
        let mut fd_table = self.fd_table.write().await;
        fd_table
            .register(fd)
            .ok_or_else(|| IoUringError::FdRegistration("FD table full".to_string()))
    }

    /// Unregister a file descriptor
    pub async fn unregister_fd(&self, fd: i32) -> Option<usize> {
        let mut fd_table = self.fd_table.write().await;
        fd_table.unregister(fd)
    }

    /// Get statistics
    pub fn stats(&self) -> IoUringStatsSnapshot {
        self.stats.snapshot()
    }

    /// Get buffer pool stats
    pub async fn buffer_stats(&self) -> BufferPoolStatsSnapshot {
        self.buffers.read().await.stats()
    }

    /// Get configuration
    pub fn config(&self) -> &IoUringConfig {
        &self.config
    }
}

/// Feature detection for io_uring capabilities
pub struct FeatureDetector {
    /// Detected features
    features: HashMap<String, bool>,
}

impl FeatureDetector {
    /// Create a new feature detector
    pub fn new() -> Self {
        Self {
            features: HashMap::new(),
        }
    }

    /// Probe available features (mock implementation)
    pub fn probe(&mut self) -> &HashMap<String, bool> {
        // In real implementation, this would probe io_uring_get_probe()
        // For mock, we assume common features are available

        self.features.insert("IORING_OP_NOP".to_string(), true);
        self.features.insert("IORING_OP_READV".to_string(), true);
        self.features.insert("IORING_OP_WRITEV".to_string(), true);
        self.features.insert("IORING_OP_FSYNC".to_string(), true);
        self.features
            .insert("IORING_OP_READ_FIXED".to_string(), true);
        self.features
            .insert("IORING_OP_WRITE_FIXED".to_string(), true);
        self.features.insert("IORING_OP_POLL_ADD".to_string(), true);
        self.features
            .insert("IORING_OP_POLL_REMOVE".to_string(), true);
        self.features.insert("IORING_OP_ACCEPT".to_string(), true);
        self.features.insert("IORING_OP_CONNECT".to_string(), true);
        self.features.insert("IORING_OP_CLOSE".to_string(), true);
        self.features.insert("IORING_OP_SEND".to_string(), true);
        self.features.insert("IORING_OP_RECV".to_string(), true);
        self.features.insert("IORING_OP_SPLICE".to_string(), true);
        self.features
            .insert("IORING_OP_PROVIDE_BUFFERS".to_string(), true);
        self.features
            .insert("IORING_OP_REMOVE_BUFFERS".to_string(), true);

        // Multishot features (newer kernels)
        self.features
            .insert("IORING_ACCEPT_MULTISHOT".to_string(), true);
        self.features
            .insert("IORING_RECV_MULTISHOT".to_string(), false); // Newer kernel

        &self.features
    }

    /// Check if a feature is supported
    pub fn supports(&self, feature: &str) -> bool {
        self.features.get(feature).copied().unwrap_or(false)
    }

    /// Get kernel version requirement for a feature
    pub fn kernel_version_for(feature: &str) -> Option<&'static str> {
        match feature {
            "IORING_OP_NOP" => Some("5.1"),
            "IORING_OP_READV" => Some("5.1"),
            "IORING_OP_WRITEV" => Some("5.1"),
            "IORING_OP_ACCEPT" => Some("5.5"),
            "IORING_OP_CONNECT" => Some("5.5"),
            "IORING_OP_CLOSE" => Some("5.6"),
            "IORING_OP_SEND" => Some("5.6"),
            "IORING_OP_RECV" => Some("5.6"),
            "IORING_OP_SPLICE" => Some("5.7"),
            "IORING_OP_PROVIDE_BUFFERS" => Some("5.7"),
            "IORING_ACCEPT_MULTISHOT" => Some("5.19"),
            "IORING_RECV_MULTISHOT" => Some("6.0"),
            _ => None,
        }
    }
}

impl Default for FeatureDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = IoUringConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.sq_depth, 4096);
        assert!(config.fixed_buffers);
        assert!(config.registered_fds);
    }

    #[test]
    fn test_op_type_display() {
        assert_eq!(format!("{}", OpType::Read), "read");
        assert_eq!(format!("{}", OpType::Write), "write");
        assert_eq!(format!("{}", OpType::Accept), "accept");
    }

    #[test]
    fn test_buffer_pool() {
        let mut pool = BufferPool::new(10, 1024);
        assert_eq!(pool.available(), 10);
        assert_eq!(pool.capacity(), 10);
        assert_eq!(pool.buffer_size(), 1024);

        // Allocate a buffer
        let (idx, buf) = pool.alloc().unwrap();
        assert_eq!(buf.len(), 1024);
        assert_eq!(pool.available(), 9);

        // Release the buffer
        pool.release(idx);
        assert_eq!(pool.available(), 10);
    }

    #[test]
    fn test_buffer_pool_exhaustion() {
        let mut pool = BufferPool::new(2, 64);

        let (idx1, _) = pool.alloc().unwrap();
        let (idx2, _) = pool.alloc().unwrap();
        assert!(pool.alloc().is_none());

        pool.release(idx1);
        assert!(pool.alloc().is_some());
        pool.release(idx2);
    }

    #[test]
    fn test_fd_table() {
        let mut table = FdTable::new(10);
        assert_eq!(table.count(), 0);
        assert_eq!(table.capacity(), 10);

        // Register FDs
        let idx1 = table.register(100).unwrap();
        let idx2 = table.register(200).unwrap();
        assert_eq!(table.count(), 2);

        // Get indices
        assert_eq!(table.get_index(100), Some(idx1));
        assert_eq!(table.get_index(200), Some(idx2));
        assert_eq!(table.get_index(300), None);

        // Unregister
        table.unregister(100);
        assert_eq!(table.count(), 1);
        assert_eq!(table.get_index(100), None);
    }

    #[test]
    fn test_completion_entry() {
        let entry = CompletionEntry {
            user_data: 1,
            result: 100,
            flags: 0,
            op_type: OpType::Read,
        };
        assert!(entry.is_success());
        assert!(entry.error_code().is_none());
        assert!(!entry.has_more());

        let error_entry = CompletionEntry {
            user_data: 2,
            result: -11, // EAGAIN
            flags: CQEF_MORE,
            op_type: OpType::Recv,
        };
        assert!(!error_entry.is_success());
        assert_eq!(error_entry.error_code(), Some(11));
        assert!(error_entry.has_more());
    }

    #[tokio::test]
    async fn test_io_uring_create() {
        let config = IoUringConfig::default();
        let ring = IoUring::new(config).unwrap();
        assert!(!ring.is_running());

        ring.start().await.unwrap();
        assert!(ring.is_running());

        ring.stop().await;
        assert!(!ring.is_running());
    }

    #[tokio::test]
    async fn test_io_uring_operations() {
        let config = IoUringConfig {
            enabled: true,
            ..Default::default()
        };
        let ring = IoUring::new(config).unwrap();
        ring.start().await.unwrap();

        // Submit operations
        let read_id = ring.submit_read(10, 1024).await.unwrap();
        let write_id = ring.submit_write(10, b"hello").await.unwrap();
        let accept_id = ring.submit_accept(5).await.unwrap();

        assert!(read_id > 0);
        assert!(write_id > read_id);
        assert!(accept_id > write_id);

        // Check stats
        let stats = ring.stats();
        assert_eq!(stats.submissions, 3);

        ring.stop().await;
    }

    #[tokio::test]
    async fn test_io_uring_fd_registration() {
        let config = IoUringConfig::default();
        let max_fds = config.max_registered_fds;
        let ring = IoUring::new(config).unwrap();

        let idx = ring.register_fd(100).await.unwrap();
        // Index is valid (within bounds)
        assert!(idx < max_fds);

        let idx2 = ring.register_fd(200).await.unwrap();
        // Second index is different from first
        assert_ne!(idx, idx2);
        assert!(idx2 < max_fds);

        ring.unregister_fd(100).await;
    }

    #[test]
    fn test_feature_detector() {
        let mut detector = FeatureDetector::new();
        detector.probe();

        assert!(detector.supports("IORING_OP_ACCEPT"));
        assert!(detector.supports("IORING_OP_RECV"));
        assert!(!detector.supports("NONEXISTENT_FEATURE"));
    }

    #[test]
    fn test_kernel_version() {
        assert_eq!(
            FeatureDetector::kernel_version_for("IORING_OP_ACCEPT"),
            Some("5.5")
        );
        assert_eq!(
            FeatureDetector::kernel_version_for("IORING_RECV_MULTISHOT"),
            Some("6.0")
        );
        assert_eq!(FeatureDetector::kernel_version_for("UNKNOWN"), None);
    }

    #[test]
    fn test_error_display() {
        let err = IoUringError::NotSupported("test".to_string());
        assert!(err.to_string().contains("not supported"));

        let err = IoUringError::SubmissionQueueFull;
        assert!(err.to_string().contains("queue full"));

        let err = IoUringError::Io(5);
        assert!(err.to_string().contains("5"));
    }

    #[tokio::test]
    async fn test_poll_completions() {
        let config = IoUringConfig {
            enabled: true,
            ..Default::default()
        };
        let ring = IoUring::new(config).unwrap();
        ring.start().await.unwrap();

        // Submit an operation
        ring.submit_read(10, 1024).await.unwrap();

        // Wait a bit for mock completion
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Poll completions
        let completions = ring.poll_completions().await;
        assert!(!completions.is_empty());

        ring.stop().await;
    }

    #[tokio::test]
    async fn test_buffer_stats() {
        let config = IoUringConfig {
            enabled: true,
            num_buffers: 100,
            ..Default::default()
        };
        let ring = IoUring::new(config).unwrap();

        let stats = ring.buffer_stats().await;
        assert_eq!(stats.capacity, 100);
        assert_eq!(stats.available, 100);
    }
}
