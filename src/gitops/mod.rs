//! GitOps Native Mode
//!
//! Provides automatic configuration synchronization from Git repositories.
//! Supports:
//! - Git repository watching (polling or webhook-based)
//! - Configuration validation before apply
//! - Automatic rollback on failure
//! - Multi-branch support (canary, blue-green)
//! - Audit trail and history

pub mod config;
pub mod repository;
pub mod sync;
pub mod validation;
pub mod webhook;

pub use config::*;
pub use repository::*;
pub use sync::*;
pub use validation::*;
pub use webhook::*;
