//! Interactive TUI Dashboard
//!
//! Provides a terminal-based dashboard for real-time monitoring:
//! - Request/response metrics
//! - Active connections
//! - Upstream server health
//! - Rate limiting statistics
//! - Error rates and latency histograms
//! - Real-time traffic visualization

#[cfg(feature = "tui")]
mod dashboard;

#[cfg(feature = "tui")]
pub use dashboard::*;

#[cfg(feature = "tui")]
mod app;

#[cfg(feature = "tui")]
pub use app::*;
