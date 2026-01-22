//! Configuration migration module for converting configs from other proxies
//!
//! Supports migration from:
//! - Nginx
//! - Envoy
//! - Traefik
//! - HAProxy

pub mod envoy;
pub mod haproxy;
pub mod nginx;
pub mod traefik;

use crate::config::Config;
use crate::error::Result;
use std::path::Path;

/// Source proxy type for migration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceProxy {
    Nginx,
    Envoy,
    Traefik,
    HAProxy,
}

impl std::str::FromStr for SourceProxy {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "nginx" => Ok(SourceProxy::Nginx),
            "envoy" => Ok(SourceProxy::Envoy),
            "traefik" => Ok(SourceProxy::Traefik),
            "haproxy" => Ok(SourceProxy::HAProxy),
            _ => Err(format!("Unknown proxy type: {}", s)),
        }
    }
}

/// Migration result with warnings
#[derive(Debug)]
pub struct MigrationResult {
    /// Generated Prism configuration
    pub config: Config,
    /// Warnings about unsupported features or mappings
    pub warnings: Vec<MigrationWarning>,
    /// Statistics about the migration
    pub stats: MigrationStats,
}

/// Migration warning
#[derive(Debug, Clone)]
pub struct MigrationWarning {
    /// Warning level
    pub level: WarningLevel,
    /// Source location (file:line if available)
    pub location: Option<String>,
    /// Warning message
    pub message: String,
    /// Suggestion for manual fix
    pub suggestion: Option<String>,
}

impl MigrationWarning {
    /// Create a new warning
    pub fn new(level: WarningLevel, message: impl Into<String>) -> Self {
        Self {
            level,
            location: None,
            message: message.into(),
            suggestion: None,
        }
    }

    /// Add location information
    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    /// Add suggestion
    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }
}

/// Warning severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningLevel {
    /// Informational - feature mapped differently
    Info,
    /// Warning - feature partially supported
    Warning,
    /// Error - feature not supported, may cause issues
    Error,
}

/// Migration statistics
#[derive(Debug, Default)]
pub struct MigrationStats {
    /// Number of servers/listeners migrated
    pub listeners: usize,
    /// Number of upstreams migrated
    pub upstreams: usize,
    /// Number of routes migrated
    pub routes: usize,
    /// Number of directives processed
    pub directives_processed: usize,
    /// Number of directives skipped
    pub directives_skipped: usize,
}

/// Migrate configuration from source proxy to Prism
pub fn migrate(source: SourceProxy, input: &Path) -> Result<MigrationResult> {
    match source {
        SourceProxy::Nginx => nginx::migrate(input),
        SourceProxy::Envoy => envoy::migrate(input),
        SourceProxy::Traefik => traefik::migrate(input),
        SourceProxy::HAProxy => haproxy::migrate(input),
    }
}

/// Validate migrated configuration
pub fn validate_config(config: &Config) -> Vec<MigrationWarning> {
    let mut warnings = Vec::new();

    // Check for at least one listener
    if config.listeners.is_empty() {
        warnings.push(MigrationWarning::new(
            WarningLevel::Error,
            "No listeners defined - server will not accept connections",
        ).with_suggestion("Add at least one listener configuration"));
    }

    // Check that routes reference existing upstreams
    for route in &config.routes {
        if let Some(upstream_name) = &route.upstream {
            if !config.upstreams.contains_key(upstream_name) {
                warnings.push(MigrationWarning::new(
                    WarningLevel::Error,
                    format!("Route references non-existent upstream: {}", upstream_name),
                ).with_suggestion("Define the upstream or correct the reference"));
            }
        }
    }

    // Check upstream health check paths
    for (name, upstream) in &config.upstreams {
        if upstream.servers.is_empty() {
            warnings.push(MigrationWarning::new(
                WarningLevel::Warning,
                format!("Upstream '{}' has no servers defined", name),
            ));
        }
    }

    warnings
}

/// Format migration report for display
pub fn format_report(result: &MigrationResult) -> String {
    let mut report = String::new();

    report.push_str("╔══════════════════════════════════════════════════════════════════════╗\n");
    report.push_str("║                    Configuration Migration Report                      ║\n");
    report.push_str("╠══════════════════════════════════════════════════════════════════════╣\n");

    // Statistics
    report.push_str(&format!(
        "║ Listeners migrated:      {:>4}                                         ║\n",
        result.stats.listeners
    ));
    report.push_str(&format!(
        "║ Upstreams migrated:      {:>4}                                         ║\n",
        result.stats.upstreams
    ));
    report.push_str(&format!(
        "║ Routes migrated:         {:>4}                                         ║\n",
        result.stats.routes
    ));
    report.push_str(&format!(
        "║ Directives processed:    {:>4}                                         ║\n",
        result.stats.directives_processed
    ));
    report.push_str(&format!(
        "║ Directives skipped:      {:>4}                                         ║\n",
        result.stats.directives_skipped
    ));

    if !result.warnings.is_empty() {
        report.push_str("╠══════════════════════════════════════════════════════════════════════╣\n");
        report.push_str("║ Warnings:                                                            ║\n");

        let errors: Vec<_> = result.warnings.iter().filter(|w| w.level == WarningLevel::Error).collect();
        let warns: Vec<_> = result.warnings.iter().filter(|w| w.level == WarningLevel::Warning).collect();
        let infos: Vec<_> = result.warnings.iter().filter(|w| w.level == WarningLevel::Info).collect();

        if !errors.is_empty() {
            report.push_str("╟──────────────────────────────────────────────────────────────────────╢\n");
            report.push_str("║ ERRORS:                                                              ║\n");
            for warning in errors {
                report.push_str(&format!("║   ✗ {}  \n", warning.message));
                if let Some(suggestion) = &warning.suggestion {
                    report.push_str(&format!("║     → {}  \n", suggestion));
                }
            }
        }

        if !warns.is_empty() {
            report.push_str("╟──────────────────────────────────────────────────────────────────────╢\n");
            report.push_str("║ WARNINGS:                                                            ║\n");
            for warning in warns {
                report.push_str(&format!("║   ⚠ {}  \n", warning.message));
                if let Some(suggestion) = &warning.suggestion {
                    report.push_str(&format!("║     → {}  \n", suggestion));
                }
            }
        }

        if !infos.is_empty() {
            report.push_str("╟──────────────────────────────────────────────────────────────────────╢\n");
            report.push_str("║ INFO:                                                                ║\n");
            for warning in infos {
                report.push_str(&format!("║   ℹ {}  \n", warning.message));
            }
        }
    }

    report.push_str("╚══════════════════════════════════════════════════════════════════════╝\n");
    report
}
