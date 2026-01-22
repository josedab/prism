//! GitOps configuration types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// GitOps configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitOpsConfig {
    /// Enable GitOps mode
    #[serde(default)]
    pub enabled: bool,

    /// Git repository configuration
    pub repository: RepositoryConfig,

    /// Sync configuration
    #[serde(default)]
    pub sync: SyncConfig,

    /// Validation configuration
    #[serde(default)]
    pub validation: ValidationConfig,

    /// Rollback configuration
    #[serde(default)]
    pub rollback: RollbackConfig,

    /// Webhook configuration for push-based updates
    #[serde(default)]
    pub webhook: Option<WebhookConfig>,

    /// Multi-environment support
    #[serde(default)]
    pub environments: HashMap<String, EnvironmentConfig>,

    /// Notification configuration
    #[serde(default)]
    pub notifications: Option<NotificationConfig>,
}

/// Git repository configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryConfig {
    /// Repository URL (HTTPS or SSH)
    pub url: String,

    /// Branch to watch
    #[serde(default = "default_branch")]
    pub branch: String,

    /// Path within repository to config files
    #[serde(default)]
    pub path: Option<String>,

    /// Authentication configuration
    #[serde(default)]
    pub auth: Option<GitAuthConfig>,

    /// Local clone directory
    #[serde(default = "default_clone_dir")]
    pub clone_dir: PathBuf,

    /// Submodule handling
    #[serde(default)]
    pub submodules: bool,

    /// Sparse checkout paths (if only specific paths needed)
    #[serde(default)]
    pub sparse_paths: Option<Vec<String>>,

    /// Git depth for shallow clones (0 = full clone)
    #[serde(default)]
    pub depth: Option<u32>,
}

fn default_branch() -> String {
    "main".to_string()
}

fn default_clone_dir() -> PathBuf {
    PathBuf::from("/var/lib/prism/gitops")
}

/// Git authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitAuthConfig {
    /// Authentication type
    #[serde(rename = "type")]
    pub auth_type: GitAuthType,

    /// SSH key path (for ssh auth)
    pub ssh_key_path: Option<String>,

    /// SSH key passphrase (for ssh auth)
    pub ssh_key_passphrase: Option<String>,

    /// Username (for basic/token auth)
    pub username: Option<String>,

    /// Password or token (for basic/token auth)
    pub password: Option<String>,

    /// GitHub App ID (for github-app auth)
    pub github_app_id: Option<u64>,

    /// GitHub App installation ID
    pub github_installation_id: Option<u64>,

    /// GitHub App private key path
    pub github_private_key_path: Option<String>,
}

/// Git authentication type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitAuthType {
    /// No authentication (public repos)
    None,
    /// SSH key authentication
    Ssh,
    /// Basic authentication (username/password)
    Basic,
    /// Token authentication (GitHub PAT, GitLab token, etc.)
    Token,
    /// GitHub App authentication
    GithubApp,
}

impl Default for GitAuthType {
    fn default() -> Self {
        Self::None
    }
}

/// Sync configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncConfig {
    /// Poll interval for checking updates
    #[serde(default = "default_poll_interval", with = "humantime_serde")]
    pub poll_interval: Duration,

    /// Maximum retries for sync failures
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Retry backoff base duration
    #[serde(default = "default_retry_backoff", with = "humantime_serde")]
    pub retry_backoff: Duration,

    /// Sync mode
    #[serde(default)]
    pub mode: SyncMode,

    /// Dry run mode (validate but don't apply)
    #[serde(default)]
    pub dry_run: bool,

    /// Prune removed configurations
    #[serde(default = "default_true")]
    pub prune: bool,

    /// Force sync even if no changes detected
    #[serde(default)]
    pub force: bool,

    /// Config file pattern (glob)
    #[serde(default = "default_config_pattern")]
    pub config_pattern: String,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            poll_interval: default_poll_interval(),
            max_retries: default_max_retries(),
            retry_backoff: default_retry_backoff(),
            mode: SyncMode::default(),
            dry_run: false,
            prune: true,
            force: false,
            config_pattern: default_config_pattern(),
        }
    }
}

fn default_poll_interval() -> Duration {
    Duration::from_secs(60)
}

fn default_max_retries() -> u32 {
    3
}

fn default_retry_backoff() -> Duration {
    Duration::from_secs(5)
}

fn default_config_pattern() -> String {
    "*.{yaml,yml,toml}".to_string()
}

fn default_true() -> bool {
    true
}

/// Sync mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    /// Poll-based sync
    #[default]
    Poll,
    /// Webhook-based sync (push)
    Webhook,
    /// Both poll and webhook
    Hybrid,
}

/// Validation configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ValidationConfig {
    /// Enable strict validation
    #[serde(default = "default_true")]
    pub strict: bool,

    /// Validate upstream connectivity
    #[serde(default)]
    pub check_upstreams: bool,

    /// Validate TLS certificates exist
    #[serde(default = "default_true")]
    pub check_tls_files: bool,

    /// Custom validation webhook
    #[serde(default)]
    pub custom_webhook: Option<String>,

    /// Required config sections
    #[serde(default)]
    pub required_sections: Vec<String>,

    /// Forbidden config patterns (regex)
    #[serde(default)]
    pub forbidden_patterns: Vec<String>,

    /// Schema validation file
    #[serde(default)]
    pub schema_file: Option<String>,
}

/// Rollback configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackConfig {
    /// Enable automatic rollback on failure
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Number of config versions to keep
    #[serde(default = "default_history_limit")]
    pub history_limit: usize,

    /// Rollback on health check failure
    #[serde(default = "default_true")]
    pub on_health_failure: bool,

    /// Grace period before rollback
    #[serde(default = "default_grace_period", with = "humantime_serde")]
    pub grace_period: Duration,

    /// Health check after apply
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
}

impl Default for RollbackConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            history_limit: default_history_limit(),
            on_health_failure: true,
            grace_period: default_grace_period(),
            health_check: None,
        }
    }
}

fn default_history_limit() -> usize {
    10
}

fn default_grace_period() -> Duration {
    Duration::from_secs(30)
}

/// Health check configuration for rollback
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// Health check endpoint
    pub endpoint: String,

    /// Expected status codes
    #[serde(default = "default_expected_statuses")]
    pub expected_statuses: Vec<u16>,

    /// Timeout for health check
    #[serde(default = "default_health_timeout", with = "humantime_serde")]
    pub timeout: Duration,

    /// Number of consecutive successes required
    #[serde(default = "default_health_threshold")]
    pub success_threshold: u32,
}

fn default_expected_statuses() -> Vec<u16> {
    vec![200]
}

fn default_health_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_health_threshold() -> u32 {
    3
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    /// Webhook listen address
    #[serde(default = "default_webhook_address")]
    pub address: String,

    /// Webhook secret for validation
    pub secret: Option<String>,

    /// Webhook path
    #[serde(default = "default_webhook_path")]
    pub path: String,

    /// Provider type for payload parsing
    #[serde(default)]
    pub provider: WebhookProvider,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            address: default_webhook_address(),
            secret: None,
            path: default_webhook_path(),
            provider: WebhookProvider::default(),
        }
    }
}

fn default_webhook_address() -> String {
    "0.0.0.0:9090".to_string()
}

fn default_webhook_path() -> String {
    "/webhook/gitops".to_string()
}

/// Webhook provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WebhookProvider {
    /// GitHub webhooks
    #[default]
    Github,
    /// GitLab webhooks
    Gitlab,
    /// Bitbucket webhooks
    Bitbucket,
    /// Gitea webhooks
    Gitea,
    /// Generic webhook (custom parsing)
    Generic,
}

/// Environment-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentConfig {
    /// Branch for this environment
    pub branch: String,

    /// Path prefix for this environment
    #[serde(default)]
    pub path_prefix: Option<String>,

    /// Auto-promote from another environment
    #[serde(default)]
    pub promote_from: Option<String>,

    /// Promotion strategy
    #[serde(default)]
    pub promotion_strategy: PromotionStrategy,

    /// Approval required before apply
    #[serde(default)]
    pub require_approval: bool,
}

/// Promotion strategy between environments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PromotionStrategy {
    /// Manual promotion only
    #[default]
    Manual,
    /// Auto-promote after delay
    TimeBased,
    /// Auto-promote after health check passes
    HealthBased,
    /// Auto-promote on tag
    TagBased,
}

/// Notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationConfig {
    /// Slack webhook URL
    #[serde(default)]
    pub slack: Option<SlackNotification>,

    /// Discord webhook URL
    #[serde(default)]
    pub discord: Option<DiscordNotification>,

    /// PagerDuty integration
    #[serde(default)]
    pub pagerduty: Option<PagerDutyNotification>,

    /// Generic webhook notifications
    #[serde(default)]
    pub webhook: Option<WebhookNotification>,

    /// Events to notify on
    #[serde(default = "default_notify_events")]
    pub events: Vec<NotifyEvent>,
}

fn default_notify_events() -> Vec<NotifyEvent> {
    vec![NotifyEvent::SyncSuccess, NotifyEvent::SyncFailure, NotifyEvent::Rollback]
}

/// Notification events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifyEvent {
    /// Successful sync
    SyncSuccess,
    /// Sync failure
    SyncFailure,
    /// Rollback triggered
    Rollback,
    /// Validation failure
    ValidationFailure,
    /// Health check failure
    HealthFailure,
    /// New commit detected
    NewCommit,
    /// Config drift detected
    Drift,
}

/// Slack notification config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackNotification {
    pub webhook_url: String,
    pub channel: Option<String>,
    pub username: Option<String>,
}

/// Discord notification config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordNotification {
    pub webhook_url: String,
}

/// PagerDuty notification config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutyNotification {
    pub routing_key: String,
    pub severity: Option<String>,
}

/// Generic webhook notification config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookNotification {
    pub url: String,
    pub method: Option<String>,
    pub headers: Option<HashMap<String, String>>,
}

/// GitOps state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitOpsState {
    /// Current commit SHA
    pub current_commit: Option<String>,

    /// Last successful sync time
    pub last_sync: Option<chrono::DateTime<chrono::Utc>>,

    /// Last sync status
    pub last_status: SyncStatus,

    /// Number of consecutive failures
    pub failure_count: u32,

    /// History of applied configs
    pub history: Vec<ConfigVersion>,

    /// Current environment
    pub environment: Option<String>,
}

impl Default for GitOpsState {
    fn default() -> Self {
        Self {
            current_commit: None,
            last_sync: None,
            last_status: SyncStatus::Unknown,
            failure_count: 0,
            history: Vec::new(),
            environment: None,
        }
    }
}

/// Sync status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    /// Status unknown
    #[default]
    Unknown,
    /// Sync in progress
    Syncing,
    /// Sync successful
    Synced,
    /// Sync failed
    Failed,
    /// Validation failed
    ValidationFailed,
    /// Rolled back
    RolledBack,
    /// Out of sync (drift detected)
    Drifted,
}

/// Config version in history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigVersion {
    /// Commit SHA
    pub commit: String,

    /// Commit message
    pub message: Option<String>,

    /// Author
    pub author: Option<String>,

    /// Applied timestamp
    pub applied_at: chrono::DateTime<chrono::Utc>,

    /// Config hash
    pub config_hash: String,

    /// Was this a rollback?
    pub is_rollback: bool,

    /// Status of this version
    pub status: VersionStatus,
}

/// Version status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionStatus {
    /// Successfully applied
    Applied,
    /// Failed to apply
    Failed,
    /// Superseded by newer version
    Superseded,
    /// Rolled back from
    RolledBack,
}
