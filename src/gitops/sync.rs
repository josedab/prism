//! GitOps synchronization engine

use super::config::{
    ConfigVersion, GitOpsConfig, GitOpsState, NotifyEvent, SyncMode,
    SyncStatus, VersionStatus,
};
use super::repository::GitRepository;
use super::validation::ConfigValidator;
use crate::config::Config;
use crate::error::{PrismError, Result};
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// Sync event for notifications
#[derive(Debug, Clone)]
pub enum SyncEvent {
    /// Sync started
    Started { commit: String },
    /// Sync completed successfully
    Success { commit: String, changes: Vec<String> },
    /// Sync failed
    Failure { commit: String, error: String },
    /// Rollback triggered
    Rollback { from: String, to: String, reason: String },
    /// Validation failed
    ValidationFailed { commit: String, errors: Vec<String> },
    /// Health check failed
    HealthFailed { commit: String, error: String },
    /// New commit detected
    NewCommit { commit: String, message: String },
    /// Drift detected
    Drift { expected: String, actual: String },
}

/// GitOps sync manager
pub struct GitOpsSyncManager {
    config: GitOpsConfig,
    repository: Arc<GitRepository>,
    validator: Arc<ConfigValidator>,
    state: Arc<RwLock<GitOpsState>>,
    event_tx: mpsc::Sender<SyncEvent>,
    event_rx: Option<mpsc::Receiver<SyncEvent>>,
    config_callback: Option<Arc<dyn Fn(Config) -> Result<()> + Send + Sync>>,
}

impl GitOpsSyncManager {
    /// Create a new sync manager
    pub fn new(gitops_config: GitOpsConfig) -> Self {
        let repository = Arc::new(GitRepository::new(gitops_config.repository.clone()));
        let validator = Arc::new(ConfigValidator::new(gitops_config.validation.clone()));
        let (event_tx, event_rx) = mpsc::channel(100);

        Self {
            config: gitops_config,
            repository,
            validator,
            state: Arc::new(RwLock::new(GitOpsState::default())),
            event_tx,
            event_rx: Some(event_rx),
            config_callback: None,
        }
    }

    /// Set callback for config changes
    pub fn on_config_change<F>(&mut self, callback: F)
    where
        F: Fn(Config) -> Result<()> + Send + Sync + 'static,
    {
        self.config_callback = Some(Arc::new(callback));
    }

    /// Take the event receiver
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<SyncEvent>> {
        self.event_rx.take()
    }

    /// Initialize the sync manager
    pub async fn init(&self) -> Result<()> {
        info!("Initializing GitOps sync manager");

        // Initialize repository
        self.repository.init().await?;

        // Get initial commit
        let commit = self.repository.get_head_commit()?;
        self.state.write().current_commit = Some(commit.clone());

        info!(commit = %commit, "GitOps initialized at commit");
        Ok(())
    }

    /// Start the sync loop
    pub async fn start(&self) -> Result<()> {
        match self.config.sync.mode {
            SyncMode::Poll | SyncMode::Hybrid => {
                self.start_poll_loop().await
            }
            SyncMode::Webhook => {
                // Webhook mode - just do initial sync
                self.sync().await?;
                Ok(())
            }
        }
    }

    /// Start polling loop
    async fn start_poll_loop(&self) -> Result<()> {
        let poll_interval = self.config.sync.poll_interval;
        let mut interval_timer = interval(poll_interval);

        info!(interval = ?poll_interval, "Starting GitOps poll loop");

        // Initial sync
        if let Err(e) = self.sync().await {
            error!(error = %e, "Initial sync failed");
        }

        loop {
            interval_timer.tick().await;

            if let Err(e) = self.poll_and_sync().await {
                error!(error = %e, "Poll sync failed");

                let mut state = self.state.write();
                state.failure_count += 1;
                state.last_status = SyncStatus::Failed;

                // Check if we should rollback
                if self.config.rollback.enabled
                    && state.failure_count >= self.config.sync.max_retries
                {
                    drop(state);
                    if let Err(re) = self.rollback("consecutive sync failures").await {
                        error!(error = %re, "Rollback also failed");
                    }
                }
            } else {
                let mut state = self.state.write();
                state.failure_count = 0;
            }
        }
    }

    /// Poll for changes and sync if needed
    async fn poll_and_sync(&self) -> Result<()> {
        debug!("Checking for updates");

        if self.repository.has_updates().await? {
            let commit = self.repository.get_head_commit()?;
            let commit_info = self.repository.get_commit_info(&commit)?;

            let _ = self.event_tx.send(SyncEvent::NewCommit {
                commit: commit.clone(),
                message: commit_info.message,
            }).await;

            self.sync().await?;
        }

        Ok(())
    }

    /// Perform a sync
    pub async fn sync(&self) -> Result<()> {
        // Get current commit info in a separate scope to release the lock
        let current_commit = {
            let state = self.state.read();
            state.current_commit.clone()
        };

        info!("Starting sync");
        self.state.write().last_status = SyncStatus::Syncing;

        // Pull latest changes
        let has_changes = self.repository.pull().await?;

        if !has_changes && !self.config.sync.force {
            debug!("No changes to sync");
            return Ok(());
        }

        let new_commit = self.repository.get_head_commit()?;
        let _ = self.event_tx.send(SyncEvent::Started {
            commit: new_commit.clone(),
        }).await;

        // Load and validate config
        let config = self.load_config().await?;

        match self.validator.validate(&config).await {
            Ok(warnings) => {
                if !warnings.is_empty() {
                    for warning in &warnings {
                        warn!(warning = %warning, "Config validation warning");
                    }
                }
            }
            Err(errors) => {
                let error_strings: Vec<String> = errors.iter().map(|e| e.to_string()).collect();

                let _ = self.event_tx.send(SyncEvent::ValidationFailed {
                    commit: new_commit.clone(),
                    errors: error_strings.clone(),
                }).await;

                self.state.write().last_status = SyncStatus::ValidationFailed;

                return Err(PrismError::Config(format!(
                    "Config validation failed: {}",
                    error_strings.join(", ")
                )));
            }
        }

        // Apply the config
        if !self.config.sync.dry_run {
            self.apply_config(config.clone()).await?;
        } else {
            info!("Dry run mode - config validated but not applied");
        }

        // Perform health check if configured
        if let Some(health_check) = &self.config.rollback.health_check {
            match self.perform_health_check(health_check).await {
                Ok(()) => {
                    debug!("Health check passed");
                }
                Err(e) => {
                    let _ = self.event_tx.send(SyncEvent::HealthFailed {
                        commit: new_commit.clone(),
                        error: e.to_string(),
                    }).await;

                    if self.config.rollback.on_health_failure {
                        self.rollback("health check failure").await?;
                        return Err(e);
                    }
                }
            }
        }

        // Update state
        {
            let mut state = self.state.write();
            state.current_commit = Some(new_commit.clone());
            state.last_sync = Some(chrono::Utc::now());
            state.last_status = SyncStatus::Synced;

            // Add to history
            let commit_info = self.repository.get_commit_info(&new_commit)?;
            let version = ConfigVersion {
                commit: new_commit.clone(),
                message: Some(commit_info.message),
                author: Some(commit_info.author),
                applied_at: chrono::Utc::now(),
                config_hash: compute_config_hash(&config),
                is_rollback: false,
                status: VersionStatus::Applied,
            };

            state.history.push(version);

            // Prune history if needed
            while state.history.len() > self.config.rollback.history_limit {
                state.history.remove(0);
            }
        }

        // Get changed files for notification
        let changes = if let Some(prev) = current_commit {
            self.repository.get_changed_files(&prev, &new_commit).unwrap_or_default()
        } else {
            vec![]
        };

        let _ = self.event_tx.send(SyncEvent::Success {
            commit: new_commit,
            changes,
        }).await;

        info!("Sync completed successfully");
        Ok(())
    }

    /// Load configuration from repository
    async fn load_config(&self) -> Result<Config> {
        let files = self.repository.list_config_files(&self.config.sync.config_pattern)?;

        if files.is_empty() {
            return Err(PrismError::Config(
                "No configuration files found in repository".to_string(),
            ));
        }

        // For now, just load the first config file
        // TODO: Support merging multiple config files
        let config_path = &files[0];

        let content = tokio::fs::read_to_string(config_path).await.map_err(|e| {
            PrismError::Config(format!("Failed to read config file: {}", e))
        })?;

        // Determine format from extension
        let config: Config = if config_path.extension().map(|e| e == "toml").unwrap_or(false) {
            toml::from_str(&content).map_err(|e| {
                PrismError::Config(format!("Failed to parse TOML config: {}", e))
            })?
        } else {
            serde_yaml::from_str(&content).map_err(|e| {
                PrismError::Config(format!("Failed to parse YAML config: {}", e))
            })?
        };

        debug!(path = %config_path.display(), "Loaded configuration");
        Ok(config)
    }

    /// Apply configuration
    async fn apply_config(&self, config: Config) -> Result<()> {
        if let Some(callback) = &self.config_callback {
            callback(config)?;
        } else {
            warn!("No config callback set - config loaded but not applied");
        }

        Ok(())
    }

    /// Perform health check
    async fn perform_health_check(&self, config: &super::config::HealthCheckConfig) -> Result<()> {
        use tokio::time::timeout;

        info!(endpoint = %config.endpoint, "Performing health check");

        let client = reqwest::Client::new();
        let mut success_count = 0;

        for attempt in 0..config.success_threshold {
            let result = timeout(
                config.timeout,
                client.get(&config.endpoint).send()
            ).await;

            match result {
                Ok(Ok(response)) => {
                    let status = response.status().as_u16();
                    if config.expected_statuses.contains(&status) {
                        success_count += 1;
                        debug!(attempt = attempt + 1, status = status, "Health check passed");
                    } else {
                        warn!(attempt = attempt + 1, status = status, "Health check returned unexpected status");
                        success_count = 0;
                    }
                }
                Ok(Err(e)) => {
                    warn!(attempt = attempt + 1, error = %e, "Health check request failed");
                    success_count = 0;
                }
                Err(_) => {
                    warn!(attempt = attempt + 1, "Health check timed out");
                    success_count = 0;
                }
            }

            if success_count >= config.success_threshold {
                return Ok(());
            }

            // Wait before next attempt
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        Err(PrismError::Config(format!(
            "Health check failed after {} attempts",
            config.success_threshold
        )))
    }

    /// Rollback to previous version
    pub async fn rollback(&self, reason: &str) -> Result<()> {
        // Collect info from state in a scoped block
        let (current_commit, previous) = {
            let state = self.state.read();
            let current = state.current_commit.clone();
            let prev = state.history.iter()
                .rev()
                .skip(1) // Skip current
                .find(|v| v.status == VersionStatus::Applied)
                .map(|v| v.commit.clone());
            (current, prev)
        };

        let target_commit = previous.ok_or_else(|| {
            PrismError::Config("No previous version available for rollback".to_string())
        })?;

        warn!(
            from = ?current_commit,
            to = %target_commit,
            reason = %reason,
            "Rolling back configuration"
        );

        // Reset to previous commit
        self.repository.reset_hard(&target_commit).await?;

        // Reload and apply config
        let config = self.load_config().await?;
        self.apply_config(config).await?;

        // Update state
        {
            let mut state = self.state.write();
            state.current_commit = Some(target_commit.clone());
            state.last_status = SyncStatus::RolledBack;
            state.failure_count = 0;

            // Mark current version as rolled back
            if let Some(current) = state.history.last_mut() {
                current.status = VersionStatus::RolledBack;
            }
        }

        let _ = self.event_tx.send(SyncEvent::Rollback {
            from: current_commit.unwrap_or_default(),
            to: target_commit,
            reason: reason.to_string(),
        }).await;

        Ok(())
    }

    /// Manually trigger a sync
    pub async fn trigger_sync(&self) -> Result<()> {
        info!("Manual sync triggered");
        self.sync().await
    }

    /// Get current state
    pub fn get_state(&self) -> GitOpsState {
        self.state.read().clone()
    }

    /// Get history
    pub fn get_history(&self) -> Vec<ConfigVersion> {
        self.state.read().history.clone()
    }

    /// Check for drift between running config and git
    pub async fn check_drift(&self) -> Result<bool> {
        let state = self.state.read();
        let git_commit = state.current_commit.clone();
        drop(state);

        // Fetch latest
        self.repository.fetch().await?;
        let remote_commit = self.repository.get_head_commit()?;

        let has_drift = git_commit != Some(remote_commit.clone());

        if has_drift {
            let _ = self.event_tx.send(SyncEvent::Drift {
                expected: git_commit.unwrap_or_default(),
                actual: remote_commit,
            }).await;

            self.state.write().last_status = SyncStatus::Drifted;
        }

        Ok(has_drift)
    }
}

/// Compute a hash of the configuration for tracking
fn compute_config_hash(config: &Config) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let yaml = serde_yaml::to_string(config).unwrap_or_default();
    let mut hasher = DefaultHasher::new();
    yaml.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Sync event handler for notifications
pub struct SyncEventHandler {
    config: super::config::NotificationConfig,
}

impl SyncEventHandler {
    pub fn new(config: super::config::NotificationConfig) -> Self {
        Self { config }
    }

    /// Handle a sync event
    pub async fn handle(&self, event: SyncEvent) {
        let notify_event = match &event {
            SyncEvent::Success { .. } => NotifyEvent::SyncSuccess,
            SyncEvent::Failure { .. } => NotifyEvent::SyncFailure,
            SyncEvent::Rollback { .. } => NotifyEvent::Rollback,
            SyncEvent::ValidationFailed { .. } => NotifyEvent::ValidationFailure,
            SyncEvent::HealthFailed { .. } => NotifyEvent::HealthFailure,
            SyncEvent::NewCommit { .. } => NotifyEvent::NewCommit,
            SyncEvent::Drift { .. } => NotifyEvent::Drift,
            SyncEvent::Started { .. } => return, // Don't notify on start
        };

        if !self.config.events.contains(&notify_event) {
            return;
        }

        let message = self.format_message(&event);

        // Send to configured notification channels
        if let Some(slack) = &self.config.slack {
            if let Err(e) = self.send_slack(slack, &message).await {
                error!(error = %e, "Failed to send Slack notification");
            }
        }

        if let Some(discord) = &self.config.discord {
            if let Err(e) = self.send_discord(discord, &message).await {
                error!(error = %e, "Failed to send Discord notification");
            }
        }

        if let Some(webhook) = &self.config.webhook {
            if let Err(e) = self.send_webhook(webhook, &event).await {
                error!(error = %e, "Failed to send webhook notification");
            }
        }
    }

    fn format_message(&self, event: &SyncEvent) -> String {
        match event {
            SyncEvent::Started { commit } => {
                format!("GitOps sync started for commit {}", &commit[..8])
            }
            SyncEvent::Success { commit, changes } => {
                format!(
                    "GitOps sync successful!\nCommit: {}\nChanged files: {}",
                    &commit[..8],
                    changes.len()
                )
            }
            SyncEvent::Failure { commit, error } => {
                format!(
                    "GitOps sync FAILED!\nCommit: {}\nError: {}",
                    &commit[..8],
                    error
                )
            }
            SyncEvent::Rollback { from, to, reason } => {
                format!(
                    "GitOps ROLLBACK triggered!\nFrom: {}\nTo: {}\nReason: {}",
                    &from[..8.min(from.len())],
                    &to[..8],
                    reason
                )
            }
            SyncEvent::ValidationFailed { commit, errors } => {
                format!(
                    "GitOps validation FAILED!\nCommit: {}\nErrors:\n- {}",
                    &commit[..8],
                    errors.join("\n- ")
                )
            }
            SyncEvent::HealthFailed { commit, error } => {
                format!(
                    "GitOps health check FAILED!\nCommit: {}\nError: {}",
                    &commit[..8],
                    error
                )
            }
            SyncEvent::NewCommit { commit, message } => {
                format!("New commit detected: {} - {}", &commit[..8], message)
            }
            SyncEvent::Drift { expected, actual } => {
                format!(
                    "Configuration DRIFT detected!\nExpected: {}\nActual: {}",
                    &expected[..8.min(expected.len())],
                    &actual[..8]
                )
            }
        }
    }

    async fn send_slack(&self, config: &super::config::SlackNotification, message: &str) -> Result<()> {
        let payload = serde_json::json!({
            "text": message,
            "channel": config.channel,
            "username": config.username.as_deref().unwrap_or("Prism GitOps"),
        });

        reqwest::Client::new()
            .post(&config.webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| PrismError::Config(format!("Slack notification failed: {}", e)))?;

        Ok(())
    }

    async fn send_discord(&self, config: &super::config::DiscordNotification, message: &str) -> Result<()> {
        let payload = serde_json::json!({
            "content": message,
        });

        reqwest::Client::new()
            .post(&config.webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| PrismError::Config(format!("Discord notification failed: {}", e)))?;

        Ok(())
    }

    async fn send_webhook(&self, config: &super::config::WebhookNotification, event: &SyncEvent) -> Result<()> {
        let method = config.method.as_deref().unwrap_or("POST");

        let mut request = match method.to_uppercase().as_str() {
            "POST" => reqwest::Client::new().post(&config.url),
            "PUT" => reqwest::Client::new().put(&config.url),
            _ => return Err(PrismError::Config(format!("Unsupported webhook method: {}", method))),
        };

        if let Some(headers) = &config.headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        let payload = serde_json::json!({
            "event": format!("{:?}", event),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        request
            .json(&payload)
            .send()
            .await
            .map_err(|e| PrismError::Config(format!("Webhook notification failed: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_config_hash() {
        let config1 = Config::default();
        let config2 = Config::default();

        let hash1 = compute_config_hash(&config1);
        let hash2 = compute_config_hash(&config2);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 16);
    }
}
