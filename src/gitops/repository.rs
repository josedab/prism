//! Git repository management

use super::config::{GitAuthType, RepositoryConfig};
use crate::error::{PrismError, Result};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

/// Git repository manager
pub struct GitRepository {
    config: RepositoryConfig,
    state: Arc<RwLock<RepoState>>,
}

/// Repository state
#[derive(Debug, Default)]
struct RepoState {
    /// Whether the repository is cloned
    cloned: bool,
    /// Current HEAD commit
    head_commit: Option<String>,
    /// Last fetch time
    last_fetch: Option<std::time::Instant>,
}

impl GitRepository {
    /// Create a new repository manager
    pub fn new(config: RepositoryConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(RepoState::default())),
        }
    }

    /// Initialize the repository (clone if needed)
    pub async fn init(&self) -> Result<()> {
        let clone_dir = &self.config.clone_dir;

        // Check if already cloned
        if clone_dir.join(".git").exists() {
            info!(?clone_dir, "Repository already cloned");
            self.state.write().cloned = true;

            // Fetch latest
            self.fetch().await?;
            return Ok(());
        }

        // Create parent directory
        if let Some(parent) = clone_dir.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                PrismError::Config(format!("Failed to create clone directory: {}", e))
            })?;
        }

        // Clone the repository
        self.clone().await?;
        self.state.write().cloned = true;

        Ok(())
    }

    /// Clone the repository
    async fn clone(&self) -> Result<()> {
        let mut cmd = Command::new("git");
        cmd.arg("clone");

        // Configure authentication
        self.configure_auth(&mut cmd);

        // Set branch
        cmd.args(["--branch", &self.config.branch]);

        // Single branch for efficiency
        cmd.arg("--single-branch");

        // Shallow clone if depth specified
        if let Some(depth) = self.config.depth {
            if depth > 0 {
                cmd.args(["--depth", &depth.to_string()]);
            }
        }

        // Sparse checkout
        if self.config.sparse_paths.is_some() {
            cmd.args(["--sparse", "--filter=blob:none"]);
        }

        // Repository URL and destination
        cmd.arg(&self.config.url);
        cmd.arg(&self.config.clone_dir);

        info!(url = %self.config.url, branch = %self.config.branch, "Cloning repository");

        let output = cmd.output().map_err(|e| {
            PrismError::Config(format!("Failed to execute git clone: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PrismError::Config(format!("Git clone failed: {}", stderr)));
        }

        // Configure sparse checkout if needed
        if let Some(sparse_paths) = &self.config.sparse_paths {
            self.configure_sparse_checkout(sparse_paths).await?;
        }

        // Initialize submodules if needed
        if self.config.submodules {
            self.init_submodules().await?;
        }

        info!("Repository cloned successfully");
        Ok(())
    }

    /// Fetch latest changes
    pub async fn fetch(&self) -> Result<()> {
        let clone_dir = &self.config.clone_dir;

        let mut cmd = Command::new("git");
        cmd.current_dir(clone_dir);
        cmd.args(["fetch", "origin", &self.config.branch]);

        // Configure authentication for fetch
        self.configure_auth(&mut cmd);

        debug!(branch = %self.config.branch, "Fetching latest changes");

        let output = cmd.output().map_err(|e| {
            PrismError::Config(format!("Failed to execute git fetch: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PrismError::Config(format!("Git fetch failed: {}", stderr)));
        }

        self.state.write().last_fetch = Some(std::time::Instant::now());
        Ok(())
    }

    /// Pull latest changes
    pub async fn pull(&self) -> Result<bool> {
        let clone_dir = &self.config.clone_dir;

        // Get current commit before pull
        let before_commit = self.get_head_commit()?;

        let mut cmd = Command::new("git");
        cmd.current_dir(clone_dir);
        cmd.args(["pull", "origin", &self.config.branch, "--ff-only"]);

        // Configure authentication
        self.configure_auth(&mut cmd);

        info!(branch = %self.config.branch, "Pulling latest changes");

        let output = cmd.output().map_err(|e| {
            PrismError::Config(format!("Failed to execute git pull: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PrismError::Config(format!("Git pull failed: {}", stderr)));
        }

        // Get commit after pull
        let after_commit = self.get_head_commit()?;

        // Update state
        self.state.write().head_commit = Some(after_commit.clone());

        // Return whether there were changes
        let changed = before_commit != after_commit;
        if changed {
            info!(commit = %after_commit, "Repository updated to new commit");
        } else {
            debug!("No new changes");
        }

        Ok(changed)
    }

    /// Check if there are new commits available
    pub async fn has_updates(&self) -> Result<bool> {
        self.fetch().await?;

        let clone_dir = &self.config.clone_dir;

        // Compare local and remote
        let local_cmd = Command::new("git")
            .current_dir(clone_dir)
            .args(["rev-parse", "HEAD"])
            .output()
            .map_err(|e| PrismError::Config(format!("Failed to get local HEAD: {}", e)))?;

        let remote_cmd = Command::new("git")
            .current_dir(clone_dir)
            .args(["rev-parse", &format!("origin/{}", self.config.branch)])
            .output()
            .map_err(|e| PrismError::Config(format!("Failed to get remote HEAD: {}", e)))?;

        let local = String::from_utf8_lossy(&local_cmd.stdout).trim().to_string();
        let remote = String::from_utf8_lossy(&remote_cmd.stdout).trim().to_string();

        let has_updates = local != remote;
        if has_updates {
            debug!(local = %local, remote = %remote, "Updates available");
        }

        Ok(has_updates)
    }

    /// Get the current HEAD commit SHA
    pub fn get_head_commit(&self) -> Result<String> {
        let clone_dir = &self.config.clone_dir;

        let output = Command::new("git")
            .current_dir(clone_dir)
            .args(["rev-parse", "HEAD"])
            .output()
            .map_err(|e| PrismError::Config(format!("Failed to get HEAD commit: {}", e)))?;

        if !output.status.success() {
            return Err(PrismError::Config("Failed to get HEAD commit".to_string()));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Get commit info
    pub fn get_commit_info(&self, commit: &str) -> Result<CommitInfo> {
        let clone_dir = &self.config.clone_dir;

        // Get commit message
        let message_output = Command::new("git")
            .current_dir(clone_dir)
            .args(["log", "-1", "--format=%s", commit])
            .output()
            .map_err(|e| PrismError::Config(format!("Failed to get commit message: {}", e)))?;

        // Get author
        let author_output = Command::new("git")
            .current_dir(clone_dir)
            .args(["log", "-1", "--format=%an <%ae>", commit])
            .output()
            .map_err(|e| PrismError::Config(format!("Failed to get commit author: {}", e)))?;

        // Get timestamp
        let date_output = Command::new("git")
            .current_dir(clone_dir)
            .args(["log", "-1", "--format=%cI", commit])
            .output()
            .map_err(|e| PrismError::Config(format!("Failed to get commit date: {}", e)))?;

        Ok(CommitInfo {
            sha: commit.to_string(),
            message: String::from_utf8_lossy(&message_output.stdout).trim().to_string(),
            author: String::from_utf8_lossy(&author_output.stdout).trim().to_string(),
            timestamp: String::from_utf8_lossy(&date_output.stdout).trim().to_string(),
        })
    }

    /// Get changed files between commits
    pub fn get_changed_files(&self, from: &str, to: &str) -> Result<Vec<String>> {
        let clone_dir = &self.config.clone_dir;

        let output = Command::new("git")
            .current_dir(clone_dir)
            .args(["diff", "--name-only", from, to])
            .output()
            .map_err(|e| PrismError::Config(format!("Failed to get changed files: {}", e)))?;

        let files: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect();

        Ok(files)
    }

    /// Checkout a specific commit
    pub async fn checkout(&self, commit: &str) -> Result<()> {
        let clone_dir = &self.config.clone_dir;

        let output = Command::new("git")
            .current_dir(clone_dir)
            .args(["checkout", commit])
            .output()
            .map_err(|e| PrismError::Config(format!("Failed to checkout: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PrismError::Config(format!("Git checkout failed: {}", stderr)));
        }

        self.state.write().head_commit = Some(commit.to_string());
        info!(commit = %commit, "Checked out commit");

        Ok(())
    }

    /// Reset to a specific commit (for rollback)
    pub async fn reset_hard(&self, commit: &str) -> Result<()> {
        let clone_dir = &self.config.clone_dir;

        warn!(commit = %commit, "Performing hard reset (rollback)");

        let output = Command::new("git")
            .current_dir(clone_dir)
            .args(["reset", "--hard", commit])
            .output()
            .map_err(|e| PrismError::Config(format!("Failed to reset: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PrismError::Config(format!("Git reset failed: {}", stderr)));
        }

        self.state.write().head_commit = Some(commit.to_string());
        Ok(())
    }

    /// Get the config file path within the repository
    pub fn get_config_path(&self) -> PathBuf {
        let mut path = self.config.clone_dir.clone();
        if let Some(subpath) = &self.config.path {
            path = path.join(subpath);
        }
        path
    }

    /// List config files in the repository
    pub fn list_config_files(&self, pattern: &str) -> Result<Vec<PathBuf>> {
        let config_path = self.get_config_path();

        if !config_path.exists() {
            return Ok(Vec::new());
        }

        let glob_pattern = format!("{}/{}", config_path.display(), pattern);
        let files: Vec<PathBuf> = glob::glob(&glob_pattern)
            .map_err(|e| PrismError::Config(format!("Invalid glob pattern: {}", e)))?
            .filter_map(|entry| entry.ok())
            .collect();

        debug!(count = files.len(), pattern = %pattern, "Found config files");
        Ok(files)
    }

    /// Configure authentication for git command
    fn configure_auth(&self, cmd: &mut Command) {
        if let Some(auth) = &self.config.auth {
            match auth.auth_type {
                GitAuthType::None => {}
                GitAuthType::Ssh => {
                    if let Some(key_path) = &auth.ssh_key_path {
                        cmd.env("GIT_SSH_COMMAND", format!("ssh -i {} -o StrictHostKeyChecking=no", key_path));
                    }
                }
                GitAuthType::Basic | GitAuthType::Token => {
                    // For HTTPS URLs with embedded credentials, we modify the URL
                    // This is handled separately in the URL construction
                }
                GitAuthType::GithubApp => {
                    // GitHub App auth requires generating a token first
                    // This should be handled by a separate token generation step
                    warn!("GitHub App authentication requires token generation - not yet implemented");
                }
            }
        }
    }

    /// Configure sparse checkout
    async fn configure_sparse_checkout(&self, paths: &[String]) -> Result<()> {
        let clone_dir = &self.config.clone_dir;

        // Initialize sparse-checkout
        let output = Command::new("git")
            .current_dir(clone_dir)
            .args(["sparse-checkout", "init", "--cone"])
            .output()
            .map_err(|e| PrismError::Config(format!("Failed to init sparse-checkout: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PrismError::Config(format!("Sparse-checkout init failed: {}", stderr)));
        }

        // Set sparse-checkout paths
        let mut cmd = Command::new("git");
        cmd.current_dir(clone_dir);
        cmd.args(["sparse-checkout", "set"]);
        cmd.args(paths);

        let output = cmd.output().map_err(|e| {
            PrismError::Config(format!("Failed to set sparse-checkout paths: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PrismError::Config(format!("Sparse-checkout set failed: {}", stderr)));
        }

        info!(?paths, "Configured sparse checkout");
        Ok(())
    }

    /// Initialize submodules
    async fn init_submodules(&self) -> Result<()> {
        let clone_dir = &self.config.clone_dir;

        let output = Command::new("git")
            .current_dir(clone_dir)
            .args(["submodule", "update", "--init", "--recursive"])
            .output()
            .map_err(|e| PrismError::Config(format!("Failed to init submodules: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PrismError::Config(format!("Submodule init failed: {}", stderr)));
        }

        info!("Initialized submodules");
        Ok(())
    }

    /// Get repository URL (for display, with credentials masked)
    pub fn display_url(&self) -> String {
        // Mask any embedded credentials
        let url = &self.config.url;
        if url.contains('@') && url.starts_with("https://") {
            // Has embedded credentials - mask them
            let parts: Vec<&str> = url.splitn(2, '@').collect();
            if parts.len() == 2 {
                return format!("https://***@{}", parts[1]);
            }
        }
        url.clone()
    }
}

/// Commit information
#[derive(Debug, Clone)]
pub struct CommitInfo {
    /// Commit SHA
    pub sha: String,
    /// Commit message
    pub message: String,
    /// Author name and email
    pub author: String,
    /// Commit timestamp (ISO 8601)
    pub timestamp: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_url_masks_credentials() {
        let config = RepositoryConfig {
            url: "https://user:token@github.com/org/repo.git".to_string(),
            branch: "main".to_string(),
            path: None,
            auth: None,
            clone_dir: PathBuf::from("/tmp/test"),
            submodules: false,
            sparse_paths: None,
            depth: None,
        };

        let repo = GitRepository::new(config);
        assert_eq!(repo.display_url(), "https://***@github.com/org/repo.git");
    }

    #[test]
    fn test_display_url_no_credentials() {
        let config = RepositoryConfig {
            url: "https://github.com/org/repo.git".to_string(),
            branch: "main".to_string(),
            path: None,
            auth: None,
            clone_dir: PathBuf::from("/tmp/test"),
            submodules: false,
            sparse_paths: None,
            depth: None,
        };

        let repo = GitRepository::new(config);
        assert_eq!(repo.display_url(), "https://github.com/org/repo.git");
    }
}
