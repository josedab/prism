//! Hot reload implementation for configuration changes

use crate::config::{load_config, Config};
use crate::server::Server;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

impl Server {
    /// Start watching for configuration file changes
    pub fn start_config_watcher(
        self: Arc<Self>,
        config_path: PathBuf,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = self.watch_config(config_path).await {
                error!("Config watcher error: {}", e);
            }
        })
    }

    /// Watch configuration file for changes
    async fn watch_config(self: Arc<Self>, config_path: PathBuf) -> crate::Result<()> {
        let (tx, mut rx) = mpsc::channel(10);

        // Create file watcher
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    if event.kind.is_modify() || event.kind.is_create() {
                        let _ = tx.blocking_send(());
                    }
                }
            },
            NotifyConfig::default().with_poll_interval(Duration::from_secs(2)),
        )
        .map_err(|e| crate::PrismError::Config(format!("Failed to create watcher: {}", e)))?;

        watcher
            .watch(&config_path, RecursiveMode::NonRecursive)
            .map_err(|e| crate::PrismError::Config(format!("Failed to watch config: {}", e)))?;

        info!("Watching configuration file: {:?}", config_path);

        // Debounce timer
        let mut last_reload = std::time::Instant::now();
        let debounce = Duration::from_secs(1);

        while rx.recv().await.is_some() {
            // Debounce rapid changes
            if last_reload.elapsed() < debounce {
                debug!("Debouncing config change");
                continue;
            }

            last_reload = std::time::Instant::now();
            info!("Configuration file changed, reloading...");

            // Small delay to ensure file write is complete
            tokio::time::sleep(Duration::from_millis(100)).await;

            match load_config(&config_path) {
                Ok(new_config) => {
                    if let Err(e) = self.reload_config(new_config) {
                        error!("Failed to apply new configuration: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to load new configuration: {}", e);
                    warn!("Keeping current configuration");
                }
            }
        }

        Ok(())
    }
}

/// Configuration reload result
#[derive(Debug)]
pub struct ReloadResult {
    /// Whether the reload was successful
    pub success: bool,
    /// Number of routes updated
    pub routes_updated: usize,
    /// Number of upstreams updated
    pub upstreams_updated: usize,
    /// Error message if failed
    pub error: Option<String>,
}

/// Validate configuration before applying
pub fn validate_reload(current: &Config, new: &Config) -> Result<(), String> {
    // Check that listeners haven't changed (would require restart)
    if current.listeners.len() != new.listeners.len() {
        return Err("Listener changes require restart".to_string());
    }

    for (old, new) in current.listeners.iter().zip(new.listeners.iter()) {
        if old.address != new.address || old.protocol != new.protocol {
            return Err(format!(
                "Listener {} changed, requires restart",
                old.address
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use std::collections::HashMap;

    fn create_test_config() -> Config {
        Config {
            listeners: vec![ListenerConfig {
                address: "0.0.0.0:8080".to_string(),
                protocol: Protocol::Http,
                tls: None,
                max_connections: 1000,
            }],
            upstreams: HashMap::new(),
            routes: vec![],
            observability: ObservabilityConfig::default(),
            admin: None,
            global: GlobalConfig::default(),
            // Next-gen features (all optional)
            spiffe: None,
            io_uring: None,
            xds: None,
            kubernetes: None,
            edge: None,
            plugins: None,
            http3: None,
            l4: None,
            anomaly_detection: None,
            ebpf: None,
            graphql: None,
        }
    }

    #[test]
    fn test_validate_reload_same_listeners() {
        let config = create_test_config();
        assert!(validate_reload(&config, &config).is_ok());
    }

    #[test]
    fn test_validate_reload_changed_listeners() {
        let mut config1 = create_test_config();
        let mut config2 = create_test_config();

        config2.listeners[0].address = "0.0.0.0:9090".to_string();

        assert!(validate_reload(&config1, &config2).is_err());
    }
}
