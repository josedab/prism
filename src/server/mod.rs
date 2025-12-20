//! Server module for running the reverse proxy
//!
//! Provides the main server implementation with:
//! - Connection handling
//! - Request proxying
//! - Hot reload support
//! - Graceful shutdown with connection draining

mod handler;
mod reload;
mod shutdown;

pub use handler::*;
pub use reload::*;
pub use shutdown::*;

use crate::config::Config;
use crate::error::Result;
use crate::listener::{Connection, ListenerManager};
use crate::observability::Observability;
use crate::router::Router;
use crate::upstream::UpstreamManager;
use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::{debug, error, info, warn};

// Feature-gated imports
#[cfg(feature = "edge")]
use crate::edge::EdgeRuntime;
#[cfg(feature = "kubernetes")]
use crate::k8s::GatewayController;
#[cfg(feature = "plugins")]
use crate::plugin::PluginManager;
#[cfg(feature = "spiffe")]
use crate::spiffe::WorkloadApiClient;
#[cfg(feature = "xds")]
use crate::xds::XdsClient;

/// The main Prism server
pub struct Server {
    /// Current configuration
    config: Arc<ArcSwap<Config>>,
    /// Listener manager
    listeners: ListenerManager,
    /// Router
    router: Arc<ArcSwap<Router>>,
    /// Upstream manager
    upstreams: Arc<UpstreamManager>,
    /// Observability
    observability: Arc<Observability>,
    /// Shutdown coordinator with connection draining
    shutdown: ShutdownCoordinator,
    /// Configuration file path (for hot reload)
    config_path: Option<PathBuf>,

    // Feature-gated components
    /// SPIFFE/SPIRE workload identity client
    #[cfg(feature = "spiffe")]
    spiffe_client: Option<Arc<WorkloadApiClient>>,

    /// Envoy xDS API client
    #[cfg(feature = "xds")]
    xds_client: Option<Arc<XdsClient>>,

    /// Kubernetes Gateway API controller
    #[cfg(feature = "kubernetes")]
    k8s_controller: Option<Arc<GatewayController>>,

    /// Edge compute runtime
    #[cfg(feature = "edge")]
    edge_runtime: Option<Arc<EdgeRuntime>>,

    /// WebAssembly plugin manager
    #[cfg(feature = "plugins")]
    plugin_manager: Option<Arc<PluginManager>>,
}

impl Server {
    /// Create a new server from configuration
    pub async fn new(config: Config) -> Result<Self> {
        Self::with_config_path(config, None).await
    }

    /// Create a new server with config path for hot reload
    pub async fn with_config_path(config: Config, config_path: Option<PathBuf>) -> Result<Self> {
        info!("Initializing Prism server v{}", crate::VERSION);

        // Create listeners
        let listeners = ListenerManager::new(config.listeners.clone()).await?;
        info!("Created {} listener(s)", listeners.len());

        // Create router
        let router = Router::new(&config.routes)?;
        info!("Loaded {} route(s)", router.len());

        // Create upstream manager
        let upstreams = UpstreamManager::from_config(&config.upstreams)?;
        info!("Configured {} upstream(s)", config.upstreams.len());

        // Create observability
        let observability = Observability::new(&config.observability)?;

        // Create shutdown coordinator with connection draining
        let shutdown = ShutdownCoordinator::new(config.global.shutdown_timeout);

        // Initialize feature-gated components

        #[cfg(feature = "spiffe")]
        let spiffe_client = if let Some(ref spiffe_config) = config.spiffe {
            info!("Initializing SPIFFE workload identity client");
            let client_config = crate::spiffe::SpiffeConfig {
                workload_api_socket: spiffe_config.workload_api_socket.clone(),
                trust_domain: spiffe_config.trust_domain.clone(),
                svid_refresh_interval: std::time::Duration::from_secs(
                    spiffe_config.svid_refresh_interval_secs.unwrap_or(300),
                ),
                timeout: std::time::Duration::from_secs(spiffe_config.timeout_secs.unwrap_or(30)),
            };
            Some(Arc::new(WorkloadApiClient::new(client_config)))
        } else {
            None
        };

        #[cfg(feature = "xds")]
        let xds_client = if let Some(ref xds_config) = config.xds {
            info!(
                "Initializing xDS client connecting to {}",
                xds_config.server_address
            );
            let client_config = crate::xds::XdsClientConfig {
                server_address: xds_config.server_address.clone(),
                node_id: xds_config.node_id.clone(),
                cluster: xds_config.cluster.clone(),
                initial_fetch_timeout: std::time::Duration::from_secs(
                    xds_config.initial_fetch_timeout_secs.unwrap_or(30),
                ),
                refresh_interval: std::time::Duration::from_secs(
                    xds_config.refresh_interval_secs.unwrap_or(30),
                ),
            };
            Some(Arc::new(XdsClient::new(client_config)))
        } else {
            None
        };

        #[cfg(feature = "kubernetes")]
        let k8s_controller = if let Some(ref k8s_config) = config.kubernetes {
            info!("Initializing Kubernetes Gateway API controller");
            let controller_config = crate::k8s::GatewayControllerConfig {
                namespace: k8s_config.namespace.clone(),
                gateway_class_name: k8s_config.gateway_class_name.clone(),
                leader_election_enabled: k8s_config.leader_election.unwrap_or(true),
                reconcile_interval: std::time::Duration::from_secs(
                    k8s_config.reconcile_interval_secs.unwrap_or(30),
                ),
            };
            Some(Arc::new(GatewayController::new(controller_config).await?))
        } else {
            None
        };

        #[cfg(feature = "edge")]
        let edge_runtime = if let Some(ref edge_config) = config.edge {
            info!("Initializing edge compute runtime");
            let runtime_config = crate::edge::EdgeRuntimeConfig {
                max_memory_mb: edge_config.max_memory_mb.unwrap_or(128),
                execution_timeout: std::time::Duration::from_millis(
                    edge_config.execution_timeout_ms.unwrap_or(30000),
                ),
                max_concurrent: edge_config.max_concurrent.unwrap_or(100),
            };
            Some(Arc::new(EdgeRuntime::new(runtime_config)))
        } else {
            None
        };

        #[cfg(feature = "plugins")]
        let plugin_manager = if let Some(ref plugin_config) = config.plugins {
            info!("Initializing WASM plugin manager");
            let manager_config = crate::plugin::PluginManagerConfig {
                plugin_dir: plugin_config
                    .plugin_dir
                    .clone()
                    .unwrap_or_else(|| "./plugins".to_string())
                    .into(),
                max_memory_pages: plugin_config.max_memory_pages.unwrap_or(256),
                enable_wasi: plugin_config.enable_wasi.unwrap_or(true),
            };
            Some(Arc::new(PluginManager::new(manager_config)?))
        } else {
            None
        };

        Ok(Self {
            config: Arc::new(ArcSwap::new(Arc::new(config))),
            listeners,
            router: Arc::new(ArcSwap::new(Arc::new(router))),
            upstreams: Arc::new(upstreams),
            observability: Arc::new(observability),
            shutdown,
            config_path,
            // Feature-gated components
            #[cfg(feature = "spiffe")]
            spiffe_client,
            #[cfg(feature = "xds")]
            xds_client,
            #[cfg(feature = "kubernetes")]
            k8s_controller,
            #[cfg(feature = "edge")]
            edge_runtime,
            #[cfg(feature = "plugins")]
            plugin_manager,
        })
    }

    /// Run the server
    pub async fn run(self) -> Result<()> {
        let server = Arc::new(self);

        // Start health checks
        let health_handles = server.upstreams.start_health_checks();
        info!("Started {} health check task(s)", health_handles.len());

        // Start hot reload watcher if config path is set
        let _reload_handle = server
            .config_path
            .as_ref()
            .map(|path| server.clone().start_config_watcher(path.clone()));

        // Start feature-gated background tasks

        #[cfg(feature = "spiffe")]
        let _spiffe_handle = if let Some(ref client) = server.spiffe_client {
            let client = client.clone();
            Some(tokio::spawn(async move {
                info!("Starting SPIFFE workload identity background refresh");
                client.start_refresh_loop().await;
            }))
        } else {
            None
        };

        #[cfg(feature = "xds")]
        let _xds_handle = if let Some(ref client) = server.xds_client {
            let client = client.clone();
            Some(tokio::spawn(async move {
                info!("Starting xDS client stream");
                if let Err(e) = client.start().await {
                    error!("xDS client error: {}", e);
                }
            }))
        } else {
            None
        };

        #[cfg(feature = "kubernetes")]
        let _k8s_handle = if let Some(ref controller) = server.k8s_controller {
            let controller = controller.clone();
            Some(tokio::spawn(async move {
                info!("Starting Kubernetes Gateway API controller");
                if let Err(e) = controller.run().await {
                    error!("Kubernetes controller error: {}", e);
                }
            }))
        } else {
            None
        };

        // Start listeners
        let mut listener_handles = Vec::new();

        for (idx, listener) in server.listeners.listeners().iter().enumerate() {
            let addr = listener.local_addr()?;
            info!("Starting listener on {}", addr);

            let server = server.clone();
            let mut shutdown_rx = server.shutdown.drain_handle().shutdown_rx();

            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        result = server.accept_connection(idx) => {
                            match result {
                                Ok(accepted) => {
                                    if !accepted {
                                        // Connection rejected (draining)
                                        debug!("Connection rejected, server is draining");
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to accept connection: {}", e);
                                }
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            info!("Listener {} stopping accept loop", addr);
                            break;
                        }
                    }
                }
            });

            listener_handles.push(handle);
        }

        // Wait for shutdown signal
        Self::wait_for_shutdown().await;

        // Initiate graceful shutdown with connection draining
        info!("Initiating graceful shutdown...");
        let active = server.shutdown.drain_handle().active_connections();
        info!("Active connections: {}", active);

        // Wait for listeners to stop accepting
        let _ = futures::future::join_all(listener_handles).await;

        // Drain connections with timeout
        let drained_gracefully = server.shutdown.shutdown().await;

        if drained_gracefully {
            info!("All connections drained gracefully");
        } else {
            warn!("Some connections were forcefully closed");
        }

        info!("Prism server stopped");
        Ok(())
    }

    /// Accept a connection on a listener
    ///
    /// Returns Ok(true) if connection was accepted, Ok(false) if rejected (draining)
    async fn accept_connection(self: &Arc<Self>, listener_idx: usize) -> Result<bool> {
        let listener = &self.listeners.listeners()[listener_idx];
        let (connection, addr) = listener.accept().await?;

        // Try to get a connection guard (will fail if draining)
        let guard = match self.shutdown.drain_handle().connection_guard() {
            Some(guard) => guard,
            None => {
                // Server is draining, reject new connections
                debug!("Rejecting connection from {} (server draining)", addr);
                return Ok(false);
            }
        };

        // Record connection metric
        self.observability.metrics.record_connection();

        // Spawn handler for this connection
        let server = self.clone();
        tokio::spawn(async move {
            // Connection guard lives for the duration of the connection
            let _guard = guard;

            if let Err(e) = server.handle_connection(connection, addr).await {
                error!("Error handling connection from {}: {}", addr, e);
                server.observability.metrics.record_error("connection");
            }
            server.observability.metrics.record_connection_closed();

            // Guard is dropped here, decrementing active connection count
        });

        Ok(true)
    }

    /// Handle an accepted connection
    async fn handle_connection(&self, connection: Connection, addr: SocketAddr) -> Result<()> {
        let handler = RequestHandler::new(
            self.router.clone(),
            self.upstreams.clone(),
            self.observability.clone(),
        );

        handler.handle(connection, addr).await
    }

    /// Wait for shutdown signal (SIGINT or SIGTERM)
    async fn wait_for_shutdown() {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received Ctrl+C signal");
            }
            _ = terminate => {
                info!("Received terminate signal");
            }
        }
    }

    /// Reload configuration
    pub fn reload_config(&self, new_config: Config) -> Result<()> {
        info!("Reloading configuration...");

        // Update router
        let new_router = Router::new(&new_config.routes)?;
        self.router.store(Arc::new(new_router));

        // Update config
        self.config.store(Arc::new(new_config));

        info!("Configuration reloaded successfully");
        Ok(())
    }

    /// Get current configuration
    pub fn config(&self) -> Arc<Config> {
        self.config.load_full()
    }

    /// Get metrics endpoint response
    pub fn metrics(&self) -> Result<String> {
        self.observability.metrics.export()
    }
}

/// Server statistics
#[derive(Debug, Clone)]
pub struct ServerStats {
    pub active_connections: i64,
    pub total_requests: u64,
    pub upstreams: Vec<crate::upstream::UpstreamStats>,
}
