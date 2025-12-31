//! Prism - High-Performance Reverse Proxy
//!
//! A memory-safe reverse proxy written in Rust.

use clap::{Parser, Subcommand};
use prism::{config, Server, NAME, VERSION};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Prism - High-Performance Reverse Proxy
#[derive(Parser)]
#[command(name = NAME)]
#[command(version = VERSION)]
#[command(about = "High-performance, memory-safe reverse proxy written in Rust")]
#[command(
    long_about = "Prism is a high-performance reverse proxy that combines \
    Nginx-level performance with Rust's memory safety guarantees.\n\n\
    Optional features (compile with --features flag):\n  \
    - http3: HTTP/3 with QUIC transport\n  \
    - io_uring: Linux io_uring for maximum throughput\n  \
    - spiffe: SPIFFE/SPIRE zero-trust identity\n  \
    - xds: Envoy xDS API compatibility\n  \
    - kubernetes: Kubernetes Gateway API\n  \
    - edge: Cloudflare Workers-style edge functions\n  \
    - plugins: WebAssembly plugin system\n  \
    - anomaly-detection: AI traffic analysis\n  \
    - ebpf: eBPF kernel observability (Linux)\n  \
    - graphql: GraphQL-aware routing\n\n\
    Feature bundles: enterprise, edge-compute, full"
)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "prism.yaml")]
    config: PathBuf,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Log format (pretty, json, compact)
    #[arg(long, default_value = "pretty")]
    log_format: String,

    /// Enable hot reload (watch config file for changes)
    #[arg(short, long)]
    watch: bool,

    /// Number of worker threads (0 = auto-detect CPU cores)
    #[arg(short = 't', long)]
    threads: Option<usize>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the proxy server
    Run,

    /// Validate configuration file
    Validate,

    /// Show configuration
    Config,

    /// Check server health
    Health {
        /// Admin API address
        #[arg(short, long, default_value = "http://127.0.0.1:9090")]
        address: String,
    },

    /// Reload configuration (send SIGHUP)
    Reload {
        /// PID file path
        #[arg(short, long)]
        pid_file: Option<PathBuf>,
    },

    /// Show enabled features
    Features,
}

#[tokio::main]
async fn main() -> prism::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli.log_level, &cli.log_format)?;

    // Handle subcommands
    match cli.command {
        Some(Commands::Validate) => validate_config(&cli.config),
        Some(Commands::Config) => show_config(&cli.config),
        Some(Commands::Health { address }) => check_health(&address).await,
        Some(Commands::Reload { pid_file }) => reload_config(pid_file),
        Some(Commands::Features) => show_features(),
        Some(Commands::Run) | None => run_server(&cli.config, cli.watch, cli.threads).await,
    }
}

/// Initialize logging based on configuration
fn init_logging(level: &str, format: &str) -> prism::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("prism={},tower_http={}", level, level)));

    match format {
        "json" => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json())
                .init();
        }
        "compact" => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().compact())
                .init();
        }
        _ => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().pretty())
                .init();
        }
    }

    Ok(())
}

/// Run the server
async fn run_server(
    config_path: &PathBuf,
    watch: bool,
    threads: Option<usize>,
) -> prism::Result<()> {
    info!("Starting {} v{} (Rust reverse proxy)", NAME, VERSION);

    // Show enabled features at startup
    print_enabled_features();

    // Load configuration
    let mut config = config::load_config(config_path)?;
    info!("Configuration loaded from {:?}", config_path);

    // Override worker threads if specified via CLI
    if let Some(t) = threads {
        config.global.worker_threads = Some(t);
        info!("Worker threads set to {} via CLI", t);
    }

    // Create and run server
    let server_config_path = if watch {
        info!("Hot reload enabled - watching for config changes");
        Some(config_path.clone())
    } else {
        None
    };

    let server = Server::with_config_path(config, server_config_path).await?;

    info!("Server starting...");
    server.run().await
}

/// Print enabled features at startup
#[allow(unused_mut)]
fn print_enabled_features() {
    let mut features: Vec<&str> = Vec::new();

    #[cfg(feature = "http3")]
    features.push("http3");

    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    features.push("io_uring");

    #[cfg(feature = "spiffe")]
    features.push("spiffe");

    #[cfg(feature = "xds")]
    features.push("xds");

    #[cfg(feature = "kubernetes")]
    features.push("kubernetes");

    #[cfg(feature = "edge")]
    features.push("edge");

    #[cfg(feature = "plugins")]
    features.push("plugins");

    #[cfg(feature = "anomaly-detection")]
    features.push("anomaly-detection");

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    features.push("ebpf");

    #[cfg(feature = "graphql")]
    features.push("graphql");

    #[cfg(feature = "opentelemetry")]
    features.push("opentelemetry");

    #[cfg(feature = "tui")]
    features.push("tui");

    if features.is_empty() {
        info!("Running with core features only");
    } else {
        info!("Enabled features: {}", features.join(", "));
    }
}

/// Show all features and their status
fn show_features() -> prism::Result<()> {
    println!("Prism {} - Enabled Features\n", VERSION);

    let features = [
        (
            "http3",
            cfg!(feature = "http3"),
            "HTTP/3 with QUIC transport",
        ),
        (
            "io_uring",
            cfg!(all(target_os = "linux", feature = "io_uring")),
            "Linux io_uring async I/O",
        ),
        (
            "spiffe",
            cfg!(feature = "spiffe"),
            "SPIFFE/SPIRE zero-trust identity",
        ),
        ("xds", cfg!(feature = "xds"), "Envoy xDS API compatibility"),
        (
            "kubernetes",
            cfg!(feature = "kubernetes"),
            "Kubernetes Gateway API",
        ),
        (
            "edge",
            cfg!(feature = "edge"),
            "Edge compute functions (WASM)",
        ),
        (
            "plugins",
            cfg!(feature = "plugins"),
            "WebAssembly plugin system",
        ),
        (
            "anomaly-detection",
            cfg!(feature = "anomaly-detection"),
            "AI traffic anomaly detection",
        ),
        (
            "ebpf",
            cfg!(all(target_os = "linux", feature = "ebpf")),
            "eBPF kernel observability",
        ),
        (
            "graphql",
            cfg!(feature = "graphql"),
            "GraphQL-aware routing",
        ),
        (
            "opentelemetry",
            cfg!(feature = "opentelemetry"),
            "OpenTelemetry tracing",
        ),
        (
            "distributed-rate-limit",
            cfg!(feature = "distributed-rate-limit"),
            "Redis-based rate limiting",
        ),
        ("tui", cfg!(feature = "tui"), "Interactive TUI dashboard"),
    ];

    let max_name_len = features.iter().map(|(n, _, _)| n.len()).max().unwrap_or(0);

    for (name, enabled, description) in features {
        let status = if enabled { "[x]" } else { "[ ]" };
        println!(
            "  {} {:<width$}  {}",
            status,
            name,
            description,
            width = max_name_len
        );
    }

    println!("\nFeature bundles:");
    println!("  enterprise    = spiffe + xds + kubernetes + anomaly-detection + ebpf");
    println!("  edge-compute  = edge + plugins + graphql");
    println!("  full          = all features");

    println!("\nTo enable features, build with:");
    println!("  cargo build --release --features \"<feature1>,<feature2>\"");

    Ok(())
}

/// Validate configuration file
fn validate_config(config_path: &PathBuf) -> prism::Result<()> {
    println!("Validating configuration: {:?}", config_path);

    match config::load_config(config_path) {
        Ok(config) => {
            println!("\n\u{2713} Configuration is valid!");
            println!("\nSummary:");
            println!("  Listeners: {}", config.listeners.len());
            println!("  Upstreams: {}", config.upstreams.len());
            println!("  Routes: {}", config.routes.len());

            for (i, listener) in config.listeners.iter().enumerate() {
                println!("\n  Listener {}:", i + 1);
                println!("    Address: {}", listener.address);
                println!("    Protocol: {:?}", listener.protocol);
            }

            for (name, upstream) in &config.upstreams {
                println!("\n  Upstream '{}':", name);
                println!("    Servers: {}", upstream.servers.len());
                println!("    Load balancing: {:?}", upstream.load_balancing);
            }

            Ok(())
        }
        Err(e) => {
            println!("\n\u{2717} Configuration is invalid!");
            println!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Show parsed configuration
fn show_config(config_path: &PathBuf) -> prism::Result<()> {
    let config = config::load_config(config_path)?;

    // Pretty print the configuration
    let yaml =
        serde_yaml::to_string(&config).map_err(|e| prism::PrismError::Config(e.to_string()))?;

    println!("{}", yaml);
    Ok(())
}

/// Check server health
async fn check_health(address: &str) -> prism::Result<()> {
    println!("Checking health at {}...", address);

    let client = reqwest::Client::new();
    let url = format!("{}/health", address);

    match client.get(&url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                println!("\u{2713} Server is healthy");
                Ok(())
            } else {
                println!("\u{2717} Server returned status: {}", response.status());
                std::process::exit(1);
            }
        }
        Err(e) => {
            println!("\u{2717} Failed to connect: {}", e);
            std::process::exit(1);
        }
    }
}

/// Reload configuration
fn reload_config(pid_file: Option<PathBuf>) -> prism::Result<()> {
    #[cfg(unix)]
    {
        use std::fs;

        let pid = if let Some(path) = pid_file {
            let pid_str = fs::read_to_string(&path).map_err(|e| {
                prism::PrismError::Config(format!("Failed to read PID file: {}", e))
            })?;
            pid_str
                .trim()
                .parse::<i32>()
                .map_err(|e| prism::PrismError::Config(format!("Invalid PID: {}", e)))?
        } else {
            // Try to find running prism process
            println!("No PID file specified, attempting to find running prism process...");
            return Err(prism::PrismError::Config(
                "Please specify --pid-file or use 'kill -HUP <pid>' directly".to_string(),
            ));
        };

        // Validate PID before sending signal
        if pid <= 0 {
            return Err(prism::PrismError::Config(format!(
                "Invalid PID: {} (must be positive)",
                pid
            )));
        }

        // Check if process exists by sending signal 0 (doesn't actually send a signal)
        let process_exists = unsafe { libc::kill(pid, 0) == 0 };
        if !process_exists {
            return Err(prism::PrismError::Config(format!(
                "Process with PID {} does not exist or is not accessible",
                pid
            )));
        }

        println!("Sending reload signal to PID {}...", pid);

        unsafe {
            if libc::kill(pid, libc::SIGHUP) == 0 {
                println!("\u{2713} Reload signal sent successfully");
                Ok(())
            } else {
                let err = std::io::Error::last_os_error();
                Err(prism::PrismError::Config(format!(
                    "Failed to send signal: {}",
                    err
                )))
            }
        }
    }

    #[cfg(not(unix))]
    {
        Err(prism::PrismError::Config(
            "Reload is only supported on Unix systems".to_string(),
        ))
    }
}
