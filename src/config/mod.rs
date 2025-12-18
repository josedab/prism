//! Configuration module for Prism reverse proxy
//!
//! Supports YAML and TOML configuration formats with validation and hot reload.
//! Environment variables can be interpolated using `${VAR}`, `${VAR:-default}`, or `${VAR:?error}` syntax.

mod env;
mod types;
mod validation;

pub use env::{
    contains_env_vars, expand_env_vars, expand_env_vars_lenient, list_env_vars, EnvExpandConfig,
    EnvExpander,
};
pub use types::*;
pub use validation::validate_config;

use crate::error::{PrismError, Result};
use std::path::Path;
use tracing::info;

/// Load configuration from a file
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    load_config_with_options(path, true)
}

/// Load configuration with control over environment variable expansion
pub fn load_config_with_options<P: AsRef<Path>>(path: P, expand_env: bool) -> Result<Config> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)
        .map_err(|e| PrismError::Config(format!("Failed to read config file {:?}: {}", path, e)))?;

    // Expand environment variables if enabled
    let content = if expand_env {
        expand_env_vars(&content)?
    } else {
        content
    };

    let config = parse_config(&content, path)?;
    validate_config(&config)?;

    info!("Configuration loaded successfully from {:?}", path);
    Ok(config)
}

/// Parse configuration from string content
fn parse_config(content: &str, path: &Path) -> Result<Config> {
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("yaml");

    match extension {
        "yaml" | "yml" => serde_yaml::from_str(content).map_err(|e| e.into()),
        "toml" => toml::from_str(content).map_err(|e| e.into()),
        _ => Err(PrismError::Config(format!(
            "Unsupported config format: {}",
            extension
        ))),
    }
}

/// Reload configuration from file
pub fn reload_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    load_config(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_yaml_config() {
        let config_content = r#"
listeners:
  - address: "0.0.0.0:8080"
    protocol: http

upstreams:
  backend:
    servers:
      - address: "127.0.0.1:3000"

routes:
  - match:
      path_prefix: "/"
    upstream: backend
"#;
        let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
        file.write_all(config_content.as_bytes()).unwrap();

        let config = load_config(file.path()).unwrap();
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.routes.len(), 1);
    }

    #[test]
    fn test_load_config_with_env_vars() {
        // Set test env vars
        std::env::set_var("PRISM_TEST_PORT", "9999");
        std::env::set_var("PRISM_TEST_BACKEND", "127.0.0.1:4000");

        let config_content = r#"
listeners:
  - address: "0.0.0.0:${PRISM_TEST_PORT}"
    protocol: http

upstreams:
  backend:
    servers:
      - address: "${PRISM_TEST_BACKEND}"

routes:
  - match:
      path_prefix: "/"
    upstream: backend
"#;
        let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
        file.write_all(config_content.as_bytes()).unwrap();

        let config = load_config(file.path()).unwrap();
        assert_eq!(config.listeners[0].address, "0.0.0.0:9999");
        assert_eq!(
            config.upstreams["backend"].servers[0].address,
            "127.0.0.1:4000"
        );

        // Clean up
        std::env::remove_var("PRISM_TEST_PORT");
        std::env::remove_var("PRISM_TEST_BACKEND");
    }

    #[test]
    fn test_load_config_with_default_values() {
        let config_content = r#"
listeners:
  - address: "0.0.0.0:${UNDEFINED_PORT:-8080}"
    protocol: http

upstreams:
  backend:
    servers:
      - address: "127.0.0.1:3000"

routes:
  - match:
      path_prefix: "/"
    upstream: backend
"#;
        let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
        file.write_all(config_content.as_bytes()).unwrap();

        let config = load_config(file.path()).unwrap();
        assert_eq!(config.listeners[0].address, "0.0.0.0:8080");
    }

    #[test]
    fn test_load_config_without_expansion() {
        let config_content = r#"
listeners:
  - address: "0.0.0.0:8080"
    protocol: http

upstreams:
  backend:
    servers:
      - address: "127.0.0.1:3000"

routes:
  - match:
      path_prefix: "/"
    upstream: backend
"#;
        let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
        file.write_all(config_content.as_bytes()).unwrap();

        let config = load_config_with_options(file.path(), false).unwrap();
        assert_eq!(config.listeners.len(), 1);
    }
}
