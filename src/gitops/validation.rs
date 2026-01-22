//! Configuration validation for GitOps

use super::config::ValidationConfig;
use crate::config::Config;
use crate::error::{PrismError, Result};
use regex::Regex;
use tracing::{debug, warn};

/// Configuration validator
pub struct ConfigValidator {
    config: ValidationConfig,
}

impl ConfigValidator {
    /// Create a new validator
    pub fn new(config: ValidationConfig) -> Self {
        Self { config }
    }

    /// Validate a configuration
    /// Returns Ok(warnings) on success, Err(errors) on failure
    pub async fn validate(&self, config: &Config) -> std::result::Result<Vec<String>, Vec<PrismError>> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Basic structural validation
        self.validate_structure(config, &mut errors, &mut warnings);

        // Required sections validation
        self.validate_required_sections(config, &mut errors);

        // Forbidden patterns validation
        self.validate_forbidden_patterns(config, &mut errors);

        // TLS file validation
        if self.config.check_tls_files {
            self.validate_tls_files(config, &mut errors);
        }

        // Upstream connectivity check
        if self.config.check_upstreams {
            self.validate_upstreams(config, &mut errors, &mut warnings).await;
        }

        // Custom webhook validation
        if let Some(webhook_url) = &self.config.custom_webhook {
            if let Err(e) = self.validate_with_webhook(config, webhook_url).await {
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(warnings)
        } else {
            Err(errors)
        }
    }

    /// Validate basic structure
    fn validate_structure(&self, config: &Config, errors: &mut Vec<PrismError>, warnings: &mut Vec<String>) {
        // Must have at least one listener
        if config.listeners.is_empty() {
            errors.push(PrismError::Config(
                "Configuration must have at least one listener".to_string(),
            ));
        }

        // Validate listeners
        for (i, listener) in config.listeners.iter().enumerate() {
            // Validate address format
            if !is_valid_address(&listener.address) {
                errors.push(PrismError::Config(format!(
                    "Invalid listener address at index {}: {}",
                    i, listener.address
                )));
            }

            // Check for TLS config if protocol implies it
            if listener.tls.is_some() {
                if let Some(tls) = &listener.tls {
                    if tls.cert.as_os_str().is_empty() {
                        errors.push(PrismError::Config(format!(
                            "Listener {} has TLS enabled but no cert path",
                            i
                        )));
                    }
                    if tls.key.as_os_str().is_empty() {
                        errors.push(PrismError::Config(format!(
                            "Listener {} has TLS enabled but no key path",
                            i
                        )));
                    }
                }
            }
        }

        // Validate routes reference existing upstreams
        for route in &config.routes {
            if let Some(upstream) = &route.upstream {
                if !config.upstreams.contains_key(upstream) {
                    errors.push(PrismError::Config(format!(
                        "Route references non-existent upstream: {}",
                        upstream
                    )));
                }
            }
        }

        // Check for empty upstreams
        for (name, upstream) in &config.upstreams {
            if upstream.servers.is_empty() {
                warnings.push(format!("Upstream '{}' has no servers defined", name));
            }

            // Validate server addresses
            for (i, server) in upstream.servers.iter().enumerate() {
                if !is_valid_address(&server.address) {
                    errors.push(PrismError::Config(format!(
                        "Invalid server address in upstream '{}' at index {}: {}",
                        name, i, server.address
                    )));
                }
            }
        }

        // Strict mode validations
        if self.config.strict {
            // All routes should have a match rule
            for (i, route) in config.routes.iter().enumerate() {
                if route.match_config.path.is_none()
                    && route.match_config.path_prefix.is_none()
                    && route.match_config.path_regex.is_none()
                    && route.match_config.host.is_none()
                {
                    warnings.push(format!(
                        "Route at index {} has no match criteria - will match all requests",
                        i
                    ));
                }
            }

            // Check for duplicate listener addresses
            let mut addresses = std::collections::HashSet::new();
            for listener in &config.listeners {
                if !addresses.insert(&listener.address) {
                    errors.push(PrismError::Config(format!(
                        "Duplicate listener address: {}",
                        listener.address
                    )));
                }
            }
        }
    }

    /// Validate required sections are present
    fn validate_required_sections(&self, config: &Config, errors: &mut Vec<PrismError>) {
        let yaml = serde_yaml::to_string(config).unwrap_or_default();

        for section in &self.config.required_sections {
            // Simple check - see if the section key exists
            let pattern = format!("{}:", section);
            if !yaml.contains(&pattern) {
                errors.push(PrismError::Config(format!(
                    "Required section '{}' is missing from configuration",
                    section
                )));
            }
        }
    }

    /// Validate forbidden patterns are not present
    fn validate_forbidden_patterns(&self, config: &Config, errors: &mut Vec<PrismError>) {
        let yaml = serde_yaml::to_string(config).unwrap_or_default();

        for pattern in &self.config.forbidden_patterns {
            match Regex::new(pattern) {
                Ok(regex) => {
                    if regex.is_match(&yaml) {
                        errors.push(PrismError::Config(format!(
                            "Configuration contains forbidden pattern: {}",
                            pattern
                        )));
                    }
                }
                Err(e) => {
                    warn!(pattern = %pattern, error = %e, "Invalid forbidden pattern regex");
                }
            }
        }
    }

    /// Validate TLS certificate and key files exist
    fn validate_tls_files(&self, config: &Config, errors: &mut Vec<PrismError>) {
        for (i, listener) in config.listeners.iter().enumerate() {
            if let Some(tls) = &listener.tls {
                // Check cert file
                if !tls.cert.exists() {
                    errors.push(PrismError::Config(format!(
                        "TLS certificate file not found for listener {}: {:?}",
                        i, tls.cert
                    )));
                }

                // Check key file
                if !tls.key.exists() {
                    errors.push(PrismError::Config(format!(
                        "TLS key file not found for listener {}: {:?}",
                        i, tls.key
                    )));
                }

                // Check CA file if specified
                if let Some(ca_path) = &tls.client_ca {
                    if !ca_path.exists() {
                        errors.push(PrismError::Config(format!(
                            "TLS CA file not found for listener {}: {:?}",
                            i, ca_path
                        )));
                    }
                }
            }
        }
    }

    /// Validate upstream connectivity
    async fn validate_upstreams(
        &self,
        config: &Config,
        errors: &mut Vec<PrismError>,
        warnings: &mut Vec<String>,
    ) {
        for (name, upstream) in &config.upstreams {
            let mut reachable = 0;
            let mut unreachable = Vec::new();

            for server in &upstream.servers {
                match check_server_connectivity(&server.address).await {
                    Ok(()) => {
                        reachable += 1;
                        debug!(upstream = %name, server = %server.address, "Server reachable");
                    }
                    Err(e) => {
                        unreachable.push((server.address.clone(), e.to_string()));
                        debug!(upstream = %name, server = %server.address, error = %e, "Server unreachable");
                    }
                }
            }

            if reachable == 0 && !upstream.servers.is_empty() {
                errors.push(PrismError::Config(format!(
                    "No servers in upstream '{}' are reachable",
                    name
                )));
            } else if !unreachable.is_empty() {
                for (addr, err) in unreachable {
                    warnings.push(format!(
                        "Server {} in upstream '{}' is unreachable: {}",
                        addr, name, err
                    ));
                }
            }
        }
    }

    /// Validate configuration with custom webhook
    async fn validate_with_webhook(&self, config: &Config, webhook_url: &str) -> Result<()> {
        debug!(url = %webhook_url, "Validating with custom webhook");

        let response = reqwest::Client::new()
            .post(webhook_url)
            .json(config)
            .send()
            .await
            .map_err(|e| PrismError::Config(format!("Custom validation webhook failed: {}", e)))?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PrismError::Config(format!(
                "Custom validation webhook rejected config: {}",
                body
            )));
        }

        Ok(())
    }
}

/// Check if an address is valid (host:port format)
fn is_valid_address(address: &str) -> bool {
    // Split by last colon to handle IPv6
    if let Some(colon_pos) = address.rfind(':') {
        let host = &address[..colon_pos];
        let port = &address[colon_pos + 1..];

        // Check port is a number
        if port.parse::<u16>().is_err() {
            return false;
        }

        // Check host is not empty
        if host.is_empty() {
            return false;
        }

        // Basic validation - could be enhanced
        true
    } else {
        false
    }
}

/// Check server connectivity
async fn check_server_connectivity(address: &str) -> Result<()> {
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    let timeout_duration = Duration::from_secs(5);

    timeout(timeout_duration, TcpStream::connect(address))
        .await
        .map_err(|_| PrismError::Config(format!("Connection timeout to {}", address)))?
        .map_err(|e| PrismError::Config(format!("Cannot connect to {}: {}", address, e)))?;

    Ok(())
}

/// Schema validator for JSON Schema validation
pub struct SchemaValidator {
    schema: serde_json::Value,
}

impl SchemaValidator {
    /// Create a new schema validator from a schema file
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| PrismError::Config(format!("Failed to read schema file: {}", e)))?;

        let schema: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| PrismError::Config(format!("Failed to parse schema: {}", e)))?;

        Ok(Self { schema })
    }

    /// Validate configuration against schema
    pub fn validate(&self, config: &Config) -> Result<()> {
        // Convert config to JSON for schema validation
        let config_json = serde_json::to_value(config)
            .map_err(|e| PrismError::Config(format!("Failed to serialize config: {}", e)))?;

        // Note: Full JSON Schema validation would require a library like jsonschema-rs
        // For now, we just do basic type checking

        self.validate_value(&config_json, &self.schema, "")
    }

    fn validate_value(
        &self,
        value: &serde_json::Value,
        schema: &serde_json::Value,
        path: &str,
    ) -> Result<()> {
        // Get the expected type
        if let Some(type_value) = schema.get("type") {
            let expected_type = type_value.as_str().unwrap_or("unknown");

            let actual_type = match value {
                serde_json::Value::Null => "null",
                serde_json::Value::Bool(_) => "boolean",
                serde_json::Value::Number(_) => "number",
                serde_json::Value::String(_) => "string",
                serde_json::Value::Array(_) => "array",
                serde_json::Value::Object(_) => "object",
            };

            // Allow integer as number
            let types_match = expected_type == actual_type
                || (expected_type == "integer" && actual_type == "number");

            if !types_match {
                return Err(PrismError::Config(format!(
                    "Schema validation failed at '{}': expected {}, got {}",
                    path, expected_type, actual_type
                )));
            }
        }

        // Check required properties for objects
        if let (Some(required), serde_json::Value::Object(obj)) =
            (schema.get("required"), value)
        {
            if let Some(required_arr) = required.as_array() {
                for req in required_arr {
                    if let Some(req_str) = req.as_str() {
                        if !obj.contains_key(req_str) {
                            return Err(PrismError::Config(format!(
                                "Schema validation failed at '{}': missing required property '{}'",
                                path, req_str
                            )));
                        }
                    }
                }
            }
        }

        // Recursively validate object properties
        if let (Some(props), serde_json::Value::Object(obj)) =
            (schema.get("properties"), value)
        {
            if let Some(props_obj) = props.as_object() {
                for (key, prop_schema) in props_obj {
                    if let Some(prop_value) = obj.get(key) {
                        let prop_path = if path.is_empty() {
                            key.clone()
                        } else {
                            format!("{}.{}", path, key)
                        };
                        self.validate_value(prop_value, prop_schema, &prop_path)?;
                    }
                }
            }
        }

        // Validate array items
        if let (Some(items_schema), serde_json::Value::Array(arr)) =
            (schema.get("items"), value)
        {
            for (i, item) in arr.iter().enumerate() {
                let item_path = format!("{}[{}]", path, i);
                self.validate_value(item, items_schema, &item_path)?;
            }
        }

        Ok(())
    }
}

/// Diff between two configurations
#[derive(Debug, Clone)]
pub struct ConfigDiff {
    /// Added listeners
    pub added_listeners: Vec<usize>,
    /// Removed listeners
    pub removed_listeners: Vec<usize>,
    /// Modified listeners
    pub modified_listeners: Vec<usize>,
    /// Added upstreams
    pub added_upstreams: Vec<String>,
    /// Removed upstreams
    pub removed_upstreams: Vec<String>,
    /// Modified upstreams
    pub modified_upstreams: Vec<String>,
    /// Added routes
    pub added_routes: usize,
    /// Removed routes
    pub removed_routes: usize,
    /// Has any changes
    pub has_changes: bool,
}

impl ConfigDiff {
    /// Compute diff between two configurations
    pub fn compute(old: &Config, new: &Config) -> Self {
        let mut diff = ConfigDiff {
            added_listeners: Vec::new(),
            removed_listeners: Vec::new(),
            modified_listeners: Vec::new(),
            added_upstreams: Vec::new(),
            removed_upstreams: Vec::new(),
            modified_upstreams: Vec::new(),
            added_routes: 0,
            removed_routes: 0,
            has_changes: false,
        };

        // Compare listeners
        let old_listeners_len = old.listeners.len();
        let new_listeners_len = new.listeners.len();

        if new_listeners_len > old_listeners_len {
            for i in old_listeners_len..new_listeners_len {
                diff.added_listeners.push(i);
            }
        } else if old_listeners_len > new_listeners_len {
            for i in new_listeners_len..old_listeners_len {
                diff.removed_listeners.push(i);
            }
        }

        // Check for modified listeners
        for i in 0..old_listeners_len.min(new_listeners_len) {
            let old_yaml = serde_yaml::to_string(&old.listeners[i]).unwrap_or_default();
            let new_yaml = serde_yaml::to_string(&new.listeners[i]).unwrap_or_default();
            if old_yaml != new_yaml {
                diff.modified_listeners.push(i);
            }
        }

        // Compare upstreams
        for name in new.upstreams.keys() {
            if !old.upstreams.contains_key(name) {
                diff.added_upstreams.push(name.clone());
            } else {
                let old_yaml = serde_yaml::to_string(&old.upstreams[name]).unwrap_or_default();
                let new_yaml = serde_yaml::to_string(&new.upstreams[name]).unwrap_or_default();
                if old_yaml != new_yaml {
                    diff.modified_upstreams.push(name.clone());
                }
            }
        }

        for name in old.upstreams.keys() {
            if !new.upstreams.contains_key(name) {
                diff.removed_upstreams.push(name.clone());
            }
        }

        // Compare routes
        let old_routes_len = old.routes.len();
        let new_routes_len = new.routes.len();

        if new_routes_len > old_routes_len {
            diff.added_routes = new_routes_len - old_routes_len;
        } else if old_routes_len > new_routes_len {
            diff.removed_routes = old_routes_len - new_routes_len;
        }

        // Determine if there are any changes
        diff.has_changes = !diff.added_listeners.is_empty()
            || !diff.removed_listeners.is_empty()
            || !diff.modified_listeners.is_empty()
            || !diff.added_upstreams.is_empty()
            || !diff.removed_upstreams.is_empty()
            || !diff.modified_upstreams.is_empty()
            || diff.added_routes > 0
            || diff.removed_routes > 0;

        diff
    }

    /// Get a summary of changes
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();

        if !self.added_listeners.is_empty() {
            parts.push(format!("+{} listeners", self.added_listeners.len()));
        }
        if !self.removed_listeners.is_empty() {
            parts.push(format!("-{} listeners", self.removed_listeners.len()));
        }
        if !self.modified_listeners.is_empty() {
            parts.push(format!("~{} listeners", self.modified_listeners.len()));
        }

        if !self.added_upstreams.is_empty() {
            parts.push(format!("+{} upstreams", self.added_upstreams.len()));
        }
        if !self.removed_upstreams.is_empty() {
            parts.push(format!("-{} upstreams", self.removed_upstreams.len()));
        }
        if !self.modified_upstreams.is_empty() {
            parts.push(format!("~{} upstreams", self.modified_upstreams.len()));
        }

        if self.added_routes > 0 {
            parts.push(format!("+{} routes", self.added_routes));
        }
        if self.removed_routes > 0 {
            parts.push(format!("-{} routes", self.removed_routes));
        }

        if parts.is_empty() {
            "No changes".to_string()
        } else {
            parts.join(", ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_address() {
        assert!(is_valid_address("127.0.0.1:8080"));
        assert!(is_valid_address("0.0.0.0:80"));
        assert!(is_valid_address("localhost:3000"));
        assert!(!is_valid_address("localhost"));
        assert!(!is_valid_address(":8080"));
        assert!(!is_valid_address("127.0.0.1:"));
        assert!(!is_valid_address("127.0.0.1:abc"));
    }

    #[test]
    fn test_config_diff_no_changes() {
        let config = Config::default();
        let diff = ConfigDiff::compute(&config, &config);

        assert!(!diff.has_changes);
        assert_eq!(diff.summary(), "No changes");
    }

    #[tokio::test]
    async fn test_validator_empty_config() {
        let validation_config = ValidationConfig::default();
        let validator = ConfigValidator::new(validation_config);
        let config = Config::default();

        let result = validator.validate(&config).await;
        assert!(result.is_err()); // Should fail - no listeners
    }
}
