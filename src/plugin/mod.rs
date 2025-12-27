//! WebAssembly Plugin System
//!
//! Provides a sandboxed plugin system for extending Prism with custom logic:
//! - Request/response transformation
//! - Custom authentication
//! - Header manipulation
//! - Body transformation
//! - Custom routing logic
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        Plugin Manager                           │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
//! │  │  Plugin 1   │  │  Plugin 2   │  │  Plugin N   │             │
//! │  │  (WASM)     │  │  (WASM)     │  │  (WASM)     │             │
//! │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
//! │         │                │                │                     │
//! │  ┌──────▼────────────────▼────────────────▼──────┐             │
//! │  │              Host Functions ABI               │             │
//! │  │  • get_header    • set_header                 │             │
//! │  │  • get_body      • set_body                   │             │
//! │  │  • log           • get_config                 │             │
//! │  │  • get_property  • set_property               │             │
//! │  └──────────────────────────────────────────────┘             │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Plugin Interface (Guest-side)
//! Plugins implement these functions:
//! - `on_request_headers()` - Called when request headers arrive
//! - `on_request_body()` - Called when request body is available
//! - `on_response_headers()` - Called when response headers arrive
//! - `on_response_body()` - Called when response body is available
//!
//! # Example Plugin (WAT)
//! ```wat
//! (module
//!   (import "env" "get_header" (func $get_header (param i32 i32) (result i32)))
//!   (import "env" "set_header" (func $set_header (param i32 i32 i32 i32)))
//!   (export "on_request_headers" (func $on_request_headers))
//!   (func $on_request_headers (result i32)
//!     ;; Plugin logic here
//!     i32.const 0  ;; Continue
//!   )
//! )
//! ```

pub mod runtime;
pub mod types;

pub use runtime::*;
pub use types::*;

use crate::error::Result;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Plugin system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    /// Enable the plugin system
    #[serde(default)]
    pub enabled: bool,

    /// Directory to load plugins from
    #[serde(default = "default_plugin_dir")]
    pub plugin_dir: PathBuf,

    /// Maximum memory per plugin instance (bytes)
    #[serde(default = "default_max_memory")]
    pub max_memory_bytes: usize,

    /// Maximum execution time per call (milliseconds)
    #[serde(default = "default_max_execution_time")]
    pub max_execution_time_ms: u64,

    /// Plugin-specific configurations
    #[serde(default)]
    pub plugins: HashMap<String, PluginInstanceConfig>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            plugin_dir: default_plugin_dir(),
            max_memory_bytes: default_max_memory(),
            max_execution_time_ms: default_max_execution_time(),
            plugins: HashMap::new(),
        }
    }
}

fn default_plugin_dir() -> PathBuf {
    PathBuf::from("./plugins")
}

fn default_max_memory() -> usize {
    16 * 1024 * 1024 // 16MB
}

fn default_max_execution_time() -> u64 {
    100 // 100ms
}

/// Configuration for a specific plugin instance
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginInstanceConfig {
    /// Path to the WASM file
    pub path: PathBuf,

    /// Whether this plugin is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Execution priority (lower = earlier)
    #[serde(default)]
    pub priority: i32,

    /// Which phases to run this plugin
    #[serde(default)]
    pub phases: PluginPhases,

    /// Plugin-specific configuration (passed to plugin)
    #[serde(default)]
    pub config: HashMap<String, serde_json::Value>,
}

fn default_true() -> bool {
    true
}

/// Which lifecycle phases the plugin runs in
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginPhases {
    #[serde(default = "default_true")]
    pub on_request_headers: bool,
    #[serde(default)]
    pub on_request_body: bool,
    #[serde(default = "default_true")]
    pub on_response_headers: bool,
    #[serde(default)]
    pub on_response_body: bool,
}

impl Default for PluginPhases {
    fn default() -> Self {
        Self {
            on_request_headers: true,
            on_request_body: false,
            on_response_headers: true,
            on_response_body: false,
        }
    }
}

/// Plugin action returned from plugin functions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginAction {
    /// Continue to the next plugin/handler
    Continue,
    /// Pause processing (for async operations)
    Pause,
    /// Stop processing and return current response
    Stop,
    /// Stop processing with an error response
    Error,
}

impl From<i32> for PluginAction {
    fn from(value: i32) -> Self {
        match value {
            0 => PluginAction::Continue,
            1 => PluginAction::Pause,
            2 => PluginAction::Stop,
            _ => PluginAction::Error,
        }
    }
}

/// Represents a loaded plugin
pub struct LoadedPlugin {
    /// Plugin name
    pub name: String,
    /// Plugin configuration
    pub config: PluginInstanceConfig,
    /// Runtime instance
    pub runtime: Box<dyn PluginRuntime>,
}

/// Plugin runtime trait (allows different WASM runtimes)
pub trait PluginRuntime: Send + Sync {
    /// Call the on_request_headers function
    fn on_request_headers(&self, ctx: &mut PluginContext) -> Result<PluginAction>;

    /// Call the on_request_body function
    fn on_request_body(&self, ctx: &mut PluginContext) -> Result<PluginAction>;

    /// Call the on_response_headers function
    fn on_response_headers(&self, ctx: &mut PluginContext) -> Result<PluginAction>;

    /// Call the on_response_body function
    fn on_response_body(&self, ctx: &mut PluginContext) -> Result<PluginAction>;
}

/// Plugin execution context (shared state during a request)
#[derive(Debug, Default)]
pub struct PluginContext {
    /// Request headers
    pub request_headers: HashMap<String, String>,
    /// Response headers
    pub response_headers: HashMap<String, String>,
    /// Request body (if buffered)
    pub request_body: Option<Vec<u8>>,
    /// Response body (if buffered)
    pub response_body: Option<Vec<u8>>,
    /// Request properties (path, method, etc.)
    pub properties: HashMap<String, String>,
    /// Plugin-local storage
    pub storage: HashMap<String, Vec<u8>>,
    /// Log messages from plugin
    pub logs: Vec<(LogLevel, String)>,
    /// Whether response was modified
    pub response_modified: bool,
}

impl PluginContext {
    /// Create a new plugin context
    pub fn new() -> Self {
        Self::default()
    }

    /// Set request headers from hyper HeaderMap
    pub fn with_request_headers(
        mut self,
        headers: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        self.request_headers = headers.into_iter().collect();
        self
    }

    /// Set request properties
    pub fn with_properties(mut self, props: impl IntoIterator<Item = (String, String)>) -> Self {
        self.properties = props.into_iter().collect();
        self
    }

    /// Get a header value
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.request_headers.get(name).map(|s| s.as_str())
    }

    /// Set a header value
    pub fn set_header(&mut self, name: String, value: String) {
        self.request_headers.insert(name, value);
    }

    /// Get a response header
    pub fn get_response_header(&self, name: &str) -> Option<&str> {
        self.response_headers.get(name).map(|s| s.as_str())
    }

    /// Set a response header
    pub fn set_response_header(&mut self, name: String, value: String) {
        self.response_headers.insert(name, value);
        self.response_modified = true;
    }

    /// Get a property
    pub fn get_property(&self, name: &str) -> Option<&str> {
        self.properties.get(name).map(|s| s.as_str())
    }

    /// Set a property
    pub fn set_property(&mut self, name: String, value: String) {
        self.properties.insert(name, value);
    }

    /// Add a log entry
    pub fn log(&mut self, level: LogLevel, message: String) {
        self.logs.push((level, message));
    }
}

/// Log level for plugin logs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<i32> for LogLevel {
    fn from(value: i32) -> Self {
        match value {
            0 => LogLevel::Trace,
            1 => LogLevel::Debug,
            2 => LogLevel::Info,
            3 => LogLevel::Warn,
            _ => LogLevel::Error,
        }
    }
}

/// Plugin manager - loads and manages plugins
pub struct PluginManager {
    config: PluginConfig,
    plugins: RwLock<Vec<Arc<LoadedPlugin>>>,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new(config: PluginConfig) -> Self {
        Self {
            config,
            plugins: RwLock::new(Vec::new()),
        }
    }

    /// Load plugins from configuration
    pub fn load_plugins(&self) -> Result<()> {
        if !self.config.enabled {
            tracing::info!("Plugin system disabled");
            return Ok(());
        }

        let mut plugins = self.plugins.write();
        plugins.clear();

        let mut sorted_configs: Vec<_> = self.config.plugins.iter().collect();
        sorted_configs.sort_by_key(|(_, cfg)| cfg.priority);

        for (name, plugin_config) in sorted_configs {
            if !plugin_config.enabled {
                tracing::debug!(plugin = %name, "Plugin disabled, skipping");
                continue;
            }

            match self.load_plugin(name, plugin_config) {
                Ok(plugin) => {
                    tracing::info!(
                        plugin = %name,
                        path = %plugin_config.path.display(),
                        "Loaded plugin"
                    );
                    plugins.push(Arc::new(plugin));
                }
                Err(e) => {
                    tracing::error!(
                        plugin = %name,
                        error = %e,
                        "Failed to load plugin"
                    );
                }
            }
        }

        tracing::info!(count = plugins.len(), "Plugins loaded");
        Ok(())
    }

    /// Load a single plugin
    fn load_plugin(&self, name: &str, config: &PluginInstanceConfig) -> Result<LoadedPlugin> {
        let runtime = MockPluginRuntime::new(name.to_string(), config.config.clone());

        Ok(LoadedPlugin {
            name: name.to_string(),
            config: config.clone(),
            runtime: Box::new(runtime),
        })
    }

    /// Execute on_request_headers for all plugins
    pub fn execute_request_headers(&self, ctx: &mut PluginContext) -> Result<PluginAction> {
        let plugins = self.plugins.read();

        for plugin in plugins.iter() {
            if !plugin.config.phases.on_request_headers {
                continue;
            }

            match plugin.runtime.on_request_headers(ctx) {
                Ok(PluginAction::Continue) => continue,
                Ok(action) => return Ok(action),
                Err(e) => {
                    tracing::error!(
                        plugin = %plugin.name,
                        error = %e,
                        "Plugin error in on_request_headers"
                    );
                    ctx.log(
                        LogLevel::Error,
                        format!("Plugin {} error: {}", plugin.name, e),
                    );
                }
            }
        }

        Ok(PluginAction::Continue)
    }

    /// Execute on_request_body for all plugins
    pub fn execute_request_body(&self, ctx: &mut PluginContext) -> Result<PluginAction> {
        let plugins = self.plugins.read();

        for plugin in plugins.iter() {
            if !plugin.config.phases.on_request_body {
                continue;
            }

            match plugin.runtime.on_request_body(ctx) {
                Ok(PluginAction::Continue) => continue,
                Ok(action) => return Ok(action),
                Err(e) => {
                    tracing::error!(
                        plugin = %plugin.name,
                        error = %e,
                        "Plugin error in on_request_body"
                    );
                }
            }
        }

        Ok(PluginAction::Continue)
    }

    /// Execute on_response_headers for all plugins
    pub fn execute_response_headers(&self, ctx: &mut PluginContext) -> Result<PluginAction> {
        let plugins = self.plugins.read();

        for plugin in plugins.iter() {
            if !plugin.config.phases.on_response_headers {
                continue;
            }

            match plugin.runtime.on_response_headers(ctx) {
                Ok(PluginAction::Continue) => continue,
                Ok(action) => return Ok(action),
                Err(e) => {
                    tracing::error!(
                        plugin = %plugin.name,
                        error = %e,
                        "Plugin error in on_response_headers"
                    );
                }
            }
        }

        Ok(PluginAction::Continue)
    }

    /// Execute on_response_body for all plugins
    pub fn execute_response_body(&self, ctx: &mut PluginContext) -> Result<PluginAction> {
        let plugins = self.plugins.read();

        for plugin in plugins.iter() {
            if !plugin.config.phases.on_response_body {
                continue;
            }

            match plugin.runtime.on_response_body(ctx) {
                Ok(PluginAction::Continue) => continue,
                Ok(action) => return Ok(action),
                Err(e) => {
                    tracing::error!(
                        plugin = %plugin.name,
                        error = %e,
                        "Plugin error in on_response_body"
                    );
                }
            }
        }

        Ok(PluginAction::Continue)
    }

    /// Get loaded plugin count
    pub fn plugin_count(&self) -> usize {
        self.plugins.read().len()
    }

    /// Get plugin names
    pub fn plugin_names(&self) -> Vec<String> {
        self.plugins.read().iter().map(|p| p.name.clone()).collect()
    }
}

/// Mock plugin runtime for testing (no real WASM)
pub struct MockPluginRuntime {
    name: String,
    config: HashMap<String, serde_json::Value>,
}

impl MockPluginRuntime {
    pub fn new(name: String, config: HashMap<String, serde_json::Value>) -> Self {
        Self { name, config }
    }
}

impl PluginRuntime for MockPluginRuntime {
    fn on_request_headers(&self, ctx: &mut PluginContext) -> Result<PluginAction> {
        ctx.log(
            LogLevel::Debug,
            format!("Plugin {} processing request headers", self.name),
        );

        // Example: Add a header showing plugin processed
        ctx.set_header(format!("X-Plugin-{}", self.name), "processed".to_string());

        // Check for configured transformations
        if let Some(serde_json::Value::Object(headers)) = self.config.get("add_headers") {
            for (key, value) in headers {
                if let serde_json::Value::String(v) = value {
                    ctx.set_header(key.clone(), v.clone());
                }
            }
        }

        Ok(PluginAction::Continue)
    }

    fn on_request_body(&self, ctx: &mut PluginContext) -> Result<PluginAction> {
        ctx.log(
            LogLevel::Debug,
            format!("Plugin {} processing request body", self.name),
        );
        Ok(PluginAction::Continue)
    }

    fn on_response_headers(&self, ctx: &mut PluginContext) -> Result<PluginAction> {
        ctx.log(
            LogLevel::Debug,
            format!("Plugin {} processing response headers", self.name),
        );

        // Example: Add response headers from config
        if let Some(serde_json::Value::Object(headers)) = self.config.get("add_response_headers") {
            for (key, value) in headers {
                if let serde_json::Value::String(v) = value {
                    ctx.set_response_header(key.clone(), v.clone());
                }
            }
        }

        Ok(PluginAction::Continue)
    }

    fn on_response_body(&self, ctx: &mut PluginContext) -> Result<PluginAction> {
        ctx.log(
            LogLevel::Debug,
            format!("Plugin {} processing response body", self.name),
        );
        Ok(PluginAction::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PluginConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_memory_bytes, 16 * 1024 * 1024);
    }

    #[test]
    fn test_plugin_action_from_i32() {
        assert_eq!(PluginAction::from(0), PluginAction::Continue);
        assert_eq!(PluginAction::from(1), PluginAction::Pause);
        assert_eq!(PluginAction::from(2), PluginAction::Stop);
        assert_eq!(PluginAction::from(99), PluginAction::Error);
    }

    #[test]
    fn test_plugin_context() {
        let mut ctx = PluginContext::new();

        ctx.set_header("Content-Type".to_string(), "application/json".to_string());
        assert_eq!(ctx.get_header("Content-Type"), Some("application/json"));

        ctx.set_property("method".to_string(), "GET".to_string());
        assert_eq!(ctx.get_property("method"), Some("GET"));

        ctx.log(LogLevel::Info, "Test message".to_string());
        assert_eq!(ctx.logs.len(), 1);
        assert_eq!(ctx.logs[0].0, LogLevel::Info);
    }

    #[test]
    fn test_plugin_manager_disabled() {
        let config = PluginConfig::default();
        let manager = PluginManager::new(config);
        manager.load_plugins().unwrap();
        assert_eq!(manager.plugin_count(), 0);
    }

    #[test]
    fn test_plugin_manager_with_plugins() {
        let mut config = PluginConfig::default();
        config.enabled = true;
        config.plugins.insert(
            "test-plugin".to_string(),
            PluginInstanceConfig {
                path: PathBuf::from("test.wasm"),
                enabled: true,
                priority: 0,
                phases: PluginPhases::default(),
                config: HashMap::new(),
            },
        );

        let manager = PluginManager::new(config);
        manager.load_plugins().unwrap();
        assert_eq!(manager.plugin_count(), 1);
        assert_eq!(manager.plugin_names(), vec!["test-plugin"]);
    }

    #[test]
    fn test_mock_runtime_request_headers() {
        let mut config_map = HashMap::new();
        config_map.insert(
            "add_headers".to_string(),
            serde_json::json!({
                "X-Custom": "value"
            }),
        );

        let runtime = MockPluginRuntime::new("test".to_string(), config_map);
        let mut ctx = PluginContext::new();

        let action = runtime.on_request_headers(&mut ctx).unwrap();
        assert_eq!(action, PluginAction::Continue);
        assert_eq!(ctx.get_header("X-Custom"), Some("value"));
        assert!(ctx.logs.len() > 0);
    }

    #[test]
    fn test_mock_runtime_response_headers() {
        let mut config_map = HashMap::new();
        config_map.insert(
            "add_response_headers".to_string(),
            serde_json::json!({
                "X-Response-Custom": "response-value"
            }),
        );

        let runtime = MockPluginRuntime::new("test".to_string(), config_map);
        let mut ctx = PluginContext::new();

        let action = runtime.on_response_headers(&mut ctx).unwrap();
        assert_eq!(action, PluginAction::Continue);
        assert_eq!(
            ctx.get_response_header("X-Response-Custom"),
            Some("response-value")
        );
        assert!(ctx.response_modified);
    }

    #[test]
    fn test_plugin_phases_default() {
        let phases = PluginPhases::default();
        assert!(phases.on_request_headers);
        assert!(!phases.on_request_body);
        assert!(phases.on_response_headers);
        assert!(!phases.on_response_body);
    }

    #[test]
    fn test_plugin_execution_chain() {
        let mut config = PluginConfig::default();
        config.enabled = true;

        // Add two plugins with different priorities
        config.plugins.insert(
            "plugin-b".to_string(),
            PluginInstanceConfig {
                path: PathBuf::from("b.wasm"),
                enabled: true,
                priority: 10, // Lower priority (runs second)
                phases: PluginPhases::default(),
                config: HashMap::new(),
            },
        );
        config.plugins.insert(
            "plugin-a".to_string(),
            PluginInstanceConfig {
                path: PathBuf::from("a.wasm"),
                enabled: true,
                priority: 5, // Higher priority (runs first)
                phases: PluginPhases::default(),
                config: HashMap::new(),
            },
        );

        let manager = PluginManager::new(config);
        manager.load_plugins().unwrap();

        // Plugins should be sorted by priority
        let names = manager.plugin_names();
        assert_eq!(names[0], "plugin-a");
        assert_eq!(names[1], "plugin-b");

        // Execute and verify all plugins run
        let mut ctx = PluginContext::new();
        let action = manager.execute_request_headers(&mut ctx).unwrap();
        assert_eq!(action, PluginAction::Continue);
        assert!(ctx.get_header("X-Plugin-plugin-a").is_some());
        assert!(ctx.get_header("X-Plugin-plugin-b").is_some());
    }

    #[test]
    fn test_log_level_from_i32() {
        assert_eq!(LogLevel::from(0), LogLevel::Trace);
        assert_eq!(LogLevel::from(1), LogLevel::Debug);
        assert_eq!(LogLevel::from(2), LogLevel::Info);
        assert_eq!(LogLevel::from(3), LogLevel::Warn);
        assert_eq!(LogLevel::from(4), LogLevel::Error);
        assert_eq!(LogLevel::from(100), LogLevel::Error);
    }

    #[test]
    fn test_context_builder_pattern() {
        let ctx = PluginContext::new()
            .with_request_headers([
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Accept".to_string(), "*/*".to_string()),
            ])
            .with_properties([
                ("method".to_string(), "POST".to_string()),
                ("path".to_string(), "/api/users".to_string()),
            ]);

        assert_eq!(ctx.get_header("Content-Type"), Some("application/json"));
        assert_eq!(ctx.get_property("method"), Some("POST"));
    }
}
