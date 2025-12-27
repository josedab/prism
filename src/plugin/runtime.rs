//! WASM Plugin Runtime
//!
//! Provides the runtime environment for executing WASM plugins.
//! This module defines the host functions exposed to plugins and
//! manages the plugin lifecycle.
//!
//! # Note
//! The actual WASM runtime (wasmtime) integration is optional.
//! This module provides the interface and a mock implementation
//! for testing without the WASM dependency.

use super::types::*;
use super::{LogLevel, PluginAction, PluginContext};
use crate::error::Result;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Runtime statistics
#[derive(Debug, Clone, Default)]
pub struct RuntimeStats {
    /// Total invocations
    pub invocations: u64,
    /// Total execution time
    pub total_execution_time: Duration,
    /// Average execution time
    pub avg_execution_time: Duration,
    /// Maximum execution time
    pub max_execution_time: Duration,
    /// Error count
    pub errors: u64,
}

/// Memory limiter for plugin sandboxing
#[derive(Debug)]
pub struct MemoryLimiter {
    /// Maximum allowed memory
    max_bytes: usize,
    /// Current allocated memory
    current_bytes: usize,
}

impl MemoryLimiter {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            current_bytes: 0,
        }
    }

    /// Try to allocate memory
    pub fn try_alloc(&mut self, bytes: usize) -> bool {
        if self.current_bytes + bytes > self.max_bytes {
            return false;
        }
        self.current_bytes += bytes;
        true
    }

    /// Free memory
    pub fn free(&mut self, bytes: usize) {
        self.current_bytes = self.current_bytes.saturating_sub(bytes);
    }

    /// Get current usage
    pub fn current_usage(&self) -> usize {
        self.current_bytes
    }

    /// Get maximum allowed
    pub fn max_allowed(&self) -> usize {
        self.max_bytes
    }
}

/// Execution limiter for time-based sandboxing
#[derive(Debug)]
pub struct ExecutionLimiter {
    /// Maximum execution time
    max_duration: Duration,
    /// Start time of current execution
    start_time: Option<Instant>,
}

impl ExecutionLimiter {
    pub fn new(max_ms: u64) -> Self {
        Self {
            max_duration: Duration::from_millis(max_ms),
            start_time: None,
        }
    }

    /// Start tracking execution
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }

    /// Check if execution has exceeded limit
    pub fn check(&self) -> bool {
        if let Some(start) = self.start_time {
            return start.elapsed() < self.max_duration;
        }
        true
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.map(|s| s.elapsed()).unwrap_or_default()
    }

    /// Stop tracking
    pub fn stop(&mut self) -> Duration {
        let elapsed = self.elapsed();
        self.start_time = None;
        elapsed
    }
}

/// Host function call context
pub struct HostCallContext<'a> {
    /// Plugin context reference
    pub ctx: &'a mut PluginContext,
    /// Memory limiter
    pub memory: &'a mut MemoryLimiter,
    /// Plugin configuration
    pub config: &'a HashMap<String, serde_json::Value>,
}

impl<'a> HostCallContext<'a> {
    /// Handle get_request_header host call
    pub fn get_request_header(&self, name: &str) -> Option<String> {
        self.ctx.request_headers.get(name).cloned()
    }

    /// Handle set_request_header host call
    pub fn set_request_header(&mut self, name: &str, value: &str) -> PluginError {
        self.ctx
            .request_headers
            .insert(name.to_string(), value.to_string());
        PluginError::Ok
    }

    /// Handle remove_request_header host call
    pub fn remove_request_header(&mut self, name: &str) -> PluginError {
        self.ctx.request_headers.remove(name);
        PluginError::Ok
    }

    /// Handle get_response_header host call
    pub fn get_response_header(&self, name: &str) -> Option<String> {
        self.ctx.response_headers.get(name).cloned()
    }

    /// Handle set_response_header host call
    pub fn set_response_header(&mut self, name: &str, value: &str) -> PluginError {
        self.ctx
            .response_headers
            .insert(name.to_string(), value.to_string());
        self.ctx.response_modified = true;
        PluginError::Ok
    }

    /// Handle get_property host call
    pub fn get_property(&self, name: &str) -> Option<String> {
        self.ctx.properties.get(name).cloned()
    }

    /// Handle set_property host call
    pub fn set_property(&mut self, name: &str, value: &str) -> PluginError {
        self.ctx
            .properties
            .insert(name.to_string(), value.to_string());
        PluginError::Ok
    }

    /// Handle log host call
    pub fn log(&mut self, level: LogLevel, message: &str) {
        self.ctx.logs.push((level, message.to_string()));
    }

    /// Handle get_plugin_config host call
    pub fn get_plugin_config(&self) -> Vec<u8> {
        serde_json::to_vec(self.config).unwrap_or_default()
    }

    /// Handle get_request_body host call
    pub fn get_request_body(&self) -> Option<&[u8]> {
        self.ctx.request_body.as_deref()
    }

    /// Handle set_request_body host call
    pub fn set_request_body(&mut self, body: Vec<u8>) -> PluginError {
        if !self.memory.try_alloc(body.len()) {
            return PluginError::ResourceExhausted;
        }
        self.ctx.request_body = Some(body);
        PluginError::Ok
    }

    /// Handle get_response_body host call
    pub fn get_response_body(&self) -> Option<&[u8]> {
        self.ctx.response_body.as_deref()
    }

    /// Handle set_response_body host call
    pub fn set_response_body(&mut self, body: Vec<u8>) -> PluginError {
        if !self.memory.try_alloc(body.len()) {
            return PluginError::ResourceExhausted;
        }
        self.ctx.response_body = Some(body);
        self.ctx.response_modified = true;
        PluginError::Ok
    }

    /// Handle get_shared_data host call
    pub fn get_shared_data(&self, key: &str) -> Option<Vec<u8>> {
        self.ctx.storage.get(key).cloned()
    }

    /// Handle set_shared_data host call
    pub fn set_shared_data(&mut self, key: &str, value: Vec<u8>) -> PluginError {
        if !self.memory.try_alloc(value.len()) {
            return PluginError::ResourceExhausted;
        }
        self.ctx.storage.insert(key.to_string(), value);
        PluginError::Ok
    }
}

/// Shared runtime state between plugin instances
pub struct SharedRuntimeState {
    /// Global shared data
    pub shared_data: Mutex<HashMap<String, Vec<u8>>>,
    /// Runtime statistics per plugin
    pub stats: Mutex<HashMap<String, RuntimeStats>>,
}

impl SharedRuntimeState {
    pub fn new() -> Self {
        Self {
            shared_data: Mutex::new(HashMap::new()),
            stats: Mutex::new(HashMap::new()),
        }
    }

    /// Get shared data
    pub fn get_shared(&self, key: &str) -> Option<Vec<u8>> {
        self.shared_data.lock().get(key).cloned()
    }

    /// Set shared data
    pub fn set_shared(&self, key: &str, value: Vec<u8>) {
        self.shared_data.lock().insert(key.to_string(), value);
    }

    /// Record execution
    pub fn record_execution(&self, plugin_name: &str, duration: Duration, is_error: bool) {
        let mut stats = self.stats.lock();
        let entry = stats.entry(plugin_name.to_string()).or_default();

        entry.invocations += 1;
        entry.total_execution_time += duration;

        if duration > entry.max_execution_time {
            entry.max_execution_time = duration;
        }

        if entry.invocations > 0 {
            entry.avg_execution_time = entry.total_execution_time / entry.invocations as u32;
        }

        if is_error {
            entry.errors += 1;
        }
    }

    /// Get stats for a plugin
    pub fn get_stats(&self, plugin_name: &str) -> Option<RuntimeStats> {
        self.stats.lock().get(plugin_name).cloned()
    }
}

impl Default for SharedRuntimeState {
    fn default() -> Self {
        Self::new()
    }
}

/// Script-based plugin runtime (for JavaScript-like configuration)
///
/// This provides a simpler alternative to full WASM plugins for common
/// use cases like header manipulation.
pub struct ScriptRuntime {
    /// Plugin name
    pub name: String,
    /// Configuration
    config: HashMap<String, serde_json::Value>,
    /// Shared state
    shared: Arc<SharedRuntimeState>,
    /// Memory limiter
    memory: Mutex<MemoryLimiter>,
    /// Execution limiter
    execution: Mutex<ExecutionLimiter>,
}

impl ScriptRuntime {
    pub fn new(
        name: String,
        config: HashMap<String, serde_json::Value>,
        shared: Arc<SharedRuntimeState>,
        max_memory: usize,
        max_execution_ms: u64,
    ) -> Self {
        Self {
            name,
            config,
            shared,
            memory: Mutex::new(MemoryLimiter::new(max_memory)),
            execution: Mutex::new(ExecutionLimiter::new(max_execution_ms)),
        }
    }

    /// Execute header transformation rules
    pub fn execute_header_rules(
        &self,
        ctx: &mut PluginContext,
        phase: &str,
    ) -> Result<PluginAction> {
        let rules_key = format!("{}_header_rules", phase);

        if let Some(serde_json::Value::Array(rules)) = self.config.get(&rules_key) {
            for rule in rules {
                if let serde_json::Value::Object(rule_obj) = rule {
                    self.apply_header_rule(ctx, rule_obj)?;
                }
            }
        }

        Ok(PluginAction::Continue)
    }

    fn apply_header_rule(
        &self,
        ctx: &mut PluginContext,
        rule: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<()> {
        let action = rule.get("action").and_then(|v| v.as_str()).unwrap_or("set");
        let header = rule.get("header").and_then(|v| v.as_str()).unwrap_or("");
        let value = rule.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let target = rule
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("request");

        match (action, target) {
            ("set", "request") => {
                ctx.request_headers
                    .insert(header.to_string(), value.to_string());
            }
            ("set", "response") => {
                ctx.response_headers
                    .insert(header.to_string(), value.to_string());
                ctx.response_modified = true;
            }
            ("remove", "request") => {
                ctx.request_headers.remove(header);
            }
            ("remove", "response") => {
                ctx.response_headers.remove(header);
                ctx.response_modified = true;
            }
            ("copy", _) => {
                // Copy from one header to another
                let from = rule.get("from").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(val) = ctx.request_headers.get(from).cloned() {
                    ctx.request_headers.insert(header.to_string(), val);
                }
            }
            _ => {}
        }

        Ok(())
    }
}

/// Compiled plugin representation (placeholder for actual WASM compilation)
pub struct CompiledPlugin {
    /// Plugin name
    pub name: String,
    /// Plugin bytes (WASM module)
    #[allow(dead_code)]
    pub module_bytes: Vec<u8>,
    /// Exported functions
    pub exports: Vec<String>,
    /// Required imports
    pub imports: Vec<String>,
    /// Compilation time
    pub compiled_at: Instant,
}

impl CompiledPlugin {
    /// Create a mock compiled plugin
    pub fn mock(name: &str) -> Self {
        Self {
            name: name.to_string(),
            module_bytes: Vec::new(),
            exports: vec![
                "on_request_headers".to_string(),
                "on_request_body".to_string(),
                "on_response_headers".to_string(),
                "on_response_body".to_string(),
            ],
            imports: vec![
                "get_header".to_string(),
                "set_header".to_string(),
                "log".to_string(),
            ],
            compiled_at: Instant::now(),
        }
    }

    /// Check if the plugin exports a function
    pub fn has_export(&self, name: &str) -> bool {
        self.exports.iter().any(|e| e == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_limiter() {
        let mut limiter = MemoryLimiter::new(1000);

        assert!(limiter.try_alloc(500));
        assert_eq!(limiter.current_usage(), 500);

        assert!(limiter.try_alloc(400));
        assert_eq!(limiter.current_usage(), 900);

        assert!(!limiter.try_alloc(200)); // Would exceed
        assert_eq!(limiter.current_usage(), 900);

        limiter.free(500);
        assert_eq!(limiter.current_usage(), 400);
    }

    #[test]
    fn test_execution_limiter() {
        let mut limiter = ExecutionLimiter::new(1000);

        limiter.start();
        assert!(limiter.check());

        std::thread::sleep(Duration::from_millis(10));
        let elapsed = limiter.stop();
        assert!(elapsed >= Duration::from_millis(10));
    }

    #[test]
    fn test_host_call_context() {
        let mut ctx = PluginContext::new();
        let mut memory = MemoryLimiter::new(1024);
        let config = HashMap::new();

        {
            let mut host_ctx = HostCallContext {
                ctx: &mut ctx,
                memory: &mut memory,
                config: &config,
            };

            host_ctx.set_request_header("X-Test", "value");
            assert_eq!(
                host_ctx.get_request_header("X-Test"),
                Some("value".to_string())
            );

            host_ctx.set_property("path", "/api");
            assert_eq!(host_ctx.get_property("path"), Some("/api".to_string()));

            host_ctx.log(LogLevel::Info, "test message");
        }

        assert_eq!(ctx.logs.len(), 1);
    }

    #[test]
    fn test_shared_runtime_state() {
        let state = SharedRuntimeState::new();

        state.set_shared("key1", vec![1, 2, 3]);
        assert_eq!(state.get_shared("key1"), Some(vec![1, 2, 3]));
        assert_eq!(state.get_shared("key2"), None);

        state.record_execution("plugin1", Duration::from_millis(10), false);
        state.record_execution("plugin1", Duration::from_millis(20), false);

        let stats = state.get_stats("plugin1").unwrap();
        assert_eq!(stats.invocations, 2);
        assert_eq!(stats.max_execution_time, Duration::from_millis(20));
    }

    #[test]
    fn test_script_runtime_header_rules() {
        let mut config = HashMap::new();
        config.insert(
            "request_header_rules".to_string(),
            serde_json::json!([
                {
                    "action": "set",
                    "header": "X-Added",
                    "value": "test-value",
                    "target": "request"
                }
            ]),
        );

        let shared = Arc::new(SharedRuntimeState::new());
        let runtime = ScriptRuntime::new("test".to_string(), config, shared, 1024 * 1024, 100);

        let mut ctx = PluginContext::new();
        let action = runtime.execute_header_rules(&mut ctx, "request").unwrap();

        assert_eq!(action, PluginAction::Continue);
        assert_eq!(
            ctx.request_headers.get("X-Added"),
            Some(&"test-value".to_string())
        );
    }

    #[test]
    fn test_compiled_plugin_mock() {
        let plugin = CompiledPlugin::mock("test-plugin");

        assert_eq!(plugin.name, "test-plugin");
        assert!(plugin.has_export("on_request_headers"));
        assert!(!plugin.has_export("unknown_function"));
    }

    #[test]
    fn test_runtime_stats_default() {
        let stats = RuntimeStats::default();
        assert_eq!(stats.invocations, 0);
        assert_eq!(stats.errors, 0);
    }
}
