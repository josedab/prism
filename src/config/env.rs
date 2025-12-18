//! Environment variable interpolation for configuration files
//!
//! Supports the following syntax:
//! - `${VAR}` - Required variable, fails if not set
//! - `${VAR:-default}` - Variable with default value if not set
//! - `${VAR:?error message}` - Required variable with custom error message
//! - `$VAR` - Simple variable reference (no braces)

use crate::error::{PrismError, Result};
use regex::{Captures, Regex};
use std::borrow::Cow;
use std::env;
use std::sync::LazyLock;

/// Regex patterns for environment variable syntax
static ENV_VAR_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Matches ${VAR}, ${VAR:-default}, ${VAR:?error}
    Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:[-?])([^}]*))?\}").unwrap()
});

static SIMPLE_VAR_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Matches $VAR (simple form, no braces)
    Regex::new(r"\$([A-Za-z_][A-Za-z0-9_]*)").unwrap()
});

/// Configuration for environment variable expansion
#[derive(Debug, Clone)]
pub struct EnvExpandConfig {
    /// Whether to fail on missing required variables
    pub fail_on_missing: bool,
    /// Whether to expand simple $VAR syntax (in addition to ${VAR})
    pub expand_simple: bool,
    /// Custom environment source (for testing)
    pub env_source: Option<std::collections::HashMap<String, String>>,
}

impl Default for EnvExpandConfig {
    fn default() -> Self {
        Self {
            fail_on_missing: true,
            expand_simple: true,
            env_source: None,
        }
    }
}

impl EnvExpandConfig {
    /// Create config that doesn't fail on missing variables
    pub fn lenient() -> Self {
        Self {
            fail_on_missing: false,
            ..Default::default()
        }
    }
}

/// Environment variable expander
pub struct EnvExpander {
    config: EnvExpandConfig,
}

impl Default for EnvExpander {
    fn default() -> Self {
        Self::new(EnvExpandConfig::default())
    }
}

impl EnvExpander {
    /// Create a new environment expander
    pub fn new(config: EnvExpandConfig) -> Self {
        Self { config }
    }

    /// Get an environment variable value
    fn get_env(&self, name: &str) -> Option<String> {
        if let Some(ref source) = self.config.env_source {
            source.get(name).cloned()
        } else {
            env::var(name).ok()
        }
    }

    /// Expand environment variables in a string
    pub fn expand(&self, input: &str) -> Result<String> {
        let mut result = Cow::Borrowed(input);
        let mut errors: Vec<String> = Vec::new();

        // First pass: expand ${VAR} syntax
        let expanded = ENV_VAR_PATTERN.replace_all(&result, |caps: &Captures| {
            let var_name = &caps[1];
            let modifier = caps.get(2).map(|m| m.as_str());
            let modifier_value = caps.get(3).map(|m| m.as_str()).unwrap_or("");

            match self.get_env(var_name) {
                Some(value) => value,
                None => match modifier {
                    Some(":-") => modifier_value.to_string(),
                    Some(":?") => {
                        let error_msg = if modifier_value.is_empty() {
                            format!("Required environment variable '{}' is not set", var_name)
                        } else {
                            modifier_value.to_string()
                        };
                        errors.push(error_msg);
                        String::new()
                    }
                    _ => {
                        if self.config.fail_on_missing {
                            errors.push(format!("Environment variable '{}' is not set", var_name));
                        }
                        String::new()
                    }
                },
            }
        });

        result = Cow::Owned(expanded.into_owned());

        // Second pass: expand simple $VAR syntax if enabled
        if self.config.expand_simple {
            let expanded = SIMPLE_VAR_PATTERN.replace_all(&result, |caps: &Captures| {
                let var_name = &caps[1];
                match self.get_env(var_name) {
                    Some(value) => value,
                    None => {
                        if self.config.fail_on_missing {
                            errors.push(format!("Environment variable '{}' is not set", var_name));
                        }
                        String::new()
                    }
                }
            });
            result = Cow::Owned(expanded.into_owned());
        }

        if !errors.is_empty() {
            return Err(PrismError::Config(format!(
                "Environment variable errors:\n  - {}",
                errors.join("\n  - ")
            )));
        }

        Ok(result.into_owned())
    }

    /// Expand with a fallback value for all missing variables
    pub fn expand_with_fallback(&self, input: &str, fallback: &str) -> String {
        let mut result = input.to_string();

        // Expand ${VAR} syntax
        result = ENV_VAR_PATTERN
            .replace_all(&result, |caps: &Captures| {
                let var_name = &caps[1];
                let modifier = caps.get(2).map(|m| m.as_str());
                let modifier_value = caps.get(3).map(|m| m.as_str()).unwrap_or("");

                match self.get_env(var_name) {
                    Some(value) => value,
                    None => match modifier {
                        Some(":-") => modifier_value.to_string(),
                        _ => fallback.to_string(),
                    },
                }
            })
            .into_owned();

        // Expand simple $VAR syntax if enabled
        if self.config.expand_simple {
            result = SIMPLE_VAR_PATTERN
                .replace_all(&result, |caps: &Captures| {
                    let var_name = &caps[1];
                    self.get_env(var_name)
                        .unwrap_or_else(|| fallback.to_string())
                })
                .into_owned();
        }

        result
    }
}

/// Expand environment variables in a config string using default settings
pub fn expand_env_vars(input: &str) -> Result<String> {
    EnvExpander::default().expand(input)
}

/// Expand environment variables with lenient settings (no failure on missing)
pub fn expand_env_vars_lenient(input: &str) -> String {
    EnvExpander::new(EnvExpandConfig::lenient())
        .expand(input)
        .unwrap_or_else(|_| input.to_string())
}

/// Check if a string contains environment variable references
pub fn contains_env_vars(input: &str) -> bool {
    ENV_VAR_PATTERN.is_match(input) || SIMPLE_VAR_PATTERN.is_match(input)
}

/// List all environment variable references in a string
pub fn list_env_vars(input: &str) -> Vec<String> {
    let mut vars = Vec::new();

    for caps in ENV_VAR_PATTERN.captures_iter(input) {
        vars.push(caps[1].to_string());
    }

    for caps in SIMPLE_VAR_PATTERN.captures_iter(input) {
        let var = caps[1].to_string();
        if !vars.contains(&var) {
            vars.push(var);
        }
    }

    vars
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn expander_with_env(vars: &[(&str, &str)]) -> EnvExpander {
        let source: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        EnvExpander::new(EnvExpandConfig {
            env_source: Some(source),
            ..Default::default()
        })
    }

    #[test]
    fn test_simple_expansion() {
        let expander = expander_with_env(&[("MY_VAR", "hello")]);
        assert_eq!(expander.expand("${MY_VAR}").unwrap(), "hello");
        assert_eq!(expander.expand("$MY_VAR").unwrap(), "hello");
    }

    #[test]
    fn test_default_value() {
        let expander = expander_with_env(&[]);
        assert_eq!(expander.expand("${MISSING:-default}").unwrap(), "default");
    }

    #[test]
    fn test_default_with_set_var() {
        let expander = expander_with_env(&[("VAR", "actual")]);
        assert_eq!(expander.expand("${VAR:-default}").unwrap(), "actual");
    }

    #[test]
    fn test_required_error() {
        let expander = expander_with_env(&[]);
        let result = expander.expand("${REQUIRED:?This is required}");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("This is required"));
    }

    #[test]
    fn test_missing_required() {
        let expander = expander_with_env(&[]);
        let result = expander.expand("${MISSING}");
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_vars() {
        let expander = expander_with_env(&[("HOST", "localhost"), ("PORT", "8080")]);
        assert_eq!(
            expander.expand("http://${HOST}:${PORT}/api").unwrap(),
            "http://localhost:8080/api"
        );
    }

    #[test]
    fn test_no_vars() {
        let expander = expander_with_env(&[]);
        assert_eq!(
            expander.expand("no variables here").unwrap(),
            "no variables here"
        );
    }

    #[test]
    fn test_yaml_config_expansion() {
        let expander = expander_with_env(&[
            ("LISTEN_PORT", "8080"),
            ("BACKEND_HOST", "api.example.com"),
            ("BACKEND_PORT", "3000"),
        ]);

        let input = r#"
listeners:
  - address: "0.0.0.0:${LISTEN_PORT}"

upstreams:
  backend:
    servers:
      - address: "${BACKEND_HOST}:${BACKEND_PORT}"
"#;

        let result = expander.expand(input).unwrap();
        assert!(result.contains("0.0.0.0:8080"));
        assert!(result.contains("api.example.com:3000"));
    }

    #[test]
    fn test_partial_expansion_with_defaults() {
        let expander = expander_with_env(&[("SET_VAR", "value")]);
        let result = expander
            .expand("${SET_VAR} and ${UNSET:-fallback}")
            .unwrap();
        assert_eq!(result, "value and fallback");
    }

    #[test]
    fn test_contains_env_vars() {
        assert!(contains_env_vars("${VAR}"));
        assert!(contains_env_vars("$VAR"));
        assert!(contains_env_vars("prefix ${VAR} suffix"));
        assert!(!contains_env_vars("no variables"));
        assert!(!contains_env_vars("$123invalid")); // must start with letter/underscore
    }

    #[test]
    fn test_list_env_vars() {
        let vars = list_env_vars("${VAR1} $VAR2 ${VAR3:-default}");
        assert!(vars.contains(&"VAR1".to_string()));
        assert!(vars.contains(&"VAR2".to_string()));
        assert!(vars.contains(&"VAR3".to_string()));
    }

    #[test]
    fn test_nested_braces() {
        // Ensure we handle edge cases
        let expander = expander_with_env(&[("VAR", "value")]);
        assert_eq!(
            expander.expand("before ${VAR} after").unwrap(),
            "before value after"
        );
    }

    #[test]
    fn test_empty_default() {
        let expander = expander_with_env(&[]);
        assert_eq!(expander.expand("${MISSING:-}").unwrap(), "");
    }

    #[test]
    fn test_lenient_mode() {
        let expander = EnvExpander::new(EnvExpandConfig {
            fail_on_missing: false,
            env_source: Some(HashMap::new()),
            ..Default::default()
        });
        // Should not fail, just leave empty
        assert_eq!(expander.expand("${MISSING}").unwrap(), "");
    }

    #[test]
    fn test_expand_with_fallback() {
        let expander = expander_with_env(&[("SET", "actual")]);
        let result = expander.expand_with_fallback("${SET} ${UNSET}", "FALLBACK");
        assert_eq!(result, "actual FALLBACK");
    }
}
