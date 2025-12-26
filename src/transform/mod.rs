//! Request/Response Transformation Module
//!
//! Provides powerful request and response transformation capabilities:
//! - Header manipulation
//! - Body transformation (JSON/XML/etc)
//! - URL rewriting
//! - JSONPath/XPath transformations
//! - Template-based transformations

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Transformation configuration
#[derive(Debug, Clone)]
pub struct TransformConfig {
    /// Enable request transformations
    pub transform_requests: bool,
    /// Enable response transformations
    pub transform_responses: bool,
    /// Maximum body size to transform
    pub max_body_size: usize,
    /// Enable caching of compiled transformations
    pub cache_transformations: bool,
}

impl Default for TransformConfig {
    fn default() -> Self {
        Self {
            transform_requests: true,
            transform_responses: true,
            max_body_size: 10 * 1024 * 1024, // 10MB
            cache_transformations: true,
        }
    }
}

/// Transformation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformRule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// Match conditions
    pub conditions: Vec<MatchCondition>,
    /// Transformations to apply
    pub transformations: Vec<Transformation>,
    /// Priority (higher = first)
    pub priority: i32,
    pub enabled: bool,
}

/// Condition for matching requests/responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCondition {
    pub field: MatchField,
    pub operator: MatchOperator,
    pub value: String,
}

/// Fields that can be matched
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchField {
    Path,
    Method,
    Header(String),
    QueryParam(String),
    StatusCode,
    ContentType,
    BodyJsonPath(String),
}

/// Match operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchOperator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
    Matches, // Regex
    Exists,
    NotExists,
}

/// Transformation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Transformation {
    /// Set header value
    SetHeader { name: String, value: String },
    /// Remove header
    RemoveHeader { name: String },
    /// Rename header
    RenameHeader { from: String, to: String },
    /// Add query parameter
    AddQueryParam { name: String, value: String },
    /// Remove query parameter
    RemoveQueryParam { name: String },
    /// Rewrite path
    RewritePath {
        pattern: String,
        replacement: String,
    },
    /// Set JSON body field
    SetJsonField { path: String, value: Value },
    /// Remove JSON body field
    RemoveJsonField { path: String },
    /// Rename JSON body field
    RenameJsonField { from: String, to: String },
    /// Map JSON field value
    MapJsonField {
        path: String,
        mappings: HashMap<String, Value>,
    },
    /// Transform JSON with template
    JsonTemplate { template: String },
    /// Set response status code
    SetStatusCode { code: u16 },
    /// Add response body wrapper
    WrapBody { wrapper: String },
    /// Filter JSON array
    FilterJsonArray { path: String, condition: String },
    /// Sort JSON array
    SortJsonArray {
        path: String,
        by: String,
        descending: bool,
    },
    /// Aggregate JSON values
    AggregateJson {
        path: String,
        operation: AggregateOp,
    },
}

/// Aggregation operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregateOp {
    Count,
    Sum,
    Average,
    Min,
    Max,
    Concat,
}

/// Request to transform
#[derive(Debug, Clone)]
pub struct TransformableRequest {
    pub method: String,
    pub path: String,
    pub query_params: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Option<Bytes>,
    pub content_type: Option<String>,
}

/// Response to transform
#[derive(Debug, Clone)]
pub struct TransformableResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<Bytes>,
    pub content_type: Option<String>,
}

/// Transformation result
#[derive(Debug, Clone)]
pub struct TransformResult<T> {
    pub data: T,
    pub applied_rules: Vec<String>,
    pub transformations_applied: u32,
}

/// Transformation engine
pub struct TransformEngine {
    config: TransformConfig,
    request_rules: RwLock<Vec<Arc<TransformRule>>>,
    response_rules: RwLock<Vec<Arc<TransformRule>>>,
    compiled_patterns: DashMap<String, regex::Regex>,
    stats: TransformStats,
}

/// Transformation statistics
#[derive(Debug, Default)]
pub struct TransformStats {
    pub requests_transformed: AtomicU64,
    pub responses_transformed: AtomicU64,
    pub transformations_applied: AtomicU64,
    pub transform_errors: AtomicU64,
    pub rules_matched: AtomicU64,
}

impl TransformEngine {
    pub fn new(config: TransformConfig) -> Self {
        Self {
            config,
            request_rules: RwLock::new(Vec::new()),
            response_rules: RwLock::new(Vec::new()),
            compiled_patterns: DashMap::new(),
            stats: TransformStats::default(),
        }
    }

    /// Add a request transformation rule
    pub fn add_request_rule(&self, rule: TransformRule) {
        let mut rules = self.request_rules.write();
        rules.push(Arc::new(rule));
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Add a response transformation rule
    pub fn add_response_rule(&self, rule: TransformRule) {
        let mut rules = self.response_rules.write();
        rules.push(Arc::new(rule));
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Transform a request
    pub fn transform_request(
        &self,
        mut request: TransformableRequest,
    ) -> TransformResult<TransformableRequest> {
        if !self.config.transform_requests {
            return TransformResult {
                data: request,
                applied_rules: Vec::new(),
                transformations_applied: 0,
            };
        }

        let rules = self.request_rules.read().clone();
        let mut applied_rules = Vec::new();
        let mut transformations_applied = 0;

        for rule in rules {
            if !rule.enabled {
                continue;
            }

            if self.matches_request(&request, &rule.conditions) {
                self.stats.rules_matched.fetch_add(1, Ordering::Relaxed);
                applied_rules.push(rule.id.clone());

                for transformation in &rule.transformations {
                    if let Ok(transformed) =
                        self.apply_request_transformation(&request, transformation)
                    {
                        request = transformed;
                        transformations_applied += 1;
                        self.stats
                            .transformations_applied
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        if transformations_applied > 0 {
            self.stats
                .requests_transformed
                .fetch_add(1, Ordering::Relaxed);
        }

        TransformResult {
            data: request,
            applied_rules,
            transformations_applied,
        }
    }

    /// Transform a response
    pub fn transform_response(
        &self,
        mut response: TransformableResponse,
        request: &TransformableRequest,
    ) -> TransformResult<TransformableResponse> {
        if !self.config.transform_responses {
            return TransformResult {
                data: response,
                applied_rules: Vec::new(),
                transformations_applied: 0,
            };
        }

        let rules = self.response_rules.read().clone();
        let mut applied_rules = Vec::new();
        let mut transformations_applied = 0;

        for rule in rules {
            if !rule.enabled {
                continue;
            }

            if self.matches_response(&response, request, &rule.conditions) {
                self.stats.rules_matched.fetch_add(1, Ordering::Relaxed);
                applied_rules.push(rule.id.clone());

                for transformation in &rule.transformations {
                    if let Ok(transformed) =
                        self.apply_response_transformation(&response, transformation)
                    {
                        response = transformed;
                        transformations_applied += 1;
                        self.stats
                            .transformations_applied
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        if transformations_applied > 0 {
            self.stats
                .responses_transformed
                .fetch_add(1, Ordering::Relaxed);
        }

        TransformResult {
            data: response,
            applied_rules,
            transformations_applied,
        }
    }

    fn matches_request(
        &self,
        request: &TransformableRequest,
        conditions: &[MatchCondition],
    ) -> bool {
        conditions.iter().all(|cond| {
            let value = match &cond.field {
                MatchField::Path => Some(request.path.clone()),
                MatchField::Method => Some(request.method.clone()),
                MatchField::Header(name) => request.headers.get(&name.to_lowercase()).cloned(),
                MatchField::QueryParam(name) => request.query_params.get(name).cloned(),
                MatchField::ContentType => request.content_type.clone(),
                MatchField::BodyJsonPath(path) => self.extract_json_path(&request.body, path),
                _ => None,
            };

            self.evaluate_condition(value.as_deref(), &cond.operator, &cond.value)
        })
    }

    fn matches_response(
        &self,
        response: &TransformableResponse,
        request: &TransformableRequest,
        conditions: &[MatchCondition],
    ) -> bool {
        conditions.iter().all(|cond| {
            let value = match &cond.field {
                MatchField::StatusCode => Some(response.status_code.to_string()),
                MatchField::Header(name) => response.headers.get(&name.to_lowercase()).cloned(),
                MatchField::ContentType => response.content_type.clone(),
                MatchField::Path => Some(request.path.clone()),
                MatchField::Method => Some(request.method.clone()),
                MatchField::BodyJsonPath(path) => self.extract_json_path(&response.body, path),
                _ => None,
            };

            self.evaluate_condition(value.as_deref(), &cond.operator, &cond.value)
        })
    }

    fn evaluate_condition(
        &self,
        value: Option<&str>,
        operator: &MatchOperator,
        expected: &str,
    ) -> bool {
        match operator {
            MatchOperator::Exists => value.is_some(),
            MatchOperator::NotExists => value.is_none(),
            MatchOperator::Equals => value.map(|v| v == expected).unwrap_or(false),
            MatchOperator::NotEquals => value.map(|v| v != expected).unwrap_or(true),
            MatchOperator::Contains => value.map(|v| v.contains(expected)).unwrap_or(false),
            MatchOperator::StartsWith => value.map(|v| v.starts_with(expected)).unwrap_or(false),
            MatchOperator::EndsWith => value.map(|v| v.ends_with(expected)).unwrap_or(false),
            MatchOperator::Matches => {
                if let Some(v) = value {
                    let regex = self.get_or_compile_regex(expected);
                    regex.map(|r| r.is_match(v)).unwrap_or(false)
                } else {
                    false
                }
            }
        }
    }

    fn get_or_compile_regex(&self, pattern: &str) -> Option<regex::Regex> {
        if let Some(compiled) = self.compiled_patterns.get(pattern) {
            return Some(compiled.clone());
        }

        if let Ok(regex) = regex::Regex::new(pattern) {
            if self.config.cache_transformations {
                self.compiled_patterns
                    .insert(pattern.to_string(), regex.clone());
            }
            return Some(regex);
        }

        None
    }

    fn extract_json_path(&self, body: &Option<Bytes>, path: &str) -> Option<String> {
        let body = body.as_ref()?;
        let json: Value = serde_json::from_slice(body).ok()?;
        let value = self.get_json_value(&json, path)?;

        match value {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => Some(value.to_string()),
        }
    }

    fn get_json_value<'a>(&self, json: &'a Value, path: &str) -> Option<&'a Value> {
        let mut current = json;
        for part in path.split('.') {
            if part.is_empty() {
                continue;
            }

            // Handle array indexing
            if let Some(bracket_pos) = part.find('[') {
                let field = &part[..bracket_pos];
                let index_str = &part[bracket_pos + 1..part.len() - 1];

                if !field.is_empty() {
                    current = current.get(field)?;
                }

                if let Ok(index) = index_str.parse::<usize>() {
                    current = current.get(index)?;
                }
            } else {
                current = current.get(part)?;
            }
        }

        Some(current)
    }

    fn apply_request_transformation(
        &self,
        request: &TransformableRequest,
        transformation: &Transformation,
    ) -> Result<TransformableRequest, TransformError> {
        let mut result = request.clone();

        match transformation {
            Transformation::SetHeader { name, value } => {
                result.headers.insert(name.to_lowercase(), value.clone());
            }
            Transformation::RemoveHeader { name } => {
                result.headers.remove(&name.to_lowercase());
            }
            Transformation::RenameHeader { from, to } => {
                if let Some(value) = result.headers.remove(&from.to_lowercase()) {
                    result.headers.insert(to.to_lowercase(), value);
                }
            }
            Transformation::AddQueryParam { name, value } => {
                result.query_params.insert(name.clone(), value.clone());
            }
            Transformation::RemoveQueryParam { name } => {
                result.query_params.remove(name);
            }
            Transformation::RewritePath {
                pattern,
                replacement,
            } => {
                if let Some(regex) = self.get_or_compile_regex(pattern) {
                    result.path = regex
                        .replace_all(&result.path, replacement.as_str())
                        .to_string();
                }
            }
            Transformation::SetJsonField { path, value } => {
                result.body = self.set_json_field(&result.body, path, value.clone())?;
            }
            Transformation::RemoveJsonField { path } => {
                result.body = self.remove_json_field(&result.body, path)?;
            }
            Transformation::RenameJsonField { from, to } => {
                result.body = self.rename_json_field(&result.body, from, to)?;
            }
            Transformation::MapJsonField { path, mappings } => {
                result.body = self.map_json_field(&result.body, path, mappings)?;
            }
            Transformation::JsonTemplate { template } => {
                result.body = self.apply_json_template(&result.body, template)?;
            }
            _ => {}
        }

        Ok(result)
    }

    fn apply_response_transformation(
        &self,
        response: &TransformableResponse,
        transformation: &Transformation,
    ) -> Result<TransformableResponse, TransformError> {
        let mut result = response.clone();

        match transformation {
            Transformation::SetHeader { name, value } => {
                result.headers.insert(name.to_lowercase(), value.clone());
            }
            Transformation::RemoveHeader { name } => {
                result.headers.remove(&name.to_lowercase());
            }
            Transformation::RenameHeader { from, to } => {
                if let Some(value) = result.headers.remove(&from.to_lowercase()) {
                    result.headers.insert(to.to_lowercase(), value);
                }
            }
            Transformation::SetStatusCode { code } => {
                result.status_code = *code;
            }
            Transformation::SetJsonField { path, value } => {
                result.body = self.set_json_field(&result.body, path, value.clone())?;
            }
            Transformation::RemoveJsonField { path } => {
                result.body = self.remove_json_field(&result.body, path)?;
            }
            Transformation::WrapBody { wrapper } => {
                result.body = self.wrap_body(&result.body, wrapper)?;
            }
            Transformation::FilterJsonArray { path, condition } => {
                result.body = self.filter_json_array(&result.body, path, condition)?;
            }
            Transformation::SortJsonArray {
                path,
                by,
                descending,
            } => {
                result.body = self.sort_json_array(&result.body, path, by, *descending)?;
            }
            _ => {}
        }

        Ok(result)
    }

    fn set_json_field(
        &self,
        body: &Option<Bytes>,
        path: &str,
        value: Value,
    ) -> Result<Option<Bytes>, TransformError> {
        let body = body.as_ref().ok_or(TransformError::NoBody)?;
        let mut json: Value =
            serde_json::from_slice(body).map_err(|e| TransformError::ParseError(e.to_string()))?;

        self.set_json_value(&mut json, path, value)?;

        Ok(Some(Bytes::from(serde_json::to_vec(&json).unwrap())))
    }

    fn set_json_value(
        &self,
        json: &mut Value,
        path: &str,
        value: Value,
    ) -> Result<(), TransformError> {
        let parts: Vec<&str> = path.split('.').filter(|p| !p.is_empty()).collect();

        if parts.is_empty() {
            return Err(TransformError::InvalidPath(path.to_string()));
        }

        let mut current = json;
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                if let Value::Object(map) = current {
                    map.insert(part.to_string(), value);
                    return Ok(());
                }
            } else {
                if current.get(part).is_none() {
                    if let Value::Object(map) = current {
                        map.insert(part.to_string(), Value::Object(serde_json::Map::new()));
                    }
                }
                current = current
                    .get_mut(part)
                    .ok_or_else(|| TransformError::InvalidPath(path.to_string()))?;
            }
        }

        Ok(())
    }

    fn remove_json_field(
        &self,
        body: &Option<Bytes>,
        path: &str,
    ) -> Result<Option<Bytes>, TransformError> {
        let body = body.as_ref().ok_or(TransformError::NoBody)?;
        let mut json: Value =
            serde_json::from_slice(body).map_err(|e| TransformError::ParseError(e.to_string()))?;

        let parts: Vec<&str> = path.split('.').filter(|p| !p.is_empty()).collect();

        if parts.is_empty() {
            return Ok(Some(Bytes::from(serde_json::to_vec(&json).unwrap())));
        }

        // Navigate to parent and remove the field
        let mut current = &mut json;
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                if let Value::Object(map) = current {
                    map.remove(*part);
                }
            } else {
                current = current
                    .get_mut(part)
                    .ok_or_else(|| TransformError::InvalidPath(path.to_string()))?;
            }
        }

        Ok(Some(Bytes::from(serde_json::to_vec(&json).unwrap())))
    }

    fn rename_json_field(
        &self,
        body: &Option<Bytes>,
        from: &str,
        to: &str,
    ) -> Result<Option<Bytes>, TransformError> {
        let body = body.as_ref().ok_or(TransformError::NoBody)?;
        let mut json: Value =
            serde_json::from_slice(body).map_err(|e| TransformError::ParseError(e.to_string()))?;

        // Get value at 'from' path
        if let Some(value) = self.get_json_value(&json, from).cloned() {
            // Remove from original path
            let _ = self.remove_json_field(&Some(Bytes::copy_from_slice(body)), from)?;
            // Set at new path
            self.set_json_value(&mut json, to, value)?;
        }

        Ok(Some(Bytes::from(serde_json::to_vec(&json).unwrap())))
    }

    fn map_json_field(
        &self,
        body: &Option<Bytes>,
        path: &str,
        mappings: &HashMap<String, Value>,
    ) -> Result<Option<Bytes>, TransformError> {
        let body = body.as_ref().ok_or(TransformError::NoBody)?;
        let mut json: Value =
            serde_json::from_slice(body).map_err(|e| TransformError::ParseError(e.to_string()))?;

        if let Some(current_value) = self.get_json_value(&json, path) {
            let key = match current_value {
                Value::String(s) => s.clone(),
                _ => current_value.to_string(),
            };

            if let Some(mapped_value) = mappings.get(&key) {
                self.set_json_value(&mut json, path, mapped_value.clone())?;
            }
        }

        Ok(Some(Bytes::from(serde_json::to_vec(&json).unwrap())))
    }

    fn apply_json_template(
        &self,
        body: &Option<Bytes>,
        template: &str,
    ) -> Result<Option<Bytes>, TransformError> {
        let body = body.as_ref().ok_or(TransformError::NoBody)?;
        let json: Value =
            serde_json::from_slice(body).map_err(|e| TransformError::ParseError(e.to_string()))?;

        // Simple template replacement: {{path}} -> value
        let re = regex::Regex::new(r"\{\{([^}]+)\}\}").unwrap();
        let result = re.replace_all(template, |caps: &regex::Captures| {
            let path = &caps[1];
            self.get_json_value(&json, path)
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    _ => v.to_string(),
                })
                .unwrap_or_default()
        });

        let new_json: Value =
            serde_json::from_str(&result).map_err(|e| TransformError::ParseError(e.to_string()))?;

        Ok(Some(Bytes::from(serde_json::to_vec(&new_json).unwrap())))
    }

    fn wrap_body(
        &self,
        body: &Option<Bytes>,
        wrapper: &str,
    ) -> Result<Option<Bytes>, TransformError> {
        let body = body.as_ref().ok_or(TransformError::NoBody)?;
        let json: Value =
            serde_json::from_slice(body).map_err(|e| TransformError::ParseError(e.to_string()))?;

        // Parse wrapper template and insert body
        let mut wrapper_json: Value =
            serde_json::from_str(wrapper).map_err(|e| TransformError::ParseError(e.to_string()))?;

        // Find {{body}} placeholder and replace
        fn replace_body_placeholder(value: &mut Value, body: &Value) {
            match value {
                Value::String(s) if s == "{{body}}" => {
                    *value = body.clone();
                }
                Value::Object(map) => {
                    for v in map.values_mut() {
                        replace_body_placeholder(v, body);
                    }
                }
                Value::Array(arr) => {
                    for v in arr.iter_mut() {
                        replace_body_placeholder(v, body);
                    }
                }
                _ => {}
            }
        }

        replace_body_placeholder(&mut wrapper_json, &json);

        Ok(Some(Bytes::from(
            serde_json::to_vec(&wrapper_json).unwrap(),
        )))
    }

    fn filter_json_array(
        &self,
        body: &Option<Bytes>,
        path: &str,
        condition: &str,
    ) -> Result<Option<Bytes>, TransformError> {
        let body = body.as_ref().ok_or(TransformError::NoBody)?;
        let mut json: Value =
            serde_json::from_slice(body).map_err(|e| TransformError::ParseError(e.to_string()))?;

        // Parse condition: "field == value" or "field > value"
        let parts: Vec<&str> = condition.splitn(3, ' ').collect();
        if parts.len() != 3 {
            return Err(TransformError::InvalidCondition(condition.to_string()));
        }

        let field = parts[0];
        let op = parts[1];
        let expected = parts[2].trim_matches('"');

        if let Some(Value::Array(arr)) = self.get_json_value(&json, path).cloned() {
            let filtered: Vec<Value> = arr
                .into_iter()
                .filter(|item| {
                    let value = item.get(field);
                    match (op, value) {
                        ("==", Some(Value::String(s))) => s == expected,
                        ("==", Some(Value::Number(n))) => n.to_string() == expected,
                        ("!=", Some(Value::String(s))) => s != expected,
                        (">", Some(Value::Number(n))) => {
                            n.as_f64().unwrap_or(0.0) > expected.parse().unwrap_or(0.0)
                        }
                        ("<", Some(Value::Number(n))) => {
                            n.as_f64().unwrap_or(0.0) < expected.parse().unwrap_or(0.0)
                        }
                        _ => true,
                    }
                })
                .collect();

            self.set_json_value(&mut json, path, Value::Array(filtered))?;
        }

        Ok(Some(Bytes::from(serde_json::to_vec(&json).unwrap())))
    }

    fn sort_json_array(
        &self,
        body: &Option<Bytes>,
        path: &str,
        by: &str,
        descending: bool,
    ) -> Result<Option<Bytes>, TransformError> {
        let body = body.as_ref().ok_or(TransformError::NoBody)?;
        let mut json: Value =
            serde_json::from_slice(body).map_err(|e| TransformError::ParseError(e.to_string()))?;

        if let Some(Value::Array(mut arr)) = self.get_json_value(&json, path).cloned() {
            arr.sort_by(|a, b| {
                let a_val = a.get(by);
                let b_val = b.get(by);

                let cmp = match (a_val, b_val) {
                    (Some(Value::String(a)), Some(Value::String(b))) => a.cmp(b),
                    (Some(Value::Number(a)), Some(Value::Number(b))) => a
                        .as_f64()
                        .partial_cmp(&b.as_f64())
                        .unwrap_or(std::cmp::Ordering::Equal),
                    _ => std::cmp::Ordering::Equal,
                };

                if descending {
                    cmp.reverse()
                } else {
                    cmp
                }
            });

            self.set_json_value(&mut json, path, Value::Array(arr))?;
        }

        Ok(Some(Bytes::from(serde_json::to_vec(&json).unwrap())))
    }

    /// Get statistics
    pub fn stats(&self) -> &TransformStats {
        &self.stats
    }
}

/// Transformation error
#[derive(Debug)]
pub enum TransformError {
    NoBody,
    ParseError(String),
    InvalidPath(String),
    InvalidCondition(String),
}

impl std::fmt::Display for TransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoBody => write!(f, "No body to transform"),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
            Self::InvalidPath(p) => write!(f, "Invalid path: {}", p),
            Self::InvalidCondition(c) => write!(f, "Invalid condition: {}", c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_header() {
        let engine = TransformEngine::new(TransformConfig::default());

        engine.add_request_rule(TransformRule {
            id: "add-header".to_string(),
            name: "Add custom header".to_string(),
            description: None,
            conditions: vec![],
            transformations: vec![Transformation::SetHeader {
                name: "X-Custom".to_string(),
                value: "test-value".to_string(),
            }],
            priority: 0,
            enabled: true,
        });

        let request = TransformableRequest {
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: None,
            content_type: None,
        };

        let result = engine.transform_request(request);
        assert_eq!(
            result.data.headers.get("x-custom"),
            Some(&"test-value".to_string())
        );
    }

    #[test]
    fn test_rewrite_path() {
        let engine = TransformEngine::new(TransformConfig::default());

        engine.add_request_rule(TransformRule {
            id: "rewrite-path".to_string(),
            name: "Rewrite API path".to_string(),
            description: None,
            conditions: vec![],
            transformations: vec![Transformation::RewritePath {
                pattern: r"^/api/v1".to_string(),
                replacement: "/api/v2".to_string(),
            }],
            priority: 0,
            enabled: true,
        });

        let request = TransformableRequest {
            method: "GET".to_string(),
            path: "/api/v1/users".to_string(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: None,
            content_type: None,
        };

        let result = engine.transform_request(request);
        assert_eq!(result.data.path, "/api/v2/users");
    }

    #[test]
    fn test_conditional_transform() {
        let engine = TransformEngine::new(TransformConfig::default());

        engine.add_request_rule(TransformRule {
            id: "conditional".to_string(),
            name: "Conditional transform".to_string(),
            description: None,
            conditions: vec![MatchCondition {
                field: MatchField::Method,
                operator: MatchOperator::Equals,
                value: "POST".to_string(),
            }],
            transformations: vec![Transformation::SetHeader {
                name: "X-Post-Request".to_string(),
                value: "true".to_string(),
            }],
            priority: 0,
            enabled: true,
        });

        // POST request should get header
        let post_request = TransformableRequest {
            method: "POST".to_string(),
            path: "/api/users".to_string(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: None,
            content_type: None,
        };

        let result = engine.transform_request(post_request);
        assert!(result.data.headers.contains_key("x-post-request"));

        // GET request should not get header
        let get_request = TransformableRequest {
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: None,
            content_type: None,
        };

        let result = engine.transform_request(get_request);
        assert!(!result.data.headers.contains_key("x-post-request"));
    }

    #[test]
    fn test_json_field_transform() {
        let engine = TransformEngine::new(TransformConfig::default());

        engine.add_request_rule(TransformRule {
            id: "json-transform".to_string(),
            name: "JSON transform".to_string(),
            description: None,
            conditions: vec![],
            transformations: vec![Transformation::SetJsonField {
                path: "metadata.source".to_string(),
                value: serde_json::json!("proxy"),
            }],
            priority: 0,
            enabled: true,
        });

        let request = TransformableRequest {
            method: "POST".to_string(),
            path: "/api/users".to_string(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: Some(Bytes::from(r#"{"name": "John"}"#)),
            content_type: Some("application/json".to_string()),
        };

        let result = engine.transform_request(request);
        let body: Value = serde_json::from_slice(&result.data.body.unwrap()).unwrap();
        assert_eq!(body["metadata"]["source"], "proxy");
    }

    #[test]
    fn test_response_status_code() {
        let engine = TransformEngine::new(TransformConfig::default());

        engine.add_response_rule(TransformRule {
            id: "status-transform".to_string(),
            name: "Status transform".to_string(),
            description: None,
            conditions: vec![MatchCondition {
                field: MatchField::StatusCode,
                operator: MatchOperator::Equals,
                value: "404".to_string(),
            }],
            transformations: vec![Transformation::SetStatusCode { code: 200 }],
            priority: 0,
            enabled: true,
        });

        let request = TransformableRequest {
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: None,
            content_type: None,
        };

        let response = TransformableResponse {
            status_code: 404,
            headers: HashMap::new(),
            body: None,
            content_type: None,
        };

        let result = engine.transform_response(response, &request);
        assert_eq!(result.data.status_code, 200);
    }

    #[test]
    fn test_wrap_body() {
        let engine = TransformEngine::new(TransformConfig::default());

        engine.add_response_rule(TransformRule {
            id: "wrap".to_string(),
            name: "Wrap body".to_string(),
            description: None,
            conditions: vec![],
            transformations: vec![Transformation::WrapBody {
                wrapper: r#"{"data": "{{body}}", "status": "ok"}"#.to_string(),
            }],
            priority: 0,
            enabled: true,
        });

        let request = TransformableRequest {
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: None,
            content_type: None,
        };

        let response = TransformableResponse {
            status_code: 200,
            headers: HashMap::new(),
            body: Some(Bytes::from(r#"{"users": []}"#)),
            content_type: Some("application/json".to_string()),
        };

        let result = engine.transform_response(response, &request);
        let body: Value = serde_json::from_slice(&result.data.body.unwrap()).unwrap();
        assert_eq!(body["status"], "ok");
        assert!(body["data"].is_object());
    }
}
