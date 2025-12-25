//! OpenAPI Validation Module
//!
//! Provides request/response validation against OpenAPI specifications:
//! - Schema validation for request/response bodies
//! - Path parameter validation
//! - Query parameter validation
//! - Header validation
//! - Content-type validation

use bytes::Bytes;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// OpenAPI validation configuration
#[derive(Debug, Clone)]
pub struct OpenApiValidationConfig {
    /// Enable request validation
    pub validate_requests: bool,
    /// Enable response validation
    pub validate_responses: bool,
    /// Reject invalid requests (vs. just logging)
    pub reject_invalid_requests: bool,
    /// Reject invalid responses
    pub reject_invalid_responses: bool,
    /// Allow unknown query parameters
    pub allow_unknown_query_params: bool,
    /// Allow unknown headers
    pub allow_unknown_headers: bool,
    /// Coerce types when possible
    pub coerce_types: bool,
    /// Enable detailed error messages
    pub detailed_errors: bool,
}

impl Default for OpenApiValidationConfig {
    fn default() -> Self {
        Self {
            validate_requests: true,
            validate_responses: true,
            reject_invalid_requests: true,
            reject_invalid_responses: false,
            allow_unknown_query_params: true,
            allow_unknown_headers: true,
            coerce_types: true,
            detailed_errors: true,
        }
    }
}

/// JSON Schema type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaType {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Object,
    Null,
}

impl SchemaType {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "string" => Some(Self::String),
            "number" => Some(Self::Number),
            "integer" => Some(Self::Integer),
            "boolean" => Some(Self::Boolean),
            "array" => Some(Self::Array),
            "object" => Some(Self::Object),
            "null" => Some(Self::Null),
            _ => None,
        }
    }
}

/// Parameter location
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParameterLocation {
    Path,
    Query,
    Header,
    Cookie,
}

/// Parameter definition
#[derive(Debug, Clone)]
pub struct ParameterDef {
    pub name: String,
    pub location: ParameterLocation,
    pub required: bool,
    pub schema: SchemaDefinition,
    pub description: Option<String>,
}

/// Schema definition (simplified)
#[derive(Debug, Clone)]
pub struct SchemaDefinition {
    pub schema_type: Option<SchemaType>,
    pub format: Option<String>,
    pub pattern: Option<String>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub enum_values: Option<Vec<Value>>,
    pub items: Option<Box<SchemaDefinition>>,
    pub properties: HashMap<String, SchemaDefinition>,
    pub required: Vec<String>,
    pub additional_properties: bool,
}

impl Default for SchemaDefinition {
    fn default() -> Self {
        Self {
            schema_type: None,
            format: None,
            pattern: None,
            min_length: None,
            max_length: None,
            minimum: None,
            maximum: None,
            enum_values: None,
            items: None,
            properties: HashMap::new(),
            required: Vec::new(),
            additional_properties: true,
        }
    }
}

/// Operation definition
#[derive(Debug, Clone)]
pub struct OperationDef {
    pub operation_id: Option<String>,
    pub parameters: Vec<ParameterDef>,
    pub request_body: Option<RequestBodyDef>,
    pub responses: HashMap<String, ResponseDef>,
}

/// Request body definition
#[derive(Debug, Clone)]
pub struct RequestBodyDef {
    pub required: bool,
    pub content: HashMap<String, MediaTypeDef>,
}

/// Media type definition
#[derive(Debug, Clone)]
pub struct MediaTypeDef {
    pub schema: SchemaDefinition,
}

/// Response definition
#[derive(Debug, Clone)]
pub struct ResponseDef {
    pub description: String,
    pub content: HashMap<String, MediaTypeDef>,
    pub headers: HashMap<String, ParameterDef>,
}

/// Path definition
#[derive(Debug, Clone)]
pub struct PathDef {
    pub pattern: String,
    pub path_regex: Option<regex::Regex>,
    pub operations: HashMap<String, OperationDef>,
}

/// OpenAPI specification
#[derive(Debug, Clone)]
pub struct OpenApiSpec {
    pub title: String,
    pub version: String,
    pub paths: HashMap<String, PathDef>,
    pub components: ComponentsDef,
}

/// Components (schemas, parameters, etc.)
#[derive(Debug, Clone, Default)]
pub struct ComponentsDef {
    pub schemas: HashMap<String, SchemaDefinition>,
    pub parameters: HashMap<String, ParameterDef>,
}

/// Validation error
#[derive(Debug, Clone, Serialize)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
    pub error_type: ValidationErrorType,
    pub expected: Option<String>,
    pub actual: Option<String>,
}

/// Validation error type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ValidationErrorType {
    MissingRequired,
    InvalidType,
    InvalidFormat,
    PatternMismatch,
    EnumMismatch,
    MinLength,
    MaxLength,
    Minimum,
    Maximum,
    UnknownParameter,
    InvalidContentType,
    InvalidPath,
    MissingBody,
}

/// Validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
}

impl ValidationResult {
    pub fn ok() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
        }
    }

    pub fn error(error: ValidationError) -> Self {
        Self {
            valid: false,
            errors: vec![error],
        }
    }

    pub fn merge(&mut self, other: ValidationResult) {
        if !other.valid {
            self.valid = false;
        }
        self.errors.extend(other.errors);
    }
}

/// OpenAPI validator
pub struct OpenApiValidator {
    config: OpenApiValidationConfig,
    specs: DashMap<String, Arc<OpenApiSpec>>,
    stats: ValidationStats,
}

/// Validation statistics
#[derive(Debug, Default)]
pub struct ValidationStats {
    pub requests_validated: AtomicU64,
    pub responses_validated: AtomicU64,
    pub requests_valid: AtomicU64,
    pub requests_invalid: AtomicU64,
    pub responses_valid: AtomicU64,
    pub responses_invalid: AtomicU64,
}

impl OpenApiValidator {
    pub fn new(config: OpenApiValidationConfig) -> Self {
        Self {
            config,
            specs: DashMap::new(),
            stats: ValidationStats::default(),
        }
    }

    /// Load OpenAPI spec from JSON
    pub fn load_spec(&self, name: &str, spec_json: &str) -> Result<(), String> {
        let spec = self.parse_spec(spec_json)?;
        self.specs.insert(name.to_string(), Arc::new(spec));
        Ok(())
    }

    /// Parse OpenAPI specification
    fn parse_spec(&self, json: &str) -> Result<OpenApiSpec, String> {
        let value: Value =
            serde_json::from_str(json).map_err(|e| format!("Invalid JSON: {}", e))?;

        let info = value.get("info").ok_or("Missing info section")?;
        let title = info
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();
        let version = info
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("1.0.0")
            .to_string();

        let mut paths = HashMap::new();
        if let Some(paths_obj) = value.get("paths").and_then(|v| v.as_object()) {
            for (path, path_item) in paths_obj {
                let path_def = self.parse_path_item(path, path_item)?;
                paths.insert(path.clone(), path_def);
            }
        }

        let components = if let Some(comp) = value.get("components") {
            self.parse_components(comp)?
        } else {
            ComponentsDef::default()
        };

        Ok(OpenApiSpec {
            title,
            version,
            paths,
            components,
        })
    }

    fn parse_path_item(&self, path: &str, item: &Value) -> Result<PathDef, String> {
        let mut operations = HashMap::new();

        for method in &["get", "post", "put", "delete", "patch", "head", "options"] {
            if let Some(op) = item.get(*method) {
                let operation = self.parse_operation(op)?;
                operations.insert(method.to_uppercase(), operation);
            }
        }

        // Convert path pattern to regex
        let regex_pattern = path.replace("{", "(?P<").replace("}", ">[^/]+)");
        let path_regex = regex::Regex::new(&format!("^{}$", regex_pattern)).ok();

        Ok(PathDef {
            pattern: path.to_string(),
            path_regex,
            operations,
        })
    }

    fn parse_operation(&self, op: &Value) -> Result<OperationDef, String> {
        let operation_id = op
            .get("operationId")
            .and_then(|v| v.as_str())
            .map(String::from);

        let mut parameters = Vec::new();
        if let Some(params) = op.get("parameters").and_then(|v| v.as_array()) {
            for param in params {
                parameters.push(self.parse_parameter(param)?);
            }
        }

        let request_body = if let Some(body) = op.get("requestBody") {
            Some(self.parse_request_body(body)?)
        } else {
            None
        };

        let mut responses = HashMap::new();
        if let Some(resps) = op.get("responses").and_then(|v| v.as_object()) {
            for (status, resp) in resps {
                responses.insert(status.clone(), self.parse_response(resp)?);
            }
        }

        Ok(OperationDef {
            operation_id,
            parameters,
            request_body,
            responses,
        })
    }

    fn parse_parameter(&self, param: &Value) -> Result<ParameterDef, String> {
        let name = param
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("Parameter missing name")?
            .to_string();

        let location = match param.get("in").and_then(|v| v.as_str()) {
            Some("path") => ParameterLocation::Path,
            Some("query") => ParameterLocation::Query,
            Some("header") => ParameterLocation::Header,
            Some("cookie") => ParameterLocation::Cookie,
            _ => return Err("Invalid parameter location".to_string()),
        };

        let required = param
            .get("required")
            .and_then(|v| v.as_bool())
            .unwrap_or(location == ParameterLocation::Path);

        let schema = if let Some(s) = param.get("schema") {
            self.parse_schema(s)?
        } else {
            SchemaDefinition::default()
        };

        Ok(ParameterDef {
            name,
            location,
            required,
            schema,
            description: param
                .get("description")
                .and_then(|v| v.as_str())
                .map(String::from),
        })
    }

    fn parse_request_body(&self, body: &Value) -> Result<RequestBodyDef, String> {
        let required = body
            .get("required")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let mut content = HashMap::new();
        if let Some(content_obj) = body.get("content").and_then(|v| v.as_object()) {
            for (media_type, media_def) in content_obj {
                let schema = if let Some(s) = media_def.get("schema") {
                    self.parse_schema(s)?
                } else {
                    SchemaDefinition::default()
                };
                content.insert(media_type.clone(), MediaTypeDef { schema });
            }
        }

        Ok(RequestBodyDef { required, content })
    }

    fn parse_response(&self, resp: &Value) -> Result<ResponseDef, String> {
        let description = resp
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let mut content = HashMap::new();
        if let Some(content_obj) = resp.get("content").and_then(|v| v.as_object()) {
            for (media_type, media_def) in content_obj {
                let schema = if let Some(s) = media_def.get("schema") {
                    self.parse_schema(s)?
                } else {
                    SchemaDefinition::default()
                };
                content.insert(media_type.clone(), MediaTypeDef { schema });
            }
        }

        Ok(ResponseDef {
            description,
            content,
            headers: HashMap::new(),
        })
    }

    #[allow(clippy::only_used_in_recursion)]
    fn parse_schema(&self, schema: &Value) -> Result<SchemaDefinition, String> {
        let schema_type = schema
            .get("type")
            .and_then(|v| v.as_str())
            .and_then(SchemaType::from_str);

        let format = schema
            .get("format")
            .and_then(|v| v.as_str())
            .map(String::from);
        let pattern = schema
            .get("pattern")
            .and_then(|v| v.as_str())
            .map(String::from);
        let min_length = schema
            .get("minLength")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize);
        let max_length = schema
            .get("maxLength")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize);
        let minimum = schema.get("minimum").and_then(|v| v.as_f64());
        let maximum = schema.get("maximum").and_then(|v| v.as_f64());
        let enum_values = schema.get("enum").and_then(|v| v.as_array()).cloned();

        let items = if let Some(items_schema) = schema.get("items") {
            Some(Box::new(self.parse_schema(items_schema)?))
        } else {
            None
        };

        let mut properties = HashMap::new();
        if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
            for (name, prop_schema) in props {
                properties.insert(name.clone(), self.parse_schema(prop_schema)?);
            }
        }

        let required = schema
            .get("required")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let additional_properties = schema
            .get("additionalProperties")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        Ok(SchemaDefinition {
            schema_type,
            format,
            pattern,
            min_length,
            max_length,
            minimum,
            maximum,
            enum_values,
            items,
            properties,
            required,
            additional_properties,
        })
    }

    fn parse_components(&self, comp: &Value) -> Result<ComponentsDef, String> {
        let mut schemas = HashMap::new();
        if let Some(schemas_obj) = comp.get("schemas").and_then(|v| v.as_object()) {
            for (name, schema) in schemas_obj {
                schemas.insert(name.clone(), self.parse_schema(schema)?);
            }
        }

        Ok(ComponentsDef {
            schemas,
            parameters: HashMap::new(),
        })
    }

    /// Validate a request
    #[allow(clippy::too_many_arguments)]
    pub fn validate_request(
        &self,
        spec_name: &str,
        method: &str,
        path: &str,
        query_params: &HashMap<String, String>,
        headers: &HashMap<String, String>,
        body: Option<&Bytes>,
        content_type: Option<&str>,
    ) -> ValidationResult {
        self.stats
            .requests_validated
            .fetch_add(1, Ordering::Relaxed);

        if !self.config.validate_requests {
            return ValidationResult::ok();
        }

        let spec = match self.specs.get(spec_name) {
            Some(s) => s.clone(),
            None => return ValidationResult::ok(),
        };

        // Find matching path
        let (path_def, path_params) = match self.match_path(&spec, path) {
            Some(result) => result,
            None => {
                self.stats.requests_invalid.fetch_add(1, Ordering::Relaxed);
                return ValidationResult::error(ValidationError {
                    path: path.to_string(),
                    message: "Path not found in specification".to_string(),
                    error_type: ValidationErrorType::InvalidPath,
                    expected: None,
                    actual: Some(path.to_string()),
                });
            }
        };

        // Find operation
        let operation = match path_def.operations.get(&method.to_uppercase()) {
            Some(op) => op,
            None => {
                self.stats.requests_invalid.fetch_add(1, Ordering::Relaxed);
                return ValidationResult::error(ValidationError {
                    path: format!("{} {}", method, path),
                    message: "Method not allowed".to_string(),
                    error_type: ValidationErrorType::InvalidPath,
                    expected: None,
                    actual: Some(method.to_string()),
                });
            }
        };

        let mut result = ValidationResult::ok();

        // Validate path parameters
        for param in &operation.parameters {
            match param.location {
                ParameterLocation::Path => {
                    if let Some(value) = path_params.get(&param.name) {
                        let param_result = self.validate_value(
                            value,
                            &param.schema,
                            &format!("path.{}", param.name),
                        );
                        result.merge(param_result);
                    } else if param.required {
                        result.merge(ValidationResult::error(ValidationError {
                            path: format!("path.{}", param.name),
                            message: "Required path parameter missing".to_string(),
                            error_type: ValidationErrorType::MissingRequired,
                            expected: Some(param.name.clone()),
                            actual: None,
                        }));
                    }
                }
                ParameterLocation::Query => {
                    if let Some(value) = query_params.get(&param.name) {
                        let param_result = self.validate_value(
                            value,
                            &param.schema,
                            &format!("query.{}", param.name),
                        );
                        result.merge(param_result);
                    } else if param.required {
                        result.merge(ValidationResult::error(ValidationError {
                            path: format!("query.{}", param.name),
                            message: "Required query parameter missing".to_string(),
                            error_type: ValidationErrorType::MissingRequired,
                            expected: Some(param.name.clone()),
                            actual: None,
                        }));
                    }
                }
                ParameterLocation::Header => {
                    let header_name = param.name.to_lowercase();
                    if let Some(value) = headers.get(&header_name) {
                        let param_result = self.validate_value(
                            value,
                            &param.schema,
                            &format!("header.{}", param.name),
                        );
                        result.merge(param_result);
                    } else if param.required {
                        result.merge(ValidationResult::error(ValidationError {
                            path: format!("header.{}", param.name),
                            message: "Required header missing".to_string(),
                            error_type: ValidationErrorType::MissingRequired,
                            expected: Some(param.name.clone()),
                            actual: None,
                        }));
                    }
                }
                _ => {}
            }
        }

        // Validate request body
        if let Some(body_def) = &operation.request_body {
            if let Some(body_bytes) = body {
                if let Some(ct) = content_type {
                    let media_type = ct.split(';').next().unwrap_or(ct).trim();
                    if let Some(media_def) = body_def.content.get(media_type) {
                        if let Ok(json) = serde_json::from_slice::<Value>(body_bytes) {
                            let body_result =
                                self.validate_json_schema(&json, &media_def.schema, "body");
                            result.merge(body_result);
                        }
                    } else if !body_def.content.is_empty() {
                        result.merge(ValidationResult::error(ValidationError {
                            path: "body".to_string(),
                            message: format!("Unsupported content type: {}", media_type),
                            error_type: ValidationErrorType::InvalidContentType,
                            expected: Some(
                                body_def
                                    .content
                                    .keys()
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            ),
                            actual: Some(media_type.to_string()),
                        }));
                    }
                }
            } else if body_def.required {
                result.merge(ValidationResult::error(ValidationError {
                    path: "body".to_string(),
                    message: "Request body is required".to_string(),
                    error_type: ValidationErrorType::MissingBody,
                    expected: None,
                    actual: None,
                }));
            }
        }

        if result.valid {
            self.stats.requests_valid.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.requests_invalid.fetch_add(1, Ordering::Relaxed);
        }

        result
    }

    /// Validate a response
    #[allow(clippy::too_many_arguments)]
    pub fn validate_response(
        &self,
        spec_name: &str,
        method: &str,
        path: &str,
        status_code: u16,
        _headers: &HashMap<String, String>,
        body: Option<&Bytes>,
        content_type: Option<&str>,
    ) -> ValidationResult {
        self.stats
            .responses_validated
            .fetch_add(1, Ordering::Relaxed);

        if !self.config.validate_responses {
            return ValidationResult::ok();
        }

        let spec = match self.specs.get(spec_name) {
            Some(s) => s.clone(),
            None => return ValidationResult::ok(),
        };

        let (path_def, _) = match self.match_path(&spec, path) {
            Some(result) => result,
            None => return ValidationResult::ok(),
        };

        let operation = match path_def.operations.get(&method.to_uppercase()) {
            Some(op) => op,
            None => return ValidationResult::ok(),
        };

        let status_str = status_code.to_string();
        let response_def = operation
            .responses
            .get(&status_str)
            .or_else(|| operation.responses.get("default"));

        let mut result = ValidationResult::ok();

        if let Some(resp_def) = response_def {
            if let Some(body_bytes) = body {
                if let Some(ct) = content_type {
                    let media_type = ct.split(';').next().unwrap_or(ct).trim();
                    if let Some(media_def) = resp_def.content.get(media_type) {
                        if let Ok(json) = serde_json::from_slice::<Value>(body_bytes) {
                            let body_result = self.validate_json_schema(
                                &json,
                                &media_def.schema,
                                "response.body",
                            );
                            result.merge(body_result);
                        }
                    }
                }
            }
        }

        if result.valid {
            self.stats.responses_valid.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.responses_invalid.fetch_add(1, Ordering::Relaxed);
        }

        result
    }

    fn match_path<'a>(
        &self,
        spec: &'a OpenApiSpec,
        path: &str,
    ) -> Option<(&'a PathDef, HashMap<String, String>)> {
        for path_def in spec.paths.values() {
            if let Some(ref regex) = path_def.path_regex {
                if let Some(captures) = regex.captures(path) {
                    let mut params = HashMap::new();
                    for name in regex.capture_names().flatten() {
                        if let Some(value) = captures.name(name) {
                            params.insert(name.to_string(), value.as_str().to_string());
                        }
                    }
                    return Some((path_def, params));
                }
            }
        }
        None
    }

    fn validate_value(
        &self,
        value: &str,
        schema: &SchemaDefinition,
        path: &str,
    ) -> ValidationResult {
        let mut result = ValidationResult::ok();

        // Type validation
        if let Some(ref schema_type) = schema.schema_type {
            let type_valid = match schema_type {
                SchemaType::String => true,
                SchemaType::Integer => value.parse::<i64>().is_ok(),
                SchemaType::Number => value.parse::<f64>().is_ok(),
                SchemaType::Boolean => value == "true" || value == "false",
                _ => true,
            };

            if !type_valid {
                result.merge(ValidationResult::error(ValidationError {
                    path: path.to_string(),
                    message: format!("Invalid type, expected {:?}", schema_type),
                    error_type: ValidationErrorType::InvalidType,
                    expected: Some(format!("{:?}", schema_type)),
                    actual: Some(value.to_string()),
                }));
            }
        }

        // String validations
        if let Some(min_len) = schema.min_length {
            if value.len() < min_len {
                result.merge(ValidationResult::error(ValidationError {
                    path: path.to_string(),
                    message: format!("String too short, minimum length is {}", min_len),
                    error_type: ValidationErrorType::MinLength,
                    expected: Some(min_len.to_string()),
                    actual: Some(value.len().to_string()),
                }));
            }
        }

        if let Some(max_len) = schema.max_length {
            if value.len() > max_len {
                result.merge(ValidationResult::error(ValidationError {
                    path: path.to_string(),
                    message: format!("String too long, maximum length is {}", max_len),
                    error_type: ValidationErrorType::MaxLength,
                    expected: Some(max_len.to_string()),
                    actual: Some(value.len().to_string()),
                }));
            }
        }

        // Pattern validation
        if let Some(ref pattern) = schema.pattern {
            if let Ok(regex) = regex::Regex::new(pattern) {
                if !regex.is_match(value) {
                    result.merge(ValidationResult::error(ValidationError {
                        path: path.to_string(),
                        message: format!("Value does not match pattern: {}", pattern),
                        error_type: ValidationErrorType::PatternMismatch,
                        expected: Some(pattern.clone()),
                        actual: Some(value.to_string()),
                    }));
                }
            }
        }

        // Enum validation
        if let Some(ref enum_values) = schema.enum_values {
            let value_json = Value::String(value.to_string());
            if !enum_values.contains(&value_json) {
                result.merge(ValidationResult::error(ValidationError {
                    path: path.to_string(),
                    message: "Value not in enum".to_string(),
                    error_type: ValidationErrorType::EnumMismatch,
                    expected: Some(format!("{:?}", enum_values)),
                    actual: Some(value.to_string()),
                }));
            }
        }

        result
    }

    #[allow(clippy::only_used_in_recursion)]
    fn validate_json_schema(
        &self,
        value: &Value,
        schema: &SchemaDefinition,
        path: &str,
    ) -> ValidationResult {
        let mut result = ValidationResult::ok();

        // Type validation
        if let Some(ref schema_type) = schema.schema_type {
            let type_valid = match (schema_type, value) {
                (SchemaType::String, Value::String(_)) => true,
                (SchemaType::Number, Value::Number(_)) => true,
                (SchemaType::Integer, Value::Number(n)) => n.is_i64(),
                (SchemaType::Boolean, Value::Bool(_)) => true,
                (SchemaType::Array, Value::Array(_)) => true,
                (SchemaType::Object, Value::Object(_)) => true,
                (SchemaType::Null, Value::Null) => true,
                _ => false,
            };

            if !type_valid {
                result.merge(ValidationResult::error(ValidationError {
                    path: path.to_string(),
                    message: format!("Invalid type, expected {:?}", schema_type),
                    error_type: ValidationErrorType::InvalidType,
                    expected: Some(format!("{:?}", schema_type)),
                    actual: Some(format!("{:?}", value)),
                }));
                return result;
            }
        }

        // Object validation
        if let Value::Object(obj) = value {
            // Check required properties
            for required_prop in &schema.required {
                if !obj.contains_key(required_prop) {
                    result.merge(ValidationResult::error(ValidationError {
                        path: format!("{}.{}", path, required_prop),
                        message: "Required property missing".to_string(),
                        error_type: ValidationErrorType::MissingRequired,
                        expected: Some(required_prop.clone()),
                        actual: None,
                    }));
                }
            }

            // Validate each property
            for (prop_name, prop_value) in obj {
                if let Some(prop_schema) = schema.properties.get(prop_name) {
                    let prop_result = self.validate_json_schema(
                        prop_value,
                        prop_schema,
                        &format!("{}.{}", path, prop_name),
                    );
                    result.merge(prop_result);
                } else if !schema.additional_properties {
                    result.merge(ValidationResult::error(ValidationError {
                        path: format!("{}.{}", path, prop_name),
                        message: "Unknown property".to_string(),
                        error_type: ValidationErrorType::UnknownParameter,
                        expected: None,
                        actual: Some(prop_name.clone()),
                    }));
                }
            }
        }

        // Array validation
        if let Value::Array(arr) = value {
            if let Some(ref items_schema) = schema.items {
                for (i, item) in arr.iter().enumerate() {
                    let item_result =
                        self.validate_json_schema(item, items_schema, &format!("{}[{}]", path, i));
                    result.merge(item_result);
                }
            }
        }

        // String validations
        if let Value::String(s) = value {
            if let Some(min_len) = schema.min_length {
                if s.len() < min_len {
                    result.merge(ValidationResult::error(ValidationError {
                        path: path.to_string(),
                        message: format!("String too short, minimum length is {}", min_len),
                        error_type: ValidationErrorType::MinLength,
                        expected: Some(min_len.to_string()),
                        actual: Some(s.len().to_string()),
                    }));
                }
            }

            if let Some(max_len) = schema.max_length {
                if s.len() > max_len {
                    result.merge(ValidationResult::error(ValidationError {
                        path: path.to_string(),
                        message: format!("String too long, maximum length is {}", max_len),
                        error_type: ValidationErrorType::MaxLength,
                        expected: Some(max_len.to_string()),
                        actual: Some(s.len().to_string()),
                    }));
                }
            }

            if let Some(ref pattern) = schema.pattern {
                if let Ok(regex) = regex::Regex::new(pattern) {
                    if !regex.is_match(s) {
                        result.merge(ValidationResult::error(ValidationError {
                            path: path.to_string(),
                            message: format!("Value does not match pattern: {}", pattern),
                            error_type: ValidationErrorType::PatternMismatch,
                            expected: Some(pattern.clone()),
                            actual: Some(s.clone()),
                        }));
                    }
                }
            }
        }

        // Number validations
        if let Value::Number(n) = value {
            if let Some(num) = n.as_f64() {
                if let Some(min) = schema.minimum {
                    if num < min {
                        result.merge(ValidationResult::error(ValidationError {
                            path: path.to_string(),
                            message: format!("Number below minimum: {}", min),
                            error_type: ValidationErrorType::Minimum,
                            expected: Some(min.to_string()),
                            actual: Some(num.to_string()),
                        }));
                    }
                }

                if let Some(max) = schema.maximum {
                    if num > max {
                        result.merge(ValidationResult::error(ValidationError {
                            path: path.to_string(),
                            message: format!("Number above maximum: {}", max),
                            error_type: ValidationErrorType::Maximum,
                            expected: Some(max.to_string()),
                            actual: Some(num.to_string()),
                        }));
                    }
                }
            }
        }

        // Enum validation
        if let Some(ref enum_values) = schema.enum_values {
            if !enum_values.contains(value) {
                result.merge(ValidationResult::error(ValidationError {
                    path: path.to_string(),
                    message: "Value not in enum".to_string(),
                    error_type: ValidationErrorType::EnumMismatch,
                    expected: Some(format!("{:?}", enum_values)),
                    actual: Some(format!("{:?}", value)),
                }));
            }
        }

        result
    }

    /// Get validation statistics
    pub fn stats(&self) -> &ValidationStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SPEC: &str = r#"{
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0"
        },
        "paths": {
            "/users/{id}": {
                "get": {
                    "operationId": "getUser",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "integer"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["id", "name"],
                                        "properties": {
                                            "id": {"type": "integer"},
                                            "name": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/users": {
                "post": {
                    "operationId": "createUser",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["name", "email"],
                                    "properties": {
                                        "name": {
                                            "type": "string",
                                            "minLength": 1,
                                            "maxLength": 100
                                        },
                                        "email": {
                                            "type": "string",
                                            "pattern": "^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$"
                                        },
                                        "age": {
                                            "type": "integer",
                                            "minimum": 0,
                                            "maximum": 150
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Created"
                        }
                    }
                }
            }
        }
    }"#;

    #[test]
    fn test_load_spec() {
        let validator = OpenApiValidator::new(OpenApiValidationConfig::default());
        assert!(validator.load_spec("test", TEST_SPEC).is_ok());
    }

    #[test]
    fn test_validate_valid_request() {
        let validator = OpenApiValidator::new(OpenApiValidationConfig::default());
        validator.load_spec("test", TEST_SPEC).unwrap();

        let result = validator.validate_request(
            "test",
            "GET",
            "/users/123",
            &HashMap::new(),
            &HashMap::new(),
            None,
            None,
        );

        assert!(result.valid);
    }

    #[test]
    fn test_validate_invalid_path_param() {
        let validator = OpenApiValidator::new(OpenApiValidationConfig::default());
        validator.load_spec("test", TEST_SPEC).unwrap();

        let result = validator.validate_request(
            "test",
            "GET",
            "/users/abc", // Should be integer
            &HashMap::new(),
            &HashMap::new(),
            None,
            None,
        );

        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.error_type == ValidationErrorType::InvalidType));
    }

    #[test]
    fn test_validate_request_body() {
        let validator = OpenApiValidator::new(OpenApiValidationConfig::default());
        validator.load_spec("test", TEST_SPEC).unwrap();

        let body = Bytes::from(r#"{"name": "John", "email": "john@example.com"}"#);

        let result = validator.validate_request(
            "test",
            "POST",
            "/users",
            &HashMap::new(),
            &HashMap::new(),
            Some(&body),
            Some("application/json"),
        );

        assert!(result.valid);
    }

    #[test]
    fn test_validate_missing_required_field() {
        let validator = OpenApiValidator::new(OpenApiValidationConfig::default());
        validator.load_spec("test", TEST_SPEC).unwrap();

        let body = Bytes::from(r#"{"name": "John"}"#); // Missing email

        let result = validator.validate_request(
            "test",
            "POST",
            "/users",
            &HashMap::new(),
            &HashMap::new(),
            Some(&body),
            Some("application/json"),
        );

        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.error_type == ValidationErrorType::MissingRequired));
    }

    #[test]
    fn test_validate_invalid_email_pattern() {
        let validator = OpenApiValidator::new(OpenApiValidationConfig::default());
        validator.load_spec("test", TEST_SPEC).unwrap();

        let body = Bytes::from(r#"{"name": "John", "email": "invalid-email"}"#);

        let result = validator.validate_request(
            "test",
            "POST",
            "/users",
            &HashMap::new(),
            &HashMap::new(),
            Some(&body),
            Some("application/json"),
        );

        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.error_type == ValidationErrorType::PatternMismatch));
    }

    #[test]
    fn test_validate_number_range() {
        let validator = OpenApiValidator::new(OpenApiValidationConfig::default());
        validator.load_spec("test", TEST_SPEC).unwrap();

        let body = Bytes::from(r#"{"name": "John", "email": "john@example.com", "age": 200}"#);

        let result = validator.validate_request(
            "test",
            "POST",
            "/users",
            &HashMap::new(),
            &HashMap::new(),
            Some(&body),
            Some("application/json"),
        );

        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.error_type == ValidationErrorType::Maximum));
    }

    #[test]
    fn test_validate_string_length() {
        let validator = OpenApiValidator::new(OpenApiValidationConfig::default());
        validator.load_spec("test", TEST_SPEC).unwrap();

        let body = Bytes::from(r#"{"name": "", "email": "john@example.com"}"#);

        let result = validator.validate_request(
            "test",
            "POST",
            "/users",
            &HashMap::new(),
            &HashMap::new(),
            Some(&body),
            Some("application/json"),
        );

        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.error_type == ValidationErrorType::MinLength));
    }
}
