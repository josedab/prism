//! GraphQL-Aware Routing
//!
//! Provides GraphQL-specific routing and middleware capabilities:
//! - Query parsing and operation detection
//! - Routing based on operation name/type
//! - Query depth and complexity limiting
//! - Per-operation rate limiting
//! - Query caching by operation

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// GraphQL operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperationType {
    Query,
    Mutation,
    Subscription,
}

impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationType::Query => write!(f, "query"),
            OperationType::Mutation => write!(f, "mutation"),
            OperationType::Subscription => write!(f, "subscription"),
        }
    }
}

/// Parsed GraphQL request
#[derive(Debug, Clone)]
pub struct GraphqlRequest {
    /// The full query string
    pub query: String,
    /// Operation name (if provided)
    pub operation_name: Option<String>,
    /// Variables (raw JSON)
    pub variables: Option<serde_json::Value>,
    /// Detected operation type
    pub operation_type: OperationType,
    /// Calculated query depth
    pub depth: usize,
    /// Estimated complexity
    pub complexity: usize,
    /// Field names referenced in the query
    pub fields: HashSet<String>,
    /// All operation names defined in the document
    pub defined_operations: Vec<String>,
}

/// GraphQL request body format
#[derive(Debug, Clone, Deserialize)]
pub struct GraphqlRequestBody {
    pub query: String,
    #[serde(rename = "operationName")]
    pub operation_name: Option<String>,
    pub variables: Option<serde_json::Value>,
}

/// GraphQL routing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphqlRoutingConfig {
    /// Enable GraphQL-aware routing
    #[serde(default)]
    pub enabled: bool,

    /// Maximum query depth allowed
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,

    /// Maximum query complexity allowed
    #[serde(default = "default_max_complexity")]
    pub max_complexity: usize,

    /// Block introspection queries in production
    #[serde(default)]
    pub block_introspection: bool,

    /// Allow persisted queries only
    #[serde(default)]
    pub persisted_queries_only: bool,

    /// Persisted query map (hash -> query)
    #[serde(default)]
    pub persisted_queries: HashMap<String, String>,

    /// Rate limits per operation type
    #[serde(default)]
    pub rate_limits: HashMap<String, u32>,

    /// Route mutations to specific upstream
    pub mutation_upstream: Option<String>,

    /// Route subscriptions to specific upstream
    pub subscription_upstream: Option<String>,

    /// Operation-specific routing
    #[serde(default)]
    pub operation_routes: HashMap<String, String>,
}

impl Default for GraphqlRoutingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_depth: default_max_depth(),
            max_complexity: default_max_complexity(),
            block_introspection: false,
            persisted_queries_only: false,
            persisted_queries: HashMap::new(),
            rate_limits: HashMap::new(),
            mutation_upstream: None,
            subscription_upstream: None,
            operation_routes: HashMap::new(),
        }
    }
}

fn default_max_depth() -> usize {
    10
}

fn default_max_complexity() -> usize {
    1000
}

/// GraphQL query analyzer
pub struct GraphqlAnalyzer {
    config: GraphqlRoutingConfig,
}

impl GraphqlAnalyzer {
    /// Create a new GraphQL analyzer
    pub fn new(config: GraphqlRoutingConfig) -> Self {
        Self { config }
    }

    /// Parse and analyze a GraphQL request body
    pub fn parse(&self, body: &[u8]) -> Result<GraphqlRequest, GraphqlError> {
        // Parse JSON body
        let request: GraphqlRequestBody =
            serde_json::from_slice(body).map_err(|e| GraphqlError::ParseError(e.to_string()))?;

        // Analyze the query
        self.analyze_query(&request.query, request.operation_name, request.variables)
    }

    /// Analyze a GraphQL query string
    pub fn analyze_query(
        &self,
        query: &str,
        operation_name: Option<String>,
        variables: Option<serde_json::Value>,
    ) -> Result<GraphqlRequest, GraphqlError> {
        let (operation_type, depth, complexity, fields, defined_ops) =
            self.analyze_query_string(query)?;

        let request = GraphqlRequest {
            query: query.to_string(),
            operation_name,
            variables,
            operation_type,
            depth,
            complexity,
            fields,
            defined_operations: defined_ops,
        };

        // Validate against limits
        self.validate(&request)?;

        Ok(request)
    }

    /// Analyze query string to extract operation type, depth, and complexity
    #[allow(clippy::type_complexity)]
    fn analyze_query_string(
        &self,
        query: &str,
    ) -> Result<(OperationType, usize, usize, HashSet<String>, Vec<String>), GraphqlError> {
        let query = query.trim();

        // Simple parser for operation type detection
        let mut operation_type = OperationType::Query;
        let mut defined_operations = Vec::new();

        // Check for explicit operation type
        if query.starts_with("mutation") {
            operation_type = OperationType::Mutation;
        } else if query.starts_with("subscription") {
            operation_type = OperationType::Subscription;
        } else if query.starts_with("query") {
            operation_type = OperationType::Query;
        }

        // Find operation names
        let op_patterns = ["query ", "mutation ", "subscription "];
        for pattern in &op_patterns {
            for part in query.split(pattern) {
                if let Some(name) = part
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
                {
                    if !name.is_empty() && name.chars().next().is_some_and(|c| c.is_alphabetic()) {
                        defined_operations.push(name.to_string());
                    }
                }
            }
        }

        // Calculate depth and extract fields
        let (depth, fields) = self.calculate_depth_and_fields(query);

        // Calculate complexity (simplified: depth * fields)
        let complexity = depth * fields.len().max(1);

        Ok((
            operation_type,
            depth,
            complexity,
            fields,
            defined_operations,
        ))
    }

    /// Calculate query depth and extract field names
    fn calculate_depth_and_fields(&self, query: &str) -> (usize, HashSet<String>) {
        let mut max_depth: usize = 0;
        let mut current_depth: usize = 0;
        let mut fields = HashSet::new();
        let mut current_field = String::new();
        let mut in_string = false;
        let mut prev_char = ' ';

        for ch in query.chars() {
            match ch {
                '"' if prev_char != '\\' => {
                    in_string = !in_string;
                }
                '{' if !in_string => {
                    current_depth += 1;
                    max_depth = max_depth.max(current_depth);
                    if !current_field.is_empty() {
                        fields.insert(std::mem::take(&mut current_field));
                    }
                }
                '}' if !in_string => {
                    current_depth = current_depth.saturating_sub(1);
                    if !current_field.is_empty() {
                        fields.insert(std::mem::take(&mut current_field));
                    }
                }
                '(' | ':' | ' ' | '\n' | '\t' | ',' if !in_string => {
                    if !current_field.is_empty() {
                        fields.insert(std::mem::take(&mut current_field));
                    }
                }
                c if !in_string && (c.is_alphanumeric() || c == '_') => {
                    current_field.push(c);
                }
                _ => {}
            }
            prev_char = ch;
        }

        if !current_field.is_empty() {
            fields.insert(current_field);
        }

        // Remove GraphQL keywords
        let keywords: HashSet<_> = [
            "query",
            "mutation",
            "subscription",
            "fragment",
            "on",
            "true",
            "false",
            "null",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let fields: HashSet<_> = fields.difference(&keywords).cloned().collect();

        (max_depth, fields)
    }

    /// Validate a parsed request against configuration
    fn validate(&self, request: &GraphqlRequest) -> Result<(), GraphqlError> {
        // Check depth limit
        if request.depth > self.config.max_depth {
            return Err(GraphqlError::DepthExceeded {
                max: self.config.max_depth,
                actual: request.depth,
            });
        }

        // Check complexity limit
        if request.complexity > self.config.max_complexity {
            return Err(GraphqlError::ComplexityExceeded {
                max: self.config.max_complexity,
                actual: request.complexity,
            });
        }

        // Check introspection blocking
        if self.config.block_introspection && self.is_introspection(&request.query) {
            return Err(GraphqlError::IntrospectionBlocked);
        }

        Ok(())
    }

    /// Check if query is an introspection query
    fn is_introspection(&self, query: &str) -> bool {
        query.contains("__schema") || query.contains("__type")
    }

    /// Get the upstream for a request based on operation type
    pub fn get_upstream(&self, request: &GraphqlRequest) -> Option<&str> {
        // Check operation-specific routes first
        if let Some(op_name) = &request.operation_name {
            if let Some(upstream) = self.config.operation_routes.get(op_name) {
                return Some(upstream);
            }
        }

        // Then check operation type routing
        match request.operation_type {
            OperationType::Mutation => self.config.mutation_upstream.as_deref(),
            OperationType::Subscription => self.config.subscription_upstream.as_deref(),
            OperationType::Query => None,
        }
    }

    /// Check rate limit for operation type
    pub fn check_rate_limit(&self, operation_type: OperationType) -> Option<u32> {
        self.config
            .rate_limits
            .get(&operation_type.to_string())
            .copied()
    }

    /// Look up a persisted query by hash
    pub fn lookup_persisted_query(&self, hash: &str) -> Option<&str> {
        self.config.persisted_queries.get(hash).map(|s| s.as_str())
    }
}

/// GraphQL-specific errors
#[derive(Debug, Clone)]
pub enum GraphqlError {
    /// Failed to parse GraphQL request
    ParseError(String),
    /// Query depth exceeded limit
    DepthExceeded { max: usize, actual: usize },
    /// Query complexity exceeded limit
    ComplexityExceeded { max: usize, actual: usize },
    /// Introspection queries are blocked
    IntrospectionBlocked,
    /// Persisted query not found
    PersistedQueryNotFound(String),
    /// Rate limit exceeded for operation type
    RateLimitExceeded(OperationType),
}

impl std::fmt::Display for GraphqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GraphqlError::ParseError(msg) => write!(f, "GraphQL parse error: {}", msg),
            GraphqlError::DepthExceeded { max, actual } => {
                write!(f, "Query depth {} exceeds maximum {}", actual, max)
            }
            GraphqlError::ComplexityExceeded { max, actual } => {
                write!(f, "Query complexity {} exceeds maximum {}", actual, max)
            }
            GraphqlError::IntrospectionBlocked => write!(f, "Introspection queries are disabled"),
            GraphqlError::PersistedQueryNotFound(hash) => {
                write!(f, "Persisted query not found: {}", hash)
            }
            GraphqlError::RateLimitExceeded(op) => {
                write!(f, "Rate limit exceeded for {} operations", op)
            }
        }
    }
}

impl std::error::Error for GraphqlError {}

/// GraphQL error response format
#[derive(Debug, Clone, Serialize)]
pub struct GraphqlErrorResponse {
    pub errors: Vec<GraphqlErrorItem>,
}

/// Individual GraphQL error
#[derive(Debug, Clone, Serialize)]
pub struct GraphqlErrorItem {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<GraphqlErrorExtensions>,
}

/// GraphQL error extensions
#[derive(Debug, Clone, Serialize)]
pub struct GraphqlErrorExtensions {
    pub code: String,
}

impl GraphqlError {
    /// Convert to a GraphQL error response
    pub fn to_response(&self) -> GraphqlErrorResponse {
        let (message, code) = match self {
            GraphqlError::ParseError(msg) => (msg.clone(), "GRAPHQL_PARSE_FAILED"),
            GraphqlError::DepthExceeded { max, actual } => (
                format!(
                    "Query depth {} exceeds maximum allowed depth of {}",
                    actual, max
                ),
                "DEPTH_LIMIT_EXCEEDED",
            ),
            GraphqlError::ComplexityExceeded { max, actual } => (
                format!(
                    "Query complexity {} exceeds maximum allowed complexity of {}",
                    actual, max
                ),
                "COMPLEXITY_LIMIT_EXCEEDED",
            ),
            GraphqlError::IntrospectionBlocked => (
                "Introspection queries are disabled".to_string(),
                "INTROSPECTION_DISABLED",
            ),
            GraphqlError::PersistedQueryNotFound(hash) => (
                format!("Persisted query not found: {}", hash),
                "PERSISTED_QUERY_NOT_FOUND",
            ),
            GraphqlError::RateLimitExceeded(op) => (
                format!("Rate limit exceeded for {} operations", op),
                "RATE_LIMIT_EXCEEDED",
            ),
        };

        GraphqlErrorResponse {
            errors: vec![GraphqlErrorItem {
                message,
                extensions: Some(GraphqlErrorExtensions {
                    code: code.to_string(),
                }),
            }],
        }
    }

    /// Get HTTP status code for this error
    pub fn status_code(&self) -> http::StatusCode {
        match self {
            GraphqlError::ParseError(_) => http::StatusCode::BAD_REQUEST,
            GraphqlError::DepthExceeded { .. } => http::StatusCode::BAD_REQUEST,
            GraphqlError::ComplexityExceeded { .. } => http::StatusCode::BAD_REQUEST,
            GraphqlError::IntrospectionBlocked => http::StatusCode::FORBIDDEN,
            GraphqlError::PersistedQueryNotFound(_) => http::StatusCode::NOT_FOUND,
            GraphqlError::RateLimitExceeded(_) => http::StatusCode::TOO_MANY_REQUESTS,
        }
    }
}

/// Check if a request is a GraphQL request based on content-type and path
pub fn is_graphql_request<B>(request: &http::Request<B>, graphql_path: &str) -> bool {
    let path = request.uri().path();
    let is_graphql_path = path == graphql_path || path.starts_with(&format!("{}/", graphql_path));

    if !is_graphql_path {
        return false;
    }

    // Check content-type
    if let Some(content_type) = request.headers().get(http::header::CONTENT_TYPE) {
        if let Ok(ct) = content_type.to_str() {
            return ct.contains("application/json") || ct.contains("application/graphql");
        }
    }

    // GET requests with query parameter are also GraphQL
    if request.method() == http::Method::GET {
        if let Some(query) = request.uri().query() {
            return query.contains("query=");
        }
    }

    true
}

/// Extract GraphQL query from GET request query parameters
pub fn extract_graphql_from_query(uri: &http::Uri) -> Option<GraphqlRequestBody> {
    let query = uri.query()?;

    let mut graphql_query = None;
    let mut operation_name = None;
    let mut variables = None;

    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let decoded_value = urlencoding::decode(value).ok()?;
            match key {
                "query" => graphql_query = Some(decoded_value.into_owned()),
                "operationName" => operation_name = Some(decoded_value.into_owned()),
                "variables" => {
                    variables = serde_json::from_str(&decoded_value).ok();
                }
                _ => {}
            }
        }
    }

    graphql_query.map(|query| GraphqlRequestBody {
        query,
        operation_name,
        variables,
    })
}

/// GraphQL query fingerprint for caching
pub fn query_fingerprint(query: &str, variables: Option<&serde_json::Value>) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    // Normalize whitespace
    let normalized: String = query.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.hash(&mut hasher);

    if let Some(vars) = variables {
        vars.to_string().hash(&mut hasher);
    }

    format!("{:x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_query() {
        let config = GraphqlRoutingConfig::default();
        let analyzer = GraphqlAnalyzer::new(config);

        let query = r#"{ user { id name } }"#;
        let body = serde_json::json!({ "query": query }).to_string();

        let result = analyzer.parse(body.as_bytes()).unwrap();
        assert_eq!(result.operation_type, OperationType::Query);
        assert!(result.depth > 0);
    }

    #[test]
    fn test_parse_mutation() {
        let config = GraphqlRoutingConfig::default();
        let analyzer = GraphqlAnalyzer::new(config);

        let query = r#"mutation CreateUser { createUser(name: "test") { id } }"#;
        let body = serde_json::json!({ "query": query }).to_string();

        let result = analyzer.parse(body.as_bytes()).unwrap();
        assert_eq!(result.operation_type, OperationType::Mutation);
    }

    #[test]
    fn test_parse_subscription() {
        let config = GraphqlRoutingConfig::default();
        let analyzer = GraphqlAnalyzer::new(config);

        let query = r#"subscription OnMessage { messageAdded { id text } }"#;
        let body = serde_json::json!({ "query": query }).to_string();

        let result = analyzer.parse(body.as_bytes()).unwrap();
        assert_eq!(result.operation_type, OperationType::Subscription);
    }

    #[test]
    fn test_depth_calculation() {
        let config = GraphqlRoutingConfig::default();
        let analyzer = GraphqlAnalyzer::new(config);

        let query = r#"{ user { posts { comments { author { name } } } } }"#;
        let body = serde_json::json!({ "query": query }).to_string();

        let result = analyzer.parse(body.as_bytes()).unwrap();
        assert!(result.depth >= 4);
    }

    #[test]
    fn test_depth_limit_exceeded() {
        let config = GraphqlRoutingConfig {
            enabled: true,
            max_depth: 2,
            ..Default::default()
        };
        let analyzer = GraphqlAnalyzer::new(config);

        let query = r#"{ user { posts { comments { author { name } } } } }"#;
        let body = serde_json::json!({ "query": query }).to_string();

        let result = analyzer.parse(body.as_bytes());
        assert!(matches!(result, Err(GraphqlError::DepthExceeded { .. })));
    }

    #[test]
    fn test_introspection_blocking() {
        let config = GraphqlRoutingConfig {
            enabled: true,
            block_introspection: true,
            ..Default::default()
        };
        let analyzer = GraphqlAnalyzer::new(config);

        let query = r#"{ __schema { types { name } } }"#;
        let body = serde_json::json!({ "query": query }).to_string();

        let result = analyzer.parse(body.as_bytes());
        assert!(matches!(result, Err(GraphqlError::IntrospectionBlocked)));
    }

    #[test]
    fn test_field_extraction() {
        let config = GraphqlRoutingConfig::default();
        let analyzer = GraphqlAnalyzer::new(config);

        let query = r#"{ user { id name email posts { title } } }"#;
        let body = serde_json::json!({ "query": query }).to_string();

        let result = analyzer.parse(body.as_bytes()).unwrap();
        assert!(result.fields.contains("user"));
        assert!(result.fields.contains("id"));
        assert!(result.fields.contains("name"));
        assert!(result.fields.contains("email"));
        assert!(result.fields.contains("posts"));
        assert!(result.fields.contains("title"));
    }

    #[test]
    fn test_query_fingerprint() {
        let query1 = "{ user { id } }";
        let query2 = "{  user  {  id  }  }";

        // Should produce same fingerprint with normalized whitespace
        let fp1 = query_fingerprint(query1, None);
        let fp2 = query_fingerprint(query2, None);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_operation_type_routing() {
        let config = GraphqlRoutingConfig {
            enabled: true,
            mutation_upstream: Some("write-backend".to_string()),
            subscription_upstream: Some("ws-backend".to_string()),
            ..Default::default()
        };
        let analyzer = GraphqlAnalyzer::new(config);

        let mutation_query = r#"mutation { updateUser { id } }"#;
        let body = serde_json::json!({ "query": mutation_query }).to_string();
        let result = analyzer.parse(body.as_bytes()).unwrap();

        let upstream = analyzer.get_upstream(&result);
        assert_eq!(upstream, Some("write-backend"));
    }

    #[test]
    fn test_operation_specific_routing() {
        let mut operation_routes = HashMap::new();
        operation_routes.insert("GetUser".to_string(), "user-service".to_string());

        let config = GraphqlRoutingConfig {
            enabled: true,
            operation_routes,
            ..Default::default()
        };
        let analyzer = GraphqlAnalyzer::new(config);

        let query = r#"query GetUser { user { id } }"#;
        let body = serde_json::json!({
            "query": query,
            "operationName": "GetUser"
        })
        .to_string();
        let result = analyzer.parse(body.as_bytes()).unwrap();

        let upstream = analyzer.get_upstream(&result);
        assert_eq!(upstream, Some("user-service"));
    }

    #[test]
    fn test_graphql_error_response() {
        let error = GraphqlError::DepthExceeded { max: 5, actual: 10 };
        let response = error.to_response();

        assert_eq!(response.errors.len(), 1);
        assert!(response.errors[0].message.contains("10"));
        assert!(response.errors[0].message.contains("5"));
    }

    #[test]
    fn test_extract_graphql_from_query_string() {
        let uri: http::Uri = "http://example.com/graphql?query=%7B%20user%20%7B%20id%20%7D%20%7D&operationName=GetUser"
            .parse()
            .unwrap();

        let result = extract_graphql_from_query(&uri).unwrap();
        assert_eq!(result.query, "{ user { id } }");
        assert_eq!(result.operation_name, Some("GetUser".to_string()));
    }
}
