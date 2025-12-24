//! GraphQL Federation Module
//!
//! Implements Apollo Federation-compatible schema composition and query routing:
//! - Schema composition from multiple subgraphs
//! - Query planning and execution
//! - Entity resolution across services
//! - Field-level routing

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Federation configuration
#[derive(Debug, Clone)]
pub struct FederationConfig {
    /// Enable query planning optimization
    pub optimize_queries: bool,
    /// Maximum query depth
    pub max_depth: usize,
    /// Maximum complexity score
    pub max_complexity: u64,
    /// Enable query batching to subgraphs
    pub batch_queries: bool,
    /// Batch window duration
    pub batch_window: Duration,
    /// Enable introspection
    pub introspection_enabled: bool,
    /// Default timeout for subgraph requests
    pub subgraph_timeout: Duration,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            optimize_queries: true,
            max_depth: 10,
            max_complexity: 1000,
            batch_queries: true,
            batch_window: Duration::from_millis(10),
            introspection_enabled: true,
            subgraph_timeout: Duration::from_secs(30),
        }
    }
}

/// Subgraph definition
#[derive(Debug, Clone)]
pub struct Subgraph {
    pub name: String,
    pub url: String,
    pub schema: SubgraphSchema,
}

/// Subgraph schema information
#[derive(Debug, Clone, Default)]
pub struct SubgraphSchema {
    /// Types defined by this subgraph
    pub types: HashMap<String, TypeDefinition>,
    /// Entity types (with @key directive)
    pub entities: HashMap<String, EntityDefinition>,
    /// Root query fields
    pub query_fields: HashMap<String, FieldDefinition>,
    /// Root mutation fields
    pub mutation_fields: HashMap<String, FieldDefinition>,
}

/// Type definition
#[derive(Debug, Clone)]
pub struct TypeDefinition {
    pub name: String,
    pub kind: TypeKind,
    pub fields: HashMap<String, FieldDefinition>,
    pub implements: Vec<String>,
}

/// Type kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeKind {
    Object,
    Interface,
    Union,
    Enum,
    Scalar,
    InputObject,
}

/// Field definition
#[derive(Debug, Clone)]
pub struct FieldDefinition {
    pub name: String,
    pub return_type: String,
    pub arguments: Vec<ArgumentDefinition>,
    pub requires: Option<String>,
    pub provides: Option<String>,
    pub external: bool,
}

/// Argument definition
#[derive(Debug, Clone)]
pub struct ArgumentDefinition {
    pub name: String,
    pub arg_type: String,
    pub default_value: Option<String>,
}

/// Entity definition (type with @key)
#[derive(Debug, Clone)]
pub struct EntityDefinition {
    pub type_name: String,
    pub keys: Vec<KeyDefinition>,
    pub owning_subgraph: String,
}

/// Key definition for entity resolution
#[derive(Debug, Clone)]
pub struct KeyDefinition {
    pub fields: String,
    pub resolvable: bool,
}

/// Supergraph (composed schema)
#[derive(Debug, Clone)]
pub struct Supergraph {
    pub types: HashMap<String, ComposedType>,
    pub entities: HashMap<String, ComposedEntity>,
    pub query_fields: HashMap<String, ComposedField>,
    pub mutation_fields: HashMap<String, ComposedField>,
}

/// Composed type from multiple subgraphs
#[derive(Debug, Clone)]
pub struct ComposedType {
    pub name: String,
    pub kind: TypeKind,
    pub fields: HashMap<String, ComposedField>,
    pub subgraphs: Vec<String>,
}

/// Composed field with routing info
#[derive(Debug, Clone)]
pub struct ComposedField {
    pub name: String,
    pub return_type: String,
    pub owning_subgraph: String,
    pub requires: Option<RequiresInfo>,
}

/// Requirements for field resolution
#[derive(Debug, Clone)]
pub struct RequiresInfo {
    pub fields: String,
    pub from_subgraph: String,
}

/// Composed entity across subgraphs
#[derive(Debug, Clone)]
pub struct ComposedEntity {
    pub type_name: String,
    pub keys: Vec<ComposedKey>,
    pub subgraphs: Vec<EntitySubgraph>,
}

/// Key with subgraph info
#[derive(Debug, Clone)]
pub struct ComposedKey {
    pub fields: String,
    pub subgraph: String,
}

/// Entity presence in a subgraph
#[derive(Debug, Clone)]
pub struct EntitySubgraph {
    pub name: String,
    pub provides: Vec<String>,
}

/// Query plan for execution
#[derive(Debug, Clone)]
pub struct QueryPlan {
    pub root: PlanNode,
    pub complexity: u64,
    pub estimated_cost: f64,
}

/// Query plan node
#[derive(Debug, Clone)]
pub enum PlanNode {
    /// Fetch from a single subgraph
    Fetch(FetchNode),
    /// Execute nodes in sequence
    Sequence(Vec<PlanNode>),
    /// Execute nodes in parallel
    Parallel(Vec<PlanNode>),
    /// Flatten nested results
    Flatten(FlattenNode),
}

/// Fetch from subgraph
#[derive(Debug, Clone)]
pub struct FetchNode {
    pub subgraph: String,
    pub query: String,
    pub requires: Option<String>,
    pub provides: Vec<String>,
}

/// Flatten nested data
#[derive(Debug, Clone)]
pub struct FlattenNode {
    pub path: Vec<String>,
    pub node: Box<PlanNode>,
}

/// GraphQL request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLRequest {
    pub query: String,
    #[serde(default)]
    pub operation_name: Option<String>,
    #[serde(default)]
    pub variables: HashMap<String, serde_json::Value>,
}

/// GraphQL response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<GraphQLError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// GraphQL error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLError {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<Location>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Source location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub line: u32,
    pub column: u32,
}

/// Federation gateway
pub struct FederationGateway {
    config: FederationConfig,
    subgraphs: DashMap<String, Arc<Subgraph>>,
    supergraph: RwLock<Option<Supergraph>>,
    client: reqwest::Client,
    stats: FederationStats,
}

/// Federation statistics
#[derive(Debug, Default)]
pub struct FederationStats {
    pub queries_received: AtomicU64,
    pub queries_planned: AtomicU64,
    pub subgraph_fetches: AtomicU64,
    pub entity_resolutions: AtomicU64,
    pub composition_errors: AtomicU64,
    pub query_errors: AtomicU64,
}

impl FederationGateway {
    pub fn new(config: FederationConfig) -> Self {
        Self {
            config,
            subgraphs: DashMap::new(),
            supergraph: RwLock::new(None),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            stats: FederationStats::default(),
        }
    }

    /// Register a subgraph
    pub fn register_subgraph(&self, subgraph: Subgraph) {
        self.subgraphs
            .insert(subgraph.name.clone(), Arc::new(subgraph));
    }

    /// Compose supergraph from subgraphs
    pub fn compose(&self) -> Result<(), Vec<CompositionError>> {
        let mut errors = Vec::new();
        let mut types: HashMap<String, ComposedType> = HashMap::new();
        let mut entities: HashMap<String, ComposedEntity> = HashMap::new();
        let mut query_fields: HashMap<String, ComposedField> = HashMap::new();
        let mut mutation_fields: HashMap<String, ComposedField> = HashMap::new();

        // Collect all types and entities from subgraphs
        for entry in self.subgraphs.iter() {
            let subgraph = entry.value();
            let subgraph_name = &subgraph.name;

            // Compose types
            for (type_name, type_def) in &subgraph.schema.types {
                let composed = types
                    .entry(type_name.clone())
                    .or_insert_with(|| ComposedType {
                        name: type_name.clone(),
                        kind: type_def.kind,
                        fields: HashMap::new(),
                        subgraphs: Vec::new(),
                    });

                // Check for conflicting type kinds
                if composed.kind != type_def.kind {
                    errors.push(CompositionError {
                        message: format!(
                            "Type {} has conflicting kinds in different subgraphs",
                            type_name
                        ),
                        subgraphs: vec![
                            composed.subgraphs.first().cloned().unwrap_or_default(),
                            subgraph_name.clone(),
                        ],
                    });
                }

                composed.subgraphs.push(subgraph_name.clone());

                // Compose fields
                for (field_name, field_def) in &type_def.fields {
                    if !field_def.external {
                        if let Some(existing) = composed.fields.get(field_name) {
                            if existing.return_type != field_def.return_type {
                                errors.push(CompositionError {
                                    message: format!(
                                        "Field {}.{} has conflicting return types",
                                        type_name, field_name
                                    ),
                                    subgraphs: vec![
                                        existing.owning_subgraph.clone(),
                                        subgraph_name.clone(),
                                    ],
                                });
                            }
                        } else {
                            composed.fields.insert(
                                field_name.clone(),
                                ComposedField {
                                    name: field_name.clone(),
                                    return_type: field_def.return_type.clone(),
                                    owning_subgraph: subgraph_name.clone(),
                                    requires: field_def.requires.as_ref().map(|r| RequiresInfo {
                                        fields: r.clone(),
                                        from_subgraph: subgraph_name.clone(),
                                    }),
                                },
                            );
                        }
                    }
                }
            }

            // Compose entities
            for (entity_name, entity_def) in &subgraph.schema.entities {
                let composed =
                    entities
                        .entry(entity_name.clone())
                        .or_insert_with(|| ComposedEntity {
                            type_name: entity_name.clone(),
                            keys: Vec::new(),
                            subgraphs: Vec::new(),
                        });

                for key in &entity_def.keys {
                    composed.keys.push(ComposedKey {
                        fields: key.fields.clone(),
                        subgraph: subgraph_name.clone(),
                    });
                }

                // Track which fields this subgraph provides
                let mut provides = Vec::new();
                if let Some(type_def) = subgraph.schema.types.get(entity_name) {
                    for (field_name, field_def) in &type_def.fields {
                        if !field_def.external {
                            provides.push(field_name.clone());
                        }
                    }
                }

                composed.subgraphs.push(EntitySubgraph {
                    name: subgraph_name.clone(),
                    provides,
                });
            }

            // Compose query fields
            for (field_name, field_def) in &subgraph.schema.query_fields {
                if query_fields.contains_key(field_name) {
                    errors.push(CompositionError {
                        message: format!("Duplicate query field: {}", field_name),
                        subgraphs: vec![subgraph_name.clone()],
                    });
                } else {
                    query_fields.insert(
                        field_name.clone(),
                        ComposedField {
                            name: field_name.clone(),
                            return_type: field_def.return_type.clone(),
                            owning_subgraph: subgraph_name.clone(),
                            requires: None,
                        },
                    );
                }
            }

            // Compose mutation fields
            for (field_name, field_def) in &subgraph.schema.mutation_fields {
                if mutation_fields.contains_key(field_name) {
                    errors.push(CompositionError {
                        message: format!("Duplicate mutation field: {}", field_name),
                        subgraphs: vec![subgraph_name.clone()],
                    });
                } else {
                    mutation_fields.insert(
                        field_name.clone(),
                        ComposedField {
                            name: field_name.clone(),
                            return_type: field_def.return_type.clone(),
                            owning_subgraph: subgraph_name.clone(),
                            requires: None,
                        },
                    );
                }
            }
        }

        if !errors.is_empty() {
            self.stats
                .composition_errors
                .fetch_add(errors.len() as u64, Ordering::Relaxed);
            return Err(errors);
        }

        let supergraph = Supergraph {
            types,
            entities,
            query_fields,
            mutation_fields,
        };

        *self.supergraph.write() = Some(supergraph);
        Ok(())
    }

    /// Plan query execution
    pub fn plan(&self, request: &GraphQLRequest) -> Result<QueryPlan, PlanningError> {
        self.stats.queries_received.fetch_add(1, Ordering::Relaxed);

        let supergraph = self.supergraph.read();
        let supergraph = supergraph.as_ref().ok_or(PlanningError::NoSupergraph)?;

        // Parse query (simplified - in real impl would use graphql-parser)
        let parsed = self.parse_query(&request.query)?;

        // Check depth
        let depth = self.calculate_depth(&parsed);
        if depth > self.config.max_depth {
            return Err(PlanningError::MaxDepthExceeded(depth));
        }

        // Calculate complexity
        let complexity = self.calculate_complexity(&parsed);
        if complexity > self.config.max_complexity {
            return Err(PlanningError::MaxComplexityExceeded(complexity));
        }

        // Build query plan
        let root = self.build_plan(&parsed, supergraph)?;

        self.stats.queries_planned.fetch_add(1, Ordering::Relaxed);

        Ok(QueryPlan {
            root,
            complexity,
            estimated_cost: complexity as f64 * 0.1,
        })
    }

    /// Execute query plan
    pub async fn execute(&self, plan: &QueryPlan) -> GraphQLResponse {
        match self.execute_node(&plan.root).await {
            Ok(data) => GraphQLResponse {
                data: Some(data),
                errors: Vec::new(),
                extensions: None,
            },
            Err(e) => {
                self.stats.query_errors.fetch_add(1, Ordering::Relaxed);
                GraphQLResponse {
                    data: None,
                    errors: vec![GraphQLError {
                        message: e.to_string(),
                        locations: None,
                        path: None,
                        extensions: None,
                    }],
                    extensions: None,
                }
            }
        }
    }

    fn execute_node<'a>(
        &'a self,
        node: &'a PlanNode,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<serde_json::Value, ExecutionError>> + Send + 'a,
        >,
    > {
        Box::pin(async move {
            match node {
                PlanNode::Fetch(fetch) => self.execute_fetch(fetch).await,
                PlanNode::Sequence(nodes) => {
                    let mut result = serde_json::Value::Null;
                    for n in nodes {
                        result = self.execute_node(n).await?;
                    }
                    Ok(result)
                }
                PlanNode::Parallel(nodes) => {
                    let futures: Vec<_> = nodes.iter().map(|n| self.execute_node(n)).collect();
                    let results = futures::future::join_all(futures).await;

                    // Merge results
                    let mut merged = serde_json::Map::new();
                    for result in results {
                        if let Ok(serde_json::Value::Object(map)) = result {
                            for (k, v) in map {
                                merged.insert(k, v);
                            }
                        }
                    }
                    Ok(serde_json::Value::Object(merged))
                }
                PlanNode::Flatten(flatten) => {
                    let inner = self.execute_node(&flatten.node).await?;
                    Ok(self.flatten_result(&flatten.path, inner))
                }
            }
        })
    }

    async fn execute_fetch(&self, fetch: &FetchNode) -> Result<serde_json::Value, ExecutionError> {
        self.stats.subgraph_fetches.fetch_add(1, Ordering::Relaxed);

        let subgraph = self
            .subgraphs
            .get(&fetch.subgraph)
            .ok_or(ExecutionError::SubgraphNotFound(fetch.subgraph.clone()))?;

        let request = GraphQLRequest {
            query: fetch.query.clone(),
            operation_name: None,
            variables: HashMap::new(),
        };

        let response = self
            .client
            .post(&subgraph.url)
            .json(&request)
            .timeout(self.config.subgraph_timeout)
            .send()
            .await
            .map_err(|e| ExecutionError::NetworkError(e.to_string()))?;

        let graphql_response: GraphQLResponse = response
            .json()
            .await
            .map_err(|e| ExecutionError::ParseError(e.to_string()))?;

        if !graphql_response.errors.is_empty() {
            return Err(ExecutionError::SubgraphError(
                graphql_response.errors.first().unwrap().message.clone(),
            ));
        }

        Ok(graphql_response.data.unwrap_or(serde_json::Value::Null))
    }

    #[allow(clippy::only_used_in_recursion)]
    fn flatten_result(&self, path: &[String], value: serde_json::Value) -> serde_json::Value {
        if path.is_empty() {
            return value;
        }

        if let serde_json::Value::Object(mut map) = value {
            if let Some(inner) = map.remove(&path[0]) {
                return self.flatten_result(&path[1..], inner);
            }
        }

        serde_json::Value::Null
    }

    /// Resolve entities from representations
    #[allow(clippy::await_holding_lock)]
    pub async fn resolve_entities(
        &self,
        type_name: &str,
        representations: Vec<serde_json::Value>,
    ) -> Result<Vec<serde_json::Value>, ExecutionError> {
        self.stats
            .entity_resolutions
            .fetch_add(representations.len() as u64, Ordering::Relaxed);

        let supergraph = self.supergraph.read();
        let supergraph = supergraph.as_ref().ok_or(ExecutionError::NoSupergraph)?;

        let entity = supergraph
            .entities
            .get(type_name)
            .ok_or(ExecutionError::EntityNotFound(type_name.to_string()))?;

        // Find subgraph that can resolve this entity
        let subgraph_name = entity
            .keys
            .first()
            .map(|k| &k.subgraph)
            .ok_or(ExecutionError::NoKeyForEntity(type_name.to_string()))?;

        let subgraph = self
            .subgraphs
            .get(subgraph_name)
            .ok_or(ExecutionError::SubgraphNotFound(subgraph_name.clone()))?;

        // Build _entities query
        let query = format!(
            r#"query($representations: [_Any!]!) {{
                _entities(representations: $representations) {{
                    ... on {} {{
                        __typename
                    }}
                }}
            }}"#,
            type_name
        );

        let mut variables = HashMap::new();
        variables.insert(
            "representations".to_string(),
            serde_json::Value::Array(representations),
        );

        let request = GraphQLRequest {
            query,
            operation_name: None,
            variables,
        };

        let response = self
            .client
            .post(&subgraph.url)
            .json(&request)
            .timeout(self.config.subgraph_timeout)
            .send()
            .await
            .map_err(|e| ExecutionError::NetworkError(e.to_string()))?;

        let graphql_response: GraphQLResponse = response
            .json()
            .await
            .map_err(|e| ExecutionError::ParseError(e.to_string()))?;

        if let Some(data) = graphql_response.data {
            if let Some(entities) = data.get("_entities").and_then(|e| e.as_array()) {
                return Ok(entities.clone());
            }
        }

        Ok(Vec::new())
    }

    // Simplified query parsing
    fn parse_query(&self, _query: &str) -> Result<ParsedQuery, PlanningError> {
        // In real impl, would use graphql-parser
        Ok(ParsedQuery {
            operation: OperationType::Query,
            selections: Vec::new(),
        })
    }

    fn calculate_depth(&self, _parsed: &ParsedQuery) -> usize {
        // Simplified
        1
    }

    fn calculate_complexity(&self, _parsed: &ParsedQuery) -> u64 {
        // Simplified
        1
    }

    fn build_plan(
        &self,
        parsed: &ParsedQuery,
        supergraph: &Supergraph,
    ) -> Result<PlanNode, PlanningError> {
        // Simplified plan building
        let fields = match parsed.operation {
            OperationType::Query => &supergraph.query_fields,
            OperationType::Mutation => &supergraph.mutation_fields,
        };

        let mut fetches = Vec::new();

        // Group fields by subgraph
        let mut by_subgraph: HashMap<String, Vec<String>> = HashMap::new();
        for (field_name, field) in fields {
            by_subgraph
                .entry(field.owning_subgraph.clone())
                .or_default()
                .push(field_name.clone());
        }

        for (subgraph, field_names) in by_subgraph {
            let query = format!("{{ {} }}", field_names.join(" "));
            fetches.push(PlanNode::Fetch(FetchNode {
                subgraph,
                query,
                requires: None,
                provides: field_names,
            }));
        }

        if fetches.len() == 1 {
            Ok(fetches.remove(0))
        } else if self.config.optimize_queries {
            Ok(PlanNode::Parallel(fetches))
        } else {
            Ok(PlanNode::Sequence(fetches))
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &FederationStats {
        &self.stats
    }
}

/// Parsed query (simplified)
#[derive(Debug)]
#[allow(dead_code)]
struct ParsedQuery {
    operation: OperationType,
    selections: Vec<Selection>,
}

#[derive(Debug)]
#[allow(dead_code)]
enum OperationType {
    Query,
    Mutation,
}

#[derive(Debug)]
#[allow(dead_code)]
struct Selection {
    name: String,
    arguments: HashMap<String, String>,
    selections: Vec<Selection>,
}

/// Composition error
#[derive(Debug, Clone)]
pub struct CompositionError {
    pub message: String,
    pub subgraphs: Vec<String>,
}

/// Planning error
#[derive(Debug)]
pub enum PlanningError {
    NoSupergraph,
    MaxDepthExceeded(usize),
    MaxComplexityExceeded(u64),
    ParseError(String),
    FieldNotFound(String),
}

impl std::fmt::Display for PlanningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSupergraph => write!(f, "No supergraph composed"),
            Self::MaxDepthExceeded(d) => write!(f, "Max depth exceeded: {}", d),
            Self::MaxComplexityExceeded(c) => write!(f, "Max complexity exceeded: {}", c),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
            Self::FieldNotFound(f_name) => write!(f, "Field not found: {}", f_name),
        }
    }
}

/// Execution error
#[derive(Debug)]
pub enum ExecutionError {
    NoSupergraph,
    SubgraphNotFound(String),
    EntityNotFound(String),
    NoKeyForEntity(String),
    NetworkError(String),
    ParseError(String),
    SubgraphError(String),
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSupergraph => write!(f, "No supergraph composed"),
            Self::SubgraphNotFound(s) => write!(f, "Subgraph not found: {}", s),
            Self::EntityNotFound(e) => write!(f, "Entity not found: {}", e),
            Self::NoKeyForEntity(e) => write!(f, "No key for entity: {}", e),
            Self::NetworkError(e) => write!(f, "Network error: {}", e),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
            Self::SubgraphError(e) => write!(f, "Subgraph error: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_subgraph(name: &str) -> Subgraph {
        let mut types = HashMap::new();
        let mut fields = HashMap::new();
        fields.insert(
            "id".to_string(),
            FieldDefinition {
                name: "id".to_string(),
                return_type: "ID!".to_string(),
                arguments: Vec::new(),
                requires: None,
                provides: None,
                external: false,
            },
        );
        fields.insert(
            "name".to_string(),
            FieldDefinition {
                name: "name".to_string(),
                return_type: "String!".to_string(),
                arguments: Vec::new(),
                requires: None,
                provides: None,
                external: false,
            },
        );

        types.insert(
            "User".to_string(),
            TypeDefinition {
                name: "User".to_string(),
                kind: TypeKind::Object,
                fields,
                implements: Vec::new(),
            },
        );

        let mut entities = HashMap::new();
        entities.insert(
            "User".to_string(),
            EntityDefinition {
                type_name: "User".to_string(),
                keys: vec![KeyDefinition {
                    fields: "id".to_string(),
                    resolvable: true,
                }],
                owning_subgraph: name.to_string(),
            },
        );

        let mut query_fields = HashMap::new();
        query_fields.insert(
            "user".to_string(),
            FieldDefinition {
                name: "user".to_string(),
                return_type: "User".to_string(),
                arguments: vec![ArgumentDefinition {
                    name: "id".to_string(),
                    arg_type: "ID!".to_string(),
                    default_value: None,
                }],
                requires: None,
                provides: None,
                external: false,
            },
        );

        Subgraph {
            name: name.to_string(),
            url: format!("http://localhost:4001/{}", name),
            schema: SubgraphSchema {
                types,
                entities,
                query_fields,
                mutation_fields: HashMap::new(),
            },
        }
    }

    #[test]
    fn test_register_subgraph() {
        let gateway = FederationGateway::new(FederationConfig::default());
        let subgraph = create_test_subgraph("users");
        gateway.register_subgraph(subgraph);

        assert!(gateway.subgraphs.contains_key("users"));
    }

    #[test]
    fn test_compose_single_subgraph() {
        let gateway = FederationGateway::new(FederationConfig::default());
        gateway.register_subgraph(create_test_subgraph("users"));

        let result = gateway.compose();
        assert!(result.is_ok());

        let supergraph = gateway.supergraph.read();
        assert!(supergraph.is_some());

        let sg = supergraph.as_ref().unwrap();
        assert!(sg.types.contains_key("User"));
        assert!(sg.entities.contains_key("User"));
        assert!(sg.query_fields.contains_key("user"));
    }

    #[test]
    fn test_compose_multiple_subgraphs() {
        let gateway = FederationGateway::new(FederationConfig::default());
        gateway.register_subgraph(create_test_subgraph("users"));

        // Add another subgraph with different types
        let mut products = create_test_subgraph("products");
        products.schema.types.clear();
        products.schema.entities.clear();
        products.schema.query_fields.clear();

        let mut fields = HashMap::new();
        fields.insert(
            "id".to_string(),
            FieldDefinition {
                name: "id".to_string(),
                return_type: "ID!".to_string(),
                arguments: Vec::new(),
                requires: None,
                provides: None,
                external: false,
            },
        );

        products.schema.types.insert(
            "Product".to_string(),
            TypeDefinition {
                name: "Product".to_string(),
                kind: TypeKind::Object,
                fields,
                implements: Vec::new(),
            },
        );

        products.schema.query_fields.insert(
            "products".to_string(),
            FieldDefinition {
                name: "products".to_string(),
                return_type: "[Product!]!".to_string(),
                arguments: Vec::new(),
                requires: None,
                provides: None,
                external: false,
            },
        );

        gateway.register_subgraph(products);

        let result = gateway.compose();
        assert!(result.is_ok());

        let supergraph = gateway.supergraph.read();
        let sg = supergraph.as_ref().unwrap();
        assert!(sg.types.contains_key("User"));
        assert!(sg.types.contains_key("Product"));
        assert!(sg.query_fields.contains_key("user"));
        assert!(sg.query_fields.contains_key("products"));
    }

    #[test]
    fn test_plan_query() {
        let gateway = FederationGateway::new(FederationConfig::default());
        gateway.register_subgraph(create_test_subgraph("users"));
        gateway.compose().unwrap();

        let request = GraphQLRequest {
            query: "{ user(id: \"1\") { id name } }".to_string(),
            operation_name: None,
            variables: HashMap::new(),
        };

        let plan = gateway.plan(&request);
        assert!(plan.is_ok());
    }

    #[test]
    fn test_graphql_request_serialization() {
        let request = GraphQLRequest {
            query: "{ hello }".to_string(),
            operation_name: Some("Hello".to_string()),
            variables: HashMap::new(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("hello"));

        let deserialized: GraphQLRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.query, request.query);
    }

    #[test]
    fn test_graphql_response_serialization() {
        let response = GraphQLResponse {
            data: Some(serde_json::json!({"hello": "world"})),
            errors: Vec::new(),
            extensions: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("hello"));
        assert!(!json.contains("errors")); // Empty errors should be skipped
    }

    #[test]
    fn test_stats() {
        let gateway = FederationGateway::new(FederationConfig::default());
        gateway.register_subgraph(create_test_subgraph("users"));
        gateway.compose().unwrap();

        let request = GraphQLRequest {
            query: "{ user(id: \"1\") { id } }".to_string(),
            operation_name: None,
            variables: HashMap::new(),
        };

        gateway.plan(&request).unwrap();

        assert_eq!(gateway.stats().queries_received.load(Ordering::Relaxed), 1);
        assert_eq!(gateway.stats().queries_planned.load(Ordering::Relaxed), 1);
    }
}
