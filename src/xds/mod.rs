//! xDS API Implementation (Envoy Data Plane API)
//!
//! Enables Prism to receive dynamic configuration from xDS control planes:
//! - Listener Discovery Service (LDS)
//! - Route Discovery Service (RDS)
//! - Cluster Discovery Service (CDS)
//! - Endpoint Discovery Service (EDS)
//! - Secret Discovery Service (SDS)
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      Control Plane (Istio/etc)                  │
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │                    xDS Server (gRPC)                        ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! └────────────────────────────┬────────────────────────────────────┘
//!                              │ gRPC Stream
//!                              │ (ADS/Delta)
//! ┌────────────────────────────▼────────────────────────────────────┐
//! │                         Prism xDS Client                         │
//! │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌────────┐│
//! │  │   LDS   │  │   RDS   │  │   CDS   │  │   EDS   │  │  SDS   ││
//! │  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  └───┬────┘│
//! │       │            │            │            │           │      │
//! │  ┌────▼────────────▼────────────▼────────────▼───────────▼────┐│
//! │  │                    Config Updater                          ││
//! │  └────────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Supported Features
//! - Aggregated Discovery Service (ADS)
//! - Incremental/Delta xDS
//! - NACK support with error details
//! - Resource versioning
//! - Locality-aware load balancing

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// xDS client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XdsConfig {
    /// Enable xDS integration
    #[serde(default)]
    pub enabled: bool,

    /// xDS server address (gRPC)
    #[serde(default = "default_server")]
    pub server_address: String,

    /// Node ID for this instance
    #[serde(default = "default_node_id")]
    pub node_id: String,

    /// Cluster name
    #[serde(default = "default_cluster")]
    pub cluster: String,

    /// Zone/locality
    #[serde(default)]
    pub zone: Option<String>,

    /// Use ADS (Aggregated Discovery Service)
    #[serde(default = "default_true")]
    pub use_ads: bool,

    /// Use Delta/Incremental xDS
    #[serde(default)]
    pub use_delta: bool,

    /// Initial fetch timeout (seconds)
    #[serde(default = "default_initial_timeout")]
    pub initial_fetch_timeout_secs: u64,

    /// Reconnect delay (milliseconds)
    #[serde(default = "default_reconnect_delay")]
    pub reconnect_delay_ms: u64,

    /// Resource types to subscribe to
    #[serde(default)]
    pub subscriptions: XdsSubscriptions,
}

impl Default for XdsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_address: default_server(),
            node_id: default_node_id(),
            cluster: default_cluster(),
            zone: None,
            use_ads: true,
            use_delta: false,
            initial_fetch_timeout_secs: default_initial_timeout(),
            reconnect_delay_ms: default_reconnect_delay(),
            subscriptions: XdsSubscriptions::default(),
        }
    }
}

fn default_server() -> String {
    "localhost:15010".to_string()
}

fn default_node_id() -> String {
    format!("prism-{}", uuid::Uuid::new_v4())
}

fn default_cluster() -> String {
    "prism".to_string()
}

fn default_true() -> bool {
    true
}

fn default_initial_timeout() -> u64 {
    15
}

fn default_reconnect_delay() -> u64 {
    1000
}

/// Which xDS resource types to subscribe to
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdsSubscriptions {
    #[serde(default = "default_true")]
    pub listeners: bool,
    #[serde(default = "default_true")]
    pub routes: bool,
    #[serde(default = "default_true")]
    pub clusters: bool,
    #[serde(default = "default_true")]
    pub endpoints: bool,
    #[serde(default)]
    pub secrets: bool,
}

impl Default for XdsSubscriptions {
    fn default() -> Self {
        Self {
            listeners: true,
            routes: true,
            clusters: true,
            endpoints: true,
            secrets: false,
        }
    }
}

/// xDS resource types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceType {
    Listener,
    RouteConfiguration,
    Cluster,
    ClusterLoadAssignment, // EDS
    Secret,
    Runtime,
    ScopedRouteConfiguration,
    VirtualHost,
}

impl ResourceType {
    /// Get the type URL for this resource
    pub fn type_url(&self) -> &'static str {
        match self {
            ResourceType::Listener => "type.googleapis.com/envoy.config.listener.v3.Listener",
            ResourceType::RouteConfiguration => {
                "type.googleapis.com/envoy.config.route.v3.RouteConfiguration"
            }
            ResourceType::Cluster => "type.googleapis.com/envoy.config.cluster.v3.Cluster",
            ResourceType::ClusterLoadAssignment => {
                "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment"
            }
            ResourceType::Secret => {
                "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"
            }
            ResourceType::Runtime => "type.googleapis.com/envoy.service.runtime.v3.Runtime",
            ResourceType::ScopedRouteConfiguration => {
                "type.googleapis.com/envoy.config.route.v3.ScopedRouteConfiguration"
            }
            ResourceType::VirtualHost => "type.googleapis.com/envoy.config.route.v3.VirtualHost",
        }
    }

    /// Parse from type URL
    pub fn from_type_url(url: &str) -> Option<Self> {
        match url {
            "type.googleapis.com/envoy.config.listener.v3.Listener" => Some(ResourceType::Listener),
            "type.googleapis.com/envoy.config.route.v3.RouteConfiguration" => {
                Some(ResourceType::RouteConfiguration)
            }
            "type.googleapis.com/envoy.config.cluster.v3.Cluster" => Some(ResourceType::Cluster),
            "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment" => {
                Some(ResourceType::ClusterLoadAssignment)
            }
            "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret" => {
                Some(ResourceType::Secret)
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceType::Listener => write!(f, "LDS"),
            ResourceType::RouteConfiguration => write!(f, "RDS"),
            ResourceType::Cluster => write!(f, "CDS"),
            ResourceType::ClusterLoadAssignment => write!(f, "EDS"),
            ResourceType::Secret => write!(f, "SDS"),
            ResourceType::Runtime => write!(f, "RTDS"),
            ResourceType::ScopedRouteConfiguration => write!(f, "SRDS"),
            ResourceType::VirtualHost => write!(f, "VHDS"),
        }
    }
}

/// Node information sent to control plane
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node identifier
    pub id: String,
    /// Cluster this node belongs to
    pub cluster: String,
    /// Metadata about this node
    pub metadata: HashMap<String, String>,
    /// Locality information
    pub locality: Option<Locality>,
    /// Build version
    pub build_version: String,
    /// User agent
    pub user_agent: String,
}

impl NodeInfo {
    pub fn new(id: String, cluster: String) -> Self {
        Self {
            id,
            cluster,
            metadata: HashMap::new(),
            locality: None,
            build_version: env!("CARGO_PKG_VERSION").to_string(),
            user_agent: format!("prism/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    pub fn with_locality(mut self, locality: Locality) -> Self {
        self.locality = Some(locality);
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Locality (region/zone/sub-zone)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Locality {
    pub region: Option<String>,
    pub zone: Option<String>,
    pub sub_zone: Option<String>,
}

impl Locality {
    pub fn new() -> Self {
        Self {
            region: None,
            zone: None,
            sub_zone: None,
        }
    }

    pub fn with_zone(mut self, zone: &str) -> Self {
        self.zone = Some(zone.to_string());
        self
    }
}

impl Default for Locality {
    fn default() -> Self {
        Self::new()
    }
}

/// Discovery request (sent to control plane)
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryRequest {
    /// Version info received in last response
    pub version_info: String,
    /// Node information
    pub node: NodeInfo,
    /// Resource names to subscribe to (empty = all)
    pub resource_names: Vec<String>,
    /// Type URL being requested
    pub type_url: String,
    /// Response nonce from last response
    pub response_nonce: String,
    /// Error detail (for NACK)
    pub error_detail: Option<ErrorDetail>,
}

/// Error detail for NACK responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: i32,
    pub message: String,
}

/// Discovery response (received from control plane)
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryResponse {
    /// Version of this response
    pub version_info: String,
    /// Resources in the response
    pub resources: Vec<Resource>,
    /// Whether this is a removal/delete
    pub canary: bool,
    /// Type URL
    pub type_url: String,
    /// Nonce for ACK/NACK
    pub nonce: String,
    /// Control plane identifier
    pub control_plane: Option<ControlPlane>,
}

/// Resource wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    /// Resource name
    pub name: String,
    /// Resource version
    pub version: String,
    /// Resource data (JSON representation)
    pub data: serde_json::Value,
}

/// Control plane identifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlane {
    pub identifier: String,
}

/// Cached resource with metadata
#[derive(Debug, Clone)]
pub struct CachedResource {
    pub name: String,
    pub version: String,
    pub data: serde_json::Value,
    pub received_at: Instant,
    pub last_updated: Instant,
}

impl CachedResource {
    pub fn new(name: String, version: String, data: serde_json::Value) -> Self {
        let now = Instant::now();
        Self {
            name,
            version,
            data,
            received_at: now,
            last_updated: now,
        }
    }

    pub fn age(&self) -> Duration {
        self.received_at.elapsed()
    }
}

/// Resource cache for xDS responses
#[derive(Debug)]
pub struct ResourceCache {
    resources: RwLock<HashMap<ResourceType, HashMap<String, CachedResource>>>,
    versions: RwLock<HashMap<ResourceType, String>>,
    nonces: RwLock<HashMap<ResourceType, String>>,
}

impl ResourceCache {
    pub fn new() -> Self {
        Self {
            resources: RwLock::new(HashMap::new()),
            versions: RwLock::new(HashMap::new()),
            nonces: RwLock::new(HashMap::new()),
        }
    }

    /// Update resources from a discovery response
    pub fn update(&self, resource_type: ResourceType, response: &DiscoveryResponse) {
        let mut resources = self.resources.write();
        let type_resources = resources.entry(resource_type).or_default();

        for resource in &response.resources {
            let cached = CachedResource::new(
                resource.name.clone(),
                resource.version.clone(),
                resource.data.clone(),
            );
            type_resources.insert(resource.name.clone(), cached);
        }

        self.versions
            .write()
            .insert(resource_type, response.version_info.clone());
        self.nonces
            .write()
            .insert(resource_type, response.nonce.clone());
    }

    /// Get a specific resource
    pub fn get(&self, resource_type: ResourceType, name: &str) -> Option<CachedResource> {
        self.resources
            .read()
            .get(&resource_type)?
            .get(name)
            .cloned()
    }

    /// Get all resources of a type
    pub fn get_all(&self, resource_type: ResourceType) -> Vec<CachedResource> {
        self.resources
            .read()
            .get(&resource_type)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Get version for a resource type
    pub fn version(&self, resource_type: ResourceType) -> String {
        self.versions
            .read()
            .get(&resource_type)
            .cloned()
            .unwrap_or_default()
    }

    /// Get nonce for a resource type
    pub fn nonce(&self, resource_type: ResourceType) -> String {
        self.nonces
            .read()
            .get(&resource_type)
            .cloned()
            .unwrap_or_default()
    }

    /// Remove a resource
    pub fn remove(&self, resource_type: ResourceType, name: &str) -> bool {
        self.resources
            .write()
            .get_mut(&resource_type)
            .map(|m| m.remove(name).is_some())
            .unwrap_or(false)
    }

    /// Get statistics
    pub fn stats(&self) -> CacheStats {
        let resources = self.resources.read();
        let mut type_counts = HashMap::new();

        for (rtype, map) in resources.iter() {
            type_counts.insert(format!("{}", rtype), map.len());
        }

        CacheStats {
            total_resources: resources.values().map(|m| m.len()).sum(),
            by_type: type_counts,
        }
    }
}

impl Default for ResourceCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize)]
pub struct CacheStats {
    pub total_resources: usize,
    pub by_type: HashMap<String, usize>,
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Disconnected => write!(f, "disconnected"),
            ConnectionState::Connecting => write!(f, "connecting"),
            ConnectionState::Connected => write!(f, "connected"),
            ConnectionState::Reconnecting => write!(f, "reconnecting"),
        }
    }
}

/// xDS client statistics
#[derive(Debug)]
pub struct XdsStats {
    pub requests_sent: AtomicU64,
    pub responses_received: AtomicU64,
    pub errors: AtomicU64,
    pub nacks_sent: AtomicU64,
    pub reconnections: AtomicU64,
}

impl XdsStats {
    pub fn new() -> Self {
        Self {
            requests_sent: AtomicU64::new(0),
            responses_received: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            nacks_sent: AtomicU64::new(0),
            reconnections: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> XdsStatsSnapshot {
        XdsStatsSnapshot {
            requests_sent: self.requests_sent.load(Ordering::Relaxed),
            responses_received: self.responses_received.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            nacks_sent: self.nacks_sent.load(Ordering::Relaxed),
            reconnections: self.reconnections.load(Ordering::Relaxed),
        }
    }
}

impl Default for XdsStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Stats snapshot
#[derive(Debug, Clone, Serialize)]
pub struct XdsStatsSnapshot {
    pub requests_sent: u64,
    pub responses_received: u64,
    pub errors: u64,
    pub nacks_sent: u64,
    pub reconnections: u64,
}

/// xDS client (mock implementation)
pub struct XdsClient {
    config: XdsConfig,
    node: NodeInfo,
    cache: Arc<ResourceCache>,
    stats: Arc<XdsStats>,
    state: RwLock<ConnectionState>,
    subscribed_resources: RwLock<HashMap<ResourceType, Vec<String>>>,
}

impl XdsClient {
    pub fn new(config: XdsConfig) -> Self {
        let node = NodeInfo::new(config.node_id.clone(), config.cluster.clone())
            .with_metadata("PRISM_VERSION", env!("CARGO_PKG_VERSION"));

        let node = if let Some(zone) = &config.zone {
            node.with_locality(Locality::new().with_zone(zone))
        } else {
            node
        };

        Self {
            config,
            node,
            cache: Arc::new(ResourceCache::new()),
            stats: Arc::new(XdsStats::new()),
            state: RwLock::new(ConnectionState::Disconnected),
            subscribed_resources: RwLock::new(HashMap::new()),
        }
    }

    /// Get the resource cache
    pub fn cache(&self) -> Arc<ResourceCache> {
        self.cache.clone()
    }

    /// Get statistics
    pub fn stats(&self) -> Arc<XdsStats> {
        self.stats.clone()
    }

    /// Get connection state
    pub fn state(&self) -> ConnectionState {
        *self.state.read()
    }

    /// Subscribe to resources
    pub fn subscribe(&self, resource_type: ResourceType, names: Vec<String>) {
        self.subscribed_resources
            .write()
            .entry(resource_type)
            .or_default()
            .extend(names);
    }

    /// Unsubscribe from resources
    pub fn unsubscribe(&self, resource_type: ResourceType, names: &[String]) {
        if let Some(subs) = self.subscribed_resources.write().get_mut(&resource_type) {
            subs.retain(|n| !names.contains(n));
        }
    }

    /// Create a discovery request
    pub fn create_request(&self, resource_type: ResourceType) -> DiscoveryRequest {
        let resource_names = self
            .subscribed_resources
            .read()
            .get(&resource_type)
            .cloned()
            .unwrap_or_default();

        self.stats.requests_sent.fetch_add(1, Ordering::Relaxed);

        DiscoveryRequest {
            version_info: self.cache.version(resource_type),
            node: self.node.clone(),
            resource_names,
            type_url: resource_type.type_url().to_string(),
            response_nonce: self.cache.nonce(resource_type),
            error_detail: None,
        }
    }

    /// Process a discovery response
    pub fn process_response(&self, response: DiscoveryResponse) -> Result<(), String> {
        let resource_type = ResourceType::from_type_url(&response.type_url)
            .ok_or_else(|| format!("Unknown type URL: {}", response.type_url))?;

        self.cache.update(resource_type, &response);
        self.stats
            .responses_received
            .fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Send a NACK
    pub fn create_nack(&self, resource_type: ResourceType, error: ErrorDetail) -> DiscoveryRequest {
        self.stats.nacks_sent.fetch_add(1, Ordering::Relaxed);

        DiscoveryRequest {
            version_info: self.cache.version(resource_type),
            node: self.node.clone(),
            resource_names: vec![],
            type_url: resource_type.type_url().to_string(),
            response_nonce: self.cache.nonce(resource_type),
            error_detail: Some(error),
        }
    }

    /// Get node info
    pub fn node(&self) -> &NodeInfo {
        &self.node
    }

    /// Get configuration
    pub fn config(&self) -> &XdsConfig {
        &self.config
    }
}

/// Convert xDS cluster to Prism upstream
pub fn cluster_to_upstream(resource: &CachedResource) -> Option<UpstreamFromXds> {
    let name = resource.name.clone();
    let data = &resource.data;

    // Parse cluster configuration
    let lb_policy = data
        .get("lb_policy")
        .and_then(|v| v.as_str())
        .unwrap_or("ROUND_ROBIN");

    let connect_timeout = data
        .get("connect_timeout")
        .and_then(|v| v.as_str())
        .and_then(|s| parse_duration(s))
        .unwrap_or(Duration::from_secs(5));

    Some(UpstreamFromXds {
        name,
        lb_policy: lb_policy.to_string(),
        connect_timeout,
        endpoints: Vec::new(),
    })
}

/// Parse protobuf duration string
fn parse_duration(s: &str) -> Option<Duration> {
    // Format: "1.5s" or "500ms" - check "ms" before "s"
    if s.ends_with("ms") {
        let num: u64 = s.trim_end_matches("ms").parse().ok()?;
        Some(Duration::from_millis(num))
    } else if s.ends_with('s') {
        let num: f64 = s.trim_end_matches('s').parse().ok()?;
        Some(Duration::from_secs_f64(num))
    } else {
        None
    }
}

/// Upstream configuration from xDS
#[derive(Debug, Clone)]
pub struct UpstreamFromXds {
    pub name: String,
    pub lb_policy: String,
    pub connect_timeout: Duration,
    pub endpoints: Vec<EndpointFromXds>,
}

/// Endpoint from xDS
#[derive(Debug, Clone)]
pub struct EndpointFromXds {
    pub address: String,
    pub port: u16,
    pub weight: u32,
    pub priority: u32,
    pub healthy: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = XdsConfig::default();
        assert!(!config.enabled);
        assert!(config.use_ads);
        assert!(!config.use_delta);
    }

    #[test]
    fn test_resource_type_url() {
        assert_eq!(
            ResourceType::Listener.type_url(),
            "type.googleapis.com/envoy.config.listener.v3.Listener"
        );
        assert_eq!(
            ResourceType::Cluster.type_url(),
            "type.googleapis.com/envoy.config.cluster.v3.Cluster"
        );
    }

    #[test]
    fn test_resource_type_from_url() {
        assert_eq!(
            ResourceType::from_type_url("type.googleapis.com/envoy.config.listener.v3.Listener"),
            Some(ResourceType::Listener)
        );
        assert_eq!(ResourceType::from_type_url("unknown"), None);
    }

    #[test]
    fn test_resource_type_display() {
        assert_eq!(ResourceType::Listener.to_string(), "LDS");
        assert_eq!(ResourceType::ClusterLoadAssignment.to_string(), "EDS");
    }

    #[test]
    fn test_node_info() {
        let node = NodeInfo::new("test-node".to_string(), "test-cluster".to_string())
            .with_metadata("env", "test")
            .with_locality(Locality::new().with_zone("us-west-2a"));

        assert_eq!(node.id, "test-node");
        assert_eq!(node.cluster, "test-cluster");
        assert_eq!(node.metadata.get("env"), Some(&"test".to_string()));
        assert!(node.locality.is_some());
    }

    #[test]
    fn test_resource_cache() {
        let cache = ResourceCache::new();

        let response = DiscoveryResponse {
            version_info: "1".to_string(),
            resources: vec![Resource {
                name: "cluster1".to_string(),
                version: "v1".to_string(),
                data: serde_json::json!({"name": "cluster1"}),
            }],
            canary: false,
            type_url: ResourceType::Cluster.type_url().to_string(),
            nonce: "nonce1".to_string(),
            control_plane: None,
        };

        cache.update(ResourceType::Cluster, &response);

        let resource = cache.get(ResourceType::Cluster, "cluster1").unwrap();
        assert_eq!(resource.name, "cluster1");
        assert_eq!(resource.version, "v1");

        assert_eq!(cache.version(ResourceType::Cluster), "1");
        assert_eq!(cache.nonce(ResourceType::Cluster), "nonce1");
    }

    #[test]
    fn test_cache_stats() {
        let cache = ResourceCache::new();

        let response = DiscoveryResponse {
            version_info: "1".to_string(),
            resources: vec![
                Resource {
                    name: "cluster1".to_string(),
                    version: "v1".to_string(),
                    data: serde_json::json!({}),
                },
                Resource {
                    name: "cluster2".to_string(),
                    version: "v1".to_string(),
                    data: serde_json::json!({}),
                },
            ],
            canary: false,
            type_url: ResourceType::Cluster.type_url().to_string(),
            nonce: "nonce1".to_string(),
            control_plane: None,
        };

        cache.update(ResourceType::Cluster, &response);

        let stats = cache.stats();
        assert_eq!(stats.total_resources, 2);
        assert_eq!(stats.by_type.get("CDS"), Some(&2));
    }

    #[test]
    fn test_xds_client() {
        let config = XdsConfig {
            enabled: true,
            node_id: "test-node".to_string(),
            cluster: "test-cluster".to_string(),
            ..Default::default()
        };

        let client = XdsClient::new(config);

        assert_eq!(client.state(), ConnectionState::Disconnected);
        assert_eq!(client.node().id, "test-node");

        // Subscribe to resources
        client.subscribe(ResourceType::Cluster, vec!["cluster1".to_string()]);

        // Create request
        let request = client.create_request(ResourceType::Cluster);
        assert_eq!(request.node.id, "test-node");
        assert_eq!(request.resource_names, vec!["cluster1"]);
    }

    #[test]
    fn test_process_response() {
        let config = XdsConfig::default();
        let client = XdsClient::new(config);

        let response = DiscoveryResponse {
            version_info: "1".to_string(),
            resources: vec![Resource {
                name: "listener1".to_string(),
                version: "v1".to_string(),
                data: serde_json::json!({"name": "listener1"}),
            }],
            canary: false,
            type_url: ResourceType::Listener.type_url().to_string(),
            nonce: "nonce1".to_string(),
            control_plane: None,
        };

        client.process_response(response).unwrap();

        let cached = client
            .cache()
            .get(ResourceType::Listener, "listener1")
            .unwrap();
        assert_eq!(cached.name, "listener1");
    }

    #[test]
    fn test_xds_stats() {
        let stats = XdsStats::new();

        stats.requests_sent.fetch_add(5, Ordering::Relaxed);
        stats.responses_received.fetch_add(4, Ordering::Relaxed);
        stats.errors.fetch_add(1, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.requests_sent, 5);
        assert_eq!(snapshot.responses_received, 4);
        assert_eq!(snapshot.errors, 1);
    }

    #[test]
    fn test_connection_state_display() {
        assert_eq!(ConnectionState::Connected.to_string(), "connected");
        assert_eq!(ConnectionState::Reconnecting.to_string(), "reconnecting");
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("1s"), Some(Duration::from_secs(1)));
        assert_eq!(parse_duration("1.5s"), Some(Duration::from_secs_f64(1.5)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("invalid"), None);
    }

    #[test]
    fn test_subscriptions_default() {
        let subs = XdsSubscriptions::default();
        assert!(subs.listeners);
        assert!(subs.routes);
        assert!(subs.clusters);
        assert!(subs.endpoints);
        assert!(!subs.secrets);
    }

    #[test]
    fn test_locality() {
        let locality = Locality::new().with_zone("us-west-2a");

        assert_eq!(locality.zone, Some("us-west-2a".to_string()));
        assert!(locality.region.is_none());
    }

    #[test]
    fn test_create_nack() {
        let config = XdsConfig::default();
        let client = XdsClient::new(config);

        let error = ErrorDetail {
            code: 400,
            message: "Invalid configuration".to_string(),
        };

        let nack = client.create_nack(ResourceType::Cluster, error);
        assert!(nack.error_detail.is_some());
        assert_eq!(nack.error_detail.unwrap().code, 400);
    }
}
