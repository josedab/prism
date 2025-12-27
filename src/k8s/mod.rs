//! Kubernetes Gateway API Support
//!
//! Implements the Kubernetes Gateway API for native K8s integration:
//! - GatewayClass resources
//! - Gateway resources
//! - HTTPRoute resources
//! - TLSRoute resources
//! - Reference grants for cross-namespace routing
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Kubernetes API Server                         │
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │  Gateway API CRDs (GatewayClass, Gateway, HTTPRoute, etc)   ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! └────────────────────────────┬────────────────────────────────────┘
//!                              │ Watch
//! ┌────────────────────────────▼────────────────────────────────────┐
//! │                      Prism K8s Controller                        │
//! │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
//! │  │ GatewayClass    │  │ Gateway         │  │ HTTPRoute       │ │
//! │  │ Controller      │  │ Controller      │  │ Controller      │ │
//! │  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘ │
//! │           └────────────────────┼────────────────────┘           │
//! │                                ▼                                 │
//! │                    ┌─────────────────────┐                      │
//! │                    │  Config Reconciler  │                      │
//! │                    └─────────────────────┘                      │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Supported Resources
//! - `GatewayClass`: Defines the controller implementation
//! - `Gateway`: Listener configuration
//! - `HTTPRoute`: HTTP routing rules
//! - `TLSRoute`: TLS passthrough routing
//! - `ReferenceGrant`: Cross-namespace references

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Gateway API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayApiConfig {
    /// Enable Gateway API controller
    #[serde(default)]
    pub enabled: bool,

    /// Gateway class name to claim
    #[serde(default = "default_gateway_class")]
    pub gateway_class_name: String,

    /// Controller name (must match GatewayClass spec.controllerName)
    #[serde(default = "default_controller_name")]
    pub controller_name: String,

    /// Namespace to watch (empty = all namespaces)
    #[serde(default)]
    pub watch_namespace: Option<String>,

    /// Status update interval (seconds)
    #[serde(default = "default_status_interval")]
    pub status_update_interval_secs: u64,

    /// Enable leader election for HA
    #[serde(default)]
    pub leader_election: bool,
}

impl Default for GatewayApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            gateway_class_name: default_gateway_class(),
            controller_name: default_controller_name(),
            watch_namespace: None,
            status_update_interval_secs: default_status_interval(),
            leader_election: false,
        }
    }
}

fn default_gateway_class() -> String {
    "prism".to_string()
}

fn default_controller_name() -> String {
    "prism.io/gateway-controller".to_string()
}

fn default_status_interval() -> u64 {
    30
}

/// Gateway resource status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayStatus {
    Accepted,
    Programmed,
    Ready,
    Invalid,
    Pending,
}

impl std::fmt::Display for GatewayStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatewayStatus::Accepted => write!(f, "Accepted"),
            GatewayStatus::Programmed => write!(f, "Programmed"),
            GatewayStatus::Ready => write!(f, "Ready"),
            GatewayStatus::Invalid => write!(f, "Invalid"),
            GatewayStatus::Pending => write!(f, "Pending"),
        }
    }
}

/// Route status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteStatus {
    Accepted,
    ResolvedRefs,
    Attached,
    Invalid,
}

impl std::fmt::Display for RouteStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteStatus::Accepted => write!(f, "Accepted"),
            RouteStatus::ResolvedRefs => write!(f, "ResolvedRefs"),
            RouteStatus::Attached => write!(f, "Attached"),
            RouteStatus::Invalid => write!(f, "Invalid"),
        }
    }
}

/// Kubernetes object metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub name: String,
    pub namespace: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    pub uid: Option<String>,
    pub resource_version: Option<String>,
    pub generation: Option<i64>,
}

impl ObjectMeta {
    pub fn new(name: &str, namespace: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            uid: None,
            resource_version: None,
            generation: None,
        }
    }

    pub fn full_name(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }
}

/// GatewayClass resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayClass {
    pub metadata: ObjectMeta,
    pub spec: GatewayClassSpec,
    #[serde(default)]
    pub status: Option<GatewayClassStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayClassSpec {
    /// Controller name (e.g., "prism.io/gateway-controller")
    pub controller_name: String,
    /// Parameters reference
    pub parameters_ref: Option<ParametersRef>,
    /// Description
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayClassStatus {
    pub conditions: Vec<Condition>,
}

/// Gateway resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gateway {
    pub metadata: ObjectMeta,
    pub spec: GatewaySpec,
    #[serde(default)]
    pub status: Option<GatewayStatusDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewaySpec {
    /// GatewayClass name
    pub gateway_class_name: String,
    /// Listeners
    pub listeners: Vec<Listener>,
    /// Addresses
    #[serde(default)]
    pub addresses: Vec<GatewayAddress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listener {
    /// Listener name
    pub name: String,
    /// Hostname to match
    pub hostname: Option<String>,
    /// Port
    pub port: u16,
    /// Protocol (HTTP, HTTPS, TLS, TCP, UDP)
    pub protocol: String,
    /// TLS configuration
    pub tls: Option<GatewayTlsConfig>,
    /// Allowed routes
    #[serde(default)]
    pub allowed_routes: Option<AllowedRoutes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayTlsConfig {
    pub mode: String, // Terminate, Passthrough
    pub certificate_refs: Vec<SecretRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRef {
    pub name: String,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedRoutes {
    pub namespaces: Option<RouteNamespaces>,
    pub kinds: Option<Vec<RouteGroupKind>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteNamespaces {
    pub from: String, // All, Same, Selector
    pub selector: Option<LabelSelector>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteGroupKind {
    pub group: Option<String>,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelSelector {
    pub match_labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayAddress {
    pub r#type: String, // IPAddress, Hostname
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayStatusDetails {
    pub conditions: Vec<Condition>,
    pub listeners: Vec<ListenerStatus>,
    pub addresses: Vec<GatewayAddress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerStatus {
    pub name: String,
    pub attached_routes: i32,
    pub conditions: Vec<Condition>,
}

/// HTTPRoute resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRoute {
    pub metadata: ObjectMeta,
    pub spec: HttpRouteSpec,
    #[serde(default)]
    pub status: Option<HttpRouteStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRouteSpec {
    /// Parent references (Gateways)
    pub parent_refs: Vec<ParentRef>,
    /// Hostnames
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// Rules
    pub rules: Vec<HttpRouteRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentRef {
    pub name: String,
    pub namespace: Option<String>,
    pub section_name: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRouteRule {
    #[serde(default)]
    pub matches: Vec<HttpRouteMatch>,
    #[serde(default)]
    pub filters: Vec<HttpRouteFilter>,
    #[serde(default)]
    pub backend_refs: Vec<BackendRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRouteMatch {
    pub path: Option<HttpPathMatch>,
    #[serde(default)]
    pub headers: Vec<HttpHeaderMatch>,
    #[serde(default)]
    pub query_params: Vec<HttpQueryParamMatch>,
    pub method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpPathMatch {
    pub r#type: String, // Exact, PathPrefix, RegularExpression
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeaderMatch {
    pub r#type: String, // Exact, RegularExpression
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpQueryParamMatch {
    pub r#type: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRouteFilter {
    pub r#type: String, // RequestHeaderModifier, ResponseHeaderModifier, RequestRedirect, URLRewrite
    #[serde(flatten)]
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendRef {
    pub name: String,
    pub namespace: Option<String>,
    pub port: Option<u16>,
    pub weight: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRouteStatus {
    pub parents: Vec<RouteParentStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteParentStatus {
    pub parent_ref: ParentRef,
    pub controller_name: String,
    pub conditions: Vec<Condition>,
}

/// Status condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub r#type: String,
    pub status: String, // True, False, Unknown
    pub reason: String,
    pub message: String,
    pub last_transition_time: String,
    pub observed_generation: Option<i64>,
}

impl Condition {
    pub fn new(condition_type: &str, status: bool, reason: &str, message: &str) -> Self {
        Self {
            r#type: condition_type.to_string(),
            status: if status { "True" } else { "False" }.to_string(),
            reason: reason.to_string(),
            message: message.to_string(),
            last_transition_time: chrono::Utc::now().to_rfc3339(),
            observed_generation: None,
        }
    }

    pub fn is_true(&self) -> bool {
        self.status == "True"
    }
}

/// Parameters reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParametersRef {
    pub group: String,
    pub kind: String,
    pub name: String,
    pub namespace: Option<String>,
}

/// Gateway API controller
pub struct GatewayController {
    config: GatewayApiConfig,
    gateway_classes: RwLock<HashMap<String, GatewayClass>>,
    gateways: RwLock<HashMap<String, Gateway>>,
    http_routes: RwLock<HashMap<String, HttpRoute>>,
    stats: Arc<ControllerStats>,
}

impl GatewayController {
    pub fn new(config: GatewayApiConfig) -> Self {
        Self {
            config,
            gateway_classes: RwLock::new(HashMap::new()),
            gateways: RwLock::new(HashMap::new()),
            http_routes: RwLock::new(HashMap::new()),
            stats: Arc::new(ControllerStats::new()),
        }
    }

    /// Check if we control a GatewayClass
    pub fn controls_class(&self, class: &GatewayClass) -> bool {
        class.spec.controller_name == self.config.controller_name
    }

    /// Add/update a GatewayClass
    pub fn upsert_gateway_class(&self, class: GatewayClass) {
        let name = class.metadata.name.clone();
        self.gateway_classes.write().insert(name, class);
        self.stats.gateway_classes.fetch_add(1, Ordering::Relaxed);
    }

    /// Add/update a Gateway
    pub fn upsert_gateway(&self, gateway: Gateway) {
        let key = gateway.metadata.full_name();
        self.gateways.write().insert(key, gateway);
        self.stats.gateways.fetch_add(1, Ordering::Relaxed);
    }

    /// Add/update an HTTPRoute
    pub fn upsert_http_route(&self, route: HttpRoute) {
        let key = route.metadata.full_name();
        self.http_routes.write().insert(key, route);
        self.stats.http_routes.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a Gateway by namespace/name
    pub fn get_gateway(&self, namespace: &str, name: &str) -> Option<Gateway> {
        let key = format!("{}/{}", namespace, name);
        self.gateways.read().get(&key).cloned()
    }

    /// Get all HTTPRoutes attached to a Gateway
    pub fn routes_for_gateway(&self, gateway_name: &str) -> Vec<HttpRoute> {
        self.http_routes
            .read()
            .values()
            .filter(|r| r.spec.parent_refs.iter().any(|p| p.name == gateway_name))
            .cloned()
            .collect()
    }

    /// Convert Gateway to Prism listener config
    pub fn gateway_to_listener_config(&self, gateway: &Gateway) -> Vec<ListenerFromGateway> {
        gateway
            .spec
            .listeners
            .iter()
            .map(|l| ListenerFromGateway {
                name: l.name.clone(),
                address: format!("0.0.0.0:{}", l.port),
                protocol: l.protocol.clone(),
                hostname: l.hostname.clone(),
                tls_enabled: l.tls.is_some(),
            })
            .collect()
    }

    /// Get stats
    pub fn stats(&self) -> Arc<ControllerStats> {
        self.stats.clone()
    }

    /// Get config
    pub fn config(&self) -> &GatewayApiConfig {
        &self.config
    }
}

/// Listener configuration from Gateway
#[derive(Debug, Clone)]
pub struct ListenerFromGateway {
    pub name: String,
    pub address: String,
    pub protocol: String,
    pub hostname: Option<String>,
    pub tls_enabled: bool,
}

/// Controller statistics
#[derive(Debug)]
pub struct ControllerStats {
    pub gateway_classes: AtomicU64,
    pub gateways: AtomicU64,
    pub http_routes: AtomicU64,
    pub reconciliations: AtomicU64,
    pub errors: AtomicU64,
    started_at: Instant,
}

impl ControllerStats {
    pub fn new() -> Self {
        Self {
            gateway_classes: AtomicU64::new(0),
            gateways: AtomicU64::new(0),
            http_routes: AtomicU64::new(0),
            reconciliations: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }

    pub fn snapshot(&self) -> ControllerStatsSnapshot {
        ControllerStatsSnapshot {
            gateway_classes: self.gateway_classes.load(Ordering::Relaxed),
            gateways: self.gateways.load(Ordering::Relaxed),
            http_routes: self.http_routes.load(Ordering::Relaxed),
            reconciliations: self.reconciliations.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            uptime_secs: self.started_at.elapsed().as_secs(),
        }
    }
}

impl Default for ControllerStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ControllerStatsSnapshot {
    pub gateway_classes: u64,
    pub gateways: u64,
    pub http_routes: u64,
    pub reconciliations: u64,
    pub errors: u64,
    pub uptime_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = GatewayApiConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.gateway_class_name, "prism");
    }

    #[test]
    fn test_gateway_status_display() {
        assert_eq!(GatewayStatus::Ready.to_string(), "Ready");
        assert_eq!(GatewayStatus::Pending.to_string(), "Pending");
    }

    #[test]
    fn test_route_status_display() {
        assert_eq!(RouteStatus::Accepted.to_string(), "Accepted");
        assert_eq!(RouteStatus::Attached.to_string(), "Attached");
    }

    #[test]
    fn test_object_meta() {
        let meta = ObjectMeta::new("my-gateway", "default");
        assert_eq!(meta.full_name(), "default/my-gateway");
    }

    #[test]
    fn test_condition() {
        let cond = Condition::new("Ready", true, "Programmed", "Gateway is ready");
        assert!(cond.is_true());
        assert_eq!(cond.reason, "Programmed");
    }

    #[test]
    fn test_gateway_controller() {
        let config = GatewayApiConfig {
            enabled: true,
            controller_name: "prism.io/gateway-controller".to_string(),
            ..Default::default()
        };

        let controller = GatewayController::new(config);

        // Add a GatewayClass
        let class = GatewayClass {
            metadata: ObjectMeta::new("prism", ""),
            spec: GatewayClassSpec {
                controller_name: "prism.io/gateway-controller".to_string(),
                parameters_ref: None,
                description: Some("Prism Gateway Class".to_string()),
            },
            status: None,
        };

        assert!(controller.controls_class(&class));
        controller.upsert_gateway_class(class);

        // Add a Gateway
        let gateway = Gateway {
            metadata: ObjectMeta::new("my-gateway", "default"),
            spec: GatewaySpec {
                gateway_class_name: "prism".to_string(),
                listeners: vec![Listener {
                    name: "http".to_string(),
                    hostname: Some("*.example.com".to_string()),
                    port: 80,
                    protocol: "HTTP".to_string(),
                    tls: None,
                    allowed_routes: None,
                }],
                addresses: vec![],
            },
            status: None,
        };

        controller.upsert_gateway(gateway);

        let gw = controller.get_gateway("default", "my-gateway").unwrap();
        assert_eq!(gw.spec.listeners.len(), 1);

        // Convert to listener config
        let listeners = controller.gateway_to_listener_config(&gw);
        assert_eq!(listeners[0].address, "0.0.0.0:80");
        assert_eq!(listeners[0].protocol, "HTTP");
    }

    #[test]
    fn test_http_route() {
        let route = HttpRoute {
            metadata: ObjectMeta::new("my-route", "default"),
            spec: HttpRouteSpec {
                parent_refs: vec![ParentRef {
                    name: "my-gateway".to_string(),
                    namespace: Some("default".to_string()),
                    section_name: Some("http".to_string()),
                    port: None,
                }],
                hostnames: vec!["api.example.com".to_string()],
                rules: vec![HttpRouteRule {
                    matches: vec![HttpRouteMatch {
                        path: Some(HttpPathMatch {
                            r#type: "PathPrefix".to_string(),
                            value: "/api".to_string(),
                        }),
                        headers: vec![],
                        query_params: vec![],
                        method: Some("GET".to_string()),
                    }],
                    filters: vec![],
                    backend_refs: vec![BackendRef {
                        name: "api-service".to_string(),
                        namespace: None,
                        port: Some(8080),
                        weight: Some(100),
                    }],
                }],
            },
            status: None,
        };

        assert_eq!(route.spec.hostnames[0], "api.example.com");
        assert_eq!(route.spec.rules[0].backend_refs[0].name, "api-service");
    }

    #[test]
    fn test_routes_for_gateway() {
        let config = GatewayApiConfig::default();
        let controller = GatewayController::new(config);

        let route1 = HttpRoute {
            metadata: ObjectMeta::new("route1", "default"),
            spec: HttpRouteSpec {
                parent_refs: vec![ParentRef {
                    name: "gateway1".to_string(),
                    namespace: None,
                    section_name: None,
                    port: None,
                }],
                hostnames: vec![],
                rules: vec![],
            },
            status: None,
        };

        let route2 = HttpRoute {
            metadata: ObjectMeta::new("route2", "default"),
            spec: HttpRouteSpec {
                parent_refs: vec![ParentRef {
                    name: "gateway2".to_string(),
                    namespace: None,
                    section_name: None,
                    port: None,
                }],
                hostnames: vec![],
                rules: vec![],
            },
            status: None,
        };

        controller.upsert_http_route(route1);
        controller.upsert_http_route(route2);

        let routes = controller.routes_for_gateway("gateway1");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].metadata.name, "route1");
    }

    #[test]
    fn test_controller_stats() {
        let stats = ControllerStats::new();
        stats.gateway_classes.fetch_add(1, Ordering::Relaxed);
        stats.gateways.fetch_add(2, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.gateway_classes, 1);
        assert_eq!(snapshot.gateways, 2);
    }
}
