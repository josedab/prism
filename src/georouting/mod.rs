//! Multi-Region Routing Module
//!
//! Provides intelligent geographic routing capabilities:
//! - Geo-IP based routing
//! - Latency-based routing
//! - Active-active/active-passive failover
//! - Traffic distribution policies
//! - Health-aware region selection

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Geographic routing configuration
#[derive(Debug, Clone)]
pub struct GeoRoutingConfig {
    /// Enable geo-routing
    pub enabled: bool,
    /// Default region when geo-lookup fails
    pub default_region: String,
    /// Enable latency-based routing
    pub latency_routing: bool,
    /// Latency measurement interval
    pub latency_probe_interval: Duration,
    /// Weight for latency vs proximity
    pub latency_weight: f64,
    /// Enable cross-region failover
    pub failover_enabled: bool,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Unhealthy threshold (consecutive failures)
    pub unhealthy_threshold: u32,
}

impl Default for GeoRoutingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_region: "us-east-1".to_string(),
            latency_routing: true,
            latency_probe_interval: Duration::from_secs(30),
            latency_weight: 0.5,
            failover_enabled: true,
            health_check_interval: Duration::from_secs(10),
            unhealthy_threshold: 3,
        }
    }
}

/// Region definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub id: String,
    pub name: String,
    pub location: GeoLocation,
    pub endpoints: Vec<RegionEndpoint>,
    pub weight: u32,
    pub priority: i32,
    pub active: bool,
}

/// Geographic location
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
}

impl GeoLocation {
    pub fn new(latitude: f64, longitude: f64) -> Self {
        Self {
            latitude,
            longitude,
        }
    }

    /// Calculate distance in kilometers using Haversine formula
    pub fn distance_to(&self, other: &GeoLocation) -> f64 {
        const EARTH_RADIUS_KM: f64 = 6371.0;

        let lat1 = self.latitude.to_radians();
        let lat2 = other.latitude.to_radians();
        let delta_lat = (other.latitude - self.latitude).to_radians();
        let delta_lon = (other.longitude - self.longitude).to_radians();

        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1.cos() * lat2.cos() * (delta_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().asin();

        EARTH_RADIUS_KM * c
    }
}

/// Region endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionEndpoint {
    pub url: String,
    pub weight: u32,
    pub backup: bool,
}

/// Routing policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RoutingPolicy {
    /// Route to nearest region by geography
    Geoproximity,
    /// Route to region with lowest latency
    LatencyBased,
    /// Round-robin across regions
    RoundRobin,
    /// Weighted distribution
    Weighted,
    /// Active-passive failover
    Failover,
    /// Route to specific region
    Static,
}

/// Traffic distribution rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRule {
    pub id: String,
    pub name: String,
    pub conditions: Vec<TrafficCondition>,
    pub policy: RoutingPolicy,
    pub target_regions: Vec<String>,
    pub priority: i32,
}

/// Traffic condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficCondition {
    pub field: TrafficField,
    pub operator: ConditionOperator,
    pub value: String,
}

/// Fields for traffic matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrafficField {
    SourceCountry,
    SourceContinent,
    SourceASN,
    Path,
    Header(String),
    Cookie(String),
}

/// Condition operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    InList,
}

/// Region health status
#[derive(Debug, Clone)]
pub struct RegionHealth {
    pub region_id: String,
    pub healthy: bool,
    pub last_check: Instant,
    pub consecutive_failures: u32,
    pub latency_ms: Option<u64>,
    pub availability_percent: f64,
}

/// Routing decision
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    pub region: Region,
    pub endpoint: RegionEndpoint,
    pub policy_used: RoutingPolicy,
    pub rule_id: Option<String>,
    pub fallback: bool,
}

/// Geo-routing statistics
#[derive(Debug, Default)]
pub struct GeoRoutingStats {
    pub requests_routed: AtomicU64,
    pub requests_by_region: DashMap<String, AtomicU64>,
    pub requests_by_policy: DashMap<RoutingPolicy, AtomicU64>,
    pub failovers: AtomicU64,
    pub geo_lookups: AtomicU64,
    pub geo_lookup_failures: AtomicU64,
}

/// Geo-IP lookup result
#[derive(Debug, Clone)]
pub struct GeoIpResult {
    pub country_code: String,
    pub country_name: String,
    pub continent: String,
    pub region: Option<String>,
    pub city: Option<String>,
    pub location: GeoLocation,
    pub asn: Option<u32>,
    pub isp: Option<String>,
}

/// Geo-routing manager
pub struct GeoRouter {
    config: GeoRoutingConfig,
    regions: DashMap<String, Arc<Region>>,
    health: DashMap<String, RegionHealth>,
    rules: RwLock<Vec<TrafficRule>>,
    geo_cache: DashMap<IpAddr, GeoIpResult>,
    round_robin_counters: DashMap<String, AtomicU64>,
    stats: GeoRoutingStats,
}

impl GeoRouter {
    pub fn new(config: GeoRoutingConfig) -> Self {
        Self {
            config,
            regions: DashMap::new(),
            health: DashMap::new(),
            rules: RwLock::new(Vec::new()),
            geo_cache: DashMap::new(),
            round_robin_counters: DashMap::new(),
            stats: GeoRoutingStats::default(),
        }
    }

    /// Register a region
    pub fn register_region(&self, region: Region) {
        let region_id = region.id.clone();
        self.regions.insert(region_id.clone(), Arc::new(region));

        // Initialize health
        self.health.insert(
            region_id.clone(),
            RegionHealth {
                region_id,
                healthy: true,
                last_check: Instant::now(),
                consecutive_failures: 0,
                latency_ms: None,
                availability_percent: 100.0,
            },
        );
    }

    /// Add a traffic rule
    pub fn add_rule(&self, rule: TrafficRule) {
        let mut rules = self.rules.write();
        rules.push(rule);
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Route request to appropriate region
    pub fn route(
        &self,
        client_ip: Option<IpAddr>,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> Option<RoutingDecision> {
        self.stats.requests_routed.fetch_add(1, Ordering::Relaxed);

        // Get geo info for client
        let geo_info = client_ip.and_then(|ip| self.lookup_geo(ip));

        // Find matching rule
        let rules = self.rules.read();
        let matched_rule = rules
            .iter()
            .find(|rule| self.matches_rule(rule, &geo_info, path, headers));

        // Determine routing policy
        let (policy, target_regions, rule_id) = if let Some(rule) = matched_rule {
            (
                rule.policy,
                rule.target_regions.clone(),
                Some(rule.id.clone()),
            )
        } else {
            (RoutingPolicy::Geoproximity, Vec::new(), None)
        };

        // Get candidate regions
        let candidates: Vec<Arc<Region>> = if target_regions.is_empty() {
            self.regions
                .iter()
                .filter(|e| e.value().active)
                .map(|e| e.value().clone())
                .collect()
        } else {
            target_regions
                .iter()
                .filter_map(|id| self.regions.get(id).map(|r| r.clone()))
                .filter(|r| r.active)
                .collect()
        };

        if candidates.is_empty() {
            return None;
        }

        // Select region based on policy
        let (region, fallback) = match policy {
            RoutingPolicy::Geoproximity => self.select_by_proximity(&candidates, &geo_info),
            RoutingPolicy::LatencyBased => self.select_by_latency(&candidates),
            RoutingPolicy::RoundRobin => self.select_round_robin(&candidates),
            RoutingPolicy::Weighted => self.select_weighted(&candidates),
            RoutingPolicy::Failover => self.select_failover(&candidates),
            RoutingPolicy::Static => (candidates.first().cloned(), false),
        };

        let region = region?;

        // Select endpoint within region
        let endpoint = self.select_endpoint(&region)?;

        // Update stats
        self.stats
            .requests_by_region
            .entry(region.id.clone())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        self.stats
            .requests_by_policy
            .entry(policy)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        if fallback {
            self.stats.failovers.fetch_add(1, Ordering::Relaxed);
        }

        Some(RoutingDecision {
            region: (*region).clone(),
            endpoint,
            policy_used: policy,
            rule_id,
            fallback,
        })
    }

    fn lookup_geo(&self, ip: IpAddr) -> Option<GeoIpResult> {
        self.stats.geo_lookups.fetch_add(1, Ordering::Relaxed);

        // Check cache
        if let Some(cached) = self.geo_cache.get(&ip) {
            return Some(cached.clone());
        }

        // In production, would use MaxMind or similar
        // For now, return mock data based on IP ranges
        let result = self.mock_geo_lookup(ip);

        if let Some(ref geo) = result {
            self.geo_cache.insert(ip, geo.clone());
        } else {
            self.stats
                .geo_lookup_failures
                .fetch_add(1, Ordering::Relaxed);
        }

        result
    }

    fn mock_geo_lookup(&self, ip: IpAddr) -> Option<GeoIpResult> {
        // Simplified mock implementation
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Mock: first octet determines "region"
                let (country, location) = match octets[0] {
                    0..=50 => ("US", GeoLocation::new(37.7749, -122.4194)), // SF
                    51..=100 => ("GB", GeoLocation::new(51.5074, -0.1278)), // London
                    101..=150 => ("DE", GeoLocation::new(52.5200, 13.4050)), // Berlin
                    151..=200 => ("JP", GeoLocation::new(35.6762, 139.6503)), // Tokyo
                    _ => ("AU", GeoLocation::new(-33.8688, 151.2093)),      // Sydney
                };

                Some(GeoIpResult {
                    country_code: country.to_string(),
                    country_name: country.to_string(),
                    continent: "Unknown".to_string(),
                    region: None,
                    city: None,
                    location,
                    asn: None,
                    isp: None,
                })
            }
            _ => None,
        }
    }

    fn matches_rule(
        &self,
        rule: &TrafficRule,
        geo: &Option<GeoIpResult>,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> bool {
        rule.conditions.iter().all(|cond| {
            let value = match &cond.field {
                TrafficField::SourceCountry => geo.as_ref().map(|g| g.country_code.clone()),
                TrafficField::SourceContinent => geo.as_ref().map(|g| g.continent.clone()),
                TrafficField::SourceASN => geo.as_ref().and_then(|g| g.asn.map(|a| a.to_string())),
                TrafficField::Path => Some(path.to_string()),
                TrafficField::Header(name) => headers.get(&name.to_lowercase()).cloned(),
                TrafficField::Cookie(name) => headers.get("cookie").and_then(|cookies| {
                    cookies.split(';').find_map(|c| {
                        let parts: Vec<&str> = c.trim().splitn(2, '=').collect();
                        if parts.len() == 2 && parts[0] == name {
                            Some(parts[1].to_string())
                        } else {
                            None
                        }
                    })
                }),
            };

            match &cond.operator {
                ConditionOperator::Equals => value.as_deref() == Some(&cond.value),
                ConditionOperator::NotEquals => value.as_deref() != Some(&cond.value),
                ConditionOperator::Contains => value
                    .as_ref()
                    .map(|v| v.contains(&cond.value))
                    .unwrap_or(false),
                ConditionOperator::StartsWith => value
                    .as_ref()
                    .map(|v| v.starts_with(&cond.value))
                    .unwrap_or(false),
                ConditionOperator::InList => {
                    let list: Vec<&str> = cond.value.split(',').map(|s| s.trim()).collect();
                    value
                        .as_ref()
                        .map(|v| list.contains(&v.as_str()))
                        .unwrap_or(false)
                }
            }
        })
    }

    fn select_by_proximity(
        &self,
        candidates: &[Arc<Region>],
        geo: &Option<GeoIpResult>,
    ) -> (Option<Arc<Region>>, bool) {
        let client_location = geo
            .as_ref()
            .map(|g| g.location)
            .unwrap_or(GeoLocation::new(0.0, 0.0));

        // Filter healthy regions
        let healthy: Vec<_> = candidates
            .iter()
            .filter(|r| self.is_healthy(&r.id))
            .collect();

        if healthy.is_empty() {
            // Fallback to any region
            if self.config.failover_enabled {
                return (candidates.first().cloned(), true);
            }
            return (None, false);
        }

        // Sort by distance
        let mut sorted: Vec<_> = healthy
            .iter()
            .map(|r| {
                let distance = client_location.distance_to(&r.location);
                (*r, distance)
            })
            .collect();

        sorted.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        (sorted.first().map(|(r, _)| (*r).clone()), false)
    }

    fn select_by_latency(&self, candidates: &[Arc<Region>]) -> (Option<Arc<Region>>, bool) {
        let mut with_latency: Vec<_> = candidates
            .iter()
            .filter_map(|r| {
                let health = self.health.get(&r.id)?;
                if !health.healthy {
                    return None;
                }
                health.latency_ms.map(|l| (r.clone(), l))
            })
            .collect();

        if with_latency.is_empty() {
            // Fallback to proximity or any region
            return self.select_by_proximity(candidates, &None);
        }

        with_latency.sort_by_key(|(_, latency)| *latency);
        (with_latency.first().map(|(r, _)| r.clone()), false)
    }

    fn select_round_robin(&self, candidates: &[Arc<Region>]) -> (Option<Arc<Region>>, bool) {
        let healthy: Vec<_> = candidates
            .iter()
            .filter(|r| self.is_healthy(&r.id))
            .cloned()
            .collect();

        if healthy.is_empty() {
            if self.config.failover_enabled {
                return (candidates.first().cloned(), true);
            }
            return (None, false);
        }

        let key = healthy
            .iter()
            .map(|r| &r.id)
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        let counter = self
            .round_robin_counters
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0));

        let index = counter.fetch_add(1, Ordering::Relaxed) as usize % healthy.len();
        (Some(healthy[index].clone()), false)
    }

    fn select_weighted(&self, candidates: &[Arc<Region>]) -> (Option<Arc<Region>>, bool) {
        let healthy: Vec<_> = candidates
            .iter()
            .filter(|r| self.is_healthy(&r.id))
            .cloned()
            .collect();

        if healthy.is_empty() {
            if self.config.failover_enabled {
                return (candidates.first().cloned(), true);
            }
            return (None, false);
        }

        let total_weight: u32 = healthy.iter().map(|r| r.weight).sum();
        if total_weight == 0 {
            return (healthy.first().cloned(), false);
        }

        let mut rng_value = rand::random::<u32>() % total_weight;
        for region in &healthy {
            if rng_value < region.weight {
                return (Some(region.clone()), false);
            }
            rng_value -= region.weight;
        }

        (healthy.first().cloned(), false)
    }

    fn select_failover(&self, candidates: &[Arc<Region>]) -> (Option<Arc<Region>>, bool) {
        // Sort by priority (higher = primary)
        let mut sorted: Vec<_> = candidates.to_vec();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Return first healthy region
        for region in &sorted {
            if self.is_healthy(&region.id) {
                let is_fallback = sorted.first().map(|r| r.id != region.id).unwrap_or(false);
                return (Some(region.clone()), is_fallback);
            }
        }

        // All unhealthy, return primary anyway
        (sorted.first().cloned(), true)
    }

    fn select_endpoint(&self, region: &Region) -> Option<RegionEndpoint> {
        let primary: Vec<_> = region.endpoints.iter().filter(|e| !e.backup).collect();
        let backup: Vec<_> = region.endpoints.iter().filter(|e| e.backup).collect();

        // Weighted selection among primary endpoints
        if !primary.is_empty() {
            let total_weight: u32 = primary.iter().map(|e| e.weight).sum();
            if total_weight > 0 {
                let mut rng_value = rand::random::<u32>() % total_weight;
                for endpoint in &primary {
                    if rng_value < endpoint.weight {
                        return Some((*endpoint).clone());
                    }
                    rng_value -= endpoint.weight;
                }
            }
            return primary.first().map(|e| (*e).clone());
        }

        // Fall back to backup endpoints
        backup.first().map(|e| (*e).clone())
    }

    fn is_healthy(&self, region_id: &str) -> bool {
        self.health
            .get(region_id)
            .map(|h| h.healthy)
            .unwrap_or(false)
    }

    /// Update region health
    pub fn update_health(&self, region_id: &str, healthy: bool, latency_ms: Option<u64>) {
        if let Some(mut health) = self.health.get_mut(region_id) {
            health.last_check = Instant::now();
            health.latency_ms = latency_ms;

            if healthy {
                health.consecutive_failures = 0;
                health.healthy = true;
            } else {
                health.consecutive_failures += 1;
                if health.consecutive_failures >= self.config.unhealthy_threshold {
                    health.healthy = false;
                }
            }

            // Update availability
            let total_checks = health.consecutive_failures as f64 + 1.0;
            health.availability_percent = (1.0 / total_checks) * 100.0;
        }
    }

    /// Get region health status
    pub fn get_health(&self, region_id: &str) -> Option<RegionHealth> {
        self.health.get(region_id).map(|h| h.clone())
    }

    /// List all regions with health
    pub fn list_regions(&self) -> Vec<(Region, RegionHealth)> {
        self.regions
            .iter()
            .filter_map(|e| {
                let health = self.health.get(e.key())?.clone();
                Some((e.value().as_ref().clone(), health))
            })
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> &GeoRoutingStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_region(id: &str, lat: f64, lon: f64) -> Region {
        Region {
            id: id.to_string(),
            name: id.to_string(),
            location: GeoLocation::new(lat, lon),
            endpoints: vec![RegionEndpoint {
                url: format!("https://{}.example.com", id),
                weight: 100,
                backup: false,
            }],
            weight: 100,
            priority: 0,
            active: true,
        }
    }

    #[test]
    fn test_geo_distance() {
        let sf = GeoLocation::new(37.7749, -122.4194);
        let nyc = GeoLocation::new(40.7128, -74.0060);

        let distance = sf.distance_to(&nyc);
        // Approximately 4130 km
        assert!(distance > 4000.0 && distance < 4200.0);
    }

    #[test]
    fn test_register_region() {
        let router = GeoRouter::new(GeoRoutingConfig::default());
        let region = create_test_region("us-west-1", 37.7749, -122.4194);
        router.register_region(region);

        assert!(router.regions.contains_key("us-west-1"));
        assert!(router.health.contains_key("us-west-1"));
    }

    #[test]
    fn test_proximity_routing() {
        let router = GeoRouter::new(GeoRoutingConfig::default());

        router.register_region(create_test_region("us-west-1", 37.7749, -122.4194)); // SF
        router.register_region(create_test_region("us-east-1", 40.7128, -74.0060)); // NYC
        router.register_region(create_test_region("eu-west-1", 51.5074, -0.1278)); // London

        // Client from SF area (IP 10.x.x.x maps to US in mock)
        let ip = "10.0.0.1".parse().ok();
        let decision = router.route(ip, "/api/users", &HashMap::new());

        assert!(decision.is_some());
        let decision = decision.unwrap();
        // Should route to nearest region
        assert_eq!(decision.policy_used, RoutingPolicy::Geoproximity);
    }

    #[test]
    fn test_failover_routing() {
        let router = GeoRouter::new(GeoRoutingConfig::default());

        let mut primary = create_test_region("primary", 37.7749, -122.4194);
        primary.priority = 10;
        router.register_region(primary);

        let mut secondary = create_test_region("secondary", 40.7128, -74.0060);
        secondary.priority = 5;
        router.register_region(secondary);

        // Add failover rule
        router.add_rule(TrafficRule {
            id: "failover".to_string(),
            name: "Failover".to_string(),
            conditions: vec![],
            policy: RoutingPolicy::Failover,
            target_regions: vec!["primary".to_string(), "secondary".to_string()],
            priority: 100,
        });

        // Should route to primary
        let decision = router.route(None, "/api", &HashMap::new()).unwrap();
        assert_eq!(decision.region.id, "primary");
        assert!(!decision.fallback);

        // Mark primary unhealthy
        for _ in 0..3 {
            router.update_health("primary", false, None);
        }

        // Should failover to secondary
        let decision = router.route(None, "/api", &HashMap::new()).unwrap();
        assert_eq!(decision.region.id, "secondary");
        assert!(decision.fallback);
    }

    #[test]
    fn test_weighted_routing() {
        let router = GeoRouter::new(GeoRoutingConfig::default());

        let mut region1 = create_test_region("region1", 0.0, 0.0);
        region1.weight = 80;
        router.register_region(region1);

        let mut region2 = create_test_region("region2", 0.0, 0.0);
        region2.weight = 20;
        router.register_region(region2);

        router.add_rule(TrafficRule {
            id: "weighted".to_string(),
            name: "Weighted".to_string(),
            conditions: vec![],
            policy: RoutingPolicy::Weighted,
            target_regions: vec!["region1".to_string(), "region2".to_string()],
            priority: 100,
        });

        let mut region1_count = 0;
        let mut region2_count = 0;

        for _ in 0..1000 {
            let decision = router.route(None, "/api", &HashMap::new()).unwrap();
            if decision.region.id == "region1" {
                region1_count += 1;
            } else {
                region2_count += 1;
            }
        }

        // Should be approximately 80/20 split
        let ratio = region1_count as f64 / (region1_count + region2_count) as f64;
        assert!(ratio > 0.7 && ratio < 0.9);
    }

    #[test]
    fn test_traffic_rule_matching() {
        let router = GeoRouter::new(GeoRoutingConfig::default());

        router.register_region(create_test_region("api-region", 0.0, 0.0));
        router.register_region(create_test_region("web-region", 0.0, 0.0));

        router.add_rule(TrafficRule {
            id: "api-rule".to_string(),
            name: "API Rule".to_string(),
            conditions: vec![TrafficCondition {
                field: TrafficField::Path,
                operator: ConditionOperator::StartsWith,
                value: "/api".to_string(),
            }],
            policy: RoutingPolicy::Static,
            target_regions: vec!["api-region".to_string()],
            priority: 100,
        });

        router.add_rule(TrafficRule {
            id: "web-rule".to_string(),
            name: "Web Rule".to_string(),
            conditions: vec![TrafficCondition {
                field: TrafficField::Path,
                operator: ConditionOperator::StartsWith,
                value: "/".to_string(),
            }],
            policy: RoutingPolicy::Static,
            target_regions: vec!["web-region".to_string()],
            priority: 50,
        });

        // API request should match api-rule
        let decision = router.route(None, "/api/users", &HashMap::new()).unwrap();
        assert_eq!(decision.region.id, "api-region");

        // Web request should match web-rule
        let decision = router.route(None, "/index.html", &HashMap::new()).unwrap();
        assert_eq!(decision.region.id, "web-region");
    }

    #[test]
    fn test_round_robin() {
        let router = GeoRouter::new(GeoRoutingConfig::default());

        router.register_region(create_test_region("region1", 0.0, 0.0));
        router.register_region(create_test_region("region2", 0.0, 0.0));
        router.register_region(create_test_region("region3", 0.0, 0.0));

        router.add_rule(TrafficRule {
            id: "rr".to_string(),
            name: "Round Robin".to_string(),
            conditions: vec![],
            policy: RoutingPolicy::RoundRobin,
            target_regions: vec![
                "region1".to_string(),
                "region2".to_string(),
                "region3".to_string(),
            ],
            priority: 100,
        });

        let mut counts: HashMap<String, u32> = HashMap::new();
        for _ in 0..9 {
            let decision = router.route(None, "/api", &HashMap::new()).unwrap();
            *counts.entry(decision.region.id).or_insert(0) += 1;
        }

        // Each region should get 3 requests
        assert_eq!(counts.get("region1"), Some(&3));
        assert_eq!(counts.get("region2"), Some(&3));
        assert_eq!(counts.get("region3"), Some(&3));
    }
}
