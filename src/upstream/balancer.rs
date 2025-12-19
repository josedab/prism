//! Load balancing algorithms

use super::ServerState;
use crate::config::LoadBalancingAlgorithm;
use rand::Rng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Load balancer trait
pub trait LoadBalancer: Send + Sync {
    /// Select a server from the list
    fn select<'a>(&self, servers: &[&'a Arc<ServerState>]) -> Option<&'a Arc<ServerState>>;

    /// Get the algorithm name
    fn name(&self) -> &'static str;
}

/// Create a load balancer from configuration
pub fn create_balancer(
    algorithm: &LoadBalancingAlgorithm,
    servers: &[Arc<ServerState>],
) -> Box<dyn LoadBalancer> {
    match algorithm {
        LoadBalancingAlgorithm::RoundRobin => Box::new(RoundRobinBalancer::new()),
        LoadBalancingAlgorithm::LeastConnections => Box::new(LeastConnectionsBalancer),
        LoadBalancingAlgorithm::Random => Box::new(RandomBalancer),
        LoadBalancingAlgorithm::Weighted => Box::new(WeightedBalancer::new(servers)),
        LoadBalancingAlgorithm::IpHash => Box::new(IpHashBalancer),
        LoadBalancingAlgorithm::ConsistentHash => {
            Box::new(ConsistentHashBalancer::new(servers, 150))
        }
    }
}

/// Round-robin load balancer
pub struct RoundRobinBalancer {
    counter: AtomicUsize,
}

impl RoundRobinBalancer {
    pub fn new() -> Self {
        Self {
            counter: AtomicUsize::new(0),
        }
    }
}

impl Default for RoundRobinBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancer for RoundRobinBalancer {
    fn select<'a>(&self, servers: &[&'a Arc<ServerState>]) -> Option<&'a Arc<ServerState>> {
        if servers.is_empty() {
            return None;
        }

        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % servers.len();
        Some(servers[idx])
    }

    fn name(&self) -> &'static str {
        "round_robin"
    }
}

/// Least connections load balancer
pub struct LeastConnectionsBalancer;

impl LoadBalancer for LeastConnectionsBalancer {
    fn select<'a>(&self, servers: &[&'a Arc<ServerState>]) -> Option<&'a Arc<ServerState>> {
        servers
            .iter()
            .min_by_key(|s| s.active_connections())
            .copied()
    }

    fn name(&self) -> &'static str {
        "least_connections"
    }
}

/// Random load balancer
pub struct RandomBalancer;

impl LoadBalancer for RandomBalancer {
    fn select<'a>(&self, servers: &[&'a Arc<ServerState>]) -> Option<&'a Arc<ServerState>> {
        if servers.is_empty() {
            return None;
        }

        let idx = rand::thread_rng().gen_range(0..servers.len());
        Some(servers[idx])
    }

    fn name(&self) -> &'static str {
        "random"
    }
}

/// Weighted round-robin load balancer
pub struct WeightedBalancer {
    /// Total weight
    total_weight: u32,
    /// Counter for weighted selection
    counter: AtomicUsize,
}

impl WeightedBalancer {
    pub fn new(servers: &[Arc<ServerState>]) -> Self {
        let total_weight: u32 = servers.iter().map(|s| s.server.weight).sum();

        Self {
            total_weight,
            counter: AtomicUsize::new(0),
        }
    }
}

impl LoadBalancer for WeightedBalancer {
    fn select<'a>(&self, servers: &[&'a Arc<ServerState>]) -> Option<&'a Arc<ServerState>> {
        if servers.is_empty() || self.total_weight == 0 {
            return None;
        }

        let current = self.counter.fetch_add(1, Ordering::Relaxed);
        let target = (current as u32) % self.total_weight;

        let mut cumulative = 0u32;
        for server in servers {
            cumulative += server.server.weight;
            if target < cumulative {
                return Some(server);
            }
        }

        // Fallback to first server
        servers.first().copied()
    }

    fn name(&self) -> &'static str {
        "weighted"
    }
}

/// IP hash load balancer (requires client IP context)
pub struct IpHashBalancer;

impl LoadBalancer for IpHashBalancer {
    fn select<'a>(&self, servers: &[&'a Arc<ServerState>]) -> Option<&'a Arc<ServerState>> {
        // Without access to request context, fall back to random
        // In practice, this would use the client IP from request context
        if servers.is_empty() {
            return None;
        }

        let idx = rand::thread_rng().gen_range(0..servers.len());
        Some(servers[idx])
    }

    fn name(&self) -> &'static str {
        "ip_hash"
    }
}

/// IP hash selection with explicit IP
pub fn select_by_ip_hash<'a>(
    servers: &[&'a Arc<ServerState>],
    client_ip: &str,
) -> Option<&'a Arc<ServerState>> {
    if servers.is_empty() {
        return None;
    }

    let mut hasher = DefaultHasher::new();
    client_ip.hash(&mut hasher);
    let hash = hasher.finish();

    let idx = (hash as usize) % servers.len();
    Some(servers[idx])
}

/// Consistent hash load balancer using ring
pub struct ConsistentHashBalancer {
    /// Hash ring (sorted list of (hash, server_index) pairs)
    ring: Vec<(u64, usize)>,
    /// Number of virtual nodes per server
    #[allow(dead_code)]
    virtual_nodes: usize,
}

impl ConsistentHashBalancer {
    pub fn new(servers: &[Arc<ServerState>], virtual_nodes: usize) -> Self {
        let mut ring = Vec::with_capacity(servers.len() * virtual_nodes);

        for (idx, server) in servers.iter().enumerate() {
            for i in 0..virtual_nodes {
                let key = format!("{}:{}", server.server.address, i);
                let hash = hash_string(&key);
                ring.push((hash, idx));
            }
        }

        ring.sort_by_key(|(hash, _)| *hash);

        Self {
            ring,
            virtual_nodes,
        }
    }

    /// Select server by key (e.g., request path, client IP)
    pub fn select_by_key<'a>(
        &self,
        servers: &[&'a Arc<ServerState>],
        key: &str,
    ) -> Option<&'a Arc<ServerState>> {
        if self.ring.is_empty() || servers.is_empty() {
            return None;
        }

        let hash = hash_string(key);

        // Binary search for the first node with hash >= target
        let idx = match self.ring.binary_search_by_key(&hash, |(h, _)| *h) {
            Ok(i) => i,
            Err(i) => {
                if i >= self.ring.len() {
                    0 // Wrap around
                } else {
                    i
                }
            }
        };

        let server_idx = self.ring[idx].1;
        servers.get(server_idx).copied()
    }
}

impl LoadBalancer for ConsistentHashBalancer {
    fn select<'a>(&self, servers: &[&'a Arc<ServerState>]) -> Option<&'a Arc<ServerState>> {
        // Without a key, fall back to random selection
        if servers.is_empty() {
            return None;
        }

        let key: u64 = rand::thread_rng().gen();
        self.select_by_key(servers, &key.to_string())
    }

    fn name(&self) -> &'static str {
        "consistent_hash"
    }
}

/// Hash a string to u64
fn hash_string(s: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

/// Sticky session (session affinity) configuration
#[derive(Debug, Clone)]
pub struct StickySessionConfig {
    /// Cookie name for session tracking
    pub cookie_name: String,
    /// Cookie TTL in seconds
    pub ttl_seconds: u64,
    /// Cookie path
    pub path: String,
    /// Whether cookie is HTTP only
    pub http_only: bool,
    /// Whether cookie requires secure connection
    pub secure: bool,
    /// SameSite attribute
    pub same_site: SameSitePolicy,
    /// Fallback balancer when no affinity exists
    pub fallback: LoadBalancingAlgorithm,
}

/// SameSite cookie policy
#[derive(Debug, Clone, Copy, Default)]
pub enum SameSitePolicy {
    /// Strict: Cookie only sent in first-party context
    Strict,
    /// Lax: Cookie sent with top-level navigations (default)
    #[default]
    Lax,
    /// None: Cookie always sent (requires Secure)
    None,
}

impl Default for StickySessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: "PRISM_AFFINITY".to_string(),
            ttl_seconds: 3600,
            path: "/".to_string(),
            http_only: true,
            secure: false,
            same_site: SameSitePolicy::Lax,
            fallback: LoadBalancingAlgorithm::RoundRobin,
        }
    }
}

impl StickySessionConfig {
    /// Create a new sticky session config
    pub fn new(cookie_name: impl Into<String>) -> Self {
        Self {
            cookie_name: cookie_name.into(),
            ..Default::default()
        }
    }

    /// Set TTL
    pub fn with_ttl(mut self, seconds: u64) -> Self {
        self.ttl_seconds = seconds;
        self
    }

    /// Set secure flag
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }
}

/// Sticky session balancer with cookie-based affinity
pub struct StickySessionBalancer {
    config: StickySessionConfig,
    /// Fallback balancer
    fallback: Box<dyn LoadBalancer>,
}

impl StickySessionBalancer {
    /// Create a new sticky session balancer
    pub fn new(config: StickySessionConfig, servers: &[Arc<ServerState>]) -> Self {
        let fallback = create_balancer(&config.fallback, servers);
        Self { config, fallback }
    }

    /// Generate a session ID for a server
    pub fn generate_session_id(server: &ServerState) -> String {
        let mut hasher = DefaultHasher::new();
        server.server.address.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    /// Parse session ID from cookie value
    pub fn parse_cookie_value(&self, cookie_header: &str) -> Option<String> {
        // Parse Cookie header format: "name1=value1; name2=value2"
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some((name, value)) = cookie.split_once('=') {
                if name.trim() == self.config.cookie_name {
                    return Some(value.trim().to_string());
                }
            }
        }
        None
    }

    /// Select server by session ID
    pub fn select_by_session<'a>(
        &self,
        servers: &[&'a Arc<ServerState>],
        session_id: &str,
    ) -> Option<&'a Arc<ServerState>> {
        // Find server matching the session ID
        for server in servers {
            let server_id = Self::generate_session_id(server);
            if server_id == session_id {
                return Some(server);
            }
        }
        // Session ID doesn't match any server (server may have been removed)
        None
    }

    /// Generate Set-Cookie header value
    pub fn generate_cookie(&self, server: &ServerState) -> String {
        let session_id = Self::generate_session_id(server);
        let mut cookie = format!(
            "{}={}; Path={}; Max-Age={}",
            self.config.cookie_name, session_id, self.config.path, self.config.ttl_seconds
        );

        if self.config.http_only {
            cookie.push_str("; HttpOnly");
        }

        if self.config.secure {
            cookie.push_str("; Secure");
        }

        match self.config.same_site {
            SameSitePolicy::Strict => cookie.push_str("; SameSite=Strict"),
            SameSitePolicy::Lax => cookie.push_str("; SameSite=Lax"),
            SameSitePolicy::None => cookie.push_str("; SameSite=None"),
        }

        cookie
    }

    /// Get cookie name
    pub fn cookie_name(&self) -> &str {
        &self.config.cookie_name
    }

    /// Get config
    pub fn config(&self) -> &StickySessionConfig {
        &self.config
    }
}

impl LoadBalancer for StickySessionBalancer {
    fn select<'a>(&self, servers: &[&'a Arc<ServerState>]) -> Option<&'a Arc<ServerState>> {
        // Without request context, fall back to default balancer
        self.fallback.select(servers)
    }

    fn name(&self) -> &'static str {
        "sticky_session"
    }
}

/// Select with sticky session support using request cookies
pub fn select_with_sticky_session<'a>(
    balancer: &StickySessionBalancer,
    servers: &[&'a Arc<ServerState>],
    cookie_header: Option<&str>,
) -> (Option<&'a Arc<ServerState>>, bool) {
    // Try to find existing session
    if let Some(cookies) = cookie_header {
        if let Some(session_id) = balancer.parse_cookie_value(cookies) {
            if let Some(server) = balancer.select_by_session(servers, &session_id) {
                return (Some(server), false); // Existing session, no new cookie needed
            }
        }
    }

    // No valid session, select new server
    let server = balancer.select(servers);
    (server, true) // New session, cookie should be set
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::Server;
    use std::net::SocketAddr;

    fn create_test_servers(count: usize) -> Vec<Arc<ServerState>> {
        (0..count)
            .map(|i| {
                let addr: SocketAddr = format!("127.0.0.1:{}", 8000 + i).parse().unwrap();
                Arc::new(ServerState::new(Server {
                    address: addr,
                    weight: 1,
                    enabled: true,
                }))
            })
            .collect()
    }

    #[test]
    fn test_round_robin() {
        let servers = create_test_servers(3);
        let balancer = RoundRobinBalancer::new();

        let refs: Vec<&Arc<ServerState>> = servers.iter().collect();

        // Should cycle through servers
        let s1 = balancer.select(&refs).unwrap();
        let s2 = balancer.select(&refs).unwrap();
        let s3 = balancer.select(&refs).unwrap();
        let s4 = balancer.select(&refs).unwrap();

        assert_ne!(s1.server.address, s2.server.address);
        assert_ne!(s2.server.address, s3.server.address);
        assert_eq!(s1.server.address, s4.server.address);
    }

    #[test]
    fn test_least_connections() {
        let servers = create_test_servers(3);
        let balancer = LeastConnectionsBalancer;

        // Simulate connections
        servers[0].start_request();
        servers[0].start_request();
        servers[1].start_request();
        // servers[2] has 0 connections

        let refs: Vec<&Arc<ServerState>> = servers.iter().collect();
        let selected = balancer.select(&refs).unwrap();

        // Should select server with least connections
        assert_eq!(selected.server.address, servers[2].server.address);
    }

    #[test]
    fn test_weighted_selection() {
        let mut servers = create_test_servers(2);
        // Make second server have higher weight
        if let Some(s) = Arc::get_mut(&mut servers[1]) {
            s.server.weight = 9;
        }

        let balancer = WeightedBalancer::new(&servers);
        let refs: Vec<&Arc<ServerState>> = servers.iter().collect();

        // Sample many selections
        let mut counts = [0usize; 2];
        for _ in 0..1000 {
            if let Some(s) = balancer.select(&refs) {
                if s.server.address == servers[0].server.address {
                    counts[0] += 1;
                } else {
                    counts[1] += 1;
                }
            }
        }

        // Server with weight 9 should be selected ~9x more often
        assert!(counts[1] > counts[0] * 5);
    }

    #[test]
    fn test_consistent_hash_stability() {
        let servers = create_test_servers(5);
        let balancer = ConsistentHashBalancer::new(&servers, 150);
        let refs: Vec<&Arc<ServerState>> = servers.iter().collect();

        // Same key should always select same server
        let key = "test-key";
        let s1 = balancer.select_by_key(&refs, key);
        let s2 = balancer.select_by_key(&refs, key);

        assert_eq!(s1.map(|s| s.server.address), s2.map(|s| s.server.address));
    }

    #[test]
    fn test_empty_servers() {
        let balancer = RoundRobinBalancer::new();
        let refs: Vec<&Arc<ServerState>> = vec![];

        assert!(balancer.select(&refs).is_none());
    }

    #[test]
    fn test_sticky_session_cookie_generation() {
        let servers = create_test_servers(3);
        let config = StickySessionConfig::default();
        let balancer = StickySessionBalancer::new(config, &servers);

        let cookie = balancer.generate_cookie(&servers[0]);
        assert!(cookie.starts_with("PRISM_AFFINITY="));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
    }

    #[test]
    fn test_sticky_session_cookie_parsing() {
        let servers = create_test_servers(3);
        let config = StickySessionConfig::new("MY_SESSION");
        let balancer = StickySessionBalancer::new(config, &servers);

        // Parse from cookie header
        let session = balancer.parse_cookie_value("other=abc; MY_SESSION=xyz123; another=def");
        assert_eq!(session, Some("xyz123".to_string()));

        // Cookie not present
        let session = balancer.parse_cookie_value("other=abc");
        assert!(session.is_none());
    }

    #[test]
    fn test_sticky_session_affinity() {
        let servers = create_test_servers(3);
        let config = StickySessionConfig::default();
        let balancer = StickySessionBalancer::new(config.clone(), &servers);
        let refs: Vec<&Arc<ServerState>> = servers.iter().collect();

        // First request - no cookie, should get new server
        let (server1, needs_cookie1) = select_with_sticky_session(&balancer, &refs, None);
        assert!(server1.is_some());
        assert!(needs_cookie1);

        // Generate cookie for selected server
        let cookie = balancer.generate_cookie(server1.unwrap());

        // Extract session value
        let session_id = balancer
            .parse_cookie_value(&cookie.replace("; ", "; "))
            .unwrap();

        // Second request with cookie - should get same server
        let cookie_header = format!("{}={}", config.cookie_name, session_id);
        let (server2, needs_cookie2) =
            select_with_sticky_session(&balancer, &refs, Some(&cookie_header));
        assert!(server2.is_some());
        assert!(!needs_cookie2);
        assert_eq!(
            server1.unwrap().server.address,
            server2.unwrap().server.address
        );
    }
}
