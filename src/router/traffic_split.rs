//! Traffic splitting for canary and A/B deployments
//!
//! Provides weighted traffic distribution between multiple upstreams.
//! Supports canary deployments, A/B testing, and gradual rollouts.

use rand::Rng;
use std::sync::atomic::{AtomicU64, Ordering};

/// Traffic split configuration
#[derive(Debug, Clone)]
pub struct TrafficSplitConfig {
    /// Name of this split configuration
    pub name: String,
    /// List of targets with weights
    pub targets: Vec<SplitTarget>,
    /// Split strategy
    pub strategy: SplitStrategy,
    /// Whether to use sticky routing (same client goes to same target)
    pub sticky: bool,
    /// Cookie name for sticky routing
    pub sticky_cookie: String,
}

impl Default for TrafficSplitConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            targets: Vec::new(),
            strategy: SplitStrategy::Weighted,
            sticky: false,
            sticky_cookie: "PRISM_CANARY".to_string(),
        }
    }
}

impl TrafficSplitConfig {
    /// Create a new traffic split config
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Add a target with weight
    pub fn with_target(mut self, upstream: impl Into<String>, weight: u32) -> Self {
        self.targets.push(SplitTarget {
            upstream: upstream.into(),
            weight,
            headers: Vec::new(),
        });
        self
    }

    /// Create a simple canary config (primary + canary with percentage)
    pub fn canary(
        primary: impl Into<String>,
        canary: impl Into<String>,
        canary_percentage: u32,
    ) -> Self {
        let primary_weight = 100 - canary_percentage.min(100);
        Self::new("canary")
            .with_target(primary, primary_weight)
            .with_target(canary, canary_percentage.min(100))
    }

    /// Create a blue/green config
    pub fn blue_green(
        blue: impl Into<String>,
        green: impl Into<String>,
        green_active: bool,
    ) -> Self {
        if green_active {
            Self::new("blue-green").with_target(green, 100)
        } else {
            Self::new("blue-green").with_target(blue, 100)
        }
    }

    /// Calculate total weight
    pub fn total_weight(&self) -> u32 {
        self.targets.iter().map(|t| t.weight).sum()
    }

    /// Normalize weights to percentages
    pub fn normalized_weights(&self) -> Vec<(String, f64)> {
        let total = self.total_weight() as f64;
        if total == 0.0 {
            return Vec::new();
        }

        self.targets
            .iter()
            .map(|t| (t.upstream.clone(), t.weight as f64 / total * 100.0))
            .collect()
    }
}

/// Split target
#[derive(Debug, Clone)]
pub struct SplitTarget {
    /// Target upstream name
    pub upstream: String,
    /// Weight for this target
    pub weight: u32,
    /// Optional headers to add when routing to this target
    pub headers: Vec<(String, String)>,
}

impl SplitTarget {
    /// Create a new split target
    pub fn new(upstream: impl Into<String>, weight: u32) -> Self {
        Self {
            upstream: upstream.into(),
            weight,
            headers: Vec::new(),
        }
    }

    /// Add a header
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// Split strategy
#[derive(Debug, Clone, Copy, Default)]
pub enum SplitStrategy {
    /// Weighted random distribution
    #[default]
    Weighted,
    /// Round-robin with weights
    RoundRobin,
    /// Header-based routing
    HeaderBased,
}

/// Traffic splitter
pub struct TrafficSplitter {
    config: TrafficSplitConfig,
    /// Counter for round-robin
    counter: AtomicU64,
    /// Total weight
    total_weight: u32,
}

impl TrafficSplitter {
    /// Create a new traffic splitter
    pub fn new(config: TrafficSplitConfig) -> Self {
        let total_weight = config.total_weight();
        Self {
            config,
            counter: AtomicU64::new(0),
            total_weight,
        }
    }

    /// Create a canary splitter
    pub fn canary(
        primary: impl Into<String>,
        canary: impl Into<String>,
        canary_percentage: u32,
    ) -> Self {
        Self::new(TrafficSplitConfig::canary(
            primary,
            canary,
            canary_percentage,
        ))
    }

    /// Select a target based on the configured strategy
    pub fn select(&self) -> Option<&SplitTarget> {
        if self.config.targets.is_empty() || self.total_weight == 0 {
            return None;
        }

        match self.config.strategy {
            SplitStrategy::Weighted => self.select_weighted(),
            SplitStrategy::RoundRobin => self.select_round_robin(),
            SplitStrategy::HeaderBased => {
                // For header-based, we need the request headers
                // Fall back to weighted
                self.select_weighted()
            }
        }
    }

    /// Select target by header value
    pub fn select_by_header(&self, header_value: Option<&str>) -> Option<&SplitTarget> {
        if let Some(value) = header_value {
            // Try to find a target that matches the header value
            for target in &self.config.targets {
                if target.upstream == value {
                    return Some(target);
                }
            }
        }

        // Fall back to normal selection
        self.select()
    }

    /// Select target by sticky cookie value
    pub fn select_by_cookie(&self, cookie_value: Option<&str>) -> Option<&SplitTarget> {
        if !self.config.sticky {
            return self.select();
        }

        if let Some(value) = cookie_value {
            // Try to find target matching cookie value
            for target in &self.config.targets {
                if target.upstream == value {
                    return Some(target);
                }
            }
        }

        // No matching cookie, select normally
        self.select()
    }

    /// Weighted random selection
    fn select_weighted(&self) -> Option<&SplitTarget> {
        let roll = rand::thread_rng().gen_range(0..self.total_weight);
        self.select_by_weight(roll)
    }

    /// Round-robin selection with weights
    fn select_round_robin(&self) -> Option<&SplitTarget> {
        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        let weight_index = (count as u32) % self.total_weight;
        self.select_by_weight(weight_index)
    }

    /// Select by weight index
    fn select_by_weight(&self, weight_index: u32) -> Option<&SplitTarget> {
        let mut cumulative = 0u32;
        for target in &self.config.targets {
            cumulative += target.weight;
            if weight_index < cumulative {
                return Some(target);
            }
        }
        self.config.targets.last()
    }

    /// Get config
    pub fn config(&self) -> &TrafficSplitConfig {
        &self.config
    }

    /// Get sticky cookie name
    pub fn sticky_cookie(&self) -> Option<&str> {
        if self.config.sticky {
            Some(&self.config.sticky_cookie)
        } else {
            None
        }
    }

    /// Generate cookie value for a target
    pub fn cookie_value_for(&self, target: &SplitTarget) -> String {
        format!("{}={}; Path=/", self.config.sticky_cookie, target.upstream)
    }
}

/// Traffic split result
#[derive(Debug, Clone)]
pub struct SplitResult {
    /// Selected upstream name
    pub upstream: String,
    /// Headers to add
    pub headers: Vec<(String, String)>,
    /// Whether a new cookie should be set
    pub set_cookie: Option<String>,
}

impl From<&SplitTarget> for SplitResult {
    fn from(target: &SplitTarget) -> Self {
        Self {
            upstream: target.upstream.clone(),
            headers: target.headers.clone(),
            set_cookie: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_canary_config() {
        let config = TrafficSplitConfig::canary("primary", "canary", 10);

        assert_eq!(config.targets.len(), 2);
        assert_eq!(config.targets[0].upstream, "primary");
        assert_eq!(config.targets[0].weight, 90);
        assert_eq!(config.targets[1].upstream, "canary");
        assert_eq!(config.targets[1].weight, 10);
    }

    #[test]
    fn test_weighted_distribution() {
        let splitter = TrafficSplitter::canary("primary", "canary", 20);

        let mut counts: HashMap<String, u32> = HashMap::new();

        // Sample many selections
        for _ in 0..10000 {
            if let Some(target) = splitter.select() {
                *counts.entry(target.upstream.clone()).or_insert(0) += 1;
            }
        }

        // Canary should get ~20% of traffic
        let canary_count = counts.get("canary").copied().unwrap_or(0);
        let canary_pct = canary_count as f64 / 10000.0 * 100.0;

        assert!(
            canary_pct > 15.0 && canary_pct < 25.0,
            "Canary got {}% of traffic, expected ~20%",
            canary_pct
        );
    }

    #[test]
    fn test_blue_green() {
        // Green active
        let config = TrafficSplitConfig::blue_green("blue", "green", true);
        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.targets[0].upstream, "green");

        // Blue active
        let config = TrafficSplitConfig::blue_green("blue", "green", false);
        assert_eq!(config.targets.len(), 1);
        assert_eq!(config.targets[0].upstream, "blue");
    }

    #[test]
    fn test_normalized_weights() {
        let config = TrafficSplitConfig::new("test")
            .with_target("a", 50)
            .with_target("b", 30)
            .with_target("c", 20);

        let normalized = config.normalized_weights();

        assert!((normalized[0].1 - 50.0).abs() < 0.01);
        assert!((normalized[1].1 - 30.0).abs() < 0.01);
        assert!((normalized[2].1 - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_round_robin_with_weights() {
        let config = TrafficSplitConfig::new("test")
            .with_target("a", 2)
            .with_target("b", 1);

        let mut splitter_config = config.clone();
        splitter_config.strategy = SplitStrategy::RoundRobin;

        let splitter = TrafficSplitter::new(splitter_config);

        // Should cycle: a, a, b, a, a, b, ...
        let mut results = Vec::new();
        for _ in 0..6 {
            results.push(splitter.select().unwrap().upstream.clone());
        }

        // Count occurrences
        let a_count = results.iter().filter(|&s| s == "a").count();
        let b_count = results.iter().filter(|&s| s == "b").count();

        assert_eq!(a_count, 4); // 2/3 of 6
        assert_eq!(b_count, 2); // 1/3 of 6
    }

    #[test]
    fn test_sticky_selection() {
        let config = TrafficSplitConfig {
            sticky: true,
            ..TrafficSplitConfig::canary("primary", "canary", 50)
        };
        let splitter = TrafficSplitter::new(config);

        // With matching cookie
        let result = splitter.select_by_cookie(Some("canary"));
        assert_eq!(result.unwrap().upstream, "canary");

        // With non-matching cookie falls back to normal selection
        let _result = splitter.select_by_cookie(Some("unknown"));
        // Will randomly select one
    }

    #[test]
    fn test_header_based_selection() {
        let config = TrafficSplitConfig::new("test")
            .with_target("v1", 50)
            .with_target("v2", 50);
        let splitter = TrafficSplitter::new(config);

        // Explicit version header
        let result = splitter.select_by_header(Some("v2"));
        assert_eq!(result.unwrap().upstream, "v2");
    }
}
