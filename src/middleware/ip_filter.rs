//! IP-based access control middleware
//!
//! Provides IP allowlisting and denylisting with CIDR range support.
//! Can be used to restrict access to specific IP ranges.

use super::{HttpRequest, HttpResponse, Middleware, Next, RequestContext};
use crate::error::Result;
use async_trait::async_trait;
use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, warn};

/// IP filter configuration
#[derive(Debug, Clone)]
pub struct IpFilterConfig {
    /// List of allowed IP ranges (CIDR notation)
    pub allow: Vec<IpRange>,
    /// List of denied IP ranges (CIDR notation)
    pub deny: Vec<IpRange>,
    /// Default action when no rule matches
    pub default_action: IpFilterAction,
    /// Whether to check X-Forwarded-For header
    pub trust_proxy: bool,
    /// Custom forbidden message
    pub forbidden_message: Option<String>,
}

impl Default for IpFilterConfig {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            deny: Vec::new(),
            default_action: IpFilterAction::Allow,
            trust_proxy: false,
            forbidden_message: None,
        }
    }
}

impl IpFilterConfig {
    /// Create an allowlist-only config (block everything not explicitly allowed)
    pub fn allowlist(ranges: Vec<&str>) -> Self {
        Self {
            allow: ranges.into_iter().filter_map(|r| r.parse().ok()).collect(),
            deny: Vec::new(),
            default_action: IpFilterAction::Deny,
            ..Default::default()
        }
    }

    /// Create a denylist-only config (allow everything not explicitly denied)
    pub fn denylist(ranges: Vec<&str>) -> Self {
        Self {
            allow: Vec::new(),
            deny: ranges.into_iter().filter_map(|r| r.parse().ok()).collect(),
            default_action: IpFilterAction::Allow,
            ..Default::default()
        }
    }

    /// Add an allowed range
    pub fn allow_range(mut self, range: &str) -> Self {
        if let Ok(r) = range.parse() {
            self.allow.push(r);
        }
        self
    }

    /// Add a denied range
    pub fn deny_range(mut self, range: &str) -> Self {
        if let Ok(r) = range.parse() {
            self.deny.push(r);
        }
        self
    }
}

/// IP filter action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpFilterAction {
    /// Allow the request
    #[default]
    Allow,
    /// Deny the request
    Deny,
}

/// IP range with CIDR support
#[derive(Debug, Clone)]
pub struct IpRange {
    /// Base IP address
    base: IpAddr,
    /// Network prefix length (bits)
    prefix_len: u8,
}

impl IpRange {
    /// Create a new IP range
    pub fn new(base: IpAddr, prefix_len: u8) -> Self {
        Self { base, prefix_len }
    }

    /// Create a single IP range
    pub fn single(ip: IpAddr) -> Self {
        let prefix_len = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self {
            base: ip,
            prefix_len,
        }
    }

    /// Check if an IP is within this range
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (&self.base, ip) {
            (IpAddr::V4(base), IpAddr::V4(test)) => self.contains_v4(*base, *test, self.prefix_len),
            (IpAddr::V6(base), IpAddr::V6(test)) => self.contains_v6(*base, *test, self.prefix_len),
            _ => false, // v4/v6 mismatch
        }
    }

    fn contains_v4(&self, base: Ipv4Addr, test: Ipv4Addr, prefix_len: u8) -> bool {
        if prefix_len == 0 {
            return true;
        }
        if prefix_len > 32 {
            return false;
        }

        let base_bits = u32::from(base);
        let test_bits = u32::from(test);
        let mask = if prefix_len == 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - prefix_len)
        };

        (base_bits & mask) == (test_bits & mask)
    }

    fn contains_v6(&self, base: Ipv6Addr, test: Ipv6Addr, prefix_len: u8) -> bool {
        if prefix_len == 0 {
            return true;
        }
        if prefix_len > 128 {
            return false;
        }

        let base_bits = u128::from(base);
        let test_bits = u128::from(test);
        let mask = if prefix_len == 128 {
            u128::MAX
        } else {
            u128::MAX << (128 - prefix_len)
        };

        (base_bits & mask) == (test_bits & mask)
    }
}

impl std::str::FromStr for IpRange {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let s = s.trim();

        // Check for CIDR notation
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let ip: IpAddr = ip_str.parse().map_err(|e| format!("Invalid IP: {}", e))?;
            let prefix_len: u8 = prefix_str
                .parse()
                .map_err(|e| format!("Invalid prefix length: {}", e))?;

            // Validate prefix length
            let max_prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix_len > max_prefix {
                return Err(format!(
                    "Prefix length {} exceeds maximum {} for IP version",
                    prefix_len, max_prefix
                ));
            }

            Ok(IpRange::new(ip, prefix_len))
        } else {
            // Single IP
            let ip: IpAddr = s.parse().map_err(|e| format!("Invalid IP: {}", e))?;
            Ok(IpRange::single(ip))
        }
    }
}

/// IP filter middleware
pub struct IpFilterMiddleware {
    config: IpFilterConfig,
}

impl IpFilterMiddleware {
    /// Create a new IP filter middleware
    pub fn new(config: IpFilterConfig) -> Self {
        Self { config }
    }

    /// Create an allowlist-only middleware
    pub fn allowlist(ranges: Vec<&str>) -> Self {
        Self::new(IpFilterConfig::allowlist(ranges))
    }

    /// Create a denylist-only middleware
    pub fn denylist(ranges: Vec<&str>) -> Self {
        Self::new(IpFilterConfig::denylist(ranges))
    }

    /// Get client IP from request context or headers
    fn get_client_ip(&self, request: &HttpRequest, ctx: &RequestContext) -> Option<IpAddr> {
        // First try X-Forwarded-For if configured to trust proxy
        if self.config.trust_proxy {
            if let Some(forwarded) = request.headers().get("x-forwarded-for") {
                if let Ok(value) = forwarded.to_str() {
                    // Take the first (original client) IP
                    if let Some(first_ip) = value.split(',').next() {
                        if let Ok(ip) = first_ip.trim().parse() {
                            return Some(ip);
                        }
                    }
                }
            }
        }

        // Fall back to context client IP
        ctx.client_ip
            .as_ref()
            .and_then(|ip_str| ip_str.parse().ok())
    }

    /// Check if an IP is allowed
    fn check_ip(&self, ip: &IpAddr) -> IpFilterAction {
        // Check deny list first (deny takes precedence)
        for range in &self.config.deny {
            if range.contains(ip) {
                debug!("IP {} matches deny rule {:?}", ip, range.base);
                return IpFilterAction::Deny;
            }
        }

        // Check allow list
        if !self.config.allow.is_empty() {
            for range in &self.config.allow {
                if range.contains(ip) {
                    debug!("IP {} matches allow rule {:?}", ip, range.base);
                    return IpFilterAction::Allow;
                }
            }
            // If there are allow rules but none matched, deny
            return IpFilterAction::Deny;
        }

        // No matching rules, use default action
        self.config.default_action
    }

    /// Create a forbidden response
    fn forbidden_response(&self) -> HttpResponse {
        let message = self
            .config
            .forbidden_message
            .clone()
            .unwrap_or_else(|| "Forbidden".to_string());

        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from(message)))
            .unwrap()
    }
}

#[async_trait]
impl Middleware for IpFilterMiddleware {
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        // Get client IP
        let client_ip = match self.get_client_ip(&request, &ctx) {
            Some(ip) => ip,
            None => {
                // If we can't determine client IP, use default action
                debug!("Could not determine client IP, using default action");
                if self.config.default_action == IpFilterAction::Deny {
                    return Ok(self.forbidden_response());
                }
                return next.run(request, ctx).await;
            }
        };

        // Check IP against rules
        match self.check_ip(&client_ip) {
            IpFilterAction::Allow => next.run(request, ctx).await,
            IpFilterAction::Deny => {
                warn!("Blocking request from IP: {}", client_ip);
                Ok(self.forbidden_response())
            }
        }
    }

    fn name(&self) -> &'static str {
        "ip_filter"
    }
}

/// Common IP ranges
pub mod common_ranges {
    /// RFC 1918 private IPv4 ranges
    pub const PRIVATE_IPV4: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

    /// Loopback addresses
    pub const LOOPBACK: &[&str] = &["127.0.0.0/8", "::1/128"];

    /// Link-local addresses
    pub const LINK_LOCAL: &[&str] = &["169.254.0.0/16", "fe80::/10"];

    /// All internal/private ranges
    pub fn all_private() -> Vec<&'static str> {
        let mut ranges = Vec::new();
        ranges.extend_from_slice(PRIVATE_IPV4);
        ranges.extend_from_slice(LOOPBACK);
        ranges.extend_from_slice(LINK_LOCAL);
        ranges
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_range_parse() {
        let range: IpRange = "192.168.1.0/24".parse().unwrap();
        assert!(range.contains(&"192.168.1.1".parse().unwrap()));
        assert!(range.contains(&"192.168.1.255".parse().unwrap()));
        assert!(!range.contains(&"192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn test_single_ip() {
        let range: IpRange = "10.0.0.1".parse().unwrap();
        assert!(range.contains(&"10.0.0.1".parse().unwrap()));
        assert!(!range.contains(&"10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_ipv6_range() {
        let range: IpRange = "2001:db8::/32".parse().unwrap();
        assert!(range.contains(&"2001:db8::1".parse().unwrap()));
        assert!(range.contains(&"2001:db8:ffff::1".parse().unwrap()));
        assert!(!range.contains(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_allowlist() {
        let config = IpFilterConfig::allowlist(vec!["192.168.0.0/16", "10.0.0.0/8"]);
        let middleware = IpFilterMiddleware::new(config);

        // Allowed
        assert_eq!(
            middleware.check_ip(&"192.168.1.1".parse().unwrap()),
            IpFilterAction::Allow
        );
        assert_eq!(
            middleware.check_ip(&"10.0.0.1".parse().unwrap()),
            IpFilterAction::Allow
        );

        // Denied (not in allowlist)
        assert_eq!(
            middleware.check_ip(&"8.8.8.8".parse().unwrap()),
            IpFilterAction::Deny
        );
    }

    #[test]
    fn test_denylist() {
        let config = IpFilterConfig::denylist(vec!["192.168.0.0/16"]);
        let middleware = IpFilterMiddleware::new(config);

        // Denied
        assert_eq!(
            middleware.check_ip(&"192.168.1.1".parse().unwrap()),
            IpFilterAction::Deny
        );

        // Allowed (not in denylist)
        assert_eq!(
            middleware.check_ip(&"10.0.0.1".parse().unwrap()),
            IpFilterAction::Allow
        );
    }

    #[test]
    fn test_deny_takes_precedence() {
        let mut config = IpFilterConfig::default();
        config.allow.push("192.168.0.0/16".parse().unwrap());
        config.deny.push("192.168.1.0/24".parse().unwrap());

        let middleware = IpFilterMiddleware::new(config);

        // 192.168.2.1 is in allow range and not in deny range
        assert_eq!(
            middleware.check_ip(&"192.168.2.1".parse().unwrap()),
            IpFilterAction::Allow
        );

        // 192.168.1.1 is in both, deny takes precedence
        assert_eq!(
            middleware.check_ip(&"192.168.1.1".parse().unwrap()),
            IpFilterAction::Deny
        );
    }

    #[test]
    fn test_cidr_edge_cases() {
        // /0 matches everything
        let range: IpRange = "0.0.0.0/0".parse().unwrap();
        assert!(range.contains(&"1.2.3.4".parse().unwrap()));
        assert!(range.contains(&"255.255.255.255".parse().unwrap()));

        // /32 matches exact IP
        let range: IpRange = "192.168.1.100/32".parse().unwrap();
        assert!(range.contains(&"192.168.1.100".parse().unwrap()));
        assert!(!range.contains(&"192.168.1.101".parse().unwrap()));
    }

    #[test]
    fn test_private_ranges() {
        for range_str in common_ranges::PRIVATE_IPV4 {
            let range: IpRange = range_str.parse().unwrap();
            // Just verify parsing works
            assert!(range.prefix_len <= 32);
        }
    }
}
