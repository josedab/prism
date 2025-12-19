//! Chaos Engineering / Fault Injection Middleware
//!
//! Provides controlled failure injection for testing system resilience:
//! - Latency injection (artificial delays)
//! - Error injection (return configured errors)
//! - Abort injection (drop connections)
//! - Response corruption (modify response bodies)
//! - Bandwidth limiting (throttle responses)

use crate::error::{PrismError, Result};
use crate::middleware::{HttpRequest, Middleware, Next, RequestContext};
use async_trait::async_trait;
use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn};

/// Chaos engineering configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChaosConfig {
    /// Whether chaos engineering is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Latency injection configuration
    #[serde(default)]
    pub latency: Option<LatencyConfig>,

    /// Error injection configuration
    #[serde(default)]
    pub error: Option<ErrorConfig>,

    /// Abort injection configuration
    #[serde(default)]
    pub abort: Option<AbortConfig>,

    /// Response corruption configuration
    #[serde(default)]
    pub corruption: Option<CorruptionConfig>,

    /// Bandwidth throttling configuration
    #[serde(default)]
    pub throttle: Option<ThrottleConfig>,

    /// Target specific paths (empty = all paths)
    #[serde(default)]
    pub target_paths: Vec<String>,

    /// Target specific methods (empty = all methods)
    #[serde(default)]
    pub target_methods: Vec<String>,

    /// Target specific headers (must match all)
    #[serde(default)]
    pub target_headers: std::collections::HashMap<String, String>,
}

/// Latency injection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LatencyConfig {
    /// Percentage of requests to affect (0-100)
    #[serde(default = "default_percentage")]
    pub percentage: f64,

    /// Fixed latency to add
    #[serde(default, with = "humantime_serde")]
    pub fixed: Option<Duration>,

    /// Minimum random latency
    #[serde(default, with = "humantime_serde")]
    pub min: Option<Duration>,

    /// Maximum random latency
    #[serde(default, with = "humantime_serde")]
    pub max: Option<Duration>,

    /// Distribution type for random latency
    #[serde(default)]
    pub distribution: LatencyDistribution,
}

/// Latency distribution types
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LatencyDistribution {
    /// Uniform random distribution
    #[default]
    Uniform,
    /// Normal (Gaussian) distribution
    Normal,
    /// Exponential distribution (models network latency well)
    Exponential,
    /// Pareto distribution (models long-tail latency)
    Pareto,
}

/// Error injection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorConfig {
    /// Percentage of requests to fail (0-100)
    #[serde(default = "default_percentage")]
    pub percentage: f64,

    /// HTTP status code to return
    #[serde(default = "default_error_status")]
    pub status: u16,

    /// Error message body
    #[serde(default = "default_error_message")]
    pub message: String,

    /// Custom headers to include in error response
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,

    /// gRPC status code (for gRPC requests)
    #[serde(default)]
    pub grpc_status: Option<i32>,
}

/// Abort injection configuration (connection drops)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortConfig {
    /// Percentage of requests to abort (0-100)
    #[serde(default = "default_percentage")]
    pub percentage: f64,

    /// When to abort: "before_request", "during_request", "before_response"
    #[serde(default)]
    pub timing: AbortTiming,
}

/// When to abort the connection
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AbortTiming {
    /// Abort before forwarding request
    #[default]
    BeforeRequest,
    /// Abort during request forwarding (partial send)
    DuringRequest,
    /// Abort before sending response
    BeforeResponse,
}

/// Response corruption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorruptionConfig {
    /// Percentage of responses to corrupt (0-100)
    #[serde(default = "default_percentage")]
    pub percentage: f64,

    /// Type of corruption to apply
    #[serde(default)]
    pub corruption_type: CorruptionType,

    /// For truncation: percentage of body to keep (0-100)
    #[serde(default = "default_truncate_percentage")]
    pub truncate_percentage: f64,

    /// For bit_flip: number of bits to flip
    #[serde(default = "default_bit_flips")]
    pub bit_flips: usize,
}

/// Types of response corruption
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CorruptionType {
    /// Truncate response body
    #[default]
    Truncate,
    /// Flip random bits in response
    BitFlip,
    /// Replace body with garbage
    Replace,
    /// Duplicate parts of the response
    Duplicate,
}

/// Bandwidth throttling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThrottleConfig {
    /// Percentage of requests to throttle (0-100)
    #[serde(default = "default_percentage")]
    pub percentage: f64,

    /// Bandwidth limit in bytes per second
    #[serde(default = "default_bandwidth")]
    pub bandwidth_bps: u64,
}

fn default_percentage() -> f64 {
    10.0
}

fn default_error_status() -> u16 {
    500
}

fn default_error_message() -> String {
    "Chaos Engineering: Injected Error".to_string()
}

fn default_truncate_percentage() -> f64 {
    50.0
}

fn default_bit_flips() -> usize {
    5
}

fn default_bandwidth() -> u64 {
    1024 // 1 KB/s
}

/// Chaos Engineering Middleware
pub struct ChaosMiddleware {
    config: ChaosConfig,
}

impl ChaosMiddleware {
    /// Create a new chaos middleware
    pub fn new(config: ChaosConfig) -> Self {
        Self { config }
    }

    /// Check if this request should be targeted
    fn should_target(&self, request: &HttpRequest, _ctx: &RequestContext) -> bool {
        // Check path targeting
        if !self.config.target_paths.is_empty() {
            let path = request.uri().path();
            let matches_path = self.config.target_paths.iter().any(|p| {
                if p.ends_with('*') {
                    path.starts_with(&p[..p.len() - 1])
                } else {
                    path == p
                }
            });
            if !matches_path {
                return false;
            }
        }

        // Check method targeting
        if !self.config.target_methods.is_empty() {
            let method = request.method().as_str();
            if !self
                .config
                .target_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method))
            {
                return false;
            }
        }

        // Check header targeting
        for (key, value) in &self.config.target_headers {
            match request.headers().get(key) {
                Some(v) if v.to_str().ok() == Some(value) => {}
                _ => return false,
            }
        }

        true
    }

    /// Check if chaos should be applied based on percentage
    fn should_apply(percentage: f64) -> bool {
        if percentage <= 0.0 {
            return false;
        }
        if percentage >= 100.0 {
            return true;
        }
        rand::thread_rng().gen::<f64>() * 100.0 < percentage
    }

    /// Calculate latency to inject
    fn calculate_latency(config: &LatencyConfig) -> Duration {
        if let Some(fixed) = config.fixed {
            return fixed;
        }

        let min = config.min.unwrap_or(Duration::ZERO);
        let max = config.max.unwrap_or(Duration::from_secs(1));

        if min >= max {
            return min;
        }

        let mut rng = rand::thread_rng();
        let range_ms = (max - min).as_millis() as f64;

        let delay_ms = match config.distribution {
            LatencyDistribution::Uniform => rng.gen::<f64>() * range_ms,
            LatencyDistribution::Normal => {
                // Normal distribution centered at middle of range
                let mean = range_ms / 2.0;
                let std_dev = range_ms / 6.0; // 99.7% within range
                let normal: f64 = rng.gen::<f64>()
                    + rng.gen::<f64>()
                    + rng.gen::<f64>()
                    + rng.gen::<f64>()
                    + rng.gen::<f64>()
                    + rng.gen::<f64>();
                let normal = (normal - 3.0) / 1.0; // Approximate standard normal
                (mean + normal * std_dev).clamp(0.0, range_ms)
            }
            LatencyDistribution::Exponential => {
                // Exponential distribution
                let lambda = 2.0 / range_ms;
                let u: f64 = rng.gen();
                (-u.ln() / lambda).min(range_ms)
            }
            LatencyDistribution::Pareto => {
                // Pareto distribution for long-tail behavior
                let alpha = 1.5;
                let u: f64 = rng.gen();
                let pareto = 1.0 / u.powf(1.0 / alpha);
                ((pareto - 1.0) * range_ms / 10.0).min(range_ms)
            }
        };

        min + Duration::from_millis(delay_ms as u64)
    }

    /// Corrupt a response body
    fn corrupt_body(body: Bytes, config: &CorruptionConfig) -> Bytes {
        if body.is_empty() {
            return body;
        }

        let mut data = body.to_vec();
        let mut rng = rand::thread_rng();

        match config.corruption_type {
            CorruptionType::Truncate => {
                let keep = (data.len() as f64 * config.truncate_percentage / 100.0) as usize;
                data.truncate(keep.max(1));
            }
            CorruptionType::BitFlip => {
                for _ in 0..config.bit_flips.min(data.len() * 8) {
                    let byte_idx = rng.gen_range(0..data.len());
                    let bit_idx = rng.gen_range(0..8);
                    data[byte_idx] ^= 1 << bit_idx;
                }
            }
            CorruptionType::Replace => {
                for byte in &mut data {
                    *byte = rng.gen();
                }
            }
            CorruptionType::Duplicate => {
                if data.len() > 10 {
                    let start = rng.gen_range(0..data.len() / 2);
                    let len = rng.gen_range(1..data.len() / 4);
                    let chunk: Vec<u8> = data[start..start + len].to_vec();
                    let insert_pos = rng.gen_range(0..data.len());
                    data.splice(insert_pos..insert_pos, chunk);
                }
            }
        }

        Bytes::from(data)
    }
}

#[async_trait]
impl Middleware for ChaosMiddleware {
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<Response<Full<Bytes>>> {
        if !self.config.enabled {
            return next.run(request, ctx).await;
        }

        if !self.should_target(&request, &ctx) {
            return next.run(request, ctx).await;
        }

        // Check for abort (before request)
        if let Some(abort) = &self.config.abort {
            if abort.timing == AbortTiming::BeforeRequest && Self::should_apply(abort.percentage) {
                warn!(
                    request_id = %ctx.request_id,
                    "Chaos: Aborting request before forwarding"
                );
                return Err(PrismError::Chaos(
                    "Connection aborted by chaos injection".to_string(),
                ));
            }
        }

        // Inject latency before request
        if let Some(latency) = &self.config.latency {
            if Self::should_apply(latency.percentage) {
                let delay = Self::calculate_latency(latency);
                debug!(
                    request_id = %ctx.request_id,
                    delay_ms = %delay.as_millis(),
                    "Chaos: Injecting latency"
                );
                tokio::time::sleep(delay).await;
            }
        }

        // Check for error injection
        if let Some(error) = &self.config.error {
            if Self::should_apply(error.percentage) {
                warn!(
                    request_id = %ctx.request_id,
                    status = %error.status,
                    "Chaos: Injecting error response"
                );

                let mut builder = Response::builder().status(
                    StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                );

                for (key, value) in &error.headers {
                    builder = builder.header(key.as_str(), value.as_str());
                }

                // Add chaos header for debugging
                builder = builder.header("X-Chaos-Injected", "error");

                return Ok(builder
                    .body(Full::new(Bytes::from(error.message.clone())))
                    .unwrap());
            }
        }

        // Forward request
        let response = next.run(request, ctx.clone()).await?;

        // Check for abort (before response)
        if let Some(abort) = &self.config.abort {
            if abort.timing == AbortTiming::BeforeResponse && Self::should_apply(abort.percentage) {
                warn!(
                    request_id = %ctx.request_id,
                    "Chaos: Aborting before sending response"
                );
                return Err(PrismError::Chaos(
                    "Connection aborted by chaos injection".to_string(),
                ));
            }
        }

        // Apply response corruption
        if let Some(corruption) = &self.config.corruption {
            if Self::should_apply(corruption.percentage) {
                let (parts, body) = response.into_parts();

                // Collect the body bytes using BodyExt
                use http_body_util::BodyExt;
                let body_bytes = body
                    .collect()
                    .await
                    .map(|c| c.to_bytes())
                    .unwrap_or_default();
                let original_len = body_bytes.len();
                let corrupted = Self::corrupt_body(body_bytes, corruption);

                debug!(
                    request_id = %ctx.request_id,
                    original_len = %original_len,
                    corrupted_len = %corrupted.len(),
                    corruption_type = ?corruption.corruption_type,
                    "Chaos: Corrupted response"
                );

                let mut response = Response::from_parts(parts, Full::new(corrupted));
                response
                    .headers_mut()
                    .insert("X-Chaos-Injected", "corruption".parse().unwrap());
                return Ok(response);
            }
        }

        Ok(response)
    }

    fn name(&self) -> &'static str {
        "chaos"
    }
}

/// Chaos engineering statistics
#[derive(Debug, Clone, Default)]
pub struct ChaosStats {
    /// Total requests processed
    pub total_requests: u64,
    /// Requests with latency injected
    pub latency_injected: u64,
    /// Requests with errors injected
    pub errors_injected: u64,
    /// Requests aborted
    pub aborts_injected: u64,
    /// Responses corrupted
    pub corruptions_injected: u64,
}

/// Helper module for humantime serde
mod humantime_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(
        duration: &Option<Duration>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(d) => {
                let s = humantime::format_duration(*d).to_string();
                serializer.serialize_some(&s)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => humantime::parse_duration(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ChaosConfig::default();
        assert!(!config.enabled);
        assert!(config.latency.is_none());
        assert!(config.error.is_none());
    }

    #[test]
    fn test_should_apply_percentage() {
        // 0% should never apply
        let mut applied = false;
        for _ in 0..100 {
            if ChaosMiddleware::should_apply(0.0) {
                applied = true;
                break;
            }
        }
        assert!(!applied);

        // 100% should always apply
        for _ in 0..100 {
            assert!(ChaosMiddleware::should_apply(100.0));
        }
    }

    #[test]
    fn test_calculate_latency_fixed() {
        let config = LatencyConfig {
            percentage: 100.0,
            fixed: Some(Duration::from_millis(100)),
            min: None,
            max: None,
            distribution: LatencyDistribution::Uniform,
        };

        let latency = ChaosMiddleware::calculate_latency(&config);
        assert_eq!(latency, Duration::from_millis(100));
    }

    #[test]
    fn test_calculate_latency_range() {
        let config = LatencyConfig {
            percentage: 100.0,
            fixed: None,
            min: Some(Duration::from_millis(10)),
            max: Some(Duration::from_millis(100)),
            distribution: LatencyDistribution::Uniform,
        };

        for _ in 0..100 {
            let latency = ChaosMiddleware::calculate_latency(&config);
            assert!(latency >= Duration::from_millis(10));
            assert!(latency <= Duration::from_millis(100));
        }
    }

    #[test]
    fn test_corrupt_body_truncate() {
        let config = CorruptionConfig {
            percentage: 100.0,
            corruption_type: CorruptionType::Truncate,
            truncate_percentage: 50.0,
            bit_flips: 0,
        };

        let body = Bytes::from("Hello, World!");
        let corrupted = ChaosMiddleware::corrupt_body(body.clone(), &config);
        assert!(corrupted.len() < body.len());
    }

    #[test]
    fn test_corrupt_body_bitflip() {
        let config = CorruptionConfig {
            percentage: 100.0,
            corruption_type: CorruptionType::BitFlip,
            truncate_percentage: 50.0,
            bit_flips: 5,
        };

        let body = Bytes::from("Hello, World!");
        let corrupted = ChaosMiddleware::corrupt_body(body.clone(), &config);
        assert_eq!(corrupted.len(), body.len());
        assert_ne!(corrupted, body); // Should be different due to bit flips
    }

    #[test]
    fn test_latency_distributions() {
        for distribution in [
            LatencyDistribution::Uniform,
            LatencyDistribution::Normal,
            LatencyDistribution::Exponential,
            LatencyDistribution::Pareto,
        ] {
            let config = LatencyConfig {
                percentage: 100.0,
                fixed: None,
                min: Some(Duration::from_millis(10)),
                max: Some(Duration::from_millis(1000)),
                distribution,
            };

            // Just verify it doesn't panic
            for _ in 0..10 {
                let _ = ChaosMiddleware::calculate_latency(&config);
            }
        }
    }
}
