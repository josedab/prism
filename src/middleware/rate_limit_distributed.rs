//! Distributed rate limiting using Redis
//!
//! Provides cluster-aware rate limiting using Redis as the shared state store.
//! Uses the sliding window algorithm for accurate rate limiting across multiple instances.

#[cfg(feature = "distributed-rate-limit")]
mod redis_impl {
    use crate::config::RateLimitKey;
    use crate::error::{PrismError, Result};
    use redis::aio::ConnectionManager;
    use redis::{AsyncCommands, Client, Script};
    use std::time::Duration;
    use tracing::{debug, warn};

    /// Configuration for distributed rate limiting
    #[derive(Debug, Clone)]
    pub struct DistributedRateLimitConfig {
        /// Redis connection URL (e.g., "redis://127.0.0.1:6379")
        pub redis_url: String,
        /// Key prefix for rate limit entries
        pub key_prefix: String,
        /// Maximum requests per window
        pub max_requests: u32,
        /// Window duration
        pub window: Duration,
        /// Key extraction method
        pub key_by: RateLimitKey,
        /// Connection timeout
        pub connection_timeout: Duration,
        /// Operation timeout
        pub operation_timeout: Duration,
    }

    impl Default for DistributedRateLimitConfig {
        fn default() -> Self {
            Self {
                redis_url: "redis://127.0.0.1:6379".to_string(),
                key_prefix: "prism:ratelimit".to_string(),
                max_requests: 100,
                window: Duration::from_secs(60),
                key_by: RateLimitKey::Ip,
                connection_timeout: Duration::from_secs(5),
                operation_timeout: Duration::from_secs(1),
            }
        }
    }

    /// Result of a rate limit check
    #[derive(Debug)]
    pub struct RateLimitInfo {
        /// Whether the request is allowed
        pub allowed: bool,
        /// Current request count in the window
        pub current: u32,
        /// Maximum allowed requests
        pub limit: u32,
        /// Seconds until the window resets
        pub reset_after: Duration,
        /// Remaining requests in the window
        pub remaining: u32,
    }

    /// Distributed rate limiter using Redis
    pub struct DistributedRateLimiter {
        /// Configuration
        config: DistributedRateLimitConfig,
        /// Redis connection manager
        connection: ConnectionManager,
        /// Lua script for atomic rate limiting
        rate_limit_script: Script,
    }

    impl DistributedRateLimiter {
        /// Create a new distributed rate limiter
        pub async fn new(config: DistributedRateLimitConfig) -> Result<Self> {
            let client = Client::open(config.redis_url.as_str())
                .map_err(|e| PrismError::Config(format!("Failed to create Redis client: {}", e)))?;

            let connection = ConnectionManager::new(client)
                .await
                .map_err(|e| PrismError::Config(format!("Failed to connect to Redis: {}", e)))?;

            // Sliding window rate limit script
            // Uses sorted sets with timestamps for precise windowing
            let rate_limit_script = Script::new(
                r#"
                local key = KEYS[1]
                local now = tonumber(ARGV[1])
                local window_ms = tonumber(ARGV[2])
                local max_requests = tonumber(ARGV[3])
                local window_start = now - window_ms

                -- Remove expired entries
                redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

                -- Count current requests in window
                local current = redis.call('ZCARD', key)

                if current < max_requests then
                    -- Add new request
                    redis.call('ZADD', key, now, now .. ':' .. math.random())
                    redis.call('PEXPIRE', key, window_ms)
                    return {1, current + 1, max_requests, window_ms}
                else
                    -- Get oldest entry to calculate reset time
                    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
                    local reset_after = 0
                    if oldest and oldest[2] then
                        reset_after = oldest[2] + window_ms - now
                        if reset_after < 0 then reset_after = 0 end
                    end
                    return {0, current, max_requests, reset_after}
                end
                "#,
            );

            debug!("Distributed rate limiter connected to Redis");

            Ok(Self {
                config,
                connection,
                rate_limit_script,
            })
        }

        /// Check if a request is allowed
        pub async fn check(&self, key: &str) -> Result<RateLimitInfo> {
            let full_key = format!("{}:{}", self.config.key_prefix, key);
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let window_ms = self.config.window.as_millis() as i64;
            let max_requests = self.config.max_requests as i64;

            let mut conn = self.connection.clone();

            let result: Vec<i64> = self
                .rate_limit_script
                .key(&full_key)
                .arg(now_ms)
                .arg(window_ms)
                .arg(max_requests)
                .invoke_async(&mut conn)
                .await
                .map_err(|e| PrismError::Internal(format!("Redis error: {}", e)))?;

            if result.len() < 4 {
                return Err(PrismError::Internal(
                    "Invalid response from Redis".to_string(),
                ));
            }

            let allowed = result[0] == 1;
            let current = result[1] as u32;
            let limit = result[2] as u32;
            let reset_after_ms = result[3] as u64;

            Ok(RateLimitInfo {
                allowed,
                current,
                limit,
                reset_after: Duration::from_millis(reset_after_ms),
                remaining: if allowed { limit - current } else { 0 },
            })
        }

        /// Check rate limit with fallback for Redis failures
        pub async fn check_with_fallback(&self, key: &str, fallback_allow: bool) -> RateLimitInfo {
            match self.check(key).await {
                Ok(info) => info,
                Err(e) => {
                    warn!(
                        "Redis rate limit check failed, using fallback (allow={}): {}",
                        fallback_allow, e
                    );
                    RateLimitInfo {
                        allowed: fallback_allow,
                        current: 0,
                        limit: self.config.max_requests,
                        reset_after: self.config.window,
                        remaining: if fallback_allow {
                            self.config.max_requests
                        } else {
                            0
                        },
                    }
                }
            }
        }

        /// Get the current config
        pub fn config(&self) -> &DistributedRateLimitConfig {
            &self.config
        }

        /// Reset rate limit for a key
        pub async fn reset(&self, key: &str) -> Result<()> {
            let full_key = format!("{}:{}", self.config.key_prefix, key);
            let mut conn = self.connection.clone();

            conn.del::<_, ()>(&full_key)
                .await
                .map_err(|e| PrismError::Internal(format!("Redis error: {}", e)))?;

            debug!("Reset rate limit for key: {}", key);
            Ok(())
        }

        /// Get current usage for a key
        pub async fn get_usage(&self, key: &str) -> Result<u32> {
            let full_key = format!("{}:{}", self.config.key_prefix, key);
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let window_start = now_ms - self.config.window.as_millis() as i64;

            let mut conn = self.connection.clone();

            // First clean up expired entries
            conn.zrembyscore::<_, _, _, ()>(&full_key, "-inf", window_start)
                .await
                .map_err(|e| PrismError::Internal(format!("Redis error: {}", e)))?;

            // Then count
            let count: i64 = conn
                .zcard(&full_key)
                .await
                .map_err(|e| PrismError::Internal(format!("Redis error: {}", e)))?;

            Ok(count as u32)
        }
    }

    /// Connection health check
    pub async fn check_redis_health(url: &str) -> Result<()> {
        let client = Client::open(url)
            .map_err(|e| PrismError::Config(format!("Invalid Redis URL: {}", e)))?;

        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| PrismError::HealthCheck(format!("Failed to connect to Redis: {}", e)))?;

        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| PrismError::HealthCheck(format!("Redis ping failed: {}", e)))?;

        Ok(())
    }
}

#[cfg(feature = "distributed-rate-limit")]
pub use redis_impl::*;

/// Stub types when Redis feature is disabled
#[cfg(not(feature = "distributed-rate-limit"))]
pub mod stub {
    use crate::config::RateLimitKey;
    use crate::error::{PrismError, Result};
    use std::time::Duration;

    /// Configuration for distributed rate limiting (stub)
    #[derive(Debug, Clone)]
    pub struct DistributedRateLimitConfig {
        pub redis_url: String,
        pub key_prefix: String,
        pub max_requests: u32,
        pub window: Duration,
        pub key_by: RateLimitKey,
        pub connection_timeout: Duration,
        pub operation_timeout: Duration,
    }

    impl Default for DistributedRateLimitConfig {
        fn default() -> Self {
            Self {
                redis_url: "redis://127.0.0.1:6379".to_string(),
                key_prefix: "prism:ratelimit".to_string(),
                max_requests: 100,
                window: Duration::from_secs(60),
                key_by: RateLimitKey::Ip,
                connection_timeout: Duration::from_secs(5),
                operation_timeout: Duration::from_secs(1),
            }
        }
    }

    /// Result of a rate limit check (stub)
    #[derive(Debug)]
    pub struct RateLimitInfo {
        pub allowed: bool,
        pub current: u32,
        pub limit: u32,
        pub reset_after: Duration,
        pub remaining: u32,
    }

    /// Distributed rate limiter (stub - always errors)
    pub struct DistributedRateLimiter;

    impl DistributedRateLimiter {
        pub async fn new(_config: DistributedRateLimitConfig) -> Result<Self> {
            Err(PrismError::Config(
                "Distributed rate limiting requires the 'distributed-rate-limit' feature"
                    .to_string(),
            ))
        }

        pub async fn check(&self, _key: &str) -> Result<RateLimitInfo> {
            Err(PrismError::Config(
                "Distributed rate limiting not enabled".to_string(),
            ))
        }
    }

    #[allow(dead_code)]
    pub async fn check_redis_health(_url: &str) -> Result<()> {
        Err(PrismError::Config(
            "Distributed rate limiting requires the 'distributed-rate-limit' feature".to_string(),
        ))
    }
}

#[cfg(not(feature = "distributed-rate-limit"))]
pub use stub::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DistributedRateLimitConfig::default();
        assert_eq!(config.redis_url, "redis://127.0.0.1:6379");
        assert_eq!(config.key_prefix, "prism:ratelimit");
        assert_eq!(config.max_requests, 100);
    }
}
