//! Rate limiting middleware using token bucket algorithm

use super::{HttpRequest, HttpResponse, Middleware, Next, RequestContext};
use crate::config::{RateLimitConfig, RateLimitKey};
use crate::error::Result;
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use http::Response;
use http_body_util::Full;
use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::error;

/// Static key for global rate limiting (avoids allocation)
const GLOBAL_KEY: &str = "global";
/// Static key for unknown clients (avoids allocation)
const UNKNOWN_KEY: &str = "unknown";

/// Rate limiter middleware using token bucket algorithm
pub struct RateLimiter {
    /// Buckets per key
    buckets: DashMap<String, TokenBucket>,
    /// Requests per second limit
    rate: u32,
    /// Burst size
    burst: u32,
    /// Key extraction method
    key_by: RateLimitKey,
}

/// Token bucket for rate limiting
struct TokenBucket {
    /// Available tokens (scaled by 1000 for precision)
    tokens: AtomicU64,
    /// Last refill time (as unix millis)
    last_refill: AtomicU64,
    /// Maximum tokens (burst size, scaled by 1000)
    max_tokens: u64,
    /// Tokens added per millisecond (scaled by 1000)
    refill_rate: u64,
}

impl TokenBucket {
    fn new(rate: u32, burst: u32) -> Self {
        let max_tokens = (burst as u64) * 1000;
        // rate tokens per second = rate/1000 tokens per ms
        let refill_rate = rate as u64;

        Self {
            tokens: AtomicU64::new(max_tokens),
            last_refill: AtomicU64::new(current_time_millis()),
            max_tokens,
            refill_rate,
        }
    }

    fn try_acquire(&self) -> bool {
        let now = current_time_millis();
        let last = self.last_refill.load(Ordering::Relaxed);
        let elapsed_ms = now.saturating_sub(last);

        // Refill tokens
        if elapsed_ms > 0 {
            let tokens_to_add = elapsed_ms * self.refill_rate;
            let current = self.tokens.load(Ordering::Relaxed);
            let new_tokens = (current + tokens_to_add).min(self.max_tokens);
            self.tokens.store(new_tokens, Ordering::Relaxed);
            self.last_refill.store(now, Ordering::Relaxed);
        }

        // Try to consume a token
        let mut current = self.tokens.load(Ordering::Relaxed);
        loop {
            if current < 1000 {
                return false;
            }

            match self.tokens.compare_exchange_weak(
                current,
                current - 1000,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(new) => current = new,
            }
        }
    }

    fn remaining(&self) -> u32 {
        (self.tokens.load(Ordering::Relaxed) / 1000) as u32
    }
}

fn current_time_millis() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl RateLimiter {
    /// Create a new rate limiter from configuration
    pub fn new(config: &RateLimitConfig) -> Result<Self> {
        Ok(Self {
            buckets: DashMap::new(),
            rate: config.requests_per_second,
            burst: config.burst,
            key_by: config.key_by.clone(),
        })
    }

    /// Extract the rate limit key from the request
    /// Returns a Cow to avoid allocations for static keys
    fn extract_key<'a>(&self, request: &HttpRequest, ctx: &'a RequestContext) -> Cow<'a, str> {
        match &self.key_by {
            RateLimitKey::Ip => match &ctx.client_ip {
                Some(ip) => Cow::Borrowed(ip.as_str()),
                None => Cow::Borrowed(UNKNOWN_KEY),
            },
            RateLimitKey::Header(name) => match request.headers().get(name) {
                Some(v) => match v.to_str() {
                    Ok(s) => Cow::Owned(s.to_string()), // Must allocate for header value
                    Err(_) => Cow::Borrowed(UNKNOWN_KEY),
                },
                None => Cow::Borrowed(UNKNOWN_KEY),
            },
            RateLimitKey::Global => Cow::Borrowed(GLOBAL_KEY),
        }
    }

    /// Check and update rate limit for a key
    fn check_rate_limit(&self, key: &str) -> RateLimitResult {
        let bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(self.rate, self.burst));

        if bucket.try_acquire() {
            RateLimitResult::Allowed {
                remaining: bucket.remaining(),
                limit: self.burst,
            }
        } else {
            RateLimitResult::Exceeded {
                retry_after: Duration::from_secs(1),
                limit: self.burst,
            }
        }
    }
}

/// Result of rate limit check
enum RateLimitResult {
    Allowed { remaining: u32, limit: u32 },
    Exceeded { retry_after: Duration, limit: u32 },
}

#[async_trait]
impl Middleware for RateLimiter {
    async fn process(
        &self,
        request: HttpRequest,
        ctx: RequestContext,
        next: &dyn Next,
    ) -> Result<HttpResponse> {
        let key = self.extract_key(&request, &ctx);

        match self.check_rate_limit(&key) {
            RateLimitResult::Allowed { remaining, limit } => {
                let mut response = next.run(request, ctx).await?;

                // Add rate limit headers to successful response
                let headers = response.headers_mut();
                headers.insert("X-RateLimit-Limit", limit.into());
                headers.insert("X-RateLimit-Remaining", remaining.into());

                Ok(response)
            }
            RateLimitResult::Exceeded { retry_after, limit } => {
                match Response::builder()
                    .status(429)
                    .header("Retry-After", retry_after.as_secs())
                    .header("X-RateLimit-Limit", limit)
                    .header("X-RateLimit-Remaining", 0u32)
                    .body(Full::new(Bytes::from("Rate limit exceeded")))
                {
                    Ok(response) => Ok(response),
                    Err(e) => {
                        error!("Failed to build rate limit response: {}", e);
                        // Return a minimal 429 response
                        Ok(Response::builder()
                            .status(429)
                            .body(Full::new(Bytes::from("Rate limit exceeded")))
                            .expect("Minimal response builder should not fail"))
                    }
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "rate_limiter"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket() {
        let bucket = TokenBucket::new(10, 10);

        // Should allow burst
        for _ in 0..10 {
            assert!(bucket.try_acquire());
        }

        // Should be exhausted
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn test_rate_limiter_key_extraction() {
        let config = RateLimitConfig {
            requests_per_second: 10,
            burst: 10,
            key_by: RateLimitKey::Global,
        };
        let _limiter = RateLimiter::new(&config).unwrap();

        let _ctx = RequestContext::new().with_client_ip("1.2.3.4".to_string());

        // For global key, should always be "global"
        // Note: We'd need an actual HttpRequest to test this properly
    }
}
