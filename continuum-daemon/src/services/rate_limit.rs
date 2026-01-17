//! Rate limiting for gRPC services.
//!
//! M3 FIX: Prevents DoS and brute-force attacks on enrollment endpoints.

use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::num::NonZeroU32;
use std::sync::Arc;
use tonic::{Request, Status};

/// Rate limiter configuration for enrollment endpoints.
pub struct EnrollmentRateLimiter {
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl EnrollmentRateLimiter {
    /// Create a new rate limiter with the specified requests per second and burst size.
    ///
    /// # Arguments
    ///
    /// * `per_second` - Number of requests allowed per second (sustained rate)
    /// * `burst_size` - Maximum burst size (allows temporary spikes)
    ///
    /// # Default values (if called with `default()`)
    ///
    /// * `per_second`: 2 requests/second
    /// * `burst_size`: 10 requests
    pub fn new(per_second: u32, burst_size: u32) -> Self {
        let per_second = NonZeroU32::new(per_second).unwrap_or(NonZeroU32::new(2).unwrap());
        let burst_size = NonZeroU32::new(burst_size).unwrap_or(NonZeroU32::new(10).unwrap());

        let quota = Quota::per_second(per_second).allow_burst(burst_size);

        Self {
            limiter: Arc::new(RateLimiter::direct(quota)),
        }
    }

    /// Check if a request should be allowed.
    ///
    /// Returns `Ok(())` if the request is within rate limits.
    /// Returns `Err(Status::resource_exhausted)` if the rate limit is exceeded.
    pub fn check(&self) -> Result<(), Status> {
        match self.limiter.check() {
            Ok(()) => Ok(()),
            Err(_) => {
                tracing::warn!("Rate limit exceeded for enrollment endpoint");
                Err(Status::resource_exhausted(
                    "Rate limit exceeded. Please try again later.",
                ))
            }
        }
    }
}

impl Default for EnrollmentRateLimiter {
    fn default() -> Self {
        // Default: 2 requests/second with burst of 10
        Self::new(2, 10)
    }
}

impl Clone for EnrollmentRateLimiter {
    fn clone(&self) -> Self {
        Self {
            limiter: Arc::clone(&self.limiter),
        }
    }
}

/// Rate limiting interceptor for tonic services.
///
/// This can be used with `tonic::service::interceptor` to add rate limiting
/// to any gRPC service.
#[derive(Clone)]
pub struct RateLimitInterceptor {
    limiter: EnrollmentRateLimiter,
}

impl RateLimitInterceptor {
    /// Create a new rate limiting interceptor.
    pub fn new(limiter: EnrollmentRateLimiter) -> Self {
        Self { limiter }
    }
}

impl tonic::service::Interceptor for RateLimitInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        self.limiter.check()?;
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_rate_limiter_allows_burst() {
        let limiter = EnrollmentRateLimiter::new(1, 5);

        // Should allow up to burst_size requests immediately
        for i in 0..5 {
            assert!(
                limiter.check().is_ok(),
                "Request {} should be allowed within burst",
                i
            );
        }

        // Next request should be rate limited
        assert!(
            limiter.check().is_err(),
            "Request after burst should be rate limited"
        );
    }

    #[tokio::test]
    async fn test_rate_limiter_refills() {
        let limiter = EnrollmentRateLimiter::new(10, 1);

        // Use up the single burst allowance
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_err());

        // Wait for refill (10 per second = 100ms per token)
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be allowed again
        assert!(limiter.check().is_ok());
    }

    #[test]
    fn test_default_rate_limiter() {
        let limiter = EnrollmentRateLimiter::default();

        // Default burst of 10 should allow 10 immediate requests
        for i in 0..10 {
            assert!(
                limiter.check().is_ok(),
                "Default request {} should be allowed",
                i
            );
        }

        // 11th request should be rate limited
        assert!(limiter.check().is_err());
    }
}
