//! Rate limiting configuration for API endpoints.
//!
//! Implements rate limiting to prevent DoS attacks and abuse of the transparency log.
//! Uses the token bucket algorithm via tower-governor.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tower_governor::GovernorError;

/// Default rate limit: requests per second per IP.
pub const RATE_LIMIT_PER_SECOND: u64 = 100;

/// Default burst capacity: maximum requests allowed in a burst.
pub const RATE_LIMIT_BURST_SIZE: u32 = 200;

/// Requests per second per client IP (`RATE_LIMIT_PER_SECOND` env override).
pub fn rate_limit_per_second() -> u64 {
    std::env::var("RATE_LIMIT_PER_SECOND")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(RATE_LIMIT_PER_SECOND)
}

/// Token replenish interval in nanoseconds for the configured rate.
///
/// tower_governor's `per_second(n)` sets the interval to replenish ONE
/// token to `n` seconds — it does NOT mean "n requests per second". To
/// allow R requests per second, one token must replenish every 1e9/R
/// nanoseconds.
pub fn replenish_interval_ns() -> u64 {
    (1_000_000_000 / rate_limit_per_second()).max(1)
}

/// Burst capacity per client IP (`RATE_LIMIT_BURST_SIZE` env override).
pub fn rate_limit_burst_size() -> u32 {
    std::env::var("RATE_LIMIT_BURST_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(RATE_LIMIT_BURST_SIZE)
}

/// Convert governor errors to HTTP responses.
pub fn rate_limit_error_handler(error: GovernorError) -> Response {
    match error {
        GovernorError::TooManyRequests { headers, .. } => {
            // Preserve Retry-After / x-ratelimit-* headers so clients can
            // back off intelligently.
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many requests. Please slow down.",
            )
                .into_response();
            if let Some(headers) = headers {
                response.headers_mut().extend(headers);
            }
            response
        }
        GovernorError::UnableToExtractKey => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to extract rate limit key",
        )
            .into_response(),
        GovernorError::Other { msg, .. } => {
            if let Some(msg) = msg {
                tracing::error!("Rate limit error: {}", msg);
            }
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_constants() {
        let config = tower_governor::governor::GovernorConfigBuilder::default()
            .per_nanosecond(replenish_interval_ns())
            .burst_size(RATE_LIMIT_BURST_SIZE)
            .finish();

        assert!(config.is_some());
    }

    #[test]
    fn test_replenish_interval_semantics() {
        // 100 req/s must replenish one token every 10ms — NOT one token
        // every 100s, which is what per_second(100) would configure.
        std::env::remove_var("RATE_LIMIT_PER_SECOND");
        assert_eq!(replenish_interval_ns(), 10_000_000);
    }
}
