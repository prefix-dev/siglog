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

/// Convert governor errors to HTTP responses.
pub fn rate_limit_error_handler(error: GovernorError) -> Response {
    match error {
        GovernorError::TooManyRequests { .. } => (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests. Please slow down.",
        )
            .into_response(),
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
            .per_second(RATE_LIMIT_PER_SECOND)
            .burst_size(RATE_LIMIT_BURST_SIZE)
            .finish();

        assert!(config.is_some());
    }
}
