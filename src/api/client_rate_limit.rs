//! Rate limiting of an OAuth2 client by its identity (issue #92).
//!
//! The router-wide limiter works on the caller's address, so a client that rotates addresses is
//! not slowed by it. The endpoints that authenticate a client call [`check`] once the client
//! has proved who it is, and the client gets one bucket (`oauth_client:<client id>`) of the same
//! [`DistributedRateLimiter`](crate::distributed::rate_limiting::DistributedRateLimiter) the
//! address buckets live in, whatever address it comes from.
//!
//! Only authenticated requests are counted. A request that merely names a client id, or
//! presents the wrong secret, does not touch that client's bucket, so a third party cannot use
//! someone else's client id to exhaust their allowance.

use crate::api::ApiState;
use crate::distributed::rate_limiting::RateLimitResult;
use std::time::Instant;

/// Why a request from an authenticated client is not served.
pub(crate) enum ClientLimited {
    /// The client used up its allowance; it may retry after this many seconds.
    Exceeded { retry_after_secs: u64 },
    /// The limiter could not be consulted; the request is refused rather than served unlimited.
    Unavailable,
}

/// Count a request from the authenticated client `client_id` against its own bucket.
pub(crate) async fn check(state: &ApiState, client_id: &str) -> Result<(), ClientLimited> {
    let key = format!("oauth_client:{client_id}");
    match state.rate_limiter.check_rate_limit(&key).await {
        Ok(RateLimitResult::Allowed { .. }) => Ok(()),
        Ok(RateLimitResult::Denied { retry_after, .. }) => {
            tracing::warn!(client_id = %client_id, "OAuth client rate limit exceeded");
            Err(ClientLimited::Exceeded {
                retry_after_secs: retry_after.as_secs().max(1),
            })
        }
        Ok(RateLimitResult::Blocked { unblock_at, reason }) => {
            tracing::warn!(client_id = %client_id, reason = %reason, "OAuth client is blocked");
            Err(ClientLimited::Exceeded {
                retry_after_secs: unblock_at
                    .checked_duration_since(Instant::now())
                    .map_or(1, |d| d.as_secs().max(1)),
            })
        }
        Err(e) => {
            tracing::error!(error = %e, "OAuth client rate limiter error");
            Err(ClientLimited::Unavailable)
        }
    }
}
