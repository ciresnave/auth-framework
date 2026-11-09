//! Rate limiting of an OAuth2 client by its identity (issue #92).
//!
//! The router-wide limiter works on the caller's address, so a client that rotates addresses is
//! not slowed by it. The endpoints that authenticate a client call [`check`] once the client
//! has proved who it is, and the client gets one bucket (`oauth_client:<client id>`) of the same
//! [`RateLimiter`] the address buckets live in, whatever address it comes from. The limiter is
//! reached only through that trait, so a different one can replace the built-in
//! [`DistributedRateLimiter`](crate::distributed::rate_limiting::DistributedRateLimiter) without
//! touching a caller.
//!
//! Only authenticated requests are counted. A request that merely names a client id, or
//! presents the wrong secret, does not touch that client's bucket, so a third party cannot use
//! someone else's client id to exhaust their allowance.

use crate::api::ApiState;
use crate::distributed::rate_limiting::{LimitDecision, RateLimiter};

/// Why a request from an authenticated client is not served.
pub(crate) enum ClientLimited {
    /// The client used up its allowance; it may retry after this many seconds.
    Exceeded { retry_after_secs: u64 },
    /// The limiter could not be consulted; the request is refused rather than served unlimited.
    Unavailable,
}

/// Count a request from the authenticated client `client_id` against its own bucket.
pub(crate) async fn check(state: &ApiState, client_id: &str) -> Result<(), ClientLimited> {
    check_with(&*state.rate_limiter, client_id).await
}

/// [`check`] against any [`RateLimiter`]; the callers above never name the limiter's type.
pub(crate) async fn check_with(
    limiter: &dyn RateLimiter,
    client_id: &str,
) -> Result<(), ClientLimited> {
    let key = format!("oauth_client:{client_id}");
    match limiter.check(&key).await {
        Ok(LimitDecision::Allow) => Ok(()),
        Ok(LimitDecision::Deny { retry_after }) => {
            tracing::warn!(client_id = %client_id, "OAuth client rate limit exceeded");
            Err(ClientLimited::Exceeded {
                retry_after_secs: retry_after.as_secs().max(1),
            })
        }
        Err(e) => {
            tracing::error!(error = %e, "OAuth client rate limiter error");
            Err(ClientLimited::Unavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::{AuthError, Result};
    use std::sync::Mutex;
    use std::time::Duration;

    /// A limiter that is not the crate's own: it records keys and answers as told.
    struct Scripted(Mutex<Vec<String>>, Option<Result<LimitDecision>>);

    #[async_trait::async_trait]
    impl RateLimiter for Scripted {
        async fn check(&self, key: &str) -> Result<LimitDecision> {
            self.0.lock().unwrap().push(key.to_string());
            match &self.1 {
                Some(Ok(d)) => Ok(d.clone()),
                _ => Err(AuthError::internal("down")),
            }
        }
    }

    #[tokio::test]
    async fn any_rate_limiter_can_stand_in_and_the_client_has_its_own_key() {
        let allow = Scripted(Mutex::default(), Some(Ok(LimitDecision::Allow)));
        assert!(check_with(&allow, "c1").await.is_ok());
        assert_eq!(*allow.0.lock().unwrap(), ["oauth_client:c1"]);

        let deny = Scripted(
            Mutex::default(),
            Some(Ok(LimitDecision::Deny {
                retry_after: Duration::from_millis(1),
            })),
        );
        // a sub-second wait is reported as one second, never zero
        assert!(matches!(
            check_with(&deny, "c1").await,
            Err(ClientLimited::Exceeded {
                retry_after_secs: 1
            })
        ));
        let err = Scripted(Mutex::default(), None);
        assert!(matches!(
            check_with(&err, "c1").await,
            Err(ClientLimited::Unavailable)
        ));
    }
}
