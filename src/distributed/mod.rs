// SPDX-License-Identifier: MIT OR Apache-2.0
//! Distributed session store abstraction.
//!
//! Provides a trait for querying the total number of active sessions across all
//! instances in a distributed deployment.  A no-op [`LocalOnlySessionStore`] is
//! provided for single-node use; it always reports zero total sessions, which
//! causes `AuthFramework`'s remote-session estimate logic to return `0`
//! instead of an incorrect `local_count * 2` estimate.
//!
//! # Production integration
//!
//! To use Redis (or any key–value store) as the distributed session backend,
//! implement this trait and inject it via
//! [`AuthFramework::set_distributed_store`][crate::auth::AuthFramework]:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use auth_framework::distributed::DistributedSessionStore;
//! use auth_framework::errors::Result;
//! use async_trait::async_trait;
//!
//! // Example: wrap your chosen backend (e.g., a Redis client) in this struct.
//! struct MySessionStore {
//!     // inner: redis::Client,  // fill in your backend type
//! }
//!
//! #[async_trait]
//! impl DistributedSessionStore for MySessionStore {
//!     async fn total_session_count(&self) -> Result<u64> {
//!         // Query DBSIZE or scan session keys in your backend.
//!         Ok(42)
//!     }
//! }
//!
//! # async fn example() -> auth_framework::errors::Result<()> {
//! let mut framework = auth_framework::AuthFramework::builder().build().await?;
//! framework.set_distributed_store(Arc::new(MySessionStore {}));
//! # Ok(())
//! # }
//! ```

pub mod rate_limiting;

use crate::errors::Result;
use async_trait::async_trait;

/// Abstraction over a distributed session backend.
///
/// Implement this trait to integrate with Redis Cluster, Valkey, Hazelcast,
/// or any other distributed key–value store that tracks session state.
#[async_trait]
pub trait DistributedSessionStore: Send + Sync {
    /// Return the **total** number of active sessions across *all* nodes,
    /// including the current one.
    ///
    /// The caller subtracts the local session count to arrive at the remote
    /// estimate; returning `0` from the default [`LocalOnlySessionStore`]
    /// therefore means "no remote sessions".
    async fn total_session_count(&self) -> Result<u64>;
}

/// No-op store used when no distributed backend is configured.
///
/// [`total_session_count`][DistributedSessionStore::total_session_count] always
/// returns `0`, so the framework correctly reports zero remote sessions instead
/// of a fabricated value.
pub struct LocalOnlySessionStore;

#[async_trait]
impl DistributedSessionStore for LocalOnlySessionStore {
    async fn total_session_count(&self) -> Result<u64> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Default local-only store always returns 0.
    #[tokio::test]
    async fn test_local_only_returns_zero() {
        let store = LocalOnlySessionStore;
        assert_eq!(store.total_session_count().await.unwrap(), 0);
    }

    /// The trait is usable via dynamic dispatch.
    #[tokio::test]
    async fn test_dyn_dispatch() {
        let store: Arc<dyn DistributedSessionStore> = Arc::new(LocalOnlySessionStore);
        assert_eq!(store.total_session_count().await.unwrap(), 0);
    }

    /// [`LocalOnlySessionStore`] satisfies Send + Sync (required for Arc).
    #[test]
    fn test_local_only_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LocalOnlySessionStore>();
    }

    /// A custom in-memory store can be injected via the trait.
    struct FixedCountStore(u64);

    #[async_trait]
    impl DistributedSessionStore for FixedCountStore {
        async fn total_session_count(&self) -> Result<u64> {
            Ok(self.0)
        }
    }

    #[tokio::test]
    async fn test_custom_store_returns_fixed_count() {
        let store: Arc<dyn DistributedSessionStore> = Arc::new(FixedCountStore(99));
        assert_eq!(store.total_session_count().await.unwrap(), 99);
    }

    /// Two calls to the same store return consistent results.
    #[tokio::test]
    async fn test_multiple_calls_consistent() {
        let store = LocalOnlySessionStore;
        for _ in 0..5 {
            assert_eq!(store.total_session_count().await.unwrap(), 0);
        }
    }
}
