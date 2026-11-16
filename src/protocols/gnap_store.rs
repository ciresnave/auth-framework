// SPDX-License-Identifier: MIT OR Apache-2.0
//! Where a GNAP authorization server keeps the access tokens it has issued.
//!
//! [`GnapService`](super::gnap::GnapService) never holds tokens itself: it goes through a
//! [`GnapTokenStore`], so a deployer chooses where they live (a database, a cache shared by
//! several server processes) and a token survives a restart when the store does.
//! [`InMemoryTokenStore`] is the default and loses its tokens on restart.
//!
//! A store failure is never read as "no such token" by the service in a way that grants anything:
//! every error is returned to the caller and the request is refused.

use super::gnap::GnapAccessRequest;
use crate::errors::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// A GNAP access token that has been issued and can be managed.
#[derive(Clone, Serialize, Deserialize)]
pub struct GnapIssuedToken {
    /// Opaque token value
    pub value: String,
    /// Access rights granted
    pub access: Vec<GnapAccessRequest>,
    /// Expiration timestamp (epoch seconds)
    pub expires_at: u64,
    /// Client key thumbprint that this token is bound to (if any)
    pub key_thumbprint: Option<String>,
    /// The proof method of that key (`dpop`, ...): how a request about this token is proved.
    #[serde(default)]
    pub key_proof: Option<String>,
    /// The transaction that produced this token
    pub transaction_id: String,
}

impl std::fmt::Debug for GnapIssuedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("GnapIssuedToken");
        d.field("value", &crate::utils::redact::redacted(&self.value));
        d.field("access", &self.access);
        d.field("expires_at", &self.expires_at);
        d.field("key_thumbprint", &self.key_thumbprint);
        d.field("key_proof", &self.key_proof);
        d.field("transaction_id", &self.transaction_id);
        d.finish()
    }
}

/// Where issued access tokens are kept, keyed by token value.
///
/// `remove` must be atomic: when two callers remove the same value, exactly one gets the token.
/// Rotation and revocation rely on that to spend a token once.
#[async_trait]
pub trait GnapTokenStore: Send + Sync {
    /// Keep a token, replacing any with the same value.
    async fn insert(&self, token: GnapIssuedToken) -> Result<()>;

    /// The token with this value, if stored. Expiry is the caller's check.
    async fn get(&self, value: &str) -> Result<Option<GnapIssuedToken>>;

    /// Take the token out of the store and return it, if it was there.
    async fn remove(&self, value: &str) -> Result<Option<GnapIssuedToken>>;

    /// Remove every token issued under this transaction; returns how many were removed.
    async fn remove_for_transaction(&self, transaction_id: &str) -> Result<usize>;

    /// How many tokens are stored, expired ones included.
    async fn count(&self) -> Result<usize>;

    /// Remove every token whose `expires_at` is at or before `now`; returns how many.
    async fn purge_expired(&self, now: u64) -> Result<usize>;
}

/// A [`GnapTokenStore`] held in memory.
#[derive(Default)]
pub struct InMemoryTokenStore {
    tokens: RwLock<HashMap<String, GnapIssuedToken>>,
}

impl InMemoryTokenStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl std::fmt::Debug for InMemoryTokenStore {
    /// The tokens are credentials, so none is printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryTokenStore").finish_non_exhaustive()
    }
}

#[async_trait]
impl GnapTokenStore for InMemoryTokenStore {
    async fn insert(&self, token: GnapIssuedToken) -> Result<()> {
        self.tokens.write().await.insert(token.value.clone(), token);
        Ok(())
    }

    async fn get(&self, value: &str) -> Result<Option<GnapIssuedToken>> {
        Ok(self.tokens.read().await.get(value).cloned())
    }

    async fn remove(&self, value: &str) -> Result<Option<GnapIssuedToken>> {
        Ok(self.tokens.write().await.remove(value))
    }

    async fn remove_for_transaction(&self, transaction_id: &str) -> Result<usize> {
        let mut tokens = self.tokens.write().await;
        let before = tokens.len();
        tokens.retain(|_, t| t.transaction_id != transaction_id);
        Ok(before - tokens.len())
    }

    async fn count(&self) -> Result<usize> {
        Ok(self.tokens.read().await.len())
    }

    async fn purge_expired(&self, now: u64) -> Result<usize> {
        let mut tokens = self.tokens.write().await;
        let before = tokens.len();
        tokens.retain(|_, t| now < t.expires_at);
        Ok(before - tokens.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(value: &str, transaction_id: &str, expires_at: u64) -> GnapIssuedToken {
        GnapIssuedToken {
            value: value.to_string(),
            access: vec![],
            expires_at,
            key_thumbprint: None,
            key_proof: None,
            transaction_id: transaction_id.to_string(),
        }
    }

    #[tokio::test]
    async fn remove_hands_a_token_to_exactly_one_caller() {
        let store = InMemoryTokenStore::new();
        store.insert(token("t", "x", 100)).await.unwrap();
        assert!(store.remove("t").await.unwrap().is_some());
        assert!(store.remove("t").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn remove_for_transaction_takes_only_that_transactions_tokens() {
        let store = InMemoryTokenStore::new();
        store.insert(token("a", "x", 100)).await.unwrap();
        store.insert(token("b", "x", 100)).await.unwrap();
        store.insert(token("c", "y", 100)).await.unwrap();
        assert_eq!(store.remove_for_transaction("x").await.unwrap(), 2);
        assert_eq!(store.count().await.unwrap(), 1);
        assert!(store.get("c").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn a_token_expiring_exactly_now_is_purged_and_a_later_one_is_kept() {
        let store = InMemoryTokenStore::new();
        store.insert(token("now", "x", 50)).await.unwrap();
        store.insert(token("later", "x", 51)).await.unwrap();
        assert_eq!(store.purge_expired(50).await.unwrap(), 1);
        assert!(store.get("now").await.unwrap().is_none());
        assert!(store.get("later").await.unwrap().is_some());
    }

    #[test]
    fn debug_output_hides_the_token_value() {
        let shown = format!("{:?}", token("super-secret-value", "x", 1));
        assert!(!shown.contains("super-secret-value"));
    }
}
