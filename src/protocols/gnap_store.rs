// SPDX-License-Identifier: MIT OR Apache-2.0
//! Where a GNAP authorization server keeps the access tokens it has issued and the transactions
//! that are still open.
//!
//! [`GnapService`](super::gnap::GnapService) never holds either itself: it goes through a
//! [`GnapTokenStore`] and a [`GnapTransactionStore`], so a deployer chooses where they live (a
//! database, a cache shared by several server processes) and they survive a restart when the
//! store does. [`InMemoryTokenStore`] and [`InMemoryTransactionStore`] are the defaults and lose
//! their contents on restart.
//!
//! A store failure is never read as "no such token" or "no such transaction" by the service in a
//! way that grants anything: every error is returned to the caller and the request is refused.

use super::gnap::{GnapAccessRequest, GnapTransaction};
use crate::errors::{AuthError, Result};
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

/// Where open transactions are kept, keyed by transaction id.
///
/// A transaction changes in place (its continuation token rotates on every poll, an approval
/// adds an interaction reference), and several requests for one transaction can run at once, so
/// the store gives two atomic operations the service builds its single-use guarantees on:
///
/// * [`replace_if_unchanged`](Self::replace_if_unchanged) is a compare-and-swap on the
///   transaction's `revision`: of two writers that read the same revision exactly one wins.
/// * [`remove`](Self::remove) hands the transaction to exactly one caller.
///
/// A store over a database implements the first as `UPDATE ... WHERE id = ? AND revision = ?`
/// and the second as `DELETE ... RETURNING`.
#[async_trait]
pub trait GnapTransactionStore: Send + Sync {
    /// Keep a new transaction. Fails when one with this id is already stored.
    async fn insert(&self, txn: GnapTransaction) -> Result<()>;

    /// The transaction with this id, if stored. Expiry is the caller's check.
    async fn get(&self, id: &str) -> Result<Option<GnapTransaction>>;

    /// Store `txn` in place of the stored transaction with its id, with `revision` one higher,
    /// only if the stored one still has `txn.revision`. Returns `false` when it was removed or
    /// changed since `txn` was read; nothing is written then.
    async fn replace_if_unchanged(&self, txn: GnapTransaction) -> Result<bool>;

    /// Take the transaction out of the store and return it, if it was there. When two callers
    /// remove the same id, exactly one gets it.
    async fn remove(&self, id: &str) -> Result<Option<GnapTransaction>>;

    /// Remove every transaction created before `cutoff` (epoch seconds); returns how many.
    async fn purge_created_before(&self, cutoff: u64) -> Result<usize>;

    /// How many transactions are stored, expired ones included.
    async fn count(&self) -> Result<usize>;

    /// The ids of the stored transactions, for an operator listing what is outstanding.
    async fn ids(&self) -> Result<Vec<String>>;
}

/// A [`GnapTransactionStore`] held in memory.
#[derive(Default)]
pub struct InMemoryTransactionStore {
    transactions: RwLock<HashMap<String, GnapTransaction>>,
}

impl InMemoryTransactionStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl std::fmt::Debug for InMemoryTransactionStore {
    /// The transactions hold continuation tokens, so none is printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryTransactionStore")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl GnapTransactionStore for InMemoryTransactionStore {
    async fn insert(&self, txn: GnapTransaction) -> Result<()> {
        use std::collections::hash_map::Entry;
        match self.transactions.write().await.entry(txn.id.clone()) {
            Entry::Occupied(_) => Err(AuthError::validation("Transaction id already in use")),
            Entry::Vacant(slot) => {
                slot.insert(txn);
                Ok(())
            }
        }
    }

    async fn get(&self, id: &str) -> Result<Option<GnapTransaction>> {
        Ok(self.transactions.read().await.get(id).cloned())
    }

    async fn replace_if_unchanged(&self, mut txn: GnapTransaction) -> Result<bool> {
        let mut transactions = self.transactions.write().await;
        match transactions.get_mut(&txn.id) {
            Some(stored) if stored.revision == txn.revision => {
                txn.revision += 1;
                *stored = txn;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn remove(&self, id: &str) -> Result<Option<GnapTransaction>> {
        Ok(self.transactions.write().await.remove(id))
    }

    async fn purge_created_before(&self, cutoff: u64) -> Result<usize> {
        let mut transactions = self.transactions.write().await;
        let before = transactions.len();
        transactions.retain(|_, t| t.created_at >= cutoff);
        Ok(before - transactions.len())
    }

    async fn count(&self) -> Result<usize> {
        Ok(self.transactions.read().await.len())
    }

    async fn ids(&self) -> Result<Vec<String>> {
        Ok(self.transactions.read().await.keys().cloned().collect())
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

    fn txn(id: &str, created_at: u64) -> GnapTransaction {
        use super::super::gnap::{GnapTransactionRequest, GnapTransactionState};
        GnapTransaction {
            id: id.to_string(),
            state: GnapTransactionState::Pending,
            request: GnapTransactionRequest {
                client: None,
                interact: None,
                access_token: None,
                subject: None,
            },
            continue_token: "ct".to_string(),
            created_at,
            interact_nonce: None,
            subject_id: None,
            interact_ref: None,
            revision: 0,
        }
    }

    #[tokio::test]
    async fn a_transaction_id_cannot_be_inserted_twice() {
        let store = InMemoryTransactionStore::new();
        store.insert(txn("a", 1)).await.unwrap();
        assert!(store.insert(txn("a", 2)).await.is_err());
        assert_eq!(store.get("a").await.unwrap().unwrap().created_at, 1);
    }

    #[tokio::test]
    async fn replace_if_unchanged_lets_exactly_one_of_two_writers_of_a_revision_win() {
        let store = InMemoryTransactionStore::new();
        store.insert(txn("a", 1)).await.unwrap();
        let first = store.get("a").await.unwrap().unwrap();
        let second = first.clone();
        assert!(store.replace_if_unchanged(first).await.unwrap());
        assert!(!store.replace_if_unchanged(second).await.unwrap());
        assert_eq!(store.get("a").await.unwrap().unwrap().revision, 1);
    }

    #[tokio::test]
    async fn replace_if_unchanged_does_not_resurrect_a_removed_transaction() {
        let store = InMemoryTransactionStore::new();
        store.insert(txn("a", 1)).await.unwrap();
        let read = store.get("a").await.unwrap().unwrap();
        store.remove("a").await.unwrap();
        assert!(!store.replace_if_unchanged(read).await.unwrap());
        assert_eq!(store.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn remove_hands_a_transaction_to_exactly_one_caller() {
        let store = InMemoryTransactionStore::new();
        store.insert(txn("a", 1)).await.unwrap();
        assert!(store.remove("a").await.unwrap().is_some());
        assert!(store.remove("a").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn purge_created_before_keeps_a_transaction_created_exactly_at_the_cutoff() {
        let store = InMemoryTransactionStore::new();
        store.insert(txn("old", 49)).await.unwrap();
        store.insert(txn("edge", 50)).await.unwrap();
        assert_eq!(store.purge_created_before(50).await.unwrap(), 1);
        assert_eq!(store.ids().await.unwrap(), vec!["edge".to_string()]);
    }

    #[test]
    fn transaction_debug_output_hides_the_continuation_token() {
        let mut t = txn("a", 1);
        t.continue_token = "super-secret-continuation".to_string();
        assert!(!format!("{t:?}").contains("super-secret-continuation"));
    }
}
