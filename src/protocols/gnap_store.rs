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

use super::gnap::{GnapAccessRequest, GnapClientInfo, GnapTransaction};
use super::gnap_interaction::user_codes_equal;
use crate::errors::{AuthError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// A GNAP access token that has been issued and can be managed.
///
/// Non-exhaustive: build one with [`GnapIssuedToken::new`] and the `with_*` methods, so a field
/// added later is not a break.
///
/// ```compile_fail
/// use auth_framework::protocols::gnap_store::GnapIssuedToken;
/// let _ = GnapIssuedToken {
///     value: String::new(),
///     access: vec![],
///     expires_at: 0,
///     key_thumbprint: None,
///     key_proof: None,
///     key_jwk: None,
///     transaction_id: String::new(),
///     manage_token: None,
///     label: None,
/// };
/// ```
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
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
    /// The public JWK of that key, kept for the proof methods that verify against the key itself
    /// (`httpsig`); a request about this token is checked against it, not only its thumbprint.
    #[serde(default)]
    pub key_jwk: Option<serde_json::Value>,
    /// The transaction that produced this token
    pub transaction_id: String,
    /// The secret that addresses this token's management URL (RFC 9635 3.2.1), distinct from
    /// `value` so the access token is never sent to the management endpoint. `None` for a record
    /// stored before this field existed: such a token is managed by its value, as before.
    #[serde(default)]
    pub manage_token: Option<String>,
    /// The client's label for this token (RFC 9635 2.1 `label`), echoed back at issue and rotation.
    #[serde(default)]
    pub label: Option<String>,
}

/// Whether `secret` can be the last segment of a management URI: 1 to 128 characters of the RFC 3986
/// unreserved set, so it needs no encoding and the route accepts it.
pub fn is_valid_manage_secret(secret: &str) -> bool {
    !secret.is_empty()
        && secret.len() <= 128
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

impl GnapIssuedToken {
    /// A token with no key binding, management secret or label.
    pub fn new(
        value: impl Into<String>,
        access: Vec<GnapAccessRequest>,
        expires_at: u64,
        transaction_id: impl Into<String>,
    ) -> Self {
        Self {
            value: value.into(),
            access,
            expires_at,
            key_thumbprint: None,
            key_proof: None,
            key_jwk: None,
            transaction_id: transaction_id.into(),
            manage_token: None,
            label: None,
        }
    }

    /// Bind the token to a client key.
    pub fn with_key(
        mut self,
        thumbprint: Option<String>,
        proof: Option<String>,
        jwk: Option<serde_json::Value>,
    ) -> Self {
        self.key_thumbprint = thumbprint;
        self.key_proof = proof;
        self.key_jwk = jwk;
        self
    }

    /// Set the management secret.
    ///
    /// A secret the management route cannot carry (see [`is_valid_manage_secret`]) is ignored: the token
    /// is then managed at the shared URI rather than at a per-token URI that would answer 404.
    pub fn with_manage_token(mut self, manage_token: Option<String>) -> Self {
        self.manage_token = manage_token.filter(|m| is_valid_manage_secret(m));
        self
    }

    /// Set the client's label.
    pub fn with_label(mut self, label: Option<String>) -> Self {
        self.label = label;
        self
    }
}

impl std::fmt::Debug for GnapIssuedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("GnapIssuedToken");
        d.field("value", &crate::utils::redact::redacted(&self.value));
        d.field("access", &self.access);
        d.field("expires_at", &self.expires_at);
        d.field("key_thumbprint", &self.key_thumbprint);
        d.field("key_proof", &self.key_proof);
        d.field("key_jwk", &self.key_jwk);
        d.field("transaction_id", &self.transaction_id);
        d.field(
            "manage_token",
            &self
                .manage_token
                .as_ref()
                .map(crate::utils::redact::redacted),
        );
        d.field("label", &self.label);
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

    /// The token whose `manage_token` is this value, if stored. Expiry is the caller's check.
    async fn get_by_manage_token(&self, manage_token: &str) -> Result<Option<GnapIssuedToken>>;

    /// Take the token out of the store and return it, if it was there.
    async fn remove(&self, value: &str) -> Result<Option<GnapIssuedToken>>;

    /// Remove every token issued under this transaction; returns how many were removed.
    async fn remove_for_transaction(&self, transaction_id: &str) -> Result<usize>;

    /// Remove every token bound to the client key with this RFC 7638 `thumbprint`; returns how
    /// many were removed. A token bound to no key is never matched.
    async fn remove_for_key(&self, thumbprint: &str) -> Result<usize>;

    /// How many tokens are stored, expired ones included.
    async fn count(&self) -> Result<usize>;

    /// Remove every token whose `expires_at` is at or before `now`; returns how many.
    async fn purge_expired(&self, now: u64) -> Result<usize>;
}

/// A [`GnapTokenStore`] held in memory.
#[derive(Default)]
pub struct InMemoryTokenStore {
    inner: RwLock<TokenMaps>,
}

/// The tokens by value, and an index from manage secret to token value, so a management request does
/// not scan every token while holding the lock.
#[derive(Default)]
struct TokenMaps {
    tokens: HashMap<String, GnapIssuedToken>,
    by_manage: HashMap<String, String>,
}

impl TokenMaps {
    fn insert(&mut self, token: GnapIssuedToken) {
        self.take(&token.value);
        if let Some(m) = &token.manage_token {
            self.by_manage.insert(m.clone(), token.value.clone());
        }
        self.tokens.insert(token.value.clone(), token);
    }

    fn take(&mut self, value: &str) -> Option<GnapIssuedToken> {
        let t = self.tokens.remove(value)?;
        if let Some(m) = &t.manage_token
            && self.by_manage.get(m).map(String::as_str) == Some(value)
        {
            self.by_manage.remove(m);
        }
        Some(t)
    }

    fn retain(&mut self, mut keep: impl FnMut(&GnapIssuedToken) -> bool) -> usize {
        let drop: Vec<String> = self
            .tokens
            .values()
            .filter(|t| !keep(t))
            .map(|t| t.value.clone())
            .collect();
        for v in &drop {
            self.take(v);
        }
        drop.len()
    }
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
        self.inner.write().await.insert(token);
        Ok(())
    }

    async fn get(&self, value: &str) -> Result<Option<GnapIssuedToken>> {
        Ok(self.inner.read().await.tokens.get(value).cloned())
    }

    async fn get_by_manage_token(&self, manage_token: &str) -> Result<Option<GnapIssuedToken>> {
        let maps = self.inner.read().await;
        Ok(maps
            .by_manage
            .get(manage_token)
            .and_then(|v| maps.tokens.get(v))
            .cloned())
    }

    async fn remove(&self, value: &str) -> Result<Option<GnapIssuedToken>> {
        Ok(self.inner.write().await.take(value))
    }

    async fn remove_for_transaction(&self, transaction_id: &str) -> Result<usize> {
        Ok(self
            .inner
            .write()
            .await
            .retain(|t| t.transaction_id != transaction_id))
    }

    async fn remove_for_key(&self, thumbprint: &str) -> Result<usize> {
        Ok(self
            .inner
            .write()
            .await
            .retain(|t| t.key_thumbprint.as_deref() != Some(thumbprint)))
    }

    async fn count(&self) -> Result<usize> {
        Ok(self.inner.read().await.tokens.len())
    }

    async fn purge_expired(&self, now: u64) -> Result<usize> {
        Ok(self.inner.write().await.retain(|t| now < t.expires_at))
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

    /// The stored transaction that was issued this normalised `user_code`, if any (RFC 9635
    /// section 3.3.3). The default reads every transaction and compares in constant time, so a
    /// store need not index codes; a database store may override it with a lookup. Expiry and
    /// state are the caller's check.
    async fn find_by_user_code(&self, user_code: &str) -> Result<Option<GnapTransaction>> {
        let mut found = None;
        for id in self.ids().await? {
            if let Some(txn) = self.get(&id).await?
                && txn
                    .user_code
                    .as_deref()
                    .is_some_and(|issued| user_codes_equal(user_code, issued))
            {
                // The first match wins, so a (negligible) code collision gives one defined answer; the scan
                // still reads every transaction.
                found.get_or_insert(txn);
            }
        }
        Ok(found)
    }
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

/// Where a GNAP authorization server keeps the client instances it has seen, keyed by the `instance_id` it
/// issued (RFC 9635 section 3.5). A client that holds an id may send it as its `client` (section 2.3.1) instead
/// of the key and display it gave the first time; the server proves the request against the key kept here.
///
/// An id is a handle, not a credential: it names a key, and a request that presents it is still checked against
/// that key. `register` is called only for a client whose proof has already verified.
#[async_trait]
pub trait GnapInstanceStore: Send + Sync {
    /// Keep `client` under the id of its key and return that id. A client key seen before keeps its id (its
    /// display is replaced by the newest one); a new key gets a new unguessable id.
    async fn register(&self, key_thumbprint: &str, client: &GnapClientInfo) -> Result<String>;

    /// The client kept under `instance_id`, if any.
    async fn get(&self, instance_id: &str) -> Result<Option<GnapClientInfo>>;
}

/// The most client instances [`InMemoryInstanceStore`] keeps; a further new key is refused, so a caller with
/// many keys cannot grow the store without bound.
pub const MAX_IN_MEMORY_INSTANCES: usize = 100_000;

/// [`GnapInstanceStore`] in this process's memory: lost on restart, not shared between processes.
#[derive(Default)]
pub struct InMemoryInstanceStore {
    /// instance id -> (key thumbprint, client)
    by_id: RwLock<HashMap<String, (String, GnapClientInfo)>>,
}

impl InMemoryInstanceStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl GnapInstanceStore for InMemoryInstanceStore {
    async fn register(&self, key_thumbprint: &str, client: &GnapClientInfo) -> Result<String> {
        let mut by_id = self.by_id.write().await;
        if let Some((id, entry)) = by_id.iter_mut().find(|(_, (t, _))| t == key_thumbprint) {
            entry.1 = client.clone();
            return Ok(id.clone());
        }
        if by_id.len() >= MAX_IN_MEMORY_INSTANCES {
            return Err(AuthError::validation(
                "too many client instances are registered",
            ));
        }
        let id = uuid::Uuid::new_v4().to_string();
        by_id.insert(id.clone(), (key_thumbprint.to_string(), client.clone()));
        Ok(id)
    }

    async fn get(&self, instance_id: &str) -> Result<Option<GnapClientInfo>> {
        Ok(self
            .by_id
            .read()
            .await
            .get(instance_id)
            .map(|(_, client)| client.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(value: &str, transaction_id: &str, expires_at: u64) -> GnapIssuedToken {
        GnapIssuedToken::new(value, vec![], expires_at, transaction_id)
    }

    #[test]
    fn an_old_record_without_the_new_fields_still_loads() {
        let old = r#"{"value":"v","access":[],"expires_at":5,"key_thumbprint":null,"transaction_id":"t"}"#;
        let t: GnapIssuedToken = serde_json::from_str(old).unwrap();
        assert_eq!((t.manage_token, t.label), (None, None));
    }

    #[test]
    fn a_manage_secret_the_route_cannot_carry_is_not_kept() {
        for bad in ["", "a/b", "a b", "a?b", &"x".repeat(129)] {
            assert!(!is_valid_manage_secret(bad), "{bad:?}");
            assert!(
                token("a", "x", 100)
                    .with_manage_token(Some(bad.into()))
                    .manage_token
                    .is_none()
            );
        }
        let ok = "Ab-1._~".to_string() + &"x".repeat(121);
        assert!(is_valid_manage_secret(&ok));
        assert_eq!(
            token("a", "x", 100)
                .with_manage_token(Some(ok.clone()))
                .manage_token,
            Some(ok)
        );
    }

    #[tokio::test]
    async fn the_manage_index_follows_replace_remove_and_purge() {
        let store = InMemoryTokenStore::new();
        store
            .insert(token("a", "x", 100).with_manage_token(Some("m1".into())))
            .await
            .unwrap();
        store
            .insert(token("b", "y", 200).with_manage_token(Some("m2".into())))
            .await
            .unwrap();
        // Replacing a value under a new secret drops the old secret.
        store
            .insert(token("a", "x", 100).with_manage_token(Some("m3".into())))
            .await
            .unwrap();
        assert!(store.get_by_manage_token("m1").await.unwrap().is_none());
        assert_eq!(
            store
                .get_by_manage_token("m3")
                .await
                .unwrap()
                .unwrap()
                .value,
            "a"
        );
        store.remove("a").await.unwrap();
        assert!(store.get_by_manage_token("m3").await.unwrap().is_none());
        // Purge and removal by transaction keep it in step as well.
        assert_eq!(store.purge_expired(300).await.unwrap(), 1);
        assert!(store.get_by_manage_token("m2").await.unwrap().is_none());
        store
            .insert(token("c", "z", 400).with_manage_token(Some("m4".into())))
            .await
            .unwrap();
        assert_eq!(store.remove_for_transaction("z").await.unwrap(), 1);
        assert!(store.get_by_manage_token("m4").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_token_is_found_by_its_manage_token() {
        let store = InMemoryTokenStore::new();
        store
            .insert(token("a", "x", 100).with_manage_token(Some("m1".into())))
            .await
            .unwrap();
        store.insert(token("b", "x", 100)).await.unwrap();
        assert_eq!(
            store
                .get_by_manage_token("m1")
                .await
                .unwrap()
                .unwrap()
                .value,
            "a"
        );
        // Controls: an unknown secret finds nothing, and the access-token value is not a manage token.
        assert!(store.get_by_manage_token("nope").await.unwrap().is_none());
        assert!(store.get_by_manage_token("a").await.unwrap().is_none());
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
                access_token_request: None,
                subject: None,
                user: None,
            },
            continue_token: "ct".to_string(),
            created_at,
            interact_nonce: None,
            subject_id: None,
            subject_updated_at: None,
            interact_ref: None,
            user_code: None,
            revision: 0,
            last_poll_at: 0,
            bad_attempts: 0,
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
