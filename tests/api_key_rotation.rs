//! `rotate_api_key` replaces a key with a new one: the new key is returned once, the old one stops
//! validating, and a rotation never leaves the caller with two working keys on a returned result.
//!
//! Semantics (also in the method's documentation): the new key is stored inert, then the old one is
//! deleted, then the new one is made live; if the delete fails the new key is removed again and the
//! call returns an error, so the old key stays the only valid one. Concurrent rotations of one key
//! are arbitrated by an atomic claim, so at most one succeeds. Behaviour when the process dies
//! part-way is in `api_key_rotation_crash.rs`.

use async_trait::async_trait;
use auth_framework::auth_modular::UserManager;
use auth_framework::config::PasswordHashAlgorithm;
use auth_framework::errors::{AuthError, Result};
use auth_framework::storage::{AuthStorage, MemoryStorage, SessionData};
use auth_framework::tokens::AuthToken;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Barrier;

/// Delegates to memory storage; can be told to fail deletes of named rows, or to lack the
/// atomic `store_kv_if_absent` (as a backend without it would).
struct Faulty {
    inner: MemoryStorage,
    fail_deletes_of: Mutex<Vec<String>>,
    no_if_absent: AtomicBool,
    /// When set, a `store_kv_if_absent` of a key row waits here (up to 300 ms) for a second writer,
    /// so two rotations can be held at the point where each is about to create its new key.
    store_gate: Mutex<Option<Arc<Barrier>>>,
}

impl Faulty {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: MemoryStorage::new(),
            fail_deletes_of: Mutex::new(Vec::new()),
            no_if_absent: AtomicBool::new(false),
            store_gate: Mutex::new(None),
        })
    }
}

#[async_trait]
impl AuthStorage for Faulty {
    async fn store_token(&self, t: &AuthToken) -> Result<()> {
        self.inner.store_token(t).await
    }
    async fn get_token(&self, id: &str) -> Result<Option<AuthToken>> {
        self.inner.get_token(id).await
    }
    async fn get_token_by_access_token(&self, a: &str) -> Result<Option<AuthToken>> {
        self.inner.get_token_by_access_token(a).await
    }
    async fn update_token(&self, t: &AuthToken) -> Result<()> {
        self.inner.update_token(t).await
    }
    async fn delete_token(&self, id: &str) -> Result<()> {
        self.inner.delete_token(id).await
    }
    async fn list_user_tokens(&self, u: &str) -> Result<Vec<AuthToken>> {
        self.inner.list_user_tokens(u).await
    }
    async fn store_session(&self, id: &str, d: &SessionData) -> Result<()> {
        self.inner.store_session(id, d).await
    }
    async fn get_session(&self, id: &str) -> Result<Option<SessionData>> {
        self.inner.get_session(id).await
    }
    async fn delete_session(&self, id: &str) -> Result<()> {
        self.inner.delete_session(id).await
    }
    async fn list_user_sessions(&self, u: &str) -> Result<Vec<SessionData>> {
        self.inner.list_user_sessions(u).await
    }
    async fn count_active_sessions(&self) -> Result<u64> {
        self.inner.count_active_sessions().await
    }
    async fn store_kv(&self, k: &str, v: &[u8], ttl: Option<Duration>) -> Result<()> {
        self.inner.store_kv(k, v, ttl).await
    }
    async fn store_kv_if_absent(&self, k: &str, v: &[u8], ttl: Option<Duration>) -> Result<bool> {
        if self.no_if_absent.load(Ordering::SeqCst) {
            return Err(AuthError::internal("no store_kv_if_absent".to_string()));
        }
        let gate = self.store_gate.lock().unwrap().clone();
        if let (Some(gate), true) = (gate, k.starts_with("api_key_h:")) {
            let _ = tokio::time::timeout(Duration::from_millis(300), gate.wait()).await;
        }
        self.inner.store_kv_if_absent(k, v, ttl).await
    }
    async fn get_kv(&self, k: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get_kv(k).await
    }
    async fn get_kv_ttl(&self, k: &str) -> Result<Option<Duration>> {
        self.inner.get_kv_ttl(k).await
    }
    fn tracks_kv_ttl(&self) -> bool {
        self.inner.tracks_kv_ttl()
    }
    async fn list_kv_keys(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list_kv_keys(prefix).await
    }
    async fn delete_kv(&self, k: &str) -> Result<()> {
        if self
            .fail_deletes_of
            .lock()
            .unwrap()
            .iter()
            .any(|name| name == k)
        {
            return Err(AuthError::internal("delete refused".to_string()));
        }
        self.inner.delete_kv(k).await
    }
    async fn cleanup_expired(&self) -> Result<()> {
        self.inner.cleanup_expired().await
    }
}

fn manager(storage: &Arc<Faulty>) -> Arc<UserManager> {
    let s: Arc<dyn AuthStorage> = storage.clone();
    Arc::new(UserManager::new(s, PasswordHashAlgorithm::Argon2))
}

/// The digest-named key rows currently stored.
async fn key_rows(storage: &Arc<Faulty>) -> Vec<String> {
    storage.list_kv_keys("api_key_h:").await.unwrap()
}

fn expires_at(row: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    let value: serde_json::Value = serde_json::from_slice(row).unwrap();
    value["expires_at"]
        .as_str()
        .map(|s| s.parse().expect("expires_at parses"))
}

#[tokio::test]
async fn rotation_returns_a_new_key_and_retires_the_old_one() {
    let storage = Faulty::new();
    let um = manager(&storage);
    let old = um.create_api_key("alice", None).await.unwrap();

    let new = um.rotate_api_key(&old).await.unwrap();

    assert_ne!(new, old);
    assert!(new.starts_with("ak_"));
    assert!(
        um.validate_api_key(&old).await.is_err(),
        "old key must stop validating"
    );
    assert_eq!(um.validate_api_key(&new).await.unwrap().id, "alice");
    assert_eq!(
        key_rows(&storage).await.len(),
        1,
        "exactly one key row remains"
    );
}

#[tokio::test]
async fn the_new_key_keeps_the_role() {
    let storage = Faulty::new();
    let um = manager(&storage);
    let old = um
        .create_api_key_with_role("alice", "admin", None)
        .await
        .unwrap();
    let new = um.rotate_api_key(&old).await.unwrap();
    let info = um.validate_api_key(&new).await.unwrap();
    assert_eq!(info.roles.iter().cloned().collect::<Vec<_>>(), ["admin"]);
}

#[tokio::test]
async fn the_new_key_gets_a_fresh_expiry_of_the_same_length() {
    let storage = Faulty::new();
    let um = manager(&storage);
    let old = um
        .create_api_key("alice", Some(Duration::from_secs(3600)))
        .await
        .unwrap();
    // Let the clock move so "fresh" is distinguishable from "copied".
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let old_expiry = {
        let row = storage
            .get_kv(&key_rows(&storage).await[0])
            .await
            .unwrap()
            .unwrap();
        expires_at(&row).unwrap()
    };

    um.rotate_api_key(&old).await.unwrap();

    let row = storage
        .get_kv(&key_rows(&storage).await[0])
        .await
        .unwrap()
        .unwrap();
    let new_expiry = expires_at(&row).expect("a key that expired still expires");
    assert!(
        new_expiry > old_expiry,
        "the expiry was copied, not renewed"
    );
    let remaining = (new_expiry - chrono::Utc::now()).num_seconds();
    assert!(
        (3590..=3600).contains(&remaining),
        "expected about an hour, got {remaining}s"
    );
}

#[tokio::test]
async fn a_key_that_never_expired_still_never_expires() {
    let storage = Faulty::new();
    let um = manager(&storage);
    let old = um.create_api_key("alice", None).await.unwrap();
    um.rotate_api_key(&old).await.unwrap();
    let row = storage
        .get_kv(&key_rows(&storage).await[0])
        .await
        .unwrap()
        .unwrap();
    assert!(expires_at(&row).is_none());
}

#[tokio::test]
async fn the_expiry_can_be_chosen_at_rotation() {
    let storage = Faulty::new();
    let um = manager(&storage);
    let old = um.create_api_key("alice", None).await.unwrap();
    um.rotate_api_key_with_expiry(&old, Some(Duration::from_secs(600)))
        .await
        .unwrap();
    let row = storage
        .get_kv(&key_rows(&storage).await[0])
        .await
        .unwrap()
        .unwrap();
    let remaining = (expires_at(&row).unwrap() - chrono::Utc::now()).num_seconds();
    assert!((590..=600).contains(&remaining), "got {remaining}s");

    // Choosing no expiry removes it.
    let current = {
        // the only row is the rotated key; rotate it again by key, which we do not have, so
        // create a fresh key to rotate onto "no expiry".
        um.create_api_key("bob", Some(Duration::from_secs(60)))
            .await
            .unwrap()
    };
    um.rotate_api_key_with_expiry(&current, None).await.unwrap();
    let rows = key_rows(&storage).await;
    assert_eq!(rows.len(), 2);
    let mut no_expiry = 0;
    for r in rows {
        let row = storage.get_kv(&r).await.unwrap().unwrap();
        if expires_at(&row).is_none() {
            no_expiry += 1;
        }
    }
    assert_eq!(no_expiry, 1);
}

#[tokio::test]
async fn a_revoked_key_cannot_be_rotated_and_nothing_is_created() {
    let storage = Faulty::new();
    let um = manager(&storage);
    let old = um.create_api_key("alice", None).await.unwrap();
    um.revoke_api_key(&old).await.unwrap();
    assert!(um.rotate_api_key(&old).await.is_err());
    assert!(
        key_rows(&storage).await.is_empty(),
        "a refused rotation created a key"
    );
}

#[tokio::test]
async fn an_expired_key_cannot_be_rotated_and_nothing_is_created() {
    let storage = Faulty::new();
    let um = manager(&storage);
    // A row whose expiry has passed but which the store still holds (no TTL), as with a backend
    // that does not evict on its own.
    let row = serde_json::json!({
        "user_id": "alice",
        "role": "user",
        "created_at": chrono::Utc::now() - chrono::Duration::hours(2),
        "expires_at": chrono::Utc::now() - chrono::Duration::hours(1),
    });
    storage
        .store_kv("api_key:ak_expired", row.to_string().as_bytes(), None)
        .await
        .unwrap();
    // Reading the legacy-named row migrates it to its digest name (existing behaviour, not part of
    // rotation); take that as the baseline and require that rotation adds nothing to it.
    assert!(um.validate_api_key("ak_expired").await.is_err());
    let baseline = key_rows(&storage).await.len();
    assert!(um.rotate_api_key("ak_expired").await.is_err());
    assert_eq!(
        key_rows(&storage).await.len(),
        baseline,
        "a refused rotation created a key"
    );
}

#[tokio::test]
async fn an_unknown_key_cannot_be_rotated() {
    let storage = Faulty::new();
    let um = manager(&storage);
    assert!(um.rotate_api_key("ak_never_issued").await.is_err());
    assert!(key_rows(&storage).await.is_empty());
}

#[tokio::test]
async fn a_failed_retirement_leaves_the_old_key_as_the_only_valid_one() {
    let storage = Faulty::new();
    let um = manager(&storage);
    let old = um.create_api_key("alice", None).await.unwrap();

    // Only the old key's rows refuse to be deleted (under both of its names); the new key's can go.
    let mut old_rows = key_rows(&storage).await;
    old_rows.push(format!("api_key:{old}"));
    *storage.fail_deletes_of.lock().unwrap() = old_rows;
    assert!(um.rotate_api_key(&old).await.is_err());
    storage.fail_deletes_of.lock().unwrap().clear();

    // The old key still validates, and the new key the failed attempt created is gone: one row.
    assert!(um.validate_api_key(&old).await.is_ok());
    assert_eq!(
        key_rows(&storage).await.len(),
        1,
        "the failed rotation left a second key"
    );
    // And the key can be rotated afterwards (the failed attempt did not wedge it behind a claim).
    assert!(um.rotate_api_key(&old).await.is_ok());
}

#[tokio::test]
async fn a_backend_without_an_atomic_claim_refuses_to_rotate() {
    let storage = Faulty::new();
    let um = manager(&storage);
    let old = um.create_api_key("alice", None).await.unwrap();
    storage.no_if_absent.store(true, Ordering::SeqCst);
    assert!(um.rotate_api_key(&old).await.is_err());
    storage.no_if_absent.store(false, Ordering::SeqCst);
    assert!(
        um.validate_api_key(&old).await.is_ok(),
        "a refused rotation changed the old key"
    );
    assert_eq!(key_rows(&storage).await.len(), 1);
}

/// Deterministic: both rotations are held where each is about to create its new key. With the
/// claim only one gets there (the other is refused first, and the first waits out the gate alone);
/// without it both would arrive together and both would create a key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_rotations_held_at_the_store_step_still_have_one_winner() {
    let storage = Faulty::new();
    let um = manager(&storage);
    let old = um.create_api_key("alice", None).await.unwrap();
    *storage.store_gate.lock().unwrap() = Some(Arc::new(Barrier::new(2)));

    let (a, b) = tokio::join!(
        {
            let um = um.clone();
            let old = old.clone();
            tokio::spawn(async move { um.rotate_api_key(&old).await })
        },
        {
            let um = um.clone();
            let old = old.clone();
            tokio::spawn(async move { um.rotate_api_key(&old).await })
        }
    );
    let results = [a.unwrap(), b.unwrap()];
    let winners: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
    assert_eq!(winners.len(), 1, "expected one winner, got {results:?}");

    *storage.store_gate.lock().unwrap() = None;
    assert!(um.validate_api_key(winners[0]).await.is_ok());
    assert!(um.validate_api_key(&old).await.is_err());
    assert_eq!(
        key_rows(&storage).await.len(),
        1,
        "more than one key survived"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_rotations_of_one_key_have_exactly_one_winner() {
    for round in 0..8 {
        let storage = Faulty::new();
        let um = manager(&storage);
        let old = um.create_api_key("alice", None).await.unwrap();

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let um = um.clone();
            let old = old.clone();
            tasks.push(tokio::spawn(async move { um.rotate_api_key(&old).await }));
        }
        let mut winners = Vec::new();
        for task in tasks {
            if let Ok(key) = task.await.unwrap() {
                winners.push(key);
            }
        }

        assert_eq!(
            winners.len(),
            1,
            "round {round}: expected one winner, got {}",
            winners.len()
        );
        assert!(um.validate_api_key(&winners[0]).await.is_ok());
        assert!(um.validate_api_key(&old).await.is_err());
        assert_eq!(
            key_rows(&storage).await.len(),
            1,
            "round {round}: more than one key survived"
        );
    }
}

#[tokio::test]
async fn a_key_can_be_rotated_repeatedly() {
    let storage = Faulty::new();
    let um = manager(&storage);
    let first = um.create_api_key("alice", None).await.unwrap();
    let second = um.rotate_api_key(&first).await.unwrap();
    let third = um.rotate_api_key(&second).await.unwrap();
    assert!(um.validate_api_key(&first).await.is_err());
    assert!(um.validate_api_key(&second).await.is_err());
    assert!(um.validate_api_key(&third).await.is_ok());
    assert_eq!(key_rows(&storage).await.len(), 1);
}
