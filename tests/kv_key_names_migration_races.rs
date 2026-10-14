//! Interleavings of API-key migration (legacy `api_key:{raw}` -> `api_key_h:{digest}`) with
//! validation and revoke. Each test pins one interleaving deterministically: a storage wrapper
//! runs a second operation at an exact point inside the first, so a failure is reproducible, not a
//! lucky race.

use async_trait::async_trait;
use auth_framework::auth_modular::UserManager;
use auth_framework::errors::Result;
use auth_framework::storage::{AuthStorage, MemoryStorage, SessionData};
use auth_framework::tokens::AuthToken;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Hook = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// Delegates to memory storage; can run a hook right after the next `get_kv` or
/// digest-row `store_kv`, and answer the next `api_key_h:` read with "absent" (a read that
/// happened before another actor's write).
struct Gated {
    inner: MemoryStorage,
    after_get: Mutex<Option<Hook>>,
    after_digest_store: Mutex<Option<Hook>>,
    stale_digest_read: Mutex<bool>,
}

impl Gated {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: MemoryStorage::new(),
            after_get: Mutex::new(None),
            after_digest_store: Mutex::new(None),
            stale_digest_read: Mutex::new(false),
        })
    }
}

#[async_trait]
impl AuthStorage for Gated {
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
        let r = self.inner.store_kv(k, v, ttl).await;
        if k.starts_with("api_key_h:") {
            let hook = self.after_digest_store.lock().unwrap().take();
            if let Some(h) = hook {
                h().await;
            }
        }
        r
    }
    async fn get_kv(&self, k: &str) -> Result<Option<Vec<u8>>> {
        if k.starts_with("api_key_h:") {
            let mut stale = self.stale_digest_read.lock().unwrap();
            if *stale {
                *stale = false;
                return Ok(None);
            }
        }
        let r = self.inner.get_kv(k).await;
        let hook = self.after_get.lock().unwrap().take();
        if let Some(h) = hook {
            h().await;
        }
        r
    }
    async fn delete_kv(&self, k: &str) -> Result<()> {
        self.inner.delete_kv(k).await
    }
    async fn cleanup_expired(&self) -> Result<()> {
        self.inner.cleanup_expired().await
    }
}

fn manager(storage: &Arc<Gated>) -> Arc<UserManager> {
    let s: Arc<dyn AuthStorage> = storage.clone();
    Arc::new(UserManager::new(s))
}

fn metadata(user_id: &str) -> Vec<u8> {
    serde_json::json!({
        "user_id": user_id,
        "created_at": chrono::Utc::now(),
        "expires_at": null,
    })
    .to_string()
    .into_bytes()
}

async fn seed_legacy(storage: &Arc<Gated>, key: &str) {
    storage
        .store_kv(&format!("api_key:{key}"), &metadata("racer"), None)
        .await
        .unwrap();
}

/// Validator A creates the digest row; before A re-reads the legacy row, validator B (which read
/// the digest row as absent before A wrote it) finishes its own migration attempt. A must not
/// read B's legacy delete as a revoke and delete the row they now share.
#[tokio::test]
async fn second_migrator_finishing_first_does_not_delete_the_shared_row() {
    let storage = Gated::new();
    let a = manager(&storage);
    let b = manager(&storage);
    let key = "ak_race_two_migrators";
    seed_legacy(&storage, key).await;

    {
        let storage2 = storage.clone();
        let b = b.clone();
        *storage.after_digest_store.lock().unwrap() = Some(Box::new(move || {
            Box::pin(async move {
                // B's earlier read of the digest row saw nothing
                *storage2.stale_digest_read.lock().unwrap() = true;
                b.validate_api_key(key).await.expect("B validates");
            })
        }));
    }

    a.validate_api_key(key)
        .await
        .expect("A: a live key must stay valid when another reader migrates it too");
    assert!(
        a.validate_api_key(key).await.is_ok(),
        "the shared digest row must still exist afterwards"
    );
}

/// Revoke reads the digest name (absent), a validator then migrates the row (digest created,
/// legacy deleted), and revoke reads the legacy name (absent): it used to answer "not found" and
/// leave the key active.
#[tokio::test]
async fn revoke_interleaved_with_a_migration_still_revokes() {
    let storage = Gated::new();
    let um = manager(&storage);
    let validator = manager(&storage);
    let key = "ak_race_revoke";
    seed_legacy(&storage, key).await;

    {
        let validator = validator.clone();
        *storage.after_get.lock().unwrap() = Some(Box::new(move || {
            Box::pin(async move {
                validator.validate_api_key(key).await.expect("migrates");
            })
        }));
    }

    um.revoke_api_key(key)
        .await
        .expect("a live key must be revocable while it is being migrated");
    assert!(
        um.validate_api_key(key).await.is_err(),
        "the key is still usable after revoke"
    );
}

/// A validator reads the digest row (absent), another validator migrates the row, then the first
/// reads the legacy row (absent): the key is live under the digest name and must validate.
#[tokio::test]
async fn validator_overtaken_by_a_migration_still_validates() {
    let storage = Gated::new();
    let slow = manager(&storage);
    let fast = manager(&storage);
    let key = "ak_race_overtaken";
    seed_legacy(&storage, key).await;

    {
        let fast = fast.clone();
        *storage.after_get.lock().unwrap() = Some(Box::new(move || {
            Box::pin(async move {
                fast.validate_api_key(key).await.expect("migrates");
            })
        }));
    }

    slow.validate_api_key(key)
        .await
        .expect("a live key must not be reported missing because another reader migrated it");
}

/// A migration reads the legacy row, a revoke then completes, and only afterwards does the
/// migration write the digest row: the key must end up revoked (the revoke marker is how the
/// migration finds out).
#[tokio::test]
async fn revoke_completing_before_the_digest_write_is_not_undone() {
    let storage = Gated::new();
    let migrator = manager(&storage);
    let revoker = manager(&storage);
    let key = "ak_race_resurrect";
    seed_legacy(&storage, key).await;

    {
        let revoker = revoker.clone();
        // fires after the migration's second get_kv (the read of the legacy row)
        let armed = Arc::new(Mutex::new(0usize));
        let storage2 = storage.clone();
        *storage.after_get.lock().unwrap() = Some(Box::new(move || {
            Box::pin(async move {
                // first get_kv done (digest read); re-arm for the legacy read
                let _ = &armed;
                let revoker2 = revoker.clone();
                *storage2.after_get.lock().unwrap() = Some(Box::new(move || {
                    Box::pin(async move {
                        revoker2.revoke_api_key(key).await.expect("revoked");
                    })
                }));
            })
        }));
    }

    let _ = migrator.validate_api_key(key).await;
    assert!(
        migrator.validate_api_key(key).await.is_err(),
        "a migration that wrote its row after the revoke resurrected the key"
    );
}
