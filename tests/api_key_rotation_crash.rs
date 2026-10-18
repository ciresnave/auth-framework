//! A process that dies part-way through `rotate_api_key` never leaves a second live key.
//!
//! A rotation writes six times: (1) the claim, (2) the new key's row, (3) the old key's legacy row
//! (a delete), (4) the old key's row, (5) the new key's row made live, (6) the claim released. The
//! storage wrapper here performs the n-th write and then plays dead: every later write fails, so
//! nothing a rotation would do to clean up after itself can run, as if the process had been killed.
//! The "restart" is a fresh `UserManager` over the same storage after the claim has expired (the
//! claim's lifetime is a minute; the test removes the claim row instead of waiting).
//!
//! Guarantee tested: after a crash at ANY step at most one key of the user is live, the old key
//! keeps working until its row is deleted, and a retry after a crash before the old key was
//! retired succeeds and leaves exactly one. The worst case is no live key (a crash after the old
//! key was retired and before the new one was made live): that is fail-safe and the user creates
//! another. "Never both, never neither" needs a storage transaction and is not claimed here.
//!
//! Backends: memory and SQLite in process; Redis and PostgreSQL need servers (`REDIS_URL`,
//! `DATABASE_URL`) and fail without them rather than skip.

use async_trait::async_trait;
use auth_framework::auth_modular::UserManager;
use auth_framework::config::PasswordHashAlgorithm;
use auth_framework::errors::{AuthError, Result};
use auth_framework::storage::{AuthStorage, MemoryStorage, SessionData};
use auth_framework::tokens::AuthToken;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

/// Delegates to a real backend; after `budget` further writes have succeeded, every write fails.
struct Crashy {
    inner: Arc<dyn AuthStorage>,
    /// Writes still allowed to succeed; negative means no limit.
    budget: AtomicI64,
    dead: AtomicBool,
}

impl Crashy {
    fn new(inner: Arc<dyn AuthStorage>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            budget: AtomicI64::new(-1),
            dead: AtomicBool::new(false),
        })
    }

    fn die_after(&self, writes: i64) {
        self.dead.store(false, Ordering::SeqCst);
        self.budget.store(writes, Ordering::SeqCst);
    }

    fn revive(&self) {
        self.budget.store(-1, Ordering::SeqCst);
        self.dead.store(false, Ordering::SeqCst);
    }

    fn gate(&self) -> Result<()> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(AuthError::internal("process died".to_string()));
        }
        Ok(())
    }

    /// Called after a write has been performed: the last permitted write kills the process.
    fn wrote(&self) {
        if self.budget.load(Ordering::SeqCst) >= 0
            && self.budget.fetch_sub(1, Ordering::SeqCst) == 1
        {
            self.dead.store(true, Ordering::SeqCst);
        }
    }
}

#[async_trait]
impl AuthStorage for Crashy {
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
        self.gate()?;
        self.inner.store_kv(k, v, ttl).await?;
        self.wrote();
        Ok(())
    }
    async fn store_kv_if_absent(&self, k: &str, v: &[u8], ttl: Option<Duration>) -> Result<bool> {
        self.gate()?;
        let stored = self.inner.store_kv_if_absent(k, v, ttl).await?;
        self.wrote();
        Ok(stored)
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
        self.gate()?;
        self.inner.delete_kv(k).await?;
        self.wrote();
        Ok(())
    }
    async fn cleanup_expired(&self) -> Result<()> {
        self.inner.cleanup_expired().await
    }
}

fn manager(storage: &Arc<Crashy>) -> Arc<UserManager> {
    let s: Arc<dyn AuthStorage> = storage.clone();
    Arc::new(UserManager::new(s, PasswordHashAlgorithm::Argon2))
}

/// How many key rows of `user` can authenticate: stored, not marked pending.
async fn live_keys(storage: &Arc<Crashy>, user: &str) -> usize {
    let mut live = 0;
    for name in storage.list_kv_keys("api_key_h:").await.unwrap() {
        let Some(bytes) = storage.get_kv(&name).await.unwrap() else {
            continue;
        };
        let row: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        if row["user_id"].as_str() == Some(user) && row["pending"].as_bool() != Some(true) {
            live += 1;
        }
    }
    live
}

/// What the claim's expiry does in production: the claim row goes away on its own.
async fn expire_claims(storage: &Arc<Crashy>) {
    for name in storage.list_kv_keys("api_key_rot:").await.unwrap() {
        storage.delete_kv(&name).await.unwrap();
    }
}

async fn crash_contract(inner: Arc<dyn AuthStorage>) {
    let storage = Crashy::new(inner);

    // Positive control: with no crash, a rotation is six writes and ends with exactly one live key.
    {
        let user = format!("ctl_{}", uuid::Uuid::new_v4().simple());
        let um = manager(&storage);
        let old = um.create_api_key(&user, None).await.unwrap();
        let new = um.rotate_api_key(&old).await.unwrap();
        assert!(um.validate_api_key(&old).await.is_err());
        assert!(um.validate_api_key(&new).await.is_ok());
        assert_eq!(live_keys(&storage, &user).await, 1);
    }

    for writes in 1..=6 {
        let user = format!("crash_{writes}_{}", uuid::Uuid::new_v4().simple());
        let um = manager(&storage);
        let old = um.create_api_key(&user, None).await.unwrap();
        assert_eq!(live_keys(&storage, &user).await, 1);

        storage.die_after(writes);
        let crashed = um.rotate_api_key(&old).await;
        let was_dead = storage.dead.load(Ordering::SeqCst);
        storage.revive();
        expire_claims(&storage).await;

        // The injection landed where it was aimed: the process died at write `writes`, and a
        // rotation that was allowed all six writes completed.
        if writes < 6 {
            assert!(was_dead, "writes={writes}: the crash was never injected");
        }
        // Dying before the new key is live (writes 1-4) cannot report success; dying after it (5,
        // when only the claim's release is lost) returns the new key, and so does no crash at all.
        if writes < 5 {
            assert!(
                crashed.is_err(),
                "writes={writes}: a rotation reported success after dying"
            );
        } else {
            assert!(
                crashed.is_ok(),
                "writes={writes}: the rotation was complete"
            );
        }

        let live = live_keys(&storage, &user).await;
        assert!(
            live <= 1,
            "crash after write {writes}: {live} keys of the user are live"
        );

        // A new manager, as after a restart.
        let um = manager(&storage);
        match writes {
            // The old key was not retired: it is still the one live key, and a retry succeeds.
            1..=3 => {
                assert_eq!(live, 1, "crash after write {writes}: no live key");
                assert!(um.validate_api_key(&old).await.is_ok());
                let new = um
                    .rotate_api_key(&old)
                    .await
                    .unwrap_or_else(|e| panic!("retry after crash {writes} failed: {e}"));
                assert!(um.validate_api_key(&old).await.is_err());
                assert!(um.validate_api_key(&new).await.is_ok());
                assert_eq!(
                    live_keys(&storage, &user).await,
                    1,
                    "retry after crash {writes}"
                );
            }
            // The old key was retired, the new one never made live: fail-safe, no live key.
            4 => {
                assert_eq!(live, 0);
                assert!(um.validate_api_key(&old).await.is_err());
            }
            // The new key was made live (and the call may have died after that): one live key.
            _ => {
                assert_eq!(live, 1);
                assert!(um.validate_api_key(&old).await.is_err());
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_rotation_survives_a_crash_at_every_step() {
    crash_contract(Arc::new(MemoryStorage::new())).await;
}

#[cfg(feature = "sqlite-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_rotation_survives_a_crash_at_every_step() {
    use auth_framework::storage::sqlite::SqliteStorage;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let storage = SqliteStorage::new(pool);
    storage.migrate().await.unwrap();
    crash_contract(Arc::new(storage)).await;
}

#[cfg(feature = "redis-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redis_rotation_survives_a_crash_at_every_step() {
    use auth_framework::storage::redis::RedisStorage;
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
    let prefix = format!("rotcrash_{}:", uuid::Uuid::new_v4().simple());
    let storage = RedisStorage::with_config(&url, prefix, Duration::from_secs(600))
        .await
        .unwrap();
    crash_contract(Arc::new(storage)).await;
}

#[cfg(feature = "postgres-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_rotation_survives_a_crash_at_every_step() {
    use auth_framework::storage::postgres::PostgresStorage;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let storage = PostgresStorage::new(pool);
    storage.migrate().await.unwrap();
    crash_contract(Arc::new(storage)).await;
}

/// A row marked pending is inert: it neither validates nor can be rotated. (The crash test counts
/// live rows by the same mark, so this is what ties that count to what actually authenticates.)
#[tokio::test]
async fn a_pending_row_authenticates_nobody() {
    let storage = Crashy::new(Arc::new(MemoryStorage::new()));
    let um = manager(&storage);
    let key = um.create_api_key("pending_user", None).await.unwrap();
    assert!(
        um.validate_api_key(&key).await.is_ok(),
        "control: the key works"
    );

    let name = storage.list_kv_keys("api_key_h:").await.unwrap().remove(0);
    let bytes = storage.get_kv(&name).await.unwrap().unwrap();
    let mut row: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    row["pending"] = serde_json::Value::Bool(true);
    storage
        .store_kv(&name, row.to_string().as_bytes(), None)
        .await
        .unwrap();

    assert!(um.validate_api_key(&key).await.is_err());
    assert!(um.rotate_api_key(&key).await.is_err());
}
