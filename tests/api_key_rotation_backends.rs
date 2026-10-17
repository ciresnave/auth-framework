//! Key rotation against each storage backend's own `store_kv_if_absent`: of several simultaneous
//! rotations of one key exactly one wins, whatever the backend.
//!
//! The rotation's single-winner guarantee rests on the backend's compare-and-set being atomic. The
//! memory backend is the control; SQLite runs in process; Redis and PostgreSQL need servers
//! (`REDIS_URL`, `DATABASE_URL`; CI's test job provides both) and fail without them rather than
//! skip. A backend that has no test here is UNVERIFIED for rotation.

use auth_framework::auth_modular::UserManager;
use auth_framework::config::PasswordHashAlgorithm;
use auth_framework::storage::{AuthStorage, MemoryStorage};
use std::sync::Arc;

const ROUNDS: usize = 6;
const RACERS: usize = 8;

fn manager(storage: Arc<dyn AuthStorage>) -> Arc<UserManager> {
    Arc::new(UserManager::new(storage, PasswordHashAlgorithm::Argon2))
}

/// Rotation retires the old key, refuses a revoked one, and has one winner under real concurrency.
async fn rotation_contract(storage: Arc<dyn AuthStorage>) {
    let um = manager(storage);

    // Plain rotation.
    let old = um.create_api_key("alice", None).await.unwrap();
    let new = um.rotate_api_key(&old).await.unwrap();
    assert!(
        um.validate_api_key(&old).await.is_err(),
        "old key still valid"
    );
    assert_eq!(um.validate_api_key(&new).await.unwrap().id, "alice");

    // A revoked key cannot be rotated.
    um.revoke_api_key(&new).await.unwrap();
    assert!(um.rotate_api_key(&new).await.is_err());

    // Simultaneous rotations of one key: exactly one winner, and exactly that key works afterwards.
    for round in 0..ROUNDS {
        let old = um.create_api_key("alice", None).await.unwrap();
        let mut tasks = Vec::new();
        for _ in 0..RACERS {
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
            "round {round}: expected one winner among {RACERS}, got {}",
            winners.len()
        );
        assert!(um.validate_api_key(&winners[0]).await.is_ok());
        assert!(um.validate_api_key(&old).await.is_err());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_rotation_has_one_winner() {
    rotation_contract(Arc::new(MemoryStorage::new())).await;
}

#[cfg(feature = "sqlite-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_rotation_has_one_winner() {
    use auth_framework::storage::sqlite::SqliteStorage;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let storage = SqliteStorage::new(pool);
    storage.migrate().await.unwrap();
    rotation_contract(Arc::new(storage)).await;
}

#[cfg(feature = "redis-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redis_rotation_has_one_winner() {
    use auth_framework::storage::redis::RedisStorage;
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
    let prefix = format!("rotation_{}:", uuid::Uuid::new_v4().simple());
    let storage = RedisStorage::with_config(&url, prefix, std::time::Duration::from_secs(600))
        .await
        .unwrap();
    rotation_contract(Arc::new(storage)).await;
}

#[cfg(feature = "postgres-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_rotation_has_one_winner() {
    use auth_framework::storage::postgres::PostgresStorage;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let storage = PostgresStorage::new(pool);
    storage.migrate().await.unwrap();
    rotation_contract(Arc::new(storage)).await;
}
