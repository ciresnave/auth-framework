//! `AuthStorage::swap_kv`: remove a key and store another in ONE atomic step.
//!
//! `swap_kv(remove, key, value, ttl)` succeeds only when at least one of the `remove` keys is
//! live AND `key` is absent; it then deletes every `remove` key and stores `value` under `key`
//! (returns `true`). Otherwise it changes nothing and returns `false`. Of several simultaneous
//! swaps of one key exactly one succeeds. Key rotation depends on it: a rotation that dies, or
//! races another, never leaves both keys or neither.
//!
//! Memory, DashMap, unified, SQLite and the encrypted wrapper run in process; Redis and
//! PostgreSQL need servers (`REDIS_URL`, `DATABASE_URL`; CI's test job provides both) and fail
//! without them rather than skip.

use auth_framework::errors::Result;
use auth_framework::storage::dashmap_memory::DashMapMemoryStorage;
use auth_framework::storage::encryption::{
    EncryptedStorage, KeyProvider, LoadedKeys, StorageEncryption,
};
use auth_framework::storage::{AuthStorage, MemoryStorage};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Longer than a 1 ms ttl by enough to cover the clock difference between this process and a
/// database server running in a VM or container (SQL backends compare the stored expiry, computed
/// here, with the server's clock).
const EXPIRY_WAIT: Duration = Duration::from_millis(2500);
const RACERS: usize = 8;
const ROUNDS: usize = 6;

fn names(keys: &[&str]) -> Vec<String> {
    keys.iter().map(|k| k.to_string()).collect()
}

async fn contract(storage: Arc<dyn AuthStorage>) {
    let run = uuid::Uuid::new_v4().simple().to_string();
    let k = |name: &str| format!("swap_{run}:{name}");
    assert!(
        storage.supports_atomic_swap(),
        "the backend must advertise swap_kv"
    );

    // A live key is replaced: the old key is gone, the new one holds the value.
    storage.store_kv(&k("old:1"), b"old", None).await.unwrap();
    assert!(
        storage
            .swap_kv(&names(&[&k("old:1")]), &k("new:1"), b"new", None)
            .await
            .unwrap()
    );
    assert_eq!(storage.get_kv(&k("old:1")).await.unwrap(), None);
    assert_eq!(
        storage.get_kv(&k("new:1")).await.unwrap(),
        Some(b"new".to_vec())
    );

    // Nothing live to remove: nothing is stored, and a second swap of the same key loses.
    assert!(
        !storage
            .swap_kv(&names(&[&k("old:1")]), &k("new:2"), b"new", None)
            .await
            .unwrap()
    );
    assert_eq!(storage.get_kv(&k("new:2")).await.unwrap(), None);

    // Several names for one thing (the legacy and the digest name of an API key): one is live,
    // both are removed.
    storage.store_kv(&k("name:b"), b"old", None).await.unwrap();
    assert!(
        storage
            .swap_kv(
                &names(&[&k("name:a"), &k("name:b")]),
                &k("new:3"),
                b"new",
                None
            )
            .await
            .unwrap()
    );
    assert_eq!(storage.get_kv(&k("name:b")).await.unwrap(), None);
    assert_eq!(
        storage.get_kv(&k("new:3")).await.unwrap(),
        Some(b"new".to_vec())
    );

    // All or nothing: the target already exists, so the swap is refused and the old key is
    // untouched (a delete that ran before the refused insert would show here).
    storage.store_kv(&k("old:4"), b"old", None).await.unwrap();
    storage.store_kv(&k("new:4"), b"taken", None).await.unwrap();
    assert!(
        !storage
            .swap_kv(&names(&[&k("old:4")]), &k("new:4"), b"new", None)
            .await
            .unwrap()
    );
    assert_eq!(
        storage.get_kv(&k("old:4")).await.unwrap(),
        Some(b"old".to_vec()),
        "a refused swap removed the old key"
    );
    assert_eq!(
        storage.get_kv(&k("new:4")).await.unwrap(),
        Some(b"taken".to_vec()),
        "a refused swap overwrote the target"
    );

    // An expired key is not live.
    storage
        .store_kv(&k("old:5"), b"old", Some(Duration::from_millis(1)))
        .await
        .unwrap();
    tokio::time::sleep(EXPIRY_WAIT).await;
    assert!(
        !storage
            .swap_kv(&names(&[&k("old:5")]), &k("new:5"), b"new", None)
            .await
            .unwrap()
    );
    assert_eq!(storage.get_kv(&k("new:5")).await.unwrap(), None);

    // The new key's lifetime is honoured.
    storage.store_kv(&k("old:6"), b"old", None).await.unwrap();
    assert!(
        storage
            .swap_kv(
                &names(&[&k("old:6")]),
                &k("new:6"),
                b"new",
                Some(Duration::from_millis(1))
            )
            .await
            .unwrap()
    );
    tokio::time::sleep(EXPIRY_WAIT).await;
    assert_eq!(
        storage.get_kv(&k("new:6")).await.unwrap(),
        None,
        "the swapped-in key outlived its ttl"
    );

    // Of several simultaneous swaps of one key exactly one wins, and exactly one target exists.
    for round in 0..ROUNDS {
        let old = k(&format!("race:{round}:old"));
        storage.store_kv(&old, b"old", None).await.unwrap();
        let mut tasks = Vec::new();
        for racer in 0..RACERS {
            let storage = storage.clone();
            let old = old.clone();
            let target = k(&format!("race:{round}:new:{racer}"));
            tasks.push(tokio::spawn(async move {
                storage.swap_kv(&[old], &target, b"new", None).await
            }));
        }
        let mut winners = 0;
        for task in tasks {
            if task.await.unwrap().unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "round {round}: {winners} swaps won");
        let targets = storage
            .list_kv_keys(&k(&format!("race:{round}:new:")))
            .await
            .unwrap();
        assert_eq!(targets.len(), 1, "round {round}: targets {targets:?}");
        assert_eq!(storage.get_kv(&old).await.unwrap(), None);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_swap_kv() {
    contract(Arc::new(MemoryStorage::new())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dashmap_swap_kv() {
    contract(Arc::new(DashMapMemoryStorage::new())).await;
}

#[cfg(feature = "performance-optimization")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unified_swap_kv() {
    use auth_framework::storage::UnifiedStorage;
    contract(Arc::new(UnifiedStorage::new())).await;
}

struct Keys;

impl KeyProvider for Keys {
    fn load_keys(&self) -> Result<LoadedKeys> {
        Ok(LoadedKeys {
            current_key_id: "k1".to_string(),
            keys: HashMap::from([("k1".to_string(), [7u8; 32])]),
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encrypted_swap_kv_stores_ciphertext_and_reads_back() {
    let inner: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
    let encryption = StorageEncryption::new(&Keys).unwrap();
    let encrypted: Arc<dyn AuthStorage> = Arc::new(EncryptedStorage::new(
        inner.clone(),
        encryption,
        false,
        false,
    ));
    contract(encrypted.clone()).await;

    // Beyond the contract: what reached the inner storage is not the plaintext.
    encrypted
        .store_kv("secret:old", b"old", None)
        .await
        .unwrap();
    assert!(
        encrypted
            .swap_kv(&names(&["secret:old"]), "secret:new", b"top secret", None)
            .await
            .unwrap()
    );
    let raw = inner.get_kv("secret:new").await.unwrap().unwrap();
    assert!(
        !raw.windows(b"top secret".len())
            .any(|window| window == b"top secret"),
        "the swapped-in value reached storage in the clear"
    );
    assert_eq!(
        encrypted.get_kv("secret:new").await.unwrap(),
        Some(b"top secret".to_vec())
    );
}

#[cfg(feature = "sqlite-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_swap_kv() {
    use auth_framework::storage::sqlite::SqliteStorage;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let storage = SqliteStorage::new(pool);
    storage.migrate().await.unwrap();
    contract(Arc::new(storage)).await;
}

#[cfg(feature = "persistant-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistant_memory_swap_kv() {
    use auth_framework::storage::persistant::PersistantStorage;
    contract(Arc::new(PersistantStorage::in_memory())).await;
}

#[cfg(feature = "persistant-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistant_sqlite_swap_kv() {
    use auth_framework::storage::persistant::PersistantStorage;
    let dir = tempfile::tempdir().unwrap();
    let storage = PersistantStorage::open_sqlite(dir.path().join("swap.sqlite"))
        .await
        .unwrap();
    contract(Arc::new(storage)).await;
}

#[cfg(feature = "redis-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redis_swap_kv() {
    use auth_framework::storage::redis::RedisStorage;
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
    let prefix = format!("swap_{}:", uuid::Uuid::new_v4().simple());
    let storage = RedisStorage::with_config(&url, prefix, Duration::from_secs(600))
        .await
        .unwrap();
    contract(Arc::new(storage)).await;
}

#[cfg(feature = "postgres-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_swap_kv() {
    use auth_framework::storage::postgres::PostgresStorage;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let storage = PostgresStorage::new(pool);
    storage.migrate().await.unwrap();
    // Other tests share the database: only this run's keys are looked at.
    contract(Arc::new(storage)).await;
}
