//! `AuthStorage::store_kv_if_absent` is a compare-and-set: of simultaneous callers exactly one wins,
//! and an expired entry no longer blocks.

use auth_framework::storage::{AuthStorage, MemoryStorage};
use std::sync::Arc;
use std::time::Duration;

async fn semantics(store: Arc<dyn AuthStorage>) {
    // Fresh keys per run: Postgres and Redis outlive the test.
    let run = uuid::Uuid::new_v4().simple().to_string();
    let (k1, race, short) = (
        format!("k1-{run}"),
        format!("race-{run}"),
        format!("short-{run}"),
    );
    // first writer wins and the value is kept
    assert!(store.store_kv_if_absent(&k1, b"first", None).await.unwrap());
    assert!(
        !store
            .store_kv_if_absent(&k1, b"second", None)
            .await
            .unwrap()
    );
    assert_eq!(store.get_kv(&k1).await.unwrap().unwrap(), b"first");

    // exactly one of many simultaneous callers wins
    let mut tasks = Vec::new();
    for i in 0..32u8 {
        let store = store.clone();
        let race = race.clone();
        tasks.push(tokio::spawn(async move {
            store
                .store_kv_if_absent(&race, &[i], Some(Duration::from_secs(60)))
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for t in tasks {
        if t.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);

    // an expired entry does not block a new one
    assert!(
        store
            .store_kv_if_absent(&short, b"a", Some(Duration::from_secs(1)))
            .await
            .unwrap()
    );
    tokio::time::sleep(Duration::from_millis(2300)).await;
    assert!(
        store
            .store_kv_if_absent(&short, b"b", Some(Duration::from_secs(60)))
            .await
            .unwrap()
    );
    assert_eq!(store.get_kv(&short).await.unwrap().unwrap(), b"b");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_storage_is_a_compare_and_set() {
    semantics(Arc::new(MemoryStorage::new())).await;
}

#[cfg(feature = "sqlite-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_storage_is_a_compare_and_set() {
    use auth_framework::storage::sqlite::SqliteStorage;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let storage = SqliteStorage::new(pool);
    storage.migrate().await.unwrap();
    semantics(Arc::new(storage)).await;
}

#[cfg(feature = "postgres-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_storage_is_a_compare_and_set() {
    use auth_framework::storage::postgres::PostgresStorage;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let storage = PostgresStorage::new(sqlx::PgPool::connect(&url).await.unwrap());
    storage.migrate().await.unwrap();
    semantics(Arc::new(storage)).await;
}

#[cfg(feature = "redis-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redis_storage_is_a_compare_and_set() {
    use auth_framework::storage::redis::RedisStorage;
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
    semantics(Arc::new(RedisStorage::new(&url).await.unwrap())).await;
}
