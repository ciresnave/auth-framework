//! `AuthStorage::get_token`, `get_token_by_access_token` and `get_session` do not return what has
//! expired (issue #144). The memory, DashMap, SQLite and PersistAnt backends run in process;
//! PostgreSQL needs a server (`DATABASE_URL`; CI's test job provides it) and fails without it
//! rather than skips. Redis expires keys itself and is not covered here.

use auth_framework::storage::dashmap_memory::DashMapMemoryStorage;
use auth_framework::storage::{AuthStorage, MemoryStorage, SessionData};
use auth_framework::tokens::AuthToken;
use std::collections::HashMap;
use std::sync::Arc;

fn token(id: &str, user: &str, lives_seconds: i64) -> AuthToken {
    AuthToken::builder(id, user, format!("access-{id}"))
        .expires_at(chrono::Utc::now() + chrono::Duration::seconds(lives_seconds))
        .build()
}

fn session(id: &str, user: &str, lives_seconds: i64) -> SessionData {
    let now = chrono::Utc::now();
    SessionData {
        session_id: id.to_string(),
        user_id: user.to_string(),
        created_at: now - chrono::Duration::hours(2),
        expires_at: now + chrono::Duration::seconds(lives_seconds),
        last_activity: now,
        ip_address: None,
        user_agent: None,
        data: HashMap::new(),
    }
}

async fn contract(storage: Arc<dyn AuthStorage>) {
    let run = uuid::Uuid::new_v4().simple().to_string();
    let user = format!("exp-user-{run}");
    let live = token(&format!("live-{run}"), &user, 3600);
    let dead = token(&format!("dead-{run}"), &user, -3600);
    storage.store_token(&live).await.unwrap();
    storage.store_token(&dead).await.unwrap();

    // Controls: the live token is returned by both lookups.
    assert!(storage.get_token(&live.token_id).await.unwrap().is_some());
    assert!(
        storage
            .get_token_by_access_token(&live.access_token)
            .await
            .unwrap()
            .is_some()
    );
    // The expired one is not, by either.
    assert!(
        storage.get_token(&dead.token_id).await.unwrap().is_none(),
        "get_token returned an expired token"
    );
    assert!(
        storage
            .get_token_by_access_token(&dead.access_token)
            .await
            .unwrap()
            .is_none(),
        "get_token_by_access_token returned an expired token"
    );

    let live_session = session(&format!("s-live-{run}"), &user, 3600);
    let dead_session = session(&format!("s-dead-{run}"), &user, -3600);
    storage
        .store_session(&live_session.session_id, &live_session)
        .await
        .unwrap();
    storage
        .store_session(&dead_session.session_id, &dead_session)
        .await
        .unwrap();
    assert!(
        storage
            .get_session(&live_session.session_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        storage
            .get_session(&dead_session.session_id)
            .await
            .unwrap()
            .is_none(),
        "get_session returned an expired session"
    );
}

#[tokio::test]
async fn memory_does_not_return_expired() {
    contract(Arc::new(MemoryStorage::new())).await;
}

#[tokio::test]
async fn dashmap_does_not_return_expired() {
    contract(Arc::new(DashMapMemoryStorage::new())).await;
}

#[cfg(feature = "sqlite-storage")]
#[tokio::test]
async fn sqlite_does_not_return_expired() {
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
#[tokio::test]
async fn persistant_memory_does_not_return_expired() {
    use auth_framework::storage::persistant::PersistantStorage;
    contract(Arc::new(PersistantStorage::in_memory())).await;
}

#[cfg(feature = "postgres-storage")]
#[tokio::test]
async fn postgres_does_not_return_expired() {
    use auth_framework::storage::postgres::PostgresStorage;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let storage = PostgresStorage::new(pool);
    storage.migrate().await.unwrap();
    contract(Arc::new(storage)).await;
}
