//! `AuthStorage::list_user_sessions` returns each of a user's sessions whole (issue #147): the same
//! fields `store_session` was given, none of another user's. PostgreSQL needs a server
//! (`DATABASE_URL`; CI's test job provides it) and fails without it rather than skips.

use auth_framework::storage::dashmap_memory::DashMapMemoryStorage;
use auth_framework::storage::{AuthStorage, MemoryStorage, SessionData};
use std::collections::HashMap;
use std::sync::Arc;

fn session(id: &str, user: &str, ip: &str) -> SessionData {
    let now = chrono::Utc::now();
    let mut data = HashMap::new();
    data.insert("theme".to_string(), serde_json::json!("dark"));
    data.insert("visits".to_string(), serde_json::json!(3));
    SessionData {
        session_id: id.to_string(),
        user_id: user.to_string(),
        created_at: now - chrono::Duration::minutes(10),
        expires_at: now + chrono::Duration::hours(1),
        last_activity: now - chrono::Duration::minutes(1),
        ip_address: Some(ip.to_string()),
        user_agent: Some("contract-test/1.0".to_string()),
        data,
    }
}

async fn contract(storage: Arc<dyn AuthStorage>) {
    let run = uuid::Uuid::new_v4().simple().to_string();
    let alice = format!("alice-{run}");
    let bob = format!("bob-{run}");
    let a1 = session(&format!("a1-{run}"), &alice, "10.0.0.1");
    let a2 = session(&format!("a2-{run}"), &alice, "10.0.0.2");
    let b1 = session(&format!("b1-{run}"), &bob, "10.0.0.3");
    for s in [&a1, &a2, &b1] {
        storage.store_session(&s.session_id, s).await.unwrap();
    }

    let mut listed = storage.list_user_sessions(&alice).await.unwrap();
    listed.sort_by(|x, y| x.session_id.cmp(&y.session_id));
    assert_eq!(listed.len(), 2, "alice's sessions only: {listed:?}");
    for (got, want) in listed.iter().zip([&a1, &a2]) {
        assert_eq!(got.session_id, want.session_id);
        assert_eq!(got.user_id, want.user_id);
        assert_eq!(got.ip_address, want.ip_address);
        assert_eq!(got.user_agent, want.user_agent);
        assert_eq!(got.data, want.data);
        assert_eq!(got.expires_at, want.expires_at);
        assert_eq!(got.last_activity, want.last_activity);
        assert_eq!(got.created_at, want.created_at);
    }
    assert_eq!(storage.list_user_sessions(&bob).await.unwrap().len(), 1);
    assert!(
        storage
            .list_user_sessions(&format!("nobody-{run}"))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn memory_lists_whole_sessions() {
    contract(Arc::new(MemoryStorage::new())).await;
}

#[tokio::test]
async fn dashmap_lists_whole_sessions() {
    contract(Arc::new(DashMapMemoryStorage::new())).await;
}

#[cfg(feature = "sqlite-storage")]
#[tokio::test]
async fn sqlite_lists_whole_sessions() {
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

#[cfg(feature = "postgres-storage")]
#[tokio::test]
async fn postgres_lists_whole_sessions() {
    use auth_framework::storage::postgres::PostgresStorage;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let storage = PostgresStorage::new(pool);
    storage.migrate().await.unwrap();
    contract(Arc::new(storage)).await;
}
