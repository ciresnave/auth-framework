//! Copying a `SqliteStorage` database into `PersistantStorage`.
#![cfg(all(feature = "persistant-storage", feature = "sqlite-storage"))]

use auth_framework::storage::persistant::PersistantStorage;
use auth_framework::storage::persistant_migrate::{MigrationReport, migrate_sqlite_to_storage};
use auth_framework::storage::sqlite::SqliteStorage;
use auth_framework::storage::{AuthStorage, SessionData};
use auth_framework::testing::helpers::create_test_token;
use std::collections::HashMap;
use std::time::Duration;

fn session(id: &str, user: &str, lives: i64) -> SessionData {
    let now = chrono::Utc::now();
    SessionData {
        session_id: id.to_string(),
        user_id: user.to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::seconds(lives),
        last_activity: now,
        ip_address: None,
        user_agent: None,
        data: HashMap::new(),
    }
}

async fn source() -> (sqlx::SqlitePool, SqliteStorage) {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let storage = SqliteStorage::new(pool.clone());
    storage.migrate().await.unwrap();
    (pool, storage)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sqlite_database_arrives_in_persistant_storage_intact() {
    let (pool, old) = source().await;

    // Enough rows to cross the 500-row read page, for tokens and kv.
    let mut tokens = Vec::new();
    for i in 0..620 {
        let t = create_test_token(if i % 2 == 0 { "even" } else { "odd" });
        old.store_token(&t).await.unwrap();
        tokens.push(t);
    }
    let mut expired = create_test_token("gone");
    expired.expires_at = chrono::Utc::now() - chrono::Duration::seconds(30);
    old.store_token(&expired).await.unwrap();

    old.store_session("s-live", &session("s-live", "even", 600))
        .await
        .unwrap();
    old.store_session("s-dead", &session("s-dead", "even", -30))
        .await
        .unwrap();

    for i in 0..510 {
        old.store_kv(&format!("k{i:04}"), format!("v{i}").as_bytes(), None)
            .await
            .unwrap();
    }
    old.store_kv("with-ttl", b"t", Some(Duration::from_secs(120)))
        .await
        .unwrap();
    old.store_kv("dead-kv", b"x", Some(Duration::from_secs(1)))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2200)).await;

    let new = PersistantStorage::in_memory();
    let report = migrate_sqlite_to_storage(&pool, &new).await.unwrap();
    assert_eq!(
        report,
        MigrationReport {
            tokens: 620,
            sessions: 1,
            kv_entries: 511,
            skipped_expired: 3,
        }
    );

    // Every token resolves by id and by access token, and is listed under its user.
    for t in &tokens {
        let by_id = new.get_token(&t.token_id).await.unwrap().unwrap();
        assert_eq!(by_id.access_token, t.access_token);
        let by_access = new
            .get_token_by_access_token(&t.access_token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_access.token_id, t.token_id);
    }
    assert_eq!(new.list_user_tokens("even").await.unwrap().len(), 310);
    assert_eq!(new.list_user_tokens("odd").await.unwrap().len(), 310);
    assert!(new.get_token(&expired.token_id).await.unwrap().is_none());

    assert!(new.get_session("s-live").await.unwrap().is_some());
    assert!(new.get_session("s-dead").await.unwrap().is_none());
    assert_eq!(new.list_user_sessions("even").await.unwrap().len(), 1);

    assert_eq!(new.get_kv("k0509").await.unwrap().unwrap(), b"v509");
    assert_eq!(new.get_kv("dead-kv").await.unwrap(), None);
    let left = new.get_kv_ttl("with-ttl").await.unwrap().unwrap();
    assert!(left > Duration::from_secs(100) && left <= Duration::from_secs(122));
    assert_eq!(new.get_kv_ttl("k0001").await.unwrap(), None);

    // The source is untouched, and a second run changes nothing.
    assert!(old.get_token(&tokens[0].token_id).await.unwrap().is_some());
    let again = migrate_sqlite_to_storage(&pool, &new).await.unwrap();
    assert_eq!(again.tokens, 620);
    assert_eq!(new.list_user_tokens("even").await.unwrap().len(), 310);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_that_does_not_decode_stops_the_copy_with_an_error() {
    let (pool, old) = source().await;
    old.store_token(&create_test_token("fine")).await.unwrap();
    sqlx::query(
        "INSERT INTO auth_tokens (token_id, user_id, access_token, data, expires_at) VALUES ('zz', 'u', 'a', 'not json', 4102444800)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let new = PersistantStorage::in_memory();
    let err = migrate_sqlite_to_storage(&pool, &new).await.unwrap_err();
    assert!(err.to_string().contains("auth_tokens"), "{err}");
}
