//! Integration tests for the PostgreSQL storage backend.
//!
//! These tests require a running PostgreSQL server (CI's test job provides one) and are not
//! `#[ignore]`d: a missing server fails them instead of hiding them. Set the `DATABASE_URL`
//! environment variable to a valid connection string before running:
//!
//! ```sh
//! export DATABASE_URL="postgres://user:password@localhost/auth_test"
//! cargo test --test storage_postgres --features postgres-storage
//! ```

#![cfg(feature = "postgres-storage")]

use auth_framework::providers::ProviderProfile;
use auth_framework::storage::postgres::PostgresStorage;
use auth_framework::storage::{AuthStorage, SessionData};
use auth_framework::tokens::AuthToken;
use auth_framework::types::{Permissions, Roles};
use sqlx::PgPool;
use std::time::Duration;

async fn setup() -> PostgresStorage {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run PostgreSQL integration tests");
    let pool = PgPool::connect(&url)
        .await
        .expect("Failed to connect to PostgreSQL");
    let storage = PostgresStorage::new(pool);
    storage.migrate().await.expect("Migration failed");
    // Clean up before each test
    storage.cleanup_expired().await.ok();
    storage
}

#[tokio::test]
async fn pg_token_crud() {
    let storage = setup().await;
    let token = AuthToken::new("pg_user1", "pg_access1", Duration::from_secs(3600), "test");
    let tid = token.token_id.clone();
    let at = token.access_token.clone();

    storage.store_token(&token).await.unwrap();

    let got = storage.get_token(&tid).await.unwrap().unwrap();
    assert_eq!(got.user_id, "pg_user1");

    let got = storage
        .get_token_by_access_token(&at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.token_id, tid);

    let tokens = storage.list_user_tokens("pg_user1").await.unwrap();
    assert!(!tokens.is_empty());

    storage.delete_token(&tid).await.unwrap();
    assert!(storage.get_token(&tid).await.unwrap().is_none());
}

#[tokio::test]
async fn pg_token_round_trips_profile_roles_and_permissions() {
    let storage = setup().await;
    let mut token = AuthToken::new(
        "pg_rt_user",
        "pg_rt_access",
        Duration::from_secs(3600),
        "test",
    );
    let mut profile = ProviderProfile::new();
    profile.email = Some("ann@example.com".to_string());
    profile.name = Some("Ann".to_string());
    token.user_profile = Some(profile);
    token.roles = Roles(vec!["admin".to_string(), "user".to_string()]);
    token.permissions = Permissions(vec!["read".to_string(), "write".to_string()]);

    storage.store_token(&token).await.unwrap();
    let got = storage.get_token(&token.token_id).await.unwrap().unwrap();
    let got_profile = got.user_profile.expect("user_profile must round-trip");
    assert_eq!(got_profile.email.as_deref(), Some("ann@example.com"));
    assert_eq!(got_profile.name.as_deref(), Some("Ann"));
    assert_eq!(got.roles.0, vec!["admin", "user"]);
    assert_eq!(got.permissions.0, vec!["read", "write"]);

    // A token without a profile reads back without one, and update_token changes all three.
    token.user_profile = None;
    token.roles = Roles(vec!["guest".to_string()]);
    token.permissions = Permissions(Vec::new());
    storage.update_token(&token).await.unwrap();
    let got = storage.get_token(&token.token_id).await.unwrap().unwrap();
    assert!(got.user_profile.is_none());
    assert_eq!(got.roles.0, vec!["guest"]);
    assert!(got.permissions.0.is_empty());

    storage.delete_token(&token.token_id).await.unwrap();
}

#[tokio::test]
async fn pg_token_update() {
    let storage = setup().await;
    let mut token = AuthToken::new("pg_upd_user", "pg_upd_at", Duration::from_secs(3600), "pw");
    storage.store_token(&token).await.unwrap();

    token.auth_method = "mfa".to_string();
    storage.update_token(&token).await.unwrap();

    let got = storage.get_token(&token.token_id).await.unwrap().unwrap();
    assert_eq!(got.auth_method, "mfa");
    storage.delete_token(&token.token_id).await.unwrap();
}

#[tokio::test]
async fn pg_session_crud() {
    let storage = setup().await;
    let session = SessionData::new("pg_sess1", "pg_user_s", Duration::from_secs(3600))
        .with_metadata(
            Some("10.0.0.1".to_string()),
            Some("TestBot/1.0".to_string()),
        );

    storage.store_session("pg_sess1", &session).await.unwrap();

    let got = storage.get_session("pg_sess1").await.unwrap().unwrap();
    assert_eq!(got.user_id, "pg_user_s");

    storage.delete_session("pg_sess1").await.unwrap();
    assert!(storage.get_session("pg_sess1").await.unwrap().is_none());
}

#[tokio::test]
async fn pg_kv_crud() {
    let storage = setup().await;

    storage
        .store_kv("pg_test_k", b"pg_test_v", Some(Duration::from_secs(3600)))
        .await
        .unwrap();
    let got = storage.get_kv("pg_test_k").await.unwrap().unwrap();
    assert_eq!(got, b"pg_test_v");

    storage.delete_kv("pg_test_k").await.unwrap();
    assert!(storage.get_kv("pg_test_k").await.unwrap().is_none());
}

#[tokio::test]
async fn pg_kv_list_keys_prefix() {
    let storage = setup().await;
    storage
        .store_kv("pgpfx:a", b"1", Some(Duration::from_secs(3600)))
        .await
        .unwrap();
    storage
        .store_kv("pgpfx:b", b"2", Some(Duration::from_secs(3600)))
        .await
        .unwrap();
    storage
        .store_kv("other:c", b"3", Some(Duration::from_secs(3600)))
        .await
        .unwrap();

    let keys = storage.list_kv_keys("pgpfx:").await.unwrap();
    assert_eq!(keys.len(), 2);

    // Cleanup
    storage.delete_kv("pgpfx:a").await.unwrap();
    storage.delete_kv("pgpfx:b").await.unwrap();
    storage.delete_kv("other:c").await.unwrap();
}

#[tokio::test]
async fn pg_count_active_sessions() {
    let storage = setup().await;
    let s1 = SessionData::new("pg_cnt1", "u1", Duration::from_secs(3600));
    let s2 = SessionData::new("pg_cnt2", "u2", Duration::from_secs(3600));
    storage.store_session("pg_cnt1", &s1).await.unwrap();
    storage.store_session("pg_cnt2", &s2).await.unwrap();

    let count = storage.count_active_sessions().await.unwrap();
    assert!(count >= 2);

    storage.delete_session("pg_cnt1").await.unwrap();
    storage.delete_session("pg_cnt2").await.unwrap();
}

#[tokio::test]
async fn pg_cleanup_expired() {
    let storage = setup().await;

    let mut expired_token =
        AuthToken::new("pg_exp_user", "pg_exp_at", Duration::from_secs(1), "test");
    expired_token.expires_at = chrono::Utc::now() - chrono::Duration::seconds(120);
    storage.store_token(&expired_token).await.unwrap();

    let valid_token = AuthToken::new(
        "pg_exp_user",
        "pg_valid_at",
        Duration::from_secs(3600),
        "test",
    );
    storage.store_token(&valid_token).await.unwrap();

    storage.cleanup_expired().await.unwrap();

    assert!(
        storage
            .get_token(&expired_token.token_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        storage
            .get_token(&valid_token.token_id)
            .await
            .unwrap()
            .is_some()
    );

    storage.delete_token(&valid_token.token_id).await.unwrap();
}

/// Regression test for issue #89: `PostgresStorage::migrate()` used
/// `CREATE TABLE IF NOT EXISTS`, which is not safe under concurrent
/// execution -- two connections can both pass the existence check before
/// either commits, then race on Postgres's own `pg_type` catalog (every
/// table implicitly creates a composite row type there), failing with
/// `duplicate key value violates unique constraint "pg_type_typname_nsp_index"`.
/// This is a real product bug (two app instances migrating at startup at
/// the same time), not just a test artifact -- CI currently works around
/// it with `--test-threads=1` on this file rather than fixing it; the fix has landed.
///
/// Fixed by taking a transaction-scoped advisory lock around the whole migration; this runs in
/// the normal test step (it needs `DATABASE_URL`, which CI's test job provides).
#[tokio::test]
async fn pg_concurrent_migrate_is_safe() {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run PostgreSQL integration tests");

    let mut handles = Vec::new();
    for _ in 0..8 {
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let pool = PgPool::connect(&url)
                .await
                .expect("Failed to connect to PostgreSQL");
            PostgresStorage::new(pool).migrate().await
        }));
    }

    for (i, handle) in handles.into_iter().enumerate() {
        handle
            .await
            .expect("migrate task panicked")
            .unwrap_or_else(|e| panic!("concurrent migrate() call {i} failed: {e}"));
    }
}
