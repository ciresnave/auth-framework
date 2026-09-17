//! Integration tests for the MySQL storage backend.
//!
//! These tests require a running MySQL server. Set the `MYSQL_URL`
//! environment variable to a valid connection string before running:
//!
//! ```sh
//! export MYSQL_URL="mysql://user:password@localhost/auth_test"
//! cargo test --test storage_mysql --features mysql-storage -- --ignored
//! ```

#![cfg(feature = "mysql-storage")]

use auth_framework::storage::mysql::MySqlStorage;
use auth_framework::storage::{AuthStorage, SessionData};
use auth_framework::tokens::AuthToken;
use sqlx::MySqlPool;
use std::time::Duration;

async fn setup() -> MySqlStorage {
    let url =
        std::env::var("MYSQL_URL").expect("MYSQL_URL must be set to run MySQL integration tests");
    let pool = MySqlPool::connect(&url)
        .await
        .expect("Failed to connect to MySQL");
    let storage = MySqlStorage::new(pool);
    storage.migrate().await.expect("Migration failed");
    storage
}

#[tokio::test]
#[ignore]
async fn mysql_token_crud() {
    let storage = setup().await;
    let token = AuthToken::new("my_user1", "my_access1", Duration::from_secs(3600), "test");
    let tid = token.token_id.clone();
    let at = token.access_token.clone();

    storage.store_token(&token).await.unwrap();

    let got = storage.get_token(&tid).await.unwrap().unwrap();
    assert_eq!(got.user_id, "my_user1");

    let got = storage
        .get_token_by_access_token(&at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.token_id, tid);

    let tokens = storage.list_user_tokens("my_user1").await.unwrap();
    assert!(!tokens.is_empty());

    storage.delete_token(&tid).await.unwrap();
    assert!(storage.get_token(&tid).await.unwrap().is_none());
}

#[tokio::test]
#[ignore]
async fn mysql_session_crud() {
    let storage = setup().await;
    let session = SessionData::new("my_sess1", "my_user_s", Duration::from_secs(3600))
        .with_metadata(
            Some("10.0.0.2".to_string()),
            Some("TestBot/2.0".to_string()),
        );

    storage.store_session("my_sess1", &session).await.unwrap();

    let got = storage.get_session("my_sess1").await.unwrap().unwrap();
    assert_eq!(got.user_id, "my_user_s");

    storage.delete_session("my_sess1").await.unwrap();
    assert!(storage.get_session("my_sess1").await.unwrap().is_none());
}

#[tokio::test]
#[ignore]
async fn mysql_kv_crud() {
    let storage = setup().await;
    storage
        .store_kv("my_k1", b"my_v1", Some(Duration::from_secs(3600)))
        .await
        .unwrap();

    let got = storage.get_kv("my_k1").await.unwrap().unwrap();
    assert_eq!(got, b"my_v1");

    storage.delete_kv("my_k1").await.unwrap();
    assert!(storage.get_kv("my_k1").await.unwrap().is_none());
}

#[tokio::test]
#[ignore]
async fn mysql_kv_list_prefix() {
    let storage = setup().await;
    storage.store_kv("mypfx:a", b"1", None).await.unwrap();
    storage.store_kv("mypfx:b", b"2", None).await.unwrap();
    storage.store_kv("other:c", b"3", None).await.unwrap();

    let keys = storage.list_kv_keys("mypfx:").await.unwrap();
    assert_eq!(keys.len(), 2);

    storage.delete_kv("mypfx:a").await.unwrap();
    storage.delete_kv("mypfx:b").await.unwrap();
    storage.delete_kv("other:c").await.unwrap();
}

#[tokio::test]
#[ignore]
async fn mysql_cleanup_expired() {
    let storage = setup().await;

    let mut expired = AuthToken::new("my_exp_user", "my_exp_at", Duration::from_secs(1), "test");
    expired.expires_at = chrono::Utc::now() - chrono::Duration::seconds(120);
    storage.store_token(&expired).await.unwrap();

    let valid = AuthToken::new(
        "my_exp_user",
        "my_valid_at",
        Duration::from_secs(3600),
        "test",
    );
    storage.store_token(&valid).await.unwrap();

    storage.cleanup_expired().await.unwrap();

    assert!(
        storage
            .get_token(&expired.token_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(storage.get_token(&valid.token_id).await.unwrap().is_some());

    storage.delete_token(&valid.token_id).await.unwrap();
}
