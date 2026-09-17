//! Integration tests for the Redis storage backend.
//!
//! These tests require a running Redis server. Set the `REDIS_URL`
//! environment variable before running:
//!
//! ```sh
//! export REDIS_URL="redis://127.0.0.1:6379"
//! cargo test --test storage_redis --features redis-storage -- --ignored
//! ```

#![cfg(feature = "redis-storage")]

use auth_framework::storage::core::AuthStorage;
use auth_framework::storage::core::SessionData;
use auth_framework::storage::redis::RedisStorage;
use auth_framework::tokens::AuthToken;
use std::time::Duration;

async fn setup() -> RedisStorage {
    let url =
        std::env::var("REDIS_URL").expect("REDIS_URL must be set to run Redis integration tests");
    let storage = RedisStorage::new(&url)
        .await
        .expect("Failed to connect to Redis");
    storage
        .health_check()
        .await
        .expect("Redis health check failed");
    storage
}

#[tokio::test]
#[ignore]
async fn redis_token_crud() {
    let storage = setup().await;
    let token = AuthToken::new("rd_user1", "rd_access1", Duration::from_secs(3600), "test");
    let tid = token.token_id.clone();
    let at = token.access_token.clone();

    storage.store_token(&token).await.unwrap();

    let got = storage.get_token(&tid).await.unwrap().unwrap();
    assert_eq!(got.user_id, "rd_user1");

    let got = storage
        .get_token_by_access_token(&at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.token_id, tid);

    let tokens = storage.list_user_tokens("rd_user1").await.unwrap();
    assert!(!tokens.is_empty());

    storage.delete_token(&tid).await.unwrap();
    assert!(storage.get_token(&tid).await.unwrap().is_none());
}

#[tokio::test]
#[ignore]
async fn redis_session_crud() {
    let storage = setup().await;
    let session = SessionData::new("rd_sess1", "rd_user_s", Duration::from_secs(3600))
        .with_metadata(
            Some("10.0.0.3".to_string()),
            Some("RedisBot/1.0".to_string()),
        );

    storage.store_session("rd_sess1", &session).await.unwrap();

    let got = storage.get_session("rd_sess1").await.unwrap().unwrap();
    assert_eq!(got.user_id, "rd_user_s");

    storage.delete_session("rd_sess1").await.unwrap();
    assert!(storage.get_session("rd_sess1").await.unwrap().is_none());
}

#[tokio::test]
#[ignore]
async fn redis_kv_crud() {
    let storage = setup().await;

    storage
        .store_kv("rd_k1", b"rd_v1", Some(Duration::from_secs(3600)))
        .await
        .unwrap();
    let got = storage.get_kv("rd_k1").await.unwrap().unwrap();
    assert_eq!(got, b"rd_v1");

    storage.delete_kv("rd_k1").await.unwrap();
    assert!(storage.get_kv("rd_k1").await.unwrap().is_none());
}

#[tokio::test]
#[ignore]
async fn redis_kv_no_ttl() {
    let storage = setup().await;
    storage
        .store_kv("rd_persist", b"forever", None)
        .await
        .unwrap();
    let got = storage.get_kv("rd_persist").await.unwrap().unwrap();
    assert_eq!(got, b"forever");
    storage.delete_kv("rd_persist").await.unwrap();
}

#[tokio::test]
#[ignore]
async fn redis_health_check() {
    let storage = setup().await;
    storage.health_check().await.unwrap();
}
