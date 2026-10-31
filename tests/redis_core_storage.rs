//! #148: the exported `storage::RedisStorage` lists keys by cursor `SCAN`, writes a
//! token in one step, and expires the per-user token set with its longest-lived member.
//!
//! Needs a Redis server (`REDIS_URL`; CI's test job provides one).

#![cfg(feature = "redis-storage")]

use auth_framework::storage::{AuthStorage, RedisStorage, SessionData};
use auth_framework::tokens::AuthToken;
use std::time::Duration;

fn url() -> String {
    std::env::var("REDIS_URL").expect("REDIS_URL must be set")
}

fn fresh() -> (RedisStorage, String) {
    let prefix = format!("rcs_{}:", uuid::Uuid::new_v4().simple());
    (RedisStorage::new(&url(), prefix.clone()).unwrap(), prefix)
}

async fn raw() -> redis::aio::MultiplexedConnection {
    redis::Client::open(url())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap()
}

async fn ttl(conn: &mut redis::aio::MultiplexedConnection, key: &str) -> i64 {
    redis::cmd("TTL").arg(key).query_async(conn).await.unwrap()
}

fn token(id: &str, user: &str, access: &str, secs: u64) -> AuthToken {
    let mut t = AuthToken::new(user, access, Duration::from_secs(secs), "test");
    t.token_id = id.to_string();
    t
}

#[tokio::test]
async fn kv_listing_spans_every_scan_batch_once() {
    let (storage, _) = fresh();
    // Well past one SCAN batch (COUNT is 500), so a single-call listing would miss keys.
    for i in 0..1500 {
        storage
            .store_kv(&format!("k:{i}"), b"v", None)
            .await
            .unwrap();
    }
    storage.store_kv("other:1", b"v", None).await.unwrap();

    let mut keys = storage.list_kv_keys("k:").await.unwrap();
    assert_eq!(keys.len(), 1500, "every key, none twice");
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), 1500, "no duplicates");
    assert_eq!(
        storage.list_kv_keys("other:").await.unwrap(),
        vec!["other:1"]
    );
    assert!(storage.list_kv_keys("zzz:").await.unwrap().is_empty());
}

#[tokio::test]
async fn session_count_and_listing_use_the_scan() {
    let (storage, _) = fresh();
    for i in 0..700 {
        let s = SessionData::new(format!("s{i}"), "u1", Duration::from_secs(600));
        storage.store_session(&format!("s{i}"), &s).await.unwrap();
    }
    assert_eq!(storage.count_active_sessions().await.unwrap(), 700);
    assert_eq!(storage.list_user_sessions("u1").await.unwrap().len(), 700);
}

#[tokio::test]
async fn user_token_set_lives_as_long_as_its_longest_token() {
    let (storage, prefix) = fresh();
    let mut conn = raw().await;
    let set = format!("{prefix}user_tokens:u1");

    // A short token gives the set an expiry (it used to have none).
    storage
        .store_token(&token("t1", "u1", "a1", 100))
        .await
        .unwrap();
    let t = ttl(&mut conn, &set).await;
    assert!(
        (90..=100).contains(&t),
        "set expires with its token, got {t}"
    );

    // A longer one raises it.
    storage
        .store_token(&token("t2", "u1", "a2", 1000))
        .await
        .unwrap();
    let t = ttl(&mut conn, &set).await;
    assert!(
        (990..=1000).contains(&t),
        "raised to the longer token, got {t}"
    );

    // A later, shorter one does not cut it short.
    storage
        .store_token(&token("t3", "u1", "a3", 50))
        .await
        .unwrap();
    let t = ttl(&mut conn, &set).await;
    assert!(
        (990..=1000).contains(&t),
        "not shortened by a shorter token, got {t}"
    );

    assert_eq!(storage.list_user_tokens("u1").await.unwrap().len(), 3);
}

#[tokio::test]
async fn store_then_delete_token_is_whole() {
    let (storage, _) = fresh();
    let t = token("t1", "u1", "access-1", 600);
    storage.store_token(&t).await.unwrap();
    assert_eq!(
        storage.get_token("t1").await.unwrap().unwrap().token_id,
        "t1"
    );
    assert_eq!(
        storage
            .get_token_by_access_token("access-1")
            .await
            .unwrap()
            .unwrap()
            .token_id,
        "t1"
    );
    assert_eq!(storage.list_user_tokens("u1").await.unwrap().len(), 1);

    storage.delete_token("t1").await.unwrap();
    assert!(storage.get_token("t1").await.unwrap().is_none());
    assert!(
        storage
            .get_token_by_access_token("access-1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(storage.list_user_tokens("u1").await.unwrap().is_empty());
}
