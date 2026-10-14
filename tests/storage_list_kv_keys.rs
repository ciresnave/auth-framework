//! #145: every shipped `AuthStorage` must list the KV keys it stores.
//!
//! The trait default used to return `Ok(vec![])` with a warning, so a backend
//! that forgot to override `list_kv_keys` reported an empty key space while
//! `get_kv` still worked. These tests pin the behaviour of the three in-tree
//! backends that did not override it, with `MemoryStorage` as the positive
//! control (it always did), and pin that the default now fails loudly.

use async_trait::async_trait;
use auth_framework::errors::Result;
#[cfg(feature = "performance-optimization")]
use auth_framework::storage::UnifiedStorage;
use auth_framework::storage::dashmap_memory::DashMapMemoryStorage;
use auth_framework::storage::{AuthStorage, MemoryStorage, SessionData};
use auth_framework::testing::utilities::MockStorage;
use auth_framework::tokens::AuthToken;
use std::time::Duration;

async fn assert_lists_prefix<S: AuthStorage>(storage: &S, name: &str) {
    storage.store_kv("p:a", b"1", None).await.unwrap();
    storage.store_kv("p:b", b"2", None).await.unwrap();
    storage.store_kv("q:c", b"3", None).await.unwrap();

    let mut keys = storage.list_kv_keys("p:").await.unwrap();
    keys.sort();
    assert_eq!(keys, vec!["p:a", "p:b"], "{name}: prefix listing");

    let mut all = storage.list_kv_keys("").await.unwrap();
    all.sort();
    assert!(
        all.contains(&"q:c".to_string()) && all.contains(&"p:a".to_string()),
        "{name}: empty prefix lists every KV key, got {all:?}"
    );

    storage.delete_kv("p:a").await.unwrap();
    let keys = storage.list_kv_keys("p:").await.unwrap();
    assert_eq!(keys, vec!["p:b"], "{name}: a deleted key is not listed");

    assert!(
        storage.list_kv_keys("zzz:").await.unwrap().is_empty(),
        "{name}: no match is an empty list"
    );
}

async fn assert_expired_not_listed<S: AuthStorage>(storage: &S, name: &str) {
    storage
        .store_kv("e:short", b"x", Some(Duration::from_millis(50)))
        .await
        .unwrap();
    storage.store_kv("e:long", b"y", None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let keys = storage.list_kv_keys("e:").await.unwrap();
    assert_eq!(
        keys,
        vec!["e:long"],
        "{name}: an expired key must not be listed (get_kv no longer returns it)"
    );
}

#[tokio::test]
async fn control_memory_storage_lists_prefix() {
    let storage = MemoryStorage::new();
    assert_lists_prefix(&storage, "MemoryStorage").await;
}

#[tokio::test]
async fn dashmap_memory_storage_lists_prefix() {
    let storage = DashMapMemoryStorage::new();
    assert_lists_prefix(&storage, "DashMapMemoryStorage").await;
}

#[cfg(feature = "performance-optimization")]
#[tokio::test]
async fn unified_storage_lists_prefix() {
    let storage = UnifiedStorage::new();
    assert_lists_prefix(&storage, "UnifiedStorage").await;
}

#[tokio::test]
async fn dashmap_memory_storage_does_not_list_expired() {
    let storage = DashMapMemoryStorage::new();
    assert_expired_not_listed(&storage, "DashMapMemoryStorage").await;
}

#[cfg(feature = "performance-optimization")]
#[tokio::test]
async fn unified_storage_does_not_list_expired() {
    let storage = UnifiedStorage::new();
    assert_expired_not_listed(&storage, "UnifiedStorage").await;
}

#[cfg(feature = "performance-optimization")]
#[tokio::test]
async fn unified_storage_kv_listing_excludes_tokens_and_sessions() {
    // UnifiedStorage keeps tokens, sessions and KV in one map keyed by an
    // enum; a KV listing must only ever return KV keys.
    let storage = UnifiedStorage::new();
    let token = AuthToken::new("u1", "access-1", Duration::from_secs(3600), "test");
    storage.store_token(&token).await.unwrap();
    let session = SessionData::new("s1", "u1", Duration::from_secs(3600));
    storage.store_session("s1", &session).await.unwrap();
    storage.store_kv("k:1", b"v", None).await.unwrap();

    let keys = storage.list_kv_keys("").await.unwrap();
    assert_eq!(keys, vec!["k:1"], "only KV keys, got {keys:?}");
}

/// A backend that implements the required methods but not `list_kv_keys`.
struct KeepsTheDefault;

#[async_trait]
impl AuthStorage for KeepsTheDefault {
    async fn store_token(&self, _: &AuthToken) -> Result<()> {
        Ok(())
    }
    async fn get_token(&self, _: &str) -> Result<Option<AuthToken>> {
        Ok(None)
    }
    async fn get_token_by_access_token(&self, _: &str) -> Result<Option<AuthToken>> {
        Ok(None)
    }
    async fn update_token(&self, _: &AuthToken) -> Result<()> {
        Ok(())
    }
    async fn delete_token(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn list_user_tokens(&self, _: &str) -> Result<Vec<AuthToken>> {
        Ok(vec![])
    }
    async fn store_session(&self, _: &str, _: &SessionData) -> Result<()> {
        Ok(())
    }
    async fn get_session(&self, _: &str) -> Result<Option<SessionData>> {
        Ok(None)
    }
    async fn delete_session(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn list_user_sessions(&self, _: &str) -> Result<Vec<SessionData>> {
        Ok(vec![])
    }
    async fn count_active_sessions(&self) -> Result<u64> {
        Ok(0)
    }
    async fn store_kv(&self, _: &str, _: &[u8], _: Option<Duration>) -> Result<()> {
        Ok(())
    }
    async fn get_kv(&self, _: &str) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    async fn delete_kv(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn cleanup_expired(&self) -> Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn default_list_kv_keys_fails_instead_of_returning_empty() {
    let result = KeepsTheDefault.list_kv_keys("p:").await;
    let err = result.expect_err(
        "a backend that does not implement list_kv_keys must fail, not report an empty key space",
    );
    assert!(
        err.to_string().contains("list_kv_keys"),
        "the error names the missing method, got: {err}"
    );
}

#[tokio::test]
async fn mock_storage_lists_prefix() {
    let storage = MockStorage::new();
    assert_lists_prefix(&storage, "MockStorage").await;
}

/// `storage::redis::RedisStorage`: needs a server, so `#[ignore]`d like the other Redis tests:
/// `REDIS_URL=redis://127.0.0.1:6379 cargo test --test storage_list_kv_keys --features redis-storage -- --ignored`.
#[cfg(feature = "redis-storage")]
mod redis_backend {
    use super::*;
    use auth_framework::storage::redis::RedisStorage;

    #[tokio::test]
    #[ignore]
    async fn module_redis_storage_lists_prefix_and_not_expired() {
        let url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
        let prefix = format!("kvlist_{}:", std::process::id());
        let storage = RedisStorage::with_config(&url, prefix, Duration::from_secs(600))
            .await
            .unwrap();
        assert_lists_prefix(&storage, "storage::redis::RedisStorage").await;
        storage
            .store_kv("e:short", b"x", Some(Duration::from_millis(50)))
            .await
            .unwrap();
        storage.store_kv("g*b:[1]", b"z", None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(
            storage.list_kv_keys("e:").await.unwrap(),
            Vec::<String>::new(),
            "an expired key is not listed"
        );
        assert_eq!(
            storage.list_kv_keys("g*b:").await.unwrap(),
            vec!["g*b:[1]"],
            "glob metacharacters in the prefix are matched literally"
        );
        assert!(storage.list_kv_keys("g?b:").await.unwrap().is_empty());
    }
}
