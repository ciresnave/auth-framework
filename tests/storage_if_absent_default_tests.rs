//! `AuthStorage::store_kv_if_absent` is a compare-and-set that single-use markers (refresh-token
//! redemption, TOTP steps, WebAuthn sessions, PKCE codes) rely on. A backend that does not
//! implement it must make those paths fail, not silently lose the guarantee: the default used to be
//! a non-atomic `get_kv` followed by `store_kv`.

use async_trait::async_trait;
use auth_framework::errors::Result;
use auth_framework::storage::{AuthStorage, MemoryStorage, SessionData};
use auth_framework::tokens::AuthToken;
use std::time::Duration;

/// Delegates everything to memory storage and implements NOTHING about `store_kv_if_absent`.
struct KeepsTheDefault {
    inner: MemoryStorage,
}

#[async_trait]
impl AuthStorage for KeepsTheDefault {
    async fn store_token(&self, t: &AuthToken) -> Result<()> {
        self.inner.store_token(t).await
    }
    async fn get_token(&self, id: &str) -> Result<Option<AuthToken>> {
        self.inner.get_token(id).await
    }
    async fn get_token_by_access_token(&self, a: &str) -> Result<Option<AuthToken>> {
        self.inner.get_token_by_access_token(a).await
    }
    async fn update_token(&self, t: &AuthToken) -> Result<()> {
        self.inner.update_token(t).await
    }
    async fn delete_token(&self, id: &str) -> Result<()> {
        self.inner.delete_token(id).await
    }
    async fn list_user_tokens(&self, u: &str) -> Result<Vec<AuthToken>> {
        self.inner.list_user_tokens(u).await
    }
    async fn store_session(&self, id: &str, d: &SessionData) -> Result<()> {
        self.inner.store_session(id, d).await
    }
    async fn get_session(&self, id: &str) -> Result<Option<SessionData>> {
        self.inner.get_session(id).await
    }
    async fn delete_session(&self, id: &str) -> Result<()> {
        self.inner.delete_session(id).await
    }
    async fn list_user_sessions(&self, u: &str) -> Result<Vec<SessionData>> {
        self.inner.list_user_sessions(u).await
    }
    async fn count_active_sessions(&self) -> Result<u64> {
        self.inner.count_active_sessions().await
    }
    async fn store_kv(&self, k: &str, v: &[u8], ttl: Option<Duration>) -> Result<()> {
        self.inner.store_kv(k, v, ttl).await
    }
    async fn get_kv(&self, k: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get_kv(k).await
    }
    async fn delete_kv(&self, k: &str) -> Result<()> {
        self.inner.delete_kv(k).await
    }
    async fn cleanup_expired(&self) -> Result<()> {
        self.inner.cleanup_expired().await
    }
}

/// The same backend with the method implemented (delegating to the atomic memory one).
struct Overrides {
    inner: MemoryStorage,
}

#[async_trait]
impl AuthStorage for Overrides {
    async fn store_token(&self, t: &AuthToken) -> Result<()> {
        self.inner.store_token(t).await
    }
    async fn get_token(&self, id: &str) -> Result<Option<AuthToken>> {
        self.inner.get_token(id).await
    }
    async fn get_token_by_access_token(&self, a: &str) -> Result<Option<AuthToken>> {
        self.inner.get_token_by_access_token(a).await
    }
    async fn update_token(&self, t: &AuthToken) -> Result<()> {
        self.inner.update_token(t).await
    }
    async fn delete_token(&self, id: &str) -> Result<()> {
        self.inner.delete_token(id).await
    }
    async fn list_user_tokens(&self, u: &str) -> Result<Vec<AuthToken>> {
        self.inner.list_user_tokens(u).await
    }
    async fn store_session(&self, id: &str, d: &SessionData) -> Result<()> {
        self.inner.store_session(id, d).await
    }
    async fn get_session(&self, id: &str) -> Result<Option<SessionData>> {
        self.inner.get_session(id).await
    }
    async fn delete_session(&self, id: &str) -> Result<()> {
        self.inner.delete_session(id).await
    }
    async fn list_user_sessions(&self, u: &str) -> Result<Vec<SessionData>> {
        self.inner.list_user_sessions(u).await
    }
    async fn count_active_sessions(&self) -> Result<u64> {
        self.inner.count_active_sessions().await
    }
    async fn store_kv(&self, k: &str, v: &[u8], ttl: Option<Duration>) -> Result<()> {
        self.inner.store_kv(k, v, ttl).await
    }
    async fn store_kv_if_absent(&self, k: &str, v: &[u8], ttl: Option<Duration>) -> Result<bool> {
        self.inner.store_kv_if_absent(k, v, ttl).await
    }
    async fn get_kv(&self, k: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get_kv(k).await
    }
    async fn delete_kv(&self, k: &str) -> Result<()> {
        self.inner.delete_kv(k).await
    }
    async fn cleanup_expired(&self) -> Result<()> {
        self.inner.cleanup_expired().await
    }
}

#[tokio::test]
async fn a_backend_that_keeps_the_default_refuses_to_claim() {
    let s = KeepsTheDefault {
        inner: MemoryStorage::new(),
    };
    let err = s
        .store_kv_if_absent("claim:1", b"x", None)
        .await
        .expect_err("the default must not pretend to be atomic");
    assert!(
        err.to_string().contains("store_kv_if_absent"),
        "the error names the method to implement: {err}"
    );
    // nothing was written on the way to failing
    assert!(s.get_kv("claim:1").await.unwrap().is_none());
}

#[tokio::test]
async fn a_backend_that_implements_it_claims_exactly_once() {
    let s = Overrides {
        inner: MemoryStorage::new(),
    };
    assert!(s.store_kv_if_absent("claim:1", b"a", None).await.unwrap());
    assert!(!s.store_kv_if_absent("claim:1", b"b", None).await.unwrap());
    assert_eq!(s.get_kv("claim:1").await.unwrap().unwrap(), b"a");
}

#[tokio::test]
async fn the_shipped_test_backend_claims_atomically() {
    use auth_framework::testing::MockStorage;
    use std::sync::Arc;

    let s = Arc::new(MockStorage::new());
    let mut tasks = Vec::new();
    for i in 0..32u8 {
        let s = s.clone();
        tasks.push(tokio::spawn(async move {
            s.store_kv_if_absent("race", &[i], None).await.unwrap()
        }));
    }
    let mut winners = 0;
    for t in tasks {
        if t.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
}
