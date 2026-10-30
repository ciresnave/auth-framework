//! A client record the registry wrote under the old `oauth_client:` key (secret in plain text) is
//! moved to `oauth2_client:` with the secret hashed. When removing the old record fails, nothing
//! may leave the plain secret behind for good: the old record's secret is overwritten at once
//! where possible, and a later read removes the record.

use async_trait::async_trait;
use auth_framework::errors::{AuthError, Result};
use auth_framework::server::core::client_registry::{ClientConfig, ClientRegistry, ClientType};
use auth_framework::storage::{AuthStorage, MemoryStorage, SessionData};
use auth_framework::tokens::AuthToken;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const SECRET: &str = "plain-legacy-secret-value";

/// Delegates to memory storage; deleting, or storing to, the old record's key can be made to fail.
struct Faulty {
    inner: MemoryStorage,
    fail_legacy_delete: AtomicBool,
    fail_legacy_store: AtomicBool,
}

impl Faulty {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: MemoryStorage::new(),
            fail_legacy_delete: AtomicBool::new(false),
            fail_legacy_store: AtomicBool::new(false),
        })
    }
}

#[async_trait]
impl AuthStorage for Faulty {
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
        if k.starts_with("oauth_client:") && self.fail_legacy_store.load(Ordering::SeqCst) {
            return Err(AuthError::internal("store refused".to_string()));
        }
        self.inner.store_kv(k, v, ttl).await
    }
    async fn get_kv(&self, k: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get_kv(k).await
    }
    async fn get_kv_ttl(&self, k: &str) -> Result<Option<Duration>> {
        self.inner.get_kv_ttl(k).await
    }
    fn tracks_kv_ttl(&self) -> bool {
        self.inner.tracks_kv_ttl()
    }
    async fn list_kv_keys(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list_kv_keys(prefix).await
    }
    async fn delete_kv(&self, k: &str) -> Result<()> {
        if k.starts_with("oauth_client:") && self.fail_legacy_delete.load(Ordering::SeqCst) {
            return Err(AuthError::internal("delete refused".to_string()));
        }
        self.inner.delete_kv(k).await
    }
    async fn cleanup_expired(&self) -> Result<()> {
        self.inner.cleanup_expired().await
    }
}

async fn raw(storage: &Arc<Faulty>, key: &str) -> Option<String> {
    storage
        .inner
        .get_kv(key)
        .await
        .unwrap()
        .map(|data| String::from_utf8(data).unwrap())
}

async fn with_legacy_record(storage: &Arc<Faulty>, id: &str) -> ClientRegistry {
    let old = ClientConfig {
        client_id: id.to_string(),
        client_type: ClientType::Confidential,
        client_secret: Some(SECRET.to_string()),
        redirect_uris: vec!["https://example.com/callback".to_string()].into(),
        ..Default::default()
    };
    storage
        .inner
        .store_kv(
            &format!("oauth_client:{id}"),
            serde_json::to_string(&old).unwrap().as_bytes(),
            None,
        )
        .await
        .unwrap();
    // Control: the old record holds the plain secret before anything reads it.
    assert!(
        raw(storage, &format!("oauth_client:{id}"))
            .await
            .unwrap()
            .contains(SECRET)
    );
    let dynamic: Arc<dyn AuthStorage> = storage.clone();
    ClientRegistry::new(dynamic).await.unwrap()
}

#[tokio::test]
async fn a_failed_delete_does_not_leave_the_plain_secret_behind() {
    let storage = Faulty::new();
    let registry = with_legacy_record(&storage, "stuck").await;
    storage.fail_legacy_delete.store(true, Ordering::SeqCst);

    // The client is still served, and its secret still authenticates.
    let client = registry.get_client("stuck").await.unwrap().unwrap();
    assert_eq!(client.client_id, "stuck");
    assert!(registry.authenticate_client("stuck", SECRET).await.unwrap());

    // The old record could not be deleted, but it no longer holds the secret.
    let old = raw(&storage, "oauth_client:stuck").await;
    assert!(
        old.as_deref().is_none_or(|text| !text.contains(SECRET)),
        "the plain secret is still stored under oauth_client:stuck: {old:?}"
    );
    // The new record holds a hash only.
    let new = raw(&storage, "oauth2_client:stuck").await.unwrap();
    assert!(new.contains("client_secret_hash") && !new.contains(SECRET));
}

#[tokio::test]
async fn a_later_read_removes_a_record_whose_delete_failed() {
    let storage = Faulty::new();
    let registry = with_legacy_record(&storage, "retry").await;
    storage.fail_legacy_delete.store(true, Ordering::SeqCst);
    assert!(registry.get_client("retry").await.unwrap().is_some());
    assert!(
        raw(&storage, "oauth_client:retry").await.is_some(),
        "control: the delete really failed"
    );

    // The storage recovers; the next read finds the migration unfinished and completes it.
    storage.fail_legacy_delete.store(false, Ordering::SeqCst);
    assert!(registry.get_client("retry").await.unwrap().is_some());
    assert!(raw(&storage, "oauth_client:retry").await.is_none());
    let new = raw(&storage, "oauth2_client:retry").await.unwrap();
    assert!(
        !new.contains("legacy_record_pending_removal"),
        "the marker is cleared once the old record is gone: {new}"
    );
}

/// Nothing can be written to or deleted from the old key: the secret stays there for now (it
/// cannot be scrubbed), the client is still served, and a later read cleans up.
#[tokio::test]
async fn when_even_the_scrub_fails_the_next_read_still_removes_the_record() {
    let storage = Faulty::new();
    let registry = with_legacy_record(&storage, "worst").await;
    storage.fail_legacy_delete.store(true, Ordering::SeqCst);
    storage.fail_legacy_store.store(true, Ordering::SeqCst);
    assert!(registry.authenticate_client("worst", SECRET).await.unwrap());
    assert!(raw(&storage, "oauth_client:worst").await.is_some());

    storage.fail_legacy_delete.store(false, Ordering::SeqCst);
    storage.fail_legacy_store.store(false, Ordering::SeqCst);
    assert!(registry.authenticate_client("worst", SECRET).await.unwrap());
    assert!(raw(&storage, "oauth_client:worst").await.is_none());
}
