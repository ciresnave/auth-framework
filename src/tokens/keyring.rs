// SPDX-License-Identifier: MIT OR Apache-2.0
//! M3: a [`TokenManager`](super::TokenManager) signing and verifying through a
//! [`KeyStore`](crate::keys::KeyStore).
//!
//! `TokenManager` validates synchronously, a store is asynchronous, so the manager reads a
//! [`KeyRing`]: a snapshot of the store's live HMAC keys. The newest `Active` key signs;
//! `Active` and `Retiring` keys verify (a `Retiring` key is the rotation overlap); `Pending`,
//! `Revoked` and `Destroyed` keys do neither. A snapshot is refreshed after every change
//! ([`KeyRing::refresh`], or on a timer by [`KeyRing::spawn_maintenance`]) and a snapshot older
//! than its staleness bound refuses to verify, so a revocation takes effect within a known time
//! even when nobody refreshes.

use crate::errors::{AuthError, Result};
use crate::keys::{
    KeyKind, KeyState, KeyStore, Kid, SymmetricKey, due_for_rotation, retire_expired, rotate,
    unix_now,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const DEFAULT_MAX_STALENESS: Duration = Duration::from_secs(600);

#[derive(Default)]
struct Snapshot {
    signing: Option<(String, Zeroizing<[u8; 32]>)>,
    verify: HashMap<String, Zeroizing<[u8; 32]>>,
    loaded: Option<Instant>,
}

/// A snapshot of a store's live HMAC keys. Cheap to clone; clones share the snapshot.
#[derive(Clone)]
pub struct KeyRing {
    inner: Arc<RwLock<Snapshot>>,
    max_staleness: Duration,
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("max_staleness", &self.max_staleness)
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl KeyRing {
    /// Load the store's live HMAC keys. Fails if the store cannot be read.
    pub async fn load(store: &dyn KeyStore) -> Result<Self> {
        let ring = Self {
            inner: Arc::new(RwLock::new(Snapshot::default())),
            max_staleness: DEFAULT_MAX_STALENESS,
        };
        ring.refresh(store).await?;
        Ok(ring)
    }

    /// Refuse to verify once the snapshot is older than `max` (default ten minutes).
    pub fn with_max_staleness(mut self, max: Duration) -> Self {
        self.max_staleness = max;
        self
    }

    /// Re-read the store. On an error the previous snapshot stays (and ages towards the
    /// staleness bound).
    pub async fn refresh(&self, store: &dyn KeyStore) -> Result<()> {
        let mut signing: Option<(u64, String, Zeroizing<[u8; 32]>)> = None;
        let mut verify = HashMap::new();
        for info in store.list().await? {
            if info.kind != KeyKind::Hmac || !info.state.can_verify() {
                continue;
            }
            let secret = store.export_symmetric(&info.kid).await?;
            if info.state == KeyState::Active {
                let newer = match &signing {
                    Some((created, kid, _)) => {
                        (info.created_at, info.kid.as_str()) > (*created, kid.as_str())
                    }
                    None => true,
                };
                if newer {
                    signing = Some((
                        info.created_at,
                        info.kid.as_str().to_string(),
                        secret.clone(),
                    ));
                }
            }
            verify.insert(info.kid.as_str().to_string(), secret);
        }
        let next = Snapshot {
            signing: signing.map(|(_, kid, secret)| (kid, secret)),
            verify,
            loaded: Some(Instant::now()),
        };
        *self
            .inner
            .write()
            .map_err(|_| AuthError::internal("key ring lock poisoned"))? = next;
        Ok(())
    }

    /// The key to sign with now: its id and secret.
    pub(super) fn signing_key(&self) -> Result<(String, Zeroizing<[u8; 32]>)> {
        let snap = self
            .inner
            .read()
            .map_err(|_| AuthError::internal("key ring lock poisoned"))?;
        snap.signing
            .clone()
            .ok_or_else(|| AuthError::crypto("the key ring has no active signing key"))
    }

    /// The secret that verifies tokens carrying `kid`; refused for an unknown, revoked,
    /// destroyed or pending key and for a stale snapshot.
    pub(super) fn verification_key(&self, kid: &str) -> Result<Zeroizing<[u8; 32]>> {
        let snap = self
            .inner
            .read()
            .map_err(|_| AuthError::internal("key ring lock poisoned"))?;
        match snap.loaded {
            Some(at) if at.elapsed() <= self.max_staleness => {}
            _ => return Err(AuthError::crypto("the key ring is stale: refresh it")),
        }
        snap.verify
            .get(kid)
            .cloned()
            .ok_or_else(|| AuthError::crypto("no live key for this token's key id"))
    }

    /// Run [`maintain_once`] every `every` and refresh the ring after each pass, until the
    /// returned task is aborted. Errors are logged, never fatal.
    pub fn spawn_maintenance(
        &self,
        store: Arc<dyn KeyStore>,
        every: Duration,
        policy: MaintenancePolicy,
    ) -> tokio::task::JoinHandle<()> {
        let ring = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            loop {
                tick.tick().await;
                if let Err(e) = maintain_once(&*store, &policy, unix_now()).await {
                    tracing::warn!(error = %e, "key maintenance pass failed");
                }
                if let Err(e) = ring.refresh(&*store).await {
                    tracing::warn!(error = %e, "key ring refresh failed");
                }
            }
        })
    }
}

/// When to rotate and when to destroy a retired key.
#[derive(Debug, Clone, Copy)]
pub struct MaintenancePolicy {
    /// Rotate an `Active` HMAC key this old.
    pub max_key_age: Duration,
    /// Keep a `Retiring` key verifying this long before destroying it. It must be at least
    /// as long as the longest token the key signed, or those tokens stop verifying early.
    pub overlap: Duration,
}

/// One maintenance pass at `now` (Unix seconds): destroy retired keys past the overlap, then
/// rotate every `Active` HMAC key past its age. Returns the ids of the new keys.
pub async fn maintain_once(
    store: &dyn KeyStore,
    policy: &MaintenancePolicy,
    now: u64,
) -> Result<Vec<Kid>> {
    retire_expired(store, now, policy.overlap.as_secs()).await?;
    let mut created = Vec::new();
    for due in due_for_rotation(store, now, policy.max_key_age.as_secs()).await? {
        if due.kind != KeyKind::Hmac {
            continue;
        }
        let kid = Kid::new(format!("hmac-{}", uuid::Uuid::new_v4().simple()))?;
        let next = SymmetricKey::generate(KeyKind::Hmac, kid)?;
        created.push(rotate(store, &due.kid, next).await?);
    }
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MemoryKeyStore;
    use crate::tokens::TokenManager;

    fn hmac(id: &str) -> SymmetricKey {
        SymmetricKey::generate(KeyKind::Hmac, Kid::new(id).unwrap()).unwrap()
    }

    async fn store_with(id: &str) -> MemoryKeyStore {
        let s = MemoryKeyStore::new();
        s.insert_symmetric(hmac(id), KeyState::Active)
            .await
            .unwrap();
        s
    }

    async fn manager(s: &MemoryKeyStore) -> (TokenManager, KeyRing) {
        let ring = KeyRing::load(s).await.unwrap();
        let m = TokenManager::new_hmac(b"unrelated-configured-secret-000000", "iss", "aud")
            .with_keyring(ring.clone());
        (m, ring)
    }

    fn token(m: &TokenManager) -> String {
        m.create_jwt_token(
            "user-1",
            vec!["read".into()],
            Some(Duration::from_secs(3600)),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn a_token_carries_the_signing_keys_id_and_verifies() {
        let s = store_with("k1").await;
        let (m, _) = manager(&s).await;
        let t = token(&m);
        let header = jsonwebtoken::decode_header(&t).unwrap();
        assert_eq!(header.kid.as_deref(), Some("k1"));
        assert_eq!(m.validate_jwt_token(&t).unwrap().sub, "user-1");
    }

    #[tokio::test]
    async fn after_a_rotation_old_tokens_verify_and_new_ones_use_the_new_key() {
        let s = store_with("k1").await;
        let (m, ring) = manager(&s).await;
        let old = token(&m);
        rotate(&s, &Kid::new("k1").unwrap(), hmac("k2"))
            .await
            .unwrap();
        ring.refresh(&s).await.unwrap();
        assert!(
            m.validate_jwt_token(&old).is_ok(),
            "retiring key still verifies"
        );
        let new = token(&m);
        assert_eq!(
            jsonwebtoken::decode_header(&new).unwrap().kid.as_deref(),
            Some("k2")
        );
        assert!(m.validate_jwt_token(&new).is_ok());
    }

    #[tokio::test]
    async fn a_revoked_or_destroyed_key_no_longer_verifies_after_a_refresh() {
        let s = store_with("k1").await;
        let (m, ring) = manager(&s).await;
        rotate(&s, &Kid::new("k1").unwrap(), hmac("k2"))
            .await
            .unwrap();
        ring.refresh(&s).await.unwrap();
        let old = {
            // A token the (now retiring) k1 signed before the rotation.
            let before = store_with("k1").await;
            let (mb, _) = manager(&before).await;
            token(&mb)
        };
        // Different secret under the same id: refused whatever the state.
        assert!(m.validate_jwt_token(&old).is_err());
        let signed_by_k2 = token(&m);
        s.set_state(&Kid::new("k2").unwrap(), KeyState::Revoked)
            .await
            .unwrap();
        ring.refresh(&s).await.unwrap();
        assert!(m.validate_jwt_token(&signed_by_k2).is_err(), "revoked");
        assert!(
            m.create_jwt_token("u", vec![], None).is_err(),
            "k1 is retiring, k2 revoked: nothing signs"
        );
    }

    #[tokio::test]
    async fn a_destroyed_retiring_key_stops_verifying() {
        let s = store_with("k1").await;
        let (m, ring) = manager(&s).await;
        let old = token(&m);
        rotate(&s, &Kid::new("k1").unwrap(), hmac("k2"))
            .await
            .unwrap();
        ring.refresh(&s).await.unwrap();
        assert!(m.validate_jwt_token(&old).is_ok());
        s.set_state(&Kid::new("k1").unwrap(), KeyState::Destroyed)
            .await
            .unwrap();
        ring.refresh(&s).await.unwrap();
        assert!(m.validate_jwt_token(&old).is_err());
    }

    #[tokio::test]
    async fn tokens_without_or_with_an_unknown_key_id_are_refused() {
        let s = store_with("k1").await;
        let (m, _) = manager(&s).await;
        // Signed with the manager's configured secret and no kid: the ring does not fall back.
        let plain = TokenManager::new_hmac(b"unrelated-configured-secret-000000", "iss", "aud");
        let t = token(&plain);
        assert!(m.validate_jwt_token(&t).is_err());
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("nope".into());
        let claims = plain.validate_jwt_token(&t).unwrap();
        let forged = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"unrelated-configured-secret-000000"),
        )
        .unwrap();
        assert!(m.validate_jwt_token(&forged).is_err());
    }

    #[tokio::test]
    async fn a_stale_snapshot_refuses_to_verify() {
        let s = store_with("k1").await;
        let ring = KeyRing::load(&s)
            .await
            .unwrap()
            .with_max_staleness(Duration::ZERO);
        let m = TokenManager::new_hmac(b"x-configured-secret-0000000000000", "iss", "aud")
            .with_keyring(ring);
        let t = token(&m);
        std::thread::sleep(Duration::from_millis(5));
        assert!(m.validate_jwt_token(&t).is_err());
    }

    #[tokio::test]
    async fn clones_share_the_snapshot() {
        let s = store_with("k1").await;
        let (m, ring) = manager(&s).await;
        let c = m.clone();
        rotate(&s, &Kid::new("k1").unwrap(), hmac("k2"))
            .await
            .unwrap();
        ring.refresh(&s).await.unwrap();
        assert_eq!(
            jsonwebtoken::decode_header(&token(&c))
                .unwrap()
                .kid
                .as_deref(),
            Some("k2")
        );
    }

    #[tokio::test]
    async fn a_maintenance_pass_rotates_an_old_key_and_destroys_an_expired_one() {
        let s = store_with("k1").await;
        let policy = MaintenancePolicy {
            max_key_age: Duration::from_secs(100),
            overlap: Duration::from_secs(50),
        };
        let now = unix_now();
        assert!(
            maintain_once(&s, &policy, now).await.unwrap().is_empty(),
            "too young"
        );
        let made = maintain_once(&s, &policy, now + 200).await.unwrap();
        assert_eq!(made.len(), 1);
        let k1 = s.info(&Kid::new("k1").unwrap()).await.unwrap();
        assert_eq!(k1.state, KeyState::Retiring);
        maintain_once(&s, &policy, now + 400).await.unwrap();
        let k1 = s.info(&Kid::new("k1").unwrap()).await.unwrap();
        assert_eq!(k1.state, KeyState::Destroyed, "retired past the overlap");
    }

    #[tokio::test]
    async fn with_two_active_keys_the_newest_signs_and_both_verify() {
        let s = MemoryKeyStore::new();
        // Same creation second, so the key id breaks the tie: the greater id counts as newer.
        s.insert_symmetric(hmac("a1"), KeyState::Active)
            .await
            .unwrap();
        s.insert_symmetric(hmac("b1"), KeyState::Active)
            .await
            .unwrap();
        let (m, _) = manager(&s).await;
        let t = token(&m);
        assert_eq!(
            jsonwebtoken::decode_header(&t).unwrap().kid.as_deref(),
            Some("b1")
        );
        assert!(m.validate_jwt_token(&t).is_ok());
    }
}
