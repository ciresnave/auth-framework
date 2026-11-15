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

/// What one live key signs and verifies with. HMAC keys sign HS256; a `JwsSigning` key signs
/// ES256 or EdDSA (the `alg` the store reports). A key verifies only its own algorithm, so a
/// token cannot pick a weaker one for a key id.
#[derive(Clone)]
pub(super) enum RingKey {
    Hmac(Zeroizing<[u8; 32]>),
    Asymmetric {
        alg: jsonwebtoken::Algorithm,
        decoding: jsonwebtoken::DecodingKey,
        encoding: Option<Arc<jsonwebtoken::EncodingKey>>,
        /// The public half as published (no private member), for the JWKS.
        jwk: Box<crate::keys::PublicJwk>,
    },
}

impl RingKey {
    pub(super) fn algorithm(&self) -> jsonwebtoken::Algorithm {
        match self {
            Self::Hmac(_) => jsonwebtoken::Algorithm::HS256,
            Self::Asymmetric { alg, .. } => *alg,
        }
    }
    pub(super) fn encoding_key(&self) -> Result<jsonwebtoken::EncodingKey> {
        match self {
            Self::Hmac(secret) => Ok(jsonwebtoken::EncodingKey::from_secret(&secret[..])),
            Self::Asymmetric {
                encoding: Some(key),
                ..
            } => Ok((**key).clone()),
            Self::Asymmetric { .. } => Err(AuthError::crypto("this ring key cannot sign")),
        }
    }
    pub(super) fn decoding_key(&self) -> jsonwebtoken::DecodingKey {
        match self {
            Self::Hmac(secret) => jsonwebtoken::DecodingKey::from_secret(&secret[..]),
            Self::Asymmetric { decoding, .. } => decoding.clone(),
        }
    }
}

/// Build the ring entry for an asymmetric key: verify from the public JWK, sign from the
/// exported PKCS8. `None` for an algorithm the token manager does not use.
async fn asymmetric_entry(
    store: &dyn KeyStore,
    info: &crate::keys::KeyInfo,
    need_private: bool,
) -> Result<Option<RingKey>> {
    let alg = match info.alg.as_str() {
        "ES256" => jsonwebtoken::Algorithm::ES256,
        "EdDSA" => jsonwebtoken::Algorithm::EdDSA,
        _ => return Ok(None),
    };
    let Some(public) = &info.public else {
        return Ok(None);
    };
    let jwk = public.to_value();
    let member = |n: &str| jwk.get(n).and_then(|v| v.as_str()).map(str::to_string);
    let decoding = match alg {
        jsonwebtoken::Algorithm::ES256 => match (member("x"), member("y")) {
            (Some(x), Some(y)) => jsonwebtoken::DecodingKey::from_ec_components(&x, &y),
            _ => return Ok(None),
        },
        _ => match member("x") {
            Some(x) => jsonwebtoken::DecodingKey::from_ed_components(&x),
            None => return Ok(None),
        },
    }
    .map_err(|e| AuthError::crypto(format!("bad public key in the key store: {e}")))?;
    // Only an Active key signs, so only it needs its private half exported.
    let encoding = if need_private {
        let der = store.export_private_pkcs8(&info.kid).await?;
        Some(Arc::new(match alg {
            jsonwebtoken::Algorithm::ES256 => jsonwebtoken::EncodingKey::from_ec_der(&der),
            _ => jsonwebtoken::EncodingKey::from_ed_der(&der),
        }))
    } else {
        None
    };
    Ok(Some(RingKey::Asymmetric {
        alg,
        decoding,
        encoding,
        jwk: Box::new(public.clone()),
    }))
}

const DEFAULT_MAX_STALENESS: Duration = Duration::from_secs(600);

#[derive(Default)]
struct Snapshot {
    signing: Option<(String, RingKey)>,
    verify: HashMap<String, RingKey>,
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

    /// Revoke `kid` in the store and refresh this ring, so the key stops verifying here at
    /// once instead of at the next timer pass (up to the staleness bound). Use this, not the
    /// bare [`crate::keys::revoke`], for a ring that validates tokens. If the store accepted
    /// the revocation but the refresh fails, the error says so: the key is revoked in the
    /// store and this ring still trusts it until a refresh succeeds.
    pub async fn revoke(&self, store: &dyn KeyStore, kid: &Kid) -> Result<()> {
        crate::keys::revoke(store, kid).await?;
        self.refresh(store).await.map_err(|e| {
            AuthError::internal(format!(
                "{kid} is revoked in the store but the key ring could not refresh and still trusts it: {e}"
            ))
        })
    }

    /// Revoke the compromised `current` key, install `next` as its replacement (see
    /// [`crate::keys::compromise`]) and refresh this ring, so the old key stops verifying
    /// here and the new one signs at once. The ring is refreshed even when installing `next`
    /// failed, because the old key is revoked in the store either way.
    pub async fn compromise(
        &self,
        store: &dyn KeyStore,
        current: &Kid,
        next: impl Into<crate::keys::NewKey>,
    ) -> Result<Kid> {
        let outcome = crate::keys::compromise(store, current, next).await;
        let refreshed = self.refresh(store).await;
        match (outcome, refreshed) {
            (Ok(kid), Ok(())) => Ok(kid),
            (Err(e), _) => Err(e),
            (Ok(_), Err(e)) => Err(AuthError::internal(format!(
                "{current} is revoked and replaced in the store but the key ring could not refresh and still trusts it: {e}"
            ))),
        }
    }

    /// Re-read the store. On an error the previous snapshot stays (and ages towards the
    /// staleness bound).
    pub async fn refresh(&self, store: &dyn KeyStore) -> Result<()> {
        let mut signing: Option<(u64, String, RingKey)> = None;
        let mut verify = HashMap::new();
        for info in store.list().await? {
            if !info.state.can_verify() {
                continue;
            }
            let secret = match info.kind {
                KeyKind::Hmac => RingKey::Hmac(store.export_symmetric(&info.kid).await?),
                KeyKind::JwsSigning => {
                    match asymmetric_entry(store, &info, info.state == KeyState::Active).await? {
                        Some(entry) => entry,
                        None => continue,
                    }
                }
                _ => continue,
            };
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
    pub(super) fn signing_key(&self) -> Result<(String, RingKey)> {
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
    pub(super) fn verification_key(&self, kid: &str) -> Result<RingKey> {
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

    /// The JWKS of the live asymmetric keys in this snapshot: `Active` and `Retiring`
    /// ES256/EdDSA keys, sorted by key id, never an HMAC key and never a private member.
    /// A revoked or destroyed key is gone after the next refresh, and a snapshot older than
    /// its staleness bound refuses to publish (it could still advertise a revoked key).
    pub fn public_jwks(&self) -> Result<crate::keys::JwkSet> {
        let snap = self
            .inner
            .read()
            .map_err(|_| AuthError::internal("key ring lock poisoned"))?;
        match snap.loaded {
            Some(at) if at.elapsed() <= self.max_staleness => {}
            _ => return Err(AuthError::crypto("the key ring is stale: refresh it")),
        }
        let mut keys: Vec<crate::keys::PublicJwk> = snap
            .verify
            .values()
            .filter_map(|k| match k {
                RingKey::Asymmetric { jwk, .. } => Some((**jwk).clone()),
                RingKey::Hmac(_) => None,
            })
            .collect();
        keys.sort_by(|a, b| {
            a.kid
                .as_ref()
                .map(|k| k.as_str())
                .cmp(&b.kid.as_ref().map(|k| k.as_str()))
        });
        Ok(crate::keys::JwkSet { keys })
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
            jsonwebtoken::decode_header(token(&c))
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

    fn asym(id: &str, alg: crate::keys::SigningAlg) -> crate::keys::LocalKey {
        crate::keys::LocalKey::generate(KeyKind::JwsSigning, alg, Some(Kid::new(id).unwrap()))
            .unwrap()
    }

    async fn asym_manager(s: &MemoryKeyStore) -> (TokenManager, KeyRing) {
        manager(s).await
    }

    #[tokio::test]
    async fn es256_and_eddsa_keys_sign_and_verify_through_the_ring() {
        for (alg, name) in [
            (crate::keys::SigningAlg::Es256, "ES256"),
            (crate::keys::SigningAlg::EdDsa, "EdDSA"),
        ] {
            let s = MemoryKeyStore::new();
            s.insert(asym("a1", alg), KeyState::Active).await.unwrap();
            let (m, _) = asym_manager(&s).await;
            let t = token(&m);
            let h = jsonwebtoken::decode_header(&t).unwrap();
            assert_eq!(format!("{:?}", h.alg).to_uppercase(), name.to_uppercase());
            assert_eq!(h.kid.as_deref(), Some("a1"));
            assert_eq!(m.validate_jwt_token(&t).unwrap().sub, "user-1");
        }
    }

    #[tokio::test]
    async fn an_asymmetric_rotation_keeps_the_old_token_valid_and_revocation_ends_it() {
        let s = MemoryKeyStore::new();
        s.insert(asym("a1", crate::keys::SigningAlg::Es256), KeyState::Active)
            .await
            .unwrap();
        let (m, ring) = asym_manager(&s).await;
        let old = token(&m);
        let next = asym("a2", crate::keys::SigningAlg::EdDsa);
        rotate(&s, &Kid::new("a1").unwrap(), next).await.unwrap();
        ring.refresh(&s).await.unwrap();
        assert!(m.validate_jwt_token(&old).is_ok(), "retiring key verifies");
        let new = token(&m);
        assert_eq!(
            jsonwebtoken::decode_header(&new).unwrap().kid.as_deref(),
            Some("a2")
        );
        s.set_state(&Kid::new("a1").unwrap(), KeyState::Revoked)
            .await
            .unwrap();
        ring.refresh(&s).await.unwrap();
        assert!(m.validate_jwt_token(&old).is_err());
        assert!(m.validate_jwt_token(&new).is_ok());
    }

    #[tokio::test]
    async fn a_token_cannot_use_another_algorithm_for_an_asymmetric_key_id() {
        let s = MemoryKeyStore::new();
        s.insert(asym("a1", crate::keys::SigningAlg::Es256), KeyState::Active)
            .await
            .unwrap();
        let (m, _) = asym_manager(&s).await;
        let claims = m.validate_jwt_token(&token(&m)).unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("a1".into());
        let forged = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"anything"),
        )
        .unwrap();
        assert!(m.validate_jwt_token(&forged).is_err());
    }

    #[tokio::test]
    async fn revoking_through_the_ring_stops_verification_with_no_separate_refresh() {
        let s = MemoryKeyStore::new();
        s.insert(asym("a1", crate::keys::SigningAlg::Es256), KeyState::Active)
            .await
            .unwrap();
        let (m, ring) = asym_manager(&s).await;
        let t = token(&m);
        assert!(m.validate_jwt_token(&t).is_ok());
        ring.revoke(&s, &Kid::new("a1").unwrap()).await.unwrap();
        assert!(
            m.validate_jwt_token(&t).is_err(),
            "a revoked key verifies nothing the moment ring.revoke returns"
        );
    }

    #[tokio::test]
    async fn the_bare_store_revoke_leaves_a_loaded_ring_trusting_the_key_until_a_refresh() {
        let s = MemoryKeyStore::new();
        s.insert(asym("a1", crate::keys::SigningAlg::Es256), KeyState::Active)
            .await
            .unwrap();
        let (m, ring) = asym_manager(&s).await;
        let t = token(&m);
        crate::keys::revoke(&s, &Kid::new("a1").unwrap())
            .await
            .unwrap();
        assert!(
            m.validate_jwt_token(&t).is_ok(),
            "documented: the snapshot is not refreshed by a store-level revoke"
        );
        ring.refresh(&s).await.unwrap();
        assert!(m.validate_jwt_token(&t).is_err());
    }

    #[tokio::test]
    async fn compromising_through_the_ring_distrusts_the_old_key_and_signs_with_the_new_one() {
        let s = MemoryKeyStore::new();
        s.insert(asym("a1", crate::keys::SigningAlg::Es256), KeyState::Active)
            .await
            .unwrap();
        let (m, ring) = asym_manager(&s).await;
        let old = token(&m);
        let new_kid = ring
            .compromise(
                &s,
                &Kid::new("a1").unwrap(),
                asym("a2", crate::keys::SigningAlg::EdDsa),
            )
            .await
            .unwrap();
        assert_eq!(new_kid.as_str(), "a2");
        assert!(
            m.validate_jwt_token(&old).is_err(),
            "old key distrusted at once"
        );
        let fresh = token(&m);
        assert_eq!(
            jsonwebtoken::decode_header(&fresh).unwrap().kid.as_deref(),
            Some("a2")
        );
        assert!(m.validate_jwt_token(&fresh).is_ok());
    }

    #[tokio::test]
    async fn a_failed_replacement_still_distrusts_the_compromised_key_in_the_ring() {
        let s = MemoryKeyStore::new();
        s.insert(asym("a1", crate::keys::SigningAlg::Es256), KeyState::Active)
            .await
            .unwrap();
        let (m, ring) = asym_manager(&s).await;
        let t = token(&m);
        // The replacement reuses the old key id, so installing it fails after the revoke.
        let dup = asym("a1", crate::keys::SigningAlg::Es256);
        assert!(
            ring.compromise(&s, &Kid::new("a1").unwrap(), dup)
                .await
                .is_err()
        );
        assert!(
            m.validate_jwt_token(&t).is_err(),
            "revoked in the store, so refused in the ring too"
        );
    }

    fn kids(jwks: &serde_json::Value) -> Vec<String> {
        jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn the_jwks_publishes_each_live_asymmetric_key_and_its_tokens_verify_against_it() {
        let s = MemoryKeyStore::new();
        s.insert(
            asym("a-es", crate::keys::SigningAlg::Es256),
            KeyState::Active,
        )
        .await
        .unwrap();
        s.insert(
            asym("b-ed", crate::keys::SigningAlg::EdDsa),
            KeyState::Retiring,
        )
        .await
        .unwrap();
        s.insert_symmetric(hmac("h1"), KeyState::Active)
            .await
            .unwrap();
        let (m, _) = manager(&s).await;
        let jwks = m.export_jwks().unwrap();
        assert_eq!(kids(&jwks), vec!["a-es", "b-ed"], "no HMAC key, sorted");
        for k in jwks["keys"].as_array().unwrap() {
            assert!(k.get("d").is_none(), "never a private member: {k}");
            assert_eq!(k["use"], "sig");
        }
        // Independent of the ring: a token signed by the Active ES256 key verifies with
        // only the published JWK's x and y.
        let (m, _) = {
            let s2 = MemoryKeyStore::new();
            s2.insert(
                asym("only", crate::keys::SigningAlg::Es256),
                KeyState::Active,
            )
            .await
            .unwrap();
            manager(&s2).await
        };
        let t = token(&m);
        let jwks = m.export_jwks().unwrap();
        let jwk = &jwks["keys"][0];
        assert_eq!(jwk["kty"], "EC");
        let key = jsonwebtoken::DecodingKey::from_ec_components(
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap(),
        )
        .unwrap();
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        v.set_issuer(&["iss"]);
        v.set_audience(&["aud"]);
        assert!(jsonwebtoken::decode::<serde_json::Value>(&t, &key, &v).is_ok());
    }

    #[tokio::test]
    async fn a_rotation_publishes_both_keys_and_a_revocation_drops_one_after_a_refresh() {
        let s = MemoryKeyStore::new();
        s.insert(asym("a1", crate::keys::SigningAlg::Es256), KeyState::Active)
            .await
            .unwrap();
        let (m, ring) = manager(&s).await;
        rotate(
            &s,
            &Kid::new("a1").unwrap(),
            asym("a2", crate::keys::SigningAlg::EdDsa),
        )
        .await
        .unwrap();
        ring.refresh(&s).await.unwrap();
        assert_eq!(kids(&m.export_jwks().unwrap()), vec!["a1", "a2"]);
        s.set_state(&Kid::new("a1").unwrap(), KeyState::Revoked)
            .await
            .unwrap();
        assert_eq!(
            kids(&m.export_jwks().unwrap()),
            vec!["a1", "a2"],
            "the snapshot has not been refreshed yet"
        );
        ring.refresh(&s).await.unwrap();
        assert_eq!(kids(&m.export_jwks().unwrap()), vec!["a2"]);
    }

    #[tokio::test]
    async fn a_stale_ring_refuses_to_publish_and_an_hmac_only_manager_publishes_nothing() {
        let s = MemoryKeyStore::new();
        s.insert(asym("a1", crate::keys::SigningAlg::Es256), KeyState::Active)
            .await
            .unwrap();
        let ring = KeyRing::load(&s)
            .await
            .unwrap()
            .with_max_staleness(Duration::ZERO);
        let m = TokenManager::new_hmac(b"x-configured-secret-0000000000000", "iss", "aud")
            .with_keyring(ring);
        std::thread::sleep(Duration::from_millis(5));
        assert!(m.export_jwks().is_err());
        let plain = TokenManager::new_hmac(b"x-configured-secret-0000000000000", "iss", "aud");
        assert!(kids(&plain.export_jwks().unwrap()).is_empty());
    }
}
