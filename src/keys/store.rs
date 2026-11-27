// SPDX-License-Identifier: MIT OR Apache-2.0
//! KM3: key storage by capability.
//!
//! A [`KeyStore`] says what it can do ([`StoreCapabilities`]) and signs through
//! itself, so a store that cannot give a private key out (an OS keystore, a TPM, a
//! KMS, added later) fits the same trait as one that can. Two stores ship here:
//! [`MemoryKeyStore`] and [`FileKeyStore`] (one AES-256-GCM encrypted file per key,
//! sealed with the existing [`StorageEncryption`] / `KeyProvider` seam).

use super::{JwkSet, KeyKind, KeyState, Kid, LocalKey, PublicJwk, Signer, SymmetricKey};
use crate::errors::{AuthError, Result};
use crate::storage::StorageEncryption;
use async_trait::async_trait;
use base64::Engine;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

/// What a store can do. Callers check this instead of assuming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreCapabilities {
    /// Private keys can be read back out ([`KeyStore::export_private_pkcs8`]).
    pub exportable: bool,
    /// Signing happens inside the store (the key never reaches the caller).
    pub signs_in_place: bool,
    /// Keys survive a restart.
    pub persistent: bool,
}

/// What a store reports about a key; never any private material.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyInfo {
    /// Key id.
    pub kid: Kid,
    /// Purpose.
    pub kind: KeyKind,
    /// Lifecycle state.
    pub state: KeyState,
    /// JWS algorithm name.
    pub alg: String,
    /// Public half; `None` for a symmetric (HMAC or AEAD) key, which has none.
    pub public: Option<PublicJwk>,
    /// Unix seconds when the store first saw the key.
    pub created_at: u64,
    /// Unix seconds when it became `Retiring`, if it has.
    pub retiring_at: Option<u64>,
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A place keys live. Private keys never appear in this interface except through
/// [`KeyStore::export_private_pkcs8`], which a non-exportable store refuses.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// What this store can do.
    fn capabilities(&self) -> StoreCapabilities;
    /// Hold this guard across a read-check-write sequence (such as [`rotate`](super::rotate))
    /// so two of them on one store cannot interleave. It serialises callers in this
    /// process; it is not a cross-process lock.
    async fn lock_rotation(&self) -> tokio::sync::MutexGuard<'_, ()>;
    /// Add a key in `state`. Fails if the key id is already taken or `state` is
    /// `Destroyed` (a key is destroyed through [`KeyStore::set_state`], which erases it).
    async fn insert(&self, key: LocalKey, state: KeyState) -> Result<()>;
    /// Add a symmetric (HMAC or AEAD) key in `state`. Same lifecycle as any other key; it is
    /// never published ([`publish_jwks`] lists public halves only). Refuses a key id that
    /// already exists and `Destroyed`.
    async fn insert_symmetric(&self, key: SymmetricKey, state: KeyState) -> Result<()>;
    /// The 32 secret bytes of a symmetric key, for a verifier that must recompute (an HMAC
    /// verifier needs the secret). Refused for a destroyed key and by a non-exportable store.
    async fn export_symmetric(&self, kid: &Kid) -> Result<Zeroizing<[u8; 32]>>;
    /// Describe one key.
    async fn info(&self, kid: &Kid) -> Result<KeyInfo>;
    /// Describe every key, ordered by key id.
    async fn list(&self) -> Result<Vec<KeyInfo>>;
    /// Move a key to `next` (legal transitions only). `Destroyed` erases the private
    /// material and keeps the record.
    async fn set_state(&self, kid: &Kid, next: KeyState) -> Result<()>;
    /// Sign with an `Active` key.
    async fn sign(&self, kid: &Kid, message: &[u8]) -> Result<Vec<u8>>;
    /// The PKCS#8 private key, if this store is exportable and the key not destroyed.
    async fn export_private_pkcs8(&self, kid: &Kid) -> Result<Zeroizing<Vec<u8>>>;
}

/// The JWKS of a store: active and retiring keys, never pending, revoked or destroyed.
pub async fn publish_jwks(store: &dyn KeyStore) -> Result<JwkSet> {
    Ok(JwkSet {
        keys: store
            .list()
            .await?
            .into_iter()
            .filter(|i| i.state.is_published())
            .filter_map(|i| i.public)
            .collect(),
    })
}

/// A key the store has revoked or destroyed: what a relying party needs to stop trusting it.
/// No private material, and no time: the store does not record when a key was revoked.
#[derive(Debug, Clone, PartialEq)]
pub struct RevokedKey {
    /// Key id.
    pub kid: Kid,
    /// Purpose.
    pub kind: KeyKind,
    /// JWS algorithm name.
    pub alg: String,
    /// RFC 7638 thumbprint of the public half; `None` for a symmetric key.
    pub thumbprint: Option<String>,
}

/// The revocation list of a store (KM5): every `Revoked` or `Destroyed` key, ordered by key
/// id. It is the input for whatever publishes revocation (a CRL for a certificate key, a
/// feed or an event for a JWS or client key); the crate does not sign or serve it. A key
/// leaves the JWKS the moment it is revoked, but a verifier that cached the JWKS, or a
/// grant bound to the key's thumbprint, learns of it only from a list like this one.
pub async fn revocation_list(store: &dyn KeyStore) -> Result<Vec<RevokedKey>> {
    store
        .list()
        .await?
        .into_iter()
        .filter(|i| matches!(i.state, KeyState::Revoked | KeyState::Destroyed))
        .map(|i| {
            Ok(RevokedKey {
                thumbprint: i.public.as_ref().map(PublicJwk::thumbprint).transpose()?,
                kid: i.kid,
                kind: i.kind,
                alg: i.alg,
            })
        })
        .collect()
}

/// The X25519 shared secret between the key-agreement key `kid` in `store` and `peer_public`
/// (32 bytes): the call a JWE layer makes to decrypt. Only an `Active` or `Retiring` key agrees
/// (a retiring key must still open what was encrypted to it before the rotation; a pending,
/// revoked or destroyed one may not), only a [`KeyKind::JweEncryption`] key, and only in a store
/// that can export its private keys, because the agreement runs here. A peer key of low order
/// is refused (see [`LocalKey::agree`]).
#[cfg(feature = "key-agreement")]
pub async fn agree(
    store: &dyn KeyStore,
    kid: &Kid,
    peer_public: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let info = store.info(kid).await?;
    if info.kind != KeyKind::JweEncryption {
        return Err(AuthError::validation(format!(
            "key {kid} is a {:?} key: only a JweEncryption key agrees",
            info.kind
        )));
    }
    if !info.state.can_verify() {
        return Err(AuthError::validation(format!(
            "key {kid} is {:?}: only an active or retiring key agrees",
            info.state
        )));
    }
    if !store.capabilities().exportable {
        return Err(AuthError::validation(
            "this key store cannot export its private keys, so it cannot agree here",
        ));
    }
    let der = store.export_private_pkcs8(kid).await?;
    LocalKey::from_pkcs8_der(&der, info.kind, Some(kid.clone()))?.agree(peer_public)
}

struct Entry {
    kind: KeyKind,
    state: KeyState,
    public: Option<PublicJwk>,
    key: Option<LocalKey>,
    secret: Option<SymmetricKey>,
    created_at: u64,
    retiring_at: Option<u64>,
}

impl Entry {
    /// Apply a state change; `now` is the one clock reading for this change, so the
    /// persisted and in-memory timestamps agree. A revoked key keeps no retirement time.
    fn apply(&mut self, next: KeyState, now: u64) -> Result<()> {
        self.state = self.state.transition(next)?;
        match next {
            KeyState::Retiring => self.retiring_at = Some(now),
            KeyState::Revoked => self.retiring_at = None,
            _ => {}
        }
        if next == KeyState::Destroyed {
            self.key = None;
            self.secret = None;
        }
        Ok(())
    }

    fn info(&self, kid: &Kid) -> KeyInfo {
        KeyInfo {
            kid: kid.clone(),
            kind: self.kind,
            state: self.state,
            alg: match (&self.public, self.kind) {
                (Some(p), _) => p.alg.clone().unwrap_or_default(),
                (None, KeyKind::Hmac) => "HS256".to_string(),
                (None, _) => String::new(),
            },
            public: self.public.clone(),
            created_at: self.created_at,
            retiring_at: self.retiring_at,
        }
    }
}

/// A key is created live (or pending): inserting one as `Destroyed` would keep its
/// private half in a record that claims it was erased.
fn refuse_destroyed(state: KeyState) -> Result<()> {
    if state == KeyState::Destroyed {
        return Err(AuthError::validation(
            "a key cannot be inserted as Destroyed: destruction erases its private half",
        ));
    }
    Ok(())
}

fn not_found(kid: &Kid) -> AuthError {
    AuthError::validation(format!("no key with id {kid}"))
}

fn entry_of(key: LocalKey, state: KeyState) -> Entry {
    Entry {
        kind: key.kind(),
        state,
        public: Some(key.public().clone()),
        key: Some(key),
        secret: None,
        created_at: unix_now(),
        retiring_at: None,
    }
}

fn entry_of_symmetric(key: SymmetricKey, state: KeyState) -> Entry {
    Entry {
        kind: key.kind(),
        state,
        public: None,
        key: None,
        secret: Some(key),
        created_at: unix_now(),
        retiring_at: None,
    }
}

fn sign_with(map: &HashMap<Kid, Entry>, kid: &Kid, message: &[u8]) -> Result<Vec<u8>> {
    let e = map.get(kid).ok_or_else(|| not_found(kid))?;
    if !e.state.can_sign() {
        return Err(AuthError::validation(format!(
            "key {kid} is {:?}, not active: it cannot sign",
            e.state
        )));
    }
    if let Some(secret) = &e.secret {
        // HS256 over the message; only HMAC keys sign, an AEAD key does not.
        if e.kind != KeyKind::Hmac {
            return Err(AuthError::validation(format!(
                "key {kid} is {:?}: only an HMAC key signs",
                e.kind
            )));
        }
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.expose_secret());
        return Ok(ring::hmac::sign(&key, message).as_ref().to_vec());
    }
    e.key
        .as_ref()
        .ok_or_else(|| AuthError::crypto("active key has no private material"))?
        .sign(message)
}

fn export_symmetric_from(map: &HashMap<Kid, Entry>, kid: &Kid) -> Result<Zeroizing<[u8; 32]>> {
    let e = map.get(kid).ok_or_else(|| not_found(kid))?;
    let k = e.secret.as_ref().ok_or_else(|| {
        AuthError::validation(format!("key {kid} is destroyed or not a symmetric key"))
    })?;
    Ok(Zeroizing::new(*k.expose_secret()))
}

fn export_from(map: &HashMap<Kid, Entry>, kid: &Kid) -> Result<Zeroizing<Vec<u8>>> {
    let e = map.get(kid).ok_or_else(|| not_found(kid))?;
    let k = e.key.as_ref().ok_or_else(|| {
        AuthError::validation(format!("key {kid} is destroyed or has no PKCS#8 form"))
    })?;
    Ok(Zeroizing::new(k.to_pkcs8_der().to_vec()))
}

/// Keys held in process memory only. Exportable, not persistent.
#[derive(Default)]
pub struct MemoryKeyStore {
    keys: RwLock<HashMap<Kid, Entry>>,
    rotation: tokio::sync::Mutex<()>,
}

impl MemoryKeyStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn lock_rotation(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.rotation.lock().await
    }

    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            exportable: true,
            signs_in_place: false,
            persistent: false,
        }
    }

    async fn insert(&self, key: LocalKey, state: KeyState) -> Result<()> {
        refuse_destroyed(state)?;
        let kid = key.kid().clone();
        let mut map = self.keys.write().await;
        if map.contains_key(&kid) {
            return Err(AuthError::validation(format!(
                "key id {kid} already exists"
            )));
        }
        map.insert(kid, entry_of(key, state));
        Ok(())
    }

    async fn insert_symmetric(&self, key: SymmetricKey, state: KeyState) -> Result<()> {
        refuse_destroyed(state)?;
        let kid = key.kid().clone();
        let mut map = self.keys.write().await;
        if map.contains_key(&kid) {
            return Err(AuthError::validation(format!(
                "key id {kid} already exists"
            )));
        }
        map.insert(kid, entry_of_symmetric(key, state));
        Ok(())
    }

    async fn export_symmetric(&self, kid: &Kid) -> Result<Zeroizing<[u8; 32]>> {
        export_symmetric_from(&*self.keys.read().await, kid)
    }

    async fn info(&self, kid: &Kid) -> Result<KeyInfo> {
        let map = self.keys.read().await;
        Ok(map.get(kid).ok_or_else(|| not_found(kid))?.info(kid))
    }

    async fn list(&self) -> Result<Vec<KeyInfo>> {
        let map = self.keys.read().await;
        let mut v: Vec<KeyInfo> = map.iter().map(|(k, e)| e.info(k)).collect();
        v.sort_by(|a, b| a.kid.cmp(&b.kid));
        Ok(v)
    }

    async fn set_state(&self, kid: &Kid, next: KeyState) -> Result<()> {
        let mut map = self.keys.write().await;
        let e = map.get_mut(kid).ok_or_else(|| not_found(kid))?;
        e.apply(next, unix_now())
    }

    async fn sign(&self, kid: &Kid, message: &[u8]) -> Result<Vec<u8>> {
        sign_with(&*self.keys.read().await, kid, message)
    }

    async fn export_private_pkcs8(&self, kid: &Kid) -> Result<Zeroizing<Vec<u8>>> {
        export_from(&*self.keys.read().await, kid)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Record {
    v: u8,
    kind: KeyKind,
    state: KeyState,
    #[serde(default)]
    public: Option<serde_json::Value>,
    pkcs8: Option<String>,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    created_at: u64,
    #[serde(default)]
    retiring_at: Option<u64>,
}

/// Keys persisted one file per key under a directory, each sealed with AES-256-GCM
/// (the record is bound to its key id, so a file cannot be swapped for another's).
/// Exportable and persistent.
pub struct FileKeyStore {
    dir: PathBuf,
    enc: StorageEncryption,
    keys: RwLock<HashMap<Kid, Entry>>,
    rotation: tokio::sync::Mutex<()>,
}

const RECORD_SUFFIX: &str = ".key";

impl FileKeyStore {
    /// Open (creating if needed) the store at `dir` and load every record. A record
    /// that cannot be decrypted or parsed fails the open, never a silent skip.
    pub async fn open(dir: impl Into<PathBuf>, enc: StorageEncryption) -> Result<Self> {
        let dir = dir.into();
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| AuthError::internal(format!("cannot create key directory: {e}")))?;
        let mut keys = HashMap::new();
        let mut rd = tokio::fs::read_dir(&dir)
            .await
            .map_err(|e| AuthError::internal(format!("cannot read key directory: {e}")))?;
        while let Some(f) = rd
            .next_entry()
            .await
            .map_err(|e| AuthError::internal(format!("cannot read key directory: {e}")))?
        {
            let name = f.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(RECORD_SUFFIX) else {
                continue;
            };
            let kid = match hex::decode(stem)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .map(Kid::new)
            {
                Some(Ok(kid)) => kid,
                _ => {
                    // Not one of ours (a leftover from another tool): do not make the
                    // whole store unopenable. A record that IS ours still fails closed below.
                    tracing::warn!(file = %name, "ignoring a non-key file in the key directory");
                    continue;
                }
            };
            let sealed = tokio::fs::read(f.path())
                .await
                .map_err(|e| AuthError::internal(format!("cannot read key record: {e}")))?;
            let plain = Zeroizing::new(enc.decrypt_from_storage(&sealed, &aad(&kid))?);
            let rec: Record = serde_json::from_slice(&plain)
                .map_err(|_| AuthError::validation("key record is not valid"))?;
            keys.insert(kid.clone(), entry_from_record(&kid, rec)?);
        }
        Ok(Self {
            dir,
            enc,
            keys: RwLock::new(keys),
            rotation: tokio::sync::Mutex::new(()),
        })
    }

    fn path(&self, kid: &Kid) -> PathBuf {
        self.dir
            .join(format!("{}{RECORD_SUFFIX}", hex::encode(kid.as_str())))
    }

    async fn persist(&self, kid: &Kid, rec: &Record) -> Result<()> {
        let plain = Zeroizing::new(
            serde_json::to_vec(rec).map_err(|_| AuthError::internal("cannot encode key record"))?,
        );
        let sealed = self.enc.encrypt_for_storage(&plain, &aad(kid))?;
        let path = self.path(kid);
        let tmp = path.with_extension("tmp");
        tokio::fs::write(&tmp, &sealed)
            .await
            .map_err(|e| AuthError::internal(format!("cannot write key record: {e}")))?;
        tokio::fs::rename(&tmp, &path)
            .await
            .map_err(|e| AuthError::internal(format!("cannot place key record: {e}")))
    }
}

fn aad(kid: &Kid) -> Vec<u8> {
    format!("auth-framework/keystore/v1:{kid}").into_bytes()
}

fn record_of(e: &Entry, state: KeyState, keep_private: bool, now: u64) -> Record {
    let retiring_at = match state {
        KeyState::Retiring => e.retiring_at.or(Some(now)),
        KeyState::Revoked => None,
        _ => e.retiring_at,
    };
    Record {
        created_at: e.created_at,
        retiring_at,
        v: record_version(e.kind),
        kind: e.kind,
        state,
        public: e.public.as_ref().map(PublicJwk::to_value),
        pkcs8: if keep_private {
            e.key
                .as_ref()
                .map(|k| base64::engine::general_purpose::STANDARD.encode(k.to_pkcs8_der()))
        } else {
            None
        },
        secret: if keep_private {
            e.secret
                .as_ref()
                .map(|k| base64::engine::general_purpose::STANDARD.encode(k.expose_secret()))
        } else {
            None
        },
    }
}

/// The record version a key of `kind` is written with: `2` for a key-agreement key, `1` for
/// every other kind, so a store that never holds an agreement key is byte-for-byte what it was
/// before agreement keys existed, and an older build, which only reads `1`, refuses a directory
/// that holds one instead of misreading it (docs/KEY_AGREEMENT_DESIGN.md section 4).
fn record_version(kind: KeyKind) -> u8 {
    if kind == KeyKind::JweEncryption { 2 } else { 1 }
}

fn entry_from_record(kid: &Kid, rec: Record) -> Result<Entry> {
    if rec.v != record_version(rec.kind) {
        return Err(AuthError::validation(format!(
            "unsupported key record version {} for a {:?} key: this key directory was written by a              different version of auth-framework (to downgrade, destroy its key-agreement keys              with the newer version first)",
            rec.v, rec.kind
        )));
    }
    let bad = || AuthError::validation("key record is not valid");
    let mut key = None;
    let mut secret = None;
    let mut public = None;
    if rec.kind.is_asymmetric() {
        let p = PublicJwk::from_value(rec.public.as_ref().ok_or_else(bad)?)?;
        if rec.secret.is_some() {
            return Err(bad());
        }
        if let Some(b64) = rec.pkcs8 {
            let der = Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|_| bad())?,
            );
            let k = LocalKey::from_pkcs8_der(&der, rec.kind, Some(kid.clone()))?;
            if k.public().thumbprint()? != p.thumbprint()? {
                return Err(AuthError::validation(
                    "key record's private and public halves do not match",
                ));
            }
            key = Some(k);
        }
        public = Some(p);
    } else {
        if rec.public.is_some() || rec.pkcs8.is_some() {
            return Err(bad());
        }
        if let Some(b64) = rec.secret {
            let raw = Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|_| bad())?,
            );
            let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| bad())?;
            secret = Some(SymmetricKey::from_bytes(rec.kind, kid.clone(), bytes)?);
        }
    }
    if key.is_none() && secret.is_none() && rec.state != KeyState::Destroyed {
        return Err(AuthError::validation(
            "a key record without private material must be destroyed",
        ));
    }
    Ok(Entry {
        kind: rec.kind,
        state: rec.state,
        public,
        key,
        secret,
        created_at: rec.created_at,
        retiring_at: rec.retiring_at,
    })
}

#[async_trait]
impl KeyStore for FileKeyStore {
    async fn lock_rotation(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.rotation.lock().await
    }

    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            exportable: true,
            signs_in_place: false,
            persistent: true,
        }
    }

    async fn insert(&self, key: LocalKey, state: KeyState) -> Result<()> {
        refuse_destroyed(state)?;
        let kid = key.kid().clone();
        let mut map = self.keys.write().await;
        if map.contains_key(&kid) {
            return Err(AuthError::validation(format!(
                "key id {kid} already exists"
            )));
        }
        let entry = entry_of(key, state);
        self.persist(&kid, &record_of(&entry, state, true, unix_now()))
            .await?;
        map.insert(kid, entry);
        Ok(())
    }

    async fn insert_symmetric(&self, key: SymmetricKey, state: KeyState) -> Result<()> {
        refuse_destroyed(state)?;
        let kid = key.kid().clone();
        let mut map = self.keys.write().await;
        if map.contains_key(&kid) {
            return Err(AuthError::validation(format!(
                "key id {kid} already exists"
            )));
        }
        let entry = entry_of_symmetric(key, state);
        self.persist(&kid, &record_of(&entry, state, true, unix_now()))
            .await?;
        map.insert(kid, entry);
        Ok(())
    }

    async fn export_symmetric(&self, kid: &Kid) -> Result<Zeroizing<[u8; 32]>> {
        export_symmetric_from(&*self.keys.read().await, kid)
    }

    async fn info(&self, kid: &Kid) -> Result<KeyInfo> {
        let map = self.keys.read().await;
        Ok(map.get(kid).ok_or_else(|| not_found(kid))?.info(kid))
    }

    async fn list(&self) -> Result<Vec<KeyInfo>> {
        let map = self.keys.read().await;
        let mut v: Vec<KeyInfo> = map.iter().map(|(k, e)| e.info(k)).collect();
        v.sort_by(|a, b| a.kid.cmp(&b.kid));
        Ok(v)
    }

    async fn set_state(&self, kid: &Kid, next: KeyState) -> Result<()> {
        let mut map = self.keys.write().await;
        let e = map.get_mut(kid).ok_or_else(|| not_found(kid))?;
        let state = e.state.transition(next)?;
        let now = unix_now();
        // Persist first: if the write fails the in-memory key is untouched.
        self.persist(kid, &record_of(e, state, next != KeyState::Destroyed, now))
            .await?;
        e.apply(next, now)
    }

    async fn sign(&self, kid: &Kid, message: &[u8]) -> Result<Vec<u8>> {
        sign_with(&*self.keys.read().await, kid, message)
    }

    async fn export_private_pkcs8(&self, kid: &Kid) -> Result<Zeroizing<Vec<u8>>> {
        export_from(&*self.keys.read().await, kid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningAlg;
    use crate::storage::encryption::{KeyProvider, LoadedKeys};

    struct Fixed(u8);
    impl KeyProvider for Fixed {
        fn load_keys(&self) -> Result<LoadedKeys> {
            Ok(LoadedKeys {
                current_key_id: "k".into(),
                keys: HashMap::from([("k".to_string(), [self.0; 32])]),
            })
        }
    }

    fn enc(b: u8) -> StorageEncryption {
        StorageEncryption::new(&Fixed(b)).unwrap()
    }

    fn key(alg: SigningAlg) -> LocalKey {
        LocalKey::generate(KeyKind::JwsSigning, alg, None).unwrap()
    }

    #[tokio::test]
    async fn the_revocation_list_names_revoked_and_destroyed_keys_only() {
        let s = MemoryKeyStore::new();
        let mut kids = Vec::new();
        for st in [
            KeyState::Active,
            KeyState::Retiring,
            KeyState::Revoked,
            KeyState::Destroyed,
        ] {
            let k = key(SigningAlg::Es256);
            kids.push(k.kid().clone());
            s.insert(k, KeyState::Pending).await.unwrap();
            if st == KeyState::Destroyed {
                s.set_state(kids.last().unwrap(), KeyState::Revoked)
                    .await
                    .unwrap();
            } else if st != KeyState::Pending {
                s.set_state(kids.last().unwrap(), KeyState::Active)
                    .await
                    .unwrap();
                if st != KeyState::Active {
                    s.set_state(kids.last().unwrap(), st).await.unwrap();
                }
            }
            if st == KeyState::Destroyed {
                s.set_state(kids.last().unwrap(), KeyState::Destroyed)
                    .await
                    .unwrap();
            }
        }
        let list = revocation_list(&s).await.unwrap();
        let mut want = vec![kids[2].clone(), kids[3].clone()];
        want.sort();
        let got: Vec<Kid> = list.iter().map(|r| r.kid.clone()).collect();
        assert_eq!(got, want);
        for r in &list {
            let info = s.info(&r.kid).await.unwrap();
            assert_eq!(
                r.thumbprint,
                Some(info.public.unwrap().thumbprint().unwrap())
            );
            assert_eq!(r.alg, "ES256");
        }
    }

    #[tokio::test]
    async fn only_an_active_key_signs() {
        let s = MemoryKeyStore::new();
        let k = key(SigningAlg::Es256);
        let kid = k.kid().clone();
        s.insert(k, KeyState::Pending).await.unwrap();
        assert!(s.sign(&kid, b"m").await.is_err(), "pending");
        s.set_state(&kid, KeyState::Active).await.unwrap();
        assert!(!s.sign(&kid, b"m").await.unwrap().is_empty());
        s.set_state(&kid, KeyState::Retiring).await.unwrap();
        assert!(s.sign(&kid, b"m").await.is_err(), "retiring");
        s.set_state(&kid, KeyState::Revoked).await.unwrap();
        assert!(s.sign(&kid, b"m").await.is_err(), "revoked");
    }

    #[tokio::test]
    async fn duplicate_ids_and_illegal_transitions_are_refused() {
        let s = MemoryKeyStore::new();
        let k = key(SigningAlg::EdDsa);
        let kid = k.kid().clone();
        let dup = LocalKey::from_pkcs8_der(k.to_pkcs8_der(), KeyKind::JwsSigning, None).unwrap();
        s.insert(k, KeyState::Active).await.unwrap();
        assert!(s.insert(dup, KeyState::Active).await.is_err());
        assert!(s.set_state(&kid, KeyState::Pending).await.is_err());
        s.set_state(&kid, KeyState::Revoked).await.unwrap();
        assert!(s.set_state(&kid, KeyState::Active).await.is_err());
        assert!(s.info(&Kid::new("nope").unwrap()).await.is_err());
    }

    #[tokio::test]
    async fn a_key_cannot_be_inserted_as_destroyed_in_either_store() {
        let dir = tempfile::tempdir().unwrap();
        let file = FileKeyStore::open(dir.path(), enc(5)).await.unwrap();
        let mem = MemoryKeyStore::new();
        for s in [&mem as &dyn KeyStore, &file as &dyn KeyStore] {
            let k = key(SigningAlg::Es256);
            let kid = k.kid().clone();
            assert!(s.insert(k, KeyState::Destroyed).await.is_err());
            assert!(s.info(&kid).await.is_err(), "nothing was stored");
            assert!(s.export_private_pkcs8(&kid).await.is_err());
            // Control: the same key inserted live is accepted and exports.
            let k = key(SigningAlg::Es256);
            let kid = k.kid().clone();
            s.insert(k, KeyState::Active).await.unwrap();
            assert!(s.export_private_pkcs8(&kid).await.is_ok());
        }
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "one file"
        );
    }

    #[tokio::test]
    async fn a_stray_file_does_not_make_the_store_unopenable() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = FileKeyStore::open(dir.path(), enc(6)).await.unwrap();
            s.insert(key(SigningAlg::Es256), KeyState::Active)
                .await
                .unwrap();
        }
        std::fs::write(dir.path().join("not-hex.key"), b"left by another tool").unwrap();
        let s = FileKeyStore::open(dir.path(), enc(6)).await.unwrap();
        assert_eq!(s.list().await.unwrap().len(), 1);
        // A record that is ours but corrupt still fails closed (control).
        let ours = dir.path().join(format!("{}.key", hex::encode("bad")));
        std::fs::write(ours, b"garbage").unwrap();
        assert!(FileKeyStore::open(dir.path(), enc(6)).await.is_err());
    }

    #[tokio::test]
    async fn the_published_jwks_is_active_and_retiring_only_with_no_private_member() {
        let s = MemoryKeyStore::new();
        let mut kids = vec![];
        for st in [
            KeyState::Pending,
            KeyState::Active,
            KeyState::Retiring,
            KeyState::Revoked,
            KeyState::Destroyed,
        ] {
            let k = key(SigningAlg::Es256);
            kids.push(k.kid().clone());
            // Reach `st` by legal moves from Active (Pending stays Pending).
            let start = if st == KeyState::Pending {
                KeyState::Pending
            } else {
                KeyState::Active
            };
            let kid = k.kid().clone();
            s.insert(k, start).await.unwrap();
            if st == KeyState::Destroyed {
                s.set_state(&kid, KeyState::Revoked).await.unwrap();
            }
            if st != start {
                s.set_state(&kid, st).await.unwrap();
            }
        }
        let set = publish_jwks(&s).await.unwrap().to_value();
        let published: Vec<&str> = set["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap())
            .collect();
        assert_eq!(published.len(), 2);
        assert!(published.contains(&kids[1].as_str()) && published.contains(&kids[2].as_str()));
        assert!(!set.to_string().contains("\"d\""));
    }

    #[tokio::test]
    async fn destroy_erases_the_private_key() {
        let s = MemoryKeyStore::new();
        let k = key(SigningAlg::Rs256);
        let kid = k.kid().clone();
        s.insert(k, KeyState::Active).await.unwrap();
        assert!(!s.export_private_pkcs8(&kid).await.unwrap().is_empty());
        s.set_state(&kid, KeyState::Revoked).await.unwrap();
        s.set_state(&kid, KeyState::Destroyed).await.unwrap();
        assert!(s.export_private_pkcs8(&kid).await.is_err());
        assert_eq!(s.info(&kid).await.unwrap().state, KeyState::Destroyed);
    }

    #[tokio::test]
    async fn capabilities_are_declared() {
        let c = MemoryKeyStore::new().capabilities();
        assert!(c.exportable && !c.persistent && !c.signs_in_place);
    }

    #[tokio::test]
    async fn file_store_survives_a_reopen_with_state_and_signing() {
        let dir = tempfile::tempdir().unwrap();
        let k = key(SigningAlg::Es384);
        let kid = k.kid().clone();
        let public = k.public().clone();
        {
            let s = FileKeyStore::open(dir.path(), enc(7)).await.unwrap();
            s.insert(k, KeyState::Active).await.unwrap();
            let gone = key(SigningAlg::EdDsa);
            let gone_kid = gone.kid().clone();
            s.insert(gone, KeyState::Active).await.unwrap();
            s.set_state(&gone_kid, KeyState::Revoked).await.unwrap();
            s.set_state(&gone_kid, KeyState::Destroyed).await.unwrap();
        }
        let s = FileKeyStore::open(dir.path(), enc(7)).await.unwrap();
        assert!(s.capabilities().persistent);
        let list = s.list().await.unwrap();
        assert_eq!(list.len(), 2);
        let info = s.info(&kid).await.unwrap();
        assert_eq!((info.state, info.public), (KeyState::Active, Some(public)));
        assert!(!s.sign(&kid, b"m").await.unwrap().is_empty());
        let destroyed = list
            .iter()
            .find(|i| i.state == KeyState::Destroyed)
            .unwrap();
        assert!(s.export_private_pkcs8(&destroyed.kid).await.is_err());
        assert!(s.sign(&destroyed.kid, b"m").await.is_err());
    }

    #[tokio::test]
    async fn files_hold_no_plain_private_key_and_the_wrong_key_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let k = key(SigningAlg::Es256);
        let b64_priv = base64::engine::general_purpose::STANDARD.encode(k.to_pkcs8_der());
        let s = FileKeyStore::open(dir.path(), enc(1)).await.unwrap();
        s.insert(k, KeyState::Active).await.unwrap();
        for f in std::fs::read_dir(dir.path()).unwrap() {
            let text = std::fs::read(f.unwrap().path()).unwrap();
            let text = String::from_utf8_lossy(&text);
            assert!(!text.contains(&b64_priv), "plain private key on disk");
            assert!(!text.contains("PRIVATE"));
        }
        assert!(FileKeyStore::open(dir.path(), enc(2)).await.is_err());
    }

    #[tokio::test]
    async fn a_record_swapped_onto_another_key_id_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (key(SigningAlg::Es256), key(SigningAlg::Es256));
        let (ka, kb) = (a.kid().clone(), b.kid().clone());
        let s = FileKeyStore::open(dir.path(), enc(3)).await.unwrap();
        s.insert(a, KeyState::Active).await.unwrap();
        s.insert(b, KeyState::Active).await.unwrap();
        let (pa, pb) = (s.path(&ka), s.path(&kb));
        drop(s);
        let bytes_a = std::fs::read(&pa).unwrap();
        std::fs::write(&pb, bytes_a).unwrap();
        assert!(FileKeyStore::open(dir.path(), enc(3)).await.is_err());
    }

    fn hmac(id: &str) -> SymmetricKey {
        SymmetricKey::generate(KeyKind::Hmac, Kid::new(id).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn an_hmac_key_signs_hs256_only_while_active_and_is_never_published() {
        let s = MemoryKeyStore::new();
        let k = hmac("h1");
        let secret = *k.expose_secret();
        let kid = k.kid().clone();
        s.insert_symmetric(k, KeyState::Pending).await.unwrap();
        assert!(s.sign(&kid, b"m").await.is_err(), "pending");
        s.set_state(&kid, KeyState::Active).await.unwrap();
        let want = ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret),
            b"m",
        );
        assert_eq!(s.sign(&kid, b"m").await.unwrap(), want.as_ref());
        assert_eq!(s.info(&kid).await.unwrap().alg, "HS256");
        assert!(s.info(&kid).await.unwrap().public.is_none());
        assert!(publish_jwks(&s).await.unwrap().keys.is_empty());
        assert_eq!(*s.export_symmetric(&kid).await.unwrap(), secret);
        s.set_state(&kid, KeyState::Revoked).await.unwrap();
        assert!(s.sign(&kid, b"m").await.is_err(), "revoked");
        s.set_state(&kid, KeyState::Destroyed).await.unwrap();
        assert!(s.export_symmetric(&kid).await.is_err(), "destroyed");
    }

    #[tokio::test]
    async fn an_aead_key_does_not_sign_and_an_asymmetric_key_has_no_symmetric_export() {
        let s = MemoryKeyStore::new();
        let a = SymmetricKey::generate(KeyKind::Aead, Kid::new("a1").unwrap()).unwrap();
        s.insert_symmetric(a, KeyState::Active).await.unwrap();
        assert!(s.sign(&Kid::new("a1").unwrap(), b"m").await.is_err());
        let k = key(SigningAlg::Es256);
        let kid = k.kid().clone();
        s.insert(k, KeyState::Active).await.unwrap();
        assert!(s.export_symmetric(&kid).await.is_err());
        assert!(
            s.export_private_pkcs8(&Kid::new("a1").unwrap())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_file_store_keeps_an_hmac_key_across_a_reopen_and_erases_it_on_destroy() {
        let dir = tempfile::tempdir().unwrap();
        let k = hmac("h1");
        let secret = *k.expose_secret();
        let kid = k.kid().clone();
        {
            let s = FileKeyStore::open(dir.path(), enc(7)).await.unwrap();
            s.insert_symmetric(k, KeyState::Active).await.unwrap();
        }
        let s = FileKeyStore::open(dir.path(), enc(7)).await.unwrap();
        assert_eq!(*s.export_symmetric(&kid).await.unwrap(), secret);
        assert_eq!(s.info(&kid).await.unwrap().state, KeyState::Active);
        // The record is sealed: the secret does not appear in the file in the clear.
        let raw = std::fs::read(s.path(&kid)).unwrap();
        assert!(!raw.windows(32).any(|w| w == secret));
        s.set_state(&kid, KeyState::Revoked).await.unwrap();
        s.set_state(&kid, KeyState::Destroyed).await.unwrap();
        drop(s);
        let s = FileKeyStore::open(dir.path(), enc(7)).await.unwrap();
        assert_eq!(s.info(&kid).await.unwrap().state, KeyState::Destroyed);
        assert!(s.export_symmetric(&kid).await.is_err());
        assert!(
            FileKeyStore::open(dir.path(), enc(8)).await.is_err(),
            "wrong key"
        );
    }

    #[tokio::test]
    async fn a_duplicate_hmac_id_and_a_destroyed_insert_are_refused() {
        let s = MemoryKeyStore::new();
        s.insert_symmetric(hmac("h1"), KeyState::Active)
            .await
            .unwrap();
        assert!(
            s.insert_symmetric(hmac("h1"), KeyState::Active)
                .await
                .is_err()
        );
        assert!(
            s.insert_symmetric(hmac("h2"), KeyState::Destroyed)
                .await
                .is_err()
        );
    }

    #[cfg(feature = "key-agreement")]
    mod agreement {
        use super::*;
        use crate::keys::{KeyKind, rotate};

        fn key(id: &str) -> LocalKey {
            LocalKey::generate_x25519(KeyKind::JweEncryption, Some(Kid::new(id).unwrap())).unwrap()
        }

        fn x_of(k: &LocalKey) -> Vec<u8> {
            let jwk = k.public().to_value();
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwk["x"].as_str().unwrap())
                .unwrap()
        }

        #[tokio::test]
        async fn an_agreement_key_lives_in_both_stores_publishes_as_enc_and_agrees_after_a_reopen()
        {
            let peer = key("peer");
            let dir = tempfile::tempdir().unwrap();
            let mem = MemoryKeyStore::new();
            let file = FileKeyStore::open(dir.path(), enc(1)).await.unwrap();
            let mine = key("mine");
            let mine_x = x_of(&mine);
            let want = peer.agree(&mine_x).unwrap();
            for store in [&mem as &dyn KeyStore, &file as &dyn KeyStore] {
                store
                    .insert(
                        LocalKey::from_pkcs8_der(
                            mine.to_pkcs8_der(),
                            KeyKind::JweEncryption,
                            Some(Kid::new("mine").unwrap()),
                        )
                        .unwrap(),
                        KeyState::Active,
                    )
                    .await
                    .unwrap();
                let info = store.info(&Kid::new("mine").unwrap()).await.unwrap();
                assert_eq!(info.kind, KeyKind::JweEncryption);
                assert_eq!(info.alg, "ECDH-ES");
                let jwks = publish_jwks(store).await.unwrap().to_value();
                assert_eq!(jwks["keys"][0]["use"], "enc");
                assert!(jwks["keys"][0].get("d").is_none());
                let got = crate::keys::agree(store, &Kid::new("mine").unwrap(), &x_of(&peer))
                    .await
                    .unwrap();
                assert_eq!(&got[..], &want[..]);
            }
            drop(file);
            let reopened = FileKeyStore::open(dir.path(), enc(1)).await.unwrap();
            let got = crate::keys::agree(&reopened, &Kid::new("mine").unwrap(), &x_of(&peer))
                .await
                .unwrap();
            assert_eq!(&got[..], &want[..], "the key survives a reopen");
            assert!(FileKeyStore::open(dir.path(), enc(2)).await.is_err());
        }

        async fn record_json(dir: &std::path::Path, kid: &str) -> serde_json::Value {
            let kid = Kid::new(kid).unwrap();
            let path = dir.join(format!("{}{RECORD_SUFFIX}", hex::encode(kid.as_str())));
            let sealed = tokio::fs::read(path).await.unwrap();
            let plain = enc(1).decrypt_from_storage(&sealed, &aad(&kid)).unwrap();
            serde_json::from_slice(&plain).unwrap()
        }

        async fn write_record(dir: &std::path::Path, kid: &str, rec: &serde_json::Value) {
            let kid = Kid::new(kid).unwrap();
            let path = dir.join(format!("{}{RECORD_SUFFIX}", hex::encode(kid.as_str())));
            let sealed = enc(1)
                .encrypt_for_storage(&serde_json::to_vec(rec).unwrap(), &aad(&kid))
                .unwrap();
            tokio::fs::write(path, sealed).await.unwrap();
        }

        #[tokio::test]
        async fn agreement_records_are_version_2_and_every_other_kind_stays_version_1() {
            let dir = tempfile::tempdir().unwrap();
            let s = FileKeyStore::open(dir.path(), enc(1)).await.unwrap();
            s.insert(key("agree"), KeyState::Active).await.unwrap();
            s.insert(super::key(SigningAlg::Es256), KeyState::Active)
                .await
                .unwrap();
            s.insert_symmetric(
                SymmetricKey::generate(KeyKind::Hmac, Kid::new("hmac").unwrap()).unwrap(),
                KeyState::Active,
            )
            .await
            .unwrap();
            assert_eq!(record_json(dir.path(), "agree").await["v"], 2);
            assert_eq!(record_json(dir.path(), "hmac").await["v"], 1);
            let signing = s
                .list()
                .await
                .unwrap()
                .into_iter()
                .find(|i| i.kind == KeyKind::JwsSigning)
                .unwrap();
            assert_eq!(record_json(dir.path(), signing.kid.as_str()).await["v"], 1);
        }

        #[tokio::test]
        async fn a_record_whose_version_does_not_fit_its_kind_fails_the_open_with_the_downgrade_text()
         {
            let dir = tempfile::tempdir().unwrap();
            {
                let s = FileKeyStore::open(dir.path(), enc(1)).await.unwrap();
                s.insert(key("agree"), KeyState::Active).await.unwrap();
            }
            let good = record_json(dir.path(), "agree").await;
            let mut v1 = good.clone();
            v1["v"] = serde_json::json!(1);
            write_record(dir.path(), "agree", &v1).await;
            let err = FileKeyStore::open(dir.path(), enc(1))
                .await
                .err()
                .expect("an agreement key written as v1 is refused")
                .to_string();
            assert!(err.contains("unsupported key record version 1"), "{err}");
            assert!(err.contains("downgrade"), "{err}");
            let mut v3 = good.clone();
            v3["v"] = serde_json::json!(3);
            write_record(dir.path(), "agree", &v3).await;
            assert!(FileKeyStore::open(dir.path(), enc(1)).await.is_err());
            write_record(dir.path(), "agree", &good).await;
            assert!(FileKeyStore::open(dir.path(), enc(1)).await.is_ok());
        }

        #[tokio::test]
        async fn only_an_active_or_retiring_agreement_key_agrees() {
            let s = MemoryKeyStore::new();
            let peer = key("peer");
            let px = x_of(&peer);
            for (id, state) in [("pending", KeyState::Pending), ("active", KeyState::Active)] {
                s.insert(key(id), state).await.unwrap();
            }
            for id in ["retiring", "revoked", "destroyed"] {
                s.insert(key(id), KeyState::Active).await.unwrap();
            }
            s.set_state(&Kid::new("retiring").unwrap(), KeyState::Retiring)
                .await
                .unwrap();
            s.set_state(&Kid::new("revoked").unwrap(), KeyState::Revoked)
                .await
                .unwrap();
            s.set_state(&Kid::new("destroyed").unwrap(), KeyState::Retiring)
                .await
                .unwrap();
            s.set_state(&Kid::new("destroyed").unwrap(), KeyState::Destroyed)
                .await
                .unwrap();
            for (id, ok) in [
                ("active", true),
                ("retiring", true),
                ("pending", false),
                ("revoked", false),
                ("destroyed", false),
            ] {
                let r = crate::keys::agree(&s, &Kid::new(id).unwrap(), &px).await;
                assert_eq!(r.is_ok(), ok, "{id}: {r:?}");
            }
            s.insert(super::key(SigningAlg::Es256), KeyState::Active)
                .await
                .unwrap();
            let signing = s
                .list()
                .await
                .unwrap()
                .into_iter()
                .find(|i| i.kind == KeyKind::JwsSigning)
                .unwrap();
            assert!(
                crate::keys::agree(&s, &signing.kid, &px).await.is_err(),
                "a signing key does not agree"
            );
            assert!(
                crate::keys::agree(&s, &Kid::new("nope").unwrap(), &px)
                    .await
                    .is_err()
            );
        }

        #[tokio::test]
        async fn rotation_and_revocation_work_unchanged_for_agreement_keys() {
            let s = MemoryKeyStore::new();
            let peer = key("peer");
            let px = x_of(&peer);
            s.insert(key("old"), KeyState::Active).await.unwrap();
            let new = rotate(&s, &Kid::new("old").unwrap(), key("new"))
                .await
                .unwrap();
            assert_eq!(new.as_str(), "new");
            let jwks = publish_jwks(&s).await.unwrap().to_value();
            assert_eq!(
                jwks["keys"].as_array().unwrap().len(),
                2,
                "both during the overlap"
            );
            assert!(
                crate::keys::agree(&s, &Kid::new("old").unwrap(), &px)
                    .await
                    .is_ok(),
                "a retiring key still decrypts"
            );
            crate::keys::revoke(&s, &Kid::new("old").unwrap())
                .await
                .unwrap();
            assert_eq!(
                publish_jwks(&s).await.unwrap().to_value()["keys"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            assert!(
                crate::keys::agree(&s, &Kid::new("old").unwrap(), &px)
                    .await
                    .is_err()
            );
        }
    }

    /// A hand-written RFC 7748 Alice record (v2): what a build WITH the `key-agreement`
    /// feature reads, and a build WITHOUT it must refuse by naming the feature.
    async fn write_alice_record(dir: &std::path::Path) {
        let alice_private =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap();
        let alice_public =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap();
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&alice_private);
        let rec = serde_json::json!({
            "v": 2,
            "kind": "jwe_encryption",
            "state": "active",
            "public": {
                "kty": "OKP", "crv": "X25519", "kid": "alice", "use": "enc", "alg": "ECDH-ES",
                "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&alice_public),
            },
            "pkcs8": base64::engine::general_purpose::STANDARD.encode(&der),
            "created_at": 1,
            "retiring_at": null,
        });
        let kid = Kid::new("alice").unwrap();
        let sealed = enc(1)
            .encrypt_for_storage(&serde_json::to_vec(&rec).unwrap(), &aad(&kid))
            .unwrap();
        let path = dir.join(format!("{}{RECORD_SUFFIX}", hex::encode("alice")));
        tokio::fs::write(path, sealed).await.unwrap();
    }

    #[cfg(feature = "key-agreement")]
    #[tokio::test]
    async fn a_hand_written_rfc_7748_record_opens_and_reproduces_the_published_shared_secret() {
        let dir = tempfile::tempdir().unwrap();
        write_alice_record(dir.path()).await;
        let s = FileKeyStore::open(dir.path(), enc(1)).await.unwrap();
        let bob_public =
            hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .unwrap();
        let got = crate::keys::agree(&s, &Kid::new("alice").unwrap(), &bob_public)
            .await
            .unwrap();
        assert_eq!(
            hex::encode(&got[..]),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    #[cfg(not(feature = "key-agreement"))]
    #[tokio::test]
    async fn a_build_without_the_feature_refuses_a_directory_holding_an_agreement_key_by_naming_it()
    {
        let dir = tempfile::tempdir().unwrap();
        write_alice_record(dir.path()).await;
        let err = FileKeyStore::open(dir.path(), enc(1))
            .await
            .err()
            .expect("the directory must not open without the feature")
            .to_string();
        assert!(err.contains("key-agreement"), "{err}");
    }
}
