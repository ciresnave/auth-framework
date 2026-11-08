// SPDX-License-Identifier: MIT OR Apache-2.0
//! KM3: key storage by capability.
//!
//! A [`KeyStore`] says what it can do ([`StoreCapabilities`]) and signs through
//! itself, so a store that cannot give a private key out (an OS keystore, a TPM, a
//! KMS, added later) fits the same trait as one that can. Two stores ship here:
//! [`MemoryKeyStore`] and [`FileKeyStore`] (one AES-256-GCM encrypted file per key,
//! sealed with the existing [`StorageEncryption`] / `KeyProvider` seam).

use super::{JwkSet, KeyKind, KeyState, Kid, LocalKey, PublicJwk, Signer};
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
    /// Public half.
    pub public: PublicJwk,
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
            .map(|i| i.public)
            .collect(),
    })
}

struct Entry {
    kind: KeyKind,
    state: KeyState,
    public: PublicJwk,
    key: Option<LocalKey>,
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
        }
        Ok(())
    }

    fn info(&self, kid: &Kid) -> KeyInfo {
        KeyInfo {
            kid: kid.clone(),
            kind: self.kind,
            state: self.state,
            alg: self.public.alg.clone().unwrap_or_default(),
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
        public: key.public().clone(),
        key: Some(key),
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
    e.key
        .as_ref()
        .ok_or_else(|| AuthError::crypto("active key has no private material"))?
        .sign(message)
}

fn export_from(map: &HashMap<Kid, Entry>, kid: &Kid) -> Result<Zeroizing<Vec<u8>>> {
    let e = map.get(kid).ok_or_else(|| not_found(kid))?;
    let k = e
        .key
        .as_ref()
        .ok_or_else(|| AuthError::validation(format!("key {kid} is destroyed")))?;
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
    public: serde_json::Value,
    pkcs8: Option<String>,
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
        v: 1,
        kind: e.kind,
        state,
        public: e.public.to_value(),
        pkcs8: if keep_private {
            e.key
                .as_ref()
                .map(|k| base64::engine::general_purpose::STANDARD.encode(k.to_pkcs8_der()))
        } else {
            None
        },
    }
}

fn entry_from_record(kid: &Kid, rec: Record) -> Result<Entry> {
    if rec.v != 1 {
        return Err(AuthError::validation("unsupported key record version"));
    }
    let public = PublicJwk::from_value(&rec.public)?;
    let key = match rec.pkcs8 {
        Some(b64) => {
            let der = Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|_| AuthError::validation("key record is not valid"))?,
            );
            let k = LocalKey::from_pkcs8_der(&der, rec.kind, Some(kid.clone()))?;
            if k.public().thumbprint()? != public.thumbprint()? {
                return Err(AuthError::validation(
                    "key record's private and public halves do not match",
                ));
            }
            Some(k)
        }
        None => None,
    };
    if key.is_none() && rec.state != KeyState::Destroyed {
        return Err(AuthError::validation(
            "a key record without private material must be destroyed",
        ));
    }
    Ok(Entry {
        kind: rec.kind,
        state: rec.state,
        public,
        key,
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
        assert_eq!((info.state, info.public), (KeyState::Active, public));
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
}
