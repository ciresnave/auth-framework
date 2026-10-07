use crate::errors::{AuthError, Result};
use crate::storage::{AuthStorage, SessionData};
use crate::tokens::AuthToken;
use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::time::Duration;

/// Encrypted data container with metadata.
///
/// `key_id` makes this a versioned envelope: a value encrypted under one key
/// can still be decrypted after the *current* key rotates, as long as the
/// old key is still loadable (see [`KeyProvider`]). Writers always use the
/// current key; readers look up whichever key the envelope names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Base64 encoded encrypted data
    pub data: String,
    /// Base64 encoded nonce/IV (96 bits, randomly generated per encryption)
    pub nonce: String,
    /// Algorithm identifier
    pub algorithm: String,
    /// Which key (by id) encrypted this value. Required for key rotation:
    /// old envelopes keep working under their original key id even after
    /// [`KeyProvider::current_key_id`] moves on to a newer one.
    pub key_id: String,
}

/// Supplies the encryption key(s) [`StorageEncryption`] uses.
///
/// Exists as a seam so the key *source* (env var today) can be swapped for
/// a KMS or an `age`/`sops`-style file-based secret without touching
/// [`StorageEncryption`] or [`EncryptedStorage`] at all. See
/// [`EnvKeyProvider`]'s own docs for the current, deliberately narrow,
/// implementation and its known limitation.
pub trait KeyProvider: Send + Sync {
    /// Load every key this provider knows about, keyed by key id, plus
    /// which one is current (new writes use this one; any key in the map
    /// can still be used to decrypt an old envelope that names it).
    ///
    /// Returns an error if no usable key can be loaded at all -- callers
    /// must fail closed on that, never silently fall back to no
    /// encryption.
    fn load_keys(&self) -> Result<LoadedKeys>;
}

/// The result of [`KeyProvider::load_keys`]: every key this provider could
/// load, and which one is current.
pub struct LoadedKeys {
    pub current_key_id: String,
    /// All loadable keys, including the current one, by key id.
    pub keys: HashMap<String, [u8; 32]>,
}

/// Loads encryption keys from environment variables, or from a file if
/// `AUTH_STORAGE_ENCRYPTION_KEYS_FILE` is set.
///
/// **Known limitation (tracked, per CireSnave's ruling on board item 124):**
/// env vars and files sit on the same host as the data they protect. An
/// attacker with read access to the process environment or the key file
/// can decrypt everything this encrypts. This is accepted as a starting
/// point, not an endpoint -- [`KeyProvider`] exists specifically so a
/// KMS-backed or `age`/`sops`-backed provider can replace this one later
/// without any caller-visible change. See `docs/storage-backends.md` for
/// the same note aimed at operators.
///
/// ## Format
///
/// - `AUTH_STORAGE_ENCRYPTION_KEY` (required unless the keys file sets
///   `current`): the current key, base64-encoded, 32 bytes decoded.
/// - `AUTH_STORAGE_ENCRYPTION_KEY_ID` (optional, defaults to `"1"`): the id
///   under which `AUTH_STORAGE_ENCRYPTION_KEY` is recorded in new
///   envelopes.
/// - `AUTH_STORAGE_ENCRYPTION_KEYS_FILE` (optional): path to a JSON file
///   `{"current": "<key_id>", "keys": {"<key_id>": "<base64 key>", ...}}`
///   for rotation -- old keys stay loadable (decrypt-only in practice,
///   since `current` picks what new writes use) as long as they're listed
///   here. If set, this takes priority over the two env vars above.
pub struct EnvKeyProvider;

impl KeyProvider for EnvKeyProvider {
    fn load_keys(&self) -> Result<LoadedKeys> {
        if let Ok(path) = env::var("AUTH_STORAGE_ENCRYPTION_KEYS_FILE") {
            return Self::load_from_file(&path);
        }

        let key_data = env::var("AUTH_STORAGE_ENCRYPTION_KEY").map_err(|_| {
            AuthError::config(
                "No storage encryption key configured: set AUTH_STORAGE_ENCRYPTION_KEY \
                 (or AUTH_STORAGE_ENCRYPTION_KEYS_FILE for multi-key rotation). \
                 Refusing to start rather than silently storing data unencrypted.",
            )
        })?;
        let key_id = env::var("AUTH_STORAGE_ENCRYPTION_KEY_ID").unwrap_or_else(|_| "1".to_string());
        let key = decode_key(&key_data)?;

        let mut keys = HashMap::new();
        keys.insert(key_id.clone(), key);
        Ok(LoadedKeys {
            current_key_id: key_id,
            keys,
        })
    }
}

impl EnvKeyProvider {
    fn load_from_file(path: &str) -> Result<LoadedKeys> {
        #[derive(Deserialize)]
        struct KeysFile {
            current: String,
            keys: HashMap<String, String>,
        }

        let contents = fs::read_to_string(path).map_err(|e| {
            AuthError::config(format!(
                "Failed to read AUTH_STORAGE_ENCRYPTION_KEYS_FILE '{path}': {e}"
            ))
        })?;
        let parsed: KeysFile = serde_json::from_str(&contents).map_err(|e| {
            AuthError::config(format!(
                "Failed to parse AUTH_STORAGE_ENCRYPTION_KEYS_FILE '{path}': {e}"
            ))
        })?;

        if !parsed.keys.contains_key(&parsed.current) {
            return Err(AuthError::config(format!(
                "AUTH_STORAGE_ENCRYPTION_KEYS_FILE '{path}': current key id '{}' \
                 is not present in 'keys'",
                parsed.current
            )));
        }

        let mut keys = HashMap::new();
        for (id, encoded) in parsed.keys {
            let key = decode_key(&encoded)?;
            keys.insert(id, key);
        }

        Ok(LoadedKeys {
            current_key_id: parsed.current,
            keys,
        })
    }
}

fn decode_key(encoded: &str) -> Result<[u8; 32]> {
    let key_bytes = BASE64
        .decode(encoded)
        .map_err(|_| AuthError::config("Invalid base64 in storage encryption key"))?;
    if key_bytes.len() != 32 {
        return Err(AuthError::config(
            "Storage encryption key must be 32 bytes (256 bits) once base64-decoded",
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Storage encryption manager using AES-256-GCM, with per-record random
/// nonces and associated data (AAD) binding each ciphertext to the storage
/// key it was stored under -- so a ciphertext copied from one record to
/// another fails to decrypt instead of silently "succeeding" with the
/// wrong value.
pub struct StorageEncryption {
    current_key_id: String,
    ciphers: HashMap<String, Aes256Gcm>,
}

impl StorageEncryption {
    /// Create a new encryption manager, loading keys from the given
    /// provider. Fails closed: if the provider can't load a usable key,
    /// this returns `Err` rather than any fallback.
    pub fn new(provider: &dyn KeyProvider) -> Result<Self> {
        let loaded = provider.load_keys()?;
        if !loaded.keys.contains_key(&loaded.current_key_id) {
            return Err(AuthError::config(format!(
                "Key provider's current_key_id '{}' is not among the keys it loaded",
                loaded.current_key_id
            )));
        }
        let ciphers = loaded
            .keys
            .into_iter()
            .map(|(id, key_bytes)| {
                let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
                (id, Aes256Gcm::new(key))
            })
            .collect();
        Ok(Self {
            current_key_id: loaded.current_key_id,
            ciphers,
        })
    }

    /// Create a new encryption manager from the environment (see
    /// [`EnvKeyProvider`]). Convenience wrapper over `new(&EnvKeyProvider)`.
    pub fn from_env() -> Result<Self> {
        Self::new(&EnvKeyProvider)
    }

    /// Create new encryption manager for testing with a single random key.
    #[cfg(test)]
    pub fn new_random() -> Self {
        use rand::Rng;
        let mut key_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut key_bytes);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let mut ciphers = HashMap::new();
        ciphers.insert("test".to_string(), Aes256Gcm::new(key));
        Self {
            current_key_id: "test".to_string(),
            ciphers,
        }
    }

    /// Generate a new 256-bit encryption key (base64 encoded), suitable for
    /// `AUTH_STORAGE_ENCRYPTION_KEY` or a keys-file entry.
    pub fn generate_key() -> String {
        use rand::Rng;
        let mut key_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut key_bytes);
        BASE64.encode(key_bytes)
    }

    /// Encrypt raw bytes. `aad` (associated data) is authenticated but not
    /// encrypted -- callers should pass the storage key the resulting
    /// envelope will be stored under, binding the ciphertext to that
    /// specific record.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedData> {
        use rand::Rng;
        let cipher = self.ciphers.get(&self.current_key_id).ok_or_else(|| {
            AuthError::internal("Current encryption key missing from loaded cipher set")
        })?;

        // 96-bit nonce, freshly random every call. AES-GCM's security
        // depends on never reusing a nonce under the same key; a random
        // 96-bit nonce makes accidental reuse astronomically unlikely
        // (birthday bound ~2^48 encryptions under one key before a
        // collision becomes plausible) without needing a counter the
        // caller would have to persist and coordinate across instances.
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| AuthError::internal(format!("Encryption failed: {}", e)))?;

        Ok(EncryptedData {
            data: BASE64.encode(&ciphertext),
            nonce: BASE64.encode(nonce_bytes),
            algorithm: "AES-256-GCM".to_string(),
            key_id: self.current_key_id.clone(),
        })
    }

    /// Decrypt an envelope. `aad` must match exactly what was passed to
    /// [`Self::encrypt`] (the storage key the envelope is stored under) --
    /// a mismatch (e.g. a ciphertext copied to a different record) fails
    /// decryption rather than succeeding with the wrong plaintext.
    pub fn decrypt(&self, encrypted: &EncryptedData, aad: &[u8]) -> Result<Vec<u8>> {
        if encrypted.algorithm != "AES-256-GCM" {
            return Err(AuthError::internal(format!(
                "Unsupported encryption algorithm: {}",
                encrypted.algorithm
            )));
        }

        let cipher = self.ciphers.get(&encrypted.key_id).ok_or_else(|| {
            AuthError::internal(format!(
                "No loaded key for key_id '{}' -- it may have been rotated out \
                 without being kept in the keys file for decrypt-only use",
                encrypted.key_id
            ))
        })?;

        let ciphertext = BASE64
            .decode(&encrypted.data)
            .map_err(|_| AuthError::internal("Invalid base64 in encrypted data"))?;
        let nonce_bytes = BASE64
            .decode(&encrypted.nonce)
            .map_err(|_| AuthError::internal("Invalid base64 in nonce"))?;
        if nonce_bytes.len() != 12 {
            return Err(AuthError::internal("Invalid nonce length"));
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext,
                    aad,
                },
            )
            .map_err(|e| AuthError::internal(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }

    /// Encrypt raw bytes for storage, serialized as a self-describing
    /// envelope. `aad` should be the storage key this will be stored
    /// under. Accepts arbitrary bytes, not just UTF-8 text.
    pub fn encrypt_for_storage(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let encrypted = self.encrypt(data, aad)?;
        let serialized = serde_json::to_string(&encrypted).map_err(|e| {
            AuthError::internal(format!("Failed to serialize encrypted data: {}", e))
        })?;
        Ok(serialized.into_bytes())
    }

    /// Decrypt a storage envelope produced by [`Self::encrypt_for_storage`].
    /// `aad` must be the same storage key passed to that call.
    pub fn decrypt_from_storage(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let serialized = std::str::from_utf8(data)
            .map_err(|_| AuthError::internal("Stored envelope is not valid UTF-8 JSON"))?;
        let encrypted: EncryptedData = serde_json::from_str(serialized).map_err(|e| {
            AuthError::internal(format!("Failed to deserialize encrypted data: {}", e))
        })?;
        self.decrypt(&encrypted, aad)
    }

    /// Returns `true` if `data` looks like one of this module's own
    /// serialized envelopes (used by the at-rest migration tool to skip
    /// rows that are already encrypted, making re-runs idempotent).
    pub fn looks_like_envelope(data: &[u8]) -> bool {
        std::str::from_utf8(data)
            .ok()
            .and_then(|s| serde_json::from_str::<EncryptedData>(s).ok())
            .map(|e| e.algorithm == "AES-256-GCM")
            .unwrap_or(false)
    }
}

/// Wrapper for storage backends that adds encryption at rest to the
/// generic key-value (`store_kv`/`get_kv`) layer.
///
/// **Coverage note:** this wraps `store_kv`/`get_kv` only. The dedicated
/// `store_token`/`store_session` methods (and each backend's own typed
/// columns for them) are NOT touched by this wrapper -- they delegate to
/// `inner` unchanged. Encrypting those would need changes to the
/// `AuthStorage` trait itself (their fields are typed, not opaque bytes),
/// tracked separately. This wrapper covers everything that already goes
/// through `store_kv` today: API keys, TOTP secrets, OAuth2 client
/// registries, MFA codes, and most of the other KV-backed subsystems
/// found in the storage audit (`docs/STORAGE-AUDIT.md`).
pub struct EncryptedStorage<T> {
    inner: T,
    encryption: StorageEncryption,
}

impl<T> EncryptedStorage<T> {
    pub fn new(storage: T, encryption: StorageEncryption) -> Self {
        Self {
            inner: storage,
            encryption,
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

#[async_trait::async_trait]
impl<T> AuthStorage for EncryptedStorage<T>
where
    T: AuthStorage + Send + Sync,
{
    // Token/session methods — NOT encrypted by this wrapper. See the
    // "Coverage note" on `EncryptedStorage` itself.
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        self.inner.store_token(token).await
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        self.inner.get_token(token_id).await
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        self.inner.get_token_by_access_token(access_token).await
    }

    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        self.inner.update_token(token).await
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        self.inner.delete_token(token_id).await
    }

    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        self.inner.list_user_tokens(user_id).await
    }

    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()> {
        self.inner.store_session(session_id, data).await
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        self.inner.get_session(session_id).await
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        self.inner.delete_session(session_id).await
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        self.inner.list_user_sessions(user_id).await
    }

    async fn count_active_sessions(&self) -> Result<u64> {
        self.inner.count_active_sessions().await
    }

    // Key-value methods — encrypted, with the storage key itself as AAD so
    // a ciphertext can't be swapped between records.
    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()> {
        let encrypted_value = self.encryption.encrypt_for_storage(value, key.as_bytes())?;
        self.inner.store_kv(key, &encrypted_value, ttl).await
    }

    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let Some(raw) = self.inner.get_kv(key).await? else {
            return Ok(None);
        };

        // Backward compatibility for data written before encryption was
        // turned on (or before this wrapper existed at all): a value that
        // isn't one of our envelopes is read back as plaintext rather
        // than failing to decrypt. New writes always go through
        // `store_kv` above, which always encrypts -- so a deployment
        // converges to fully encrypted as rows are naturally rewritten,
        // and [`migrate_kv_to_encrypted`] can force that conversion for
        // rows that are never rewritten on their own.
        if !StorageEncryption::looks_like_envelope(&raw) {
            return Ok(Some(raw));
        }

        let decrypted_data = self.encryption.decrypt_from_storage(&raw, key.as_bytes())?;
        Ok(Some(decrypted_data))
    }

    async fn delete_kv(&self, key: &str) -> Result<()> {
        self.inner.delete_kv(key).await
    }

    // Key NAMES are never encrypted (only values) -- pass through
    // unchanged so RBAC role reload, maintenance/backup, and analytics
    // (all of which call this) keep working once this wrapper is in the
    // default path. Without this override, the AuthStorage trait's
    // default implementation silently returns an empty Vec.
    async fn list_kv_keys(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list_kv_keys(prefix).await
    }

    async fn cleanup_expired(&self) -> Result<()> {
        self.inner.cleanup_expired().await
    }
}

/// Outcome of [`migrate_kv_to_encrypted`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KvEncryptionMigrationReport {
    /// Whether this run was a dry run (no writes performed).
    pub dry_run: bool,
    /// Total keys examined under the given prefix.
    pub scanned: u64,
    /// Keys that were already an encrypted envelope -- left untouched.
    pub already_encrypted: u64,
    /// Keys that were plaintext and got encrypted (or would have, in a
    /// dry run).
    pub encrypted: u64,
    /// Keys that were read but had vanished by the time of the write-back
    /// (concurrent deletion) -- not an error, just skipped.
    pub vanished: u64,
}

/// Re-encrypts every already-plaintext value under `prefix` in the given
/// KV storage, in place.
///
/// - **Idempotent and resumable**: a value that's already one of this
///   module's encrypted envelopes ([`StorageEncryption::looks_like_envelope`])
///   is left untouched. Re-running this function (e.g. after it was
///   interrupted, or just to confirm nothing is left) only ever touches
///   the plaintext values still remaining -- there's no separate resume
///   cursor to manage.
/// - **Dry-run first**: pass `dry_run: true` to get an accurate
///   [`KvEncryptionMigrationReport`] without writing anything.
/// - **Never logs plaintext**: this function does not log key values at
///   any point, encrypted or not (only aggregate counts); callers should
///   preserve that if they add their own logging around it.
///
/// `storage` and `encryption` are the same values the caller would pass to
/// [`EncryptedStorage::new`] -- this function talks to the *inner*,
/// unwrapped storage directly, since [`EncryptedStorage::get_kv`] would
/// already transparently decrypt (and thus hide which rows still need
/// migrating).
///
/// **Known limitation:** [`AuthStorage::get_kv`] doesn't return a value's
/// remaining TTL, so a migrated value is re-stored with no TTL (it becomes
/// non-expiring) even if the original had one. This is safe for the
/// durable secrets this migration is meant for (API keys, TOTP secrets,
/// client registries), which are not normally TTL'd, but operators storing
/// short-lived data under the given `prefix` should confirm that first.
pub async fn migrate_kv_to_encrypted<S: AuthStorage + ?Sized>(
    storage: &S,
    encryption: &StorageEncryption,
    prefix: &str,
    dry_run: bool,
) -> Result<KvEncryptionMigrationReport> {
    let mut report = KvEncryptionMigrationReport {
        dry_run,
        ..Default::default()
    };

    let keys = storage.list_kv_keys(prefix).await?;
    report.scanned = keys.len() as u64;

    for key in keys {
        let Some(raw) = storage.get_kv(&key).await? else {
            // Deleted concurrently between list_kv_keys and get_kv.
            report.vanished += 1;
            continue;
        };

        if StorageEncryption::looks_like_envelope(&raw) {
            report.already_encrypted += 1;
            continue;
        }

        report.encrypted += 1;
        if !dry_run {
            let envelope = encryption.encrypt_for_storage(&raw, key.as_bytes())?;
            storage.store_kv(&key, &envelope, None).await?;
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[test]
    fn test_key_generation() {
        let key = StorageEncryption::generate_key();
        assert!(!key.is_empty());
        let decoded = BASE64.decode(&key).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let enc = StorageEncryption::new_random();
        let plaintext = b"super secret totp seed, not utf8 safe either: \xff\xfe";
        let encrypted = enc.encrypt(plaintext, b"user:alice:totp_secret").unwrap();
        let decrypted = enc.decrypt(&encrypted, b"user:alice:totp_secret").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Proves the AAD actually binds the ciphertext to its storage key:
    /// decrypting under a DIFFERENT aad than it was encrypted with must
    /// fail, not silently succeed with wrong-but-plausible plaintext. This
    /// is the mechanism that stops a ciphertext from being swapped between
    /// two records.
    #[test]
    fn test_decrypt_rejects_wrong_aad() {
        let enc = StorageEncryption::new_random();
        let encrypted = enc
            .encrypt(b"alice's secret", b"user:alice:totp_secret")
            .unwrap();
        let result = enc.decrypt(&encrypted, b"user:bob:totp_secret");
        assert!(
            result.is_err(),
            "decrypting with the wrong AAD (a different record's key) must fail"
        );
    }

    /// Proves nonces are actually random per call, not reused -- the
    /// security of AES-GCM depends on this. Encrypts the same plaintext
    /// many times and checks every nonce is unique.
    #[test]
    fn test_nonces_are_unique_across_many_encryptions() {
        let enc = StorageEncryption::new_random();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let encrypted = enc
                .encrypt(b"same plaintext every time", b"same:aad")
                .unwrap();
            assert_eq!(
                BASE64.decode(&encrypted.nonce).unwrap().len(),
                12,
                "nonce must be 96 bits"
            );
            assert!(
                seen.insert(encrypted.nonce.clone()),
                "nonce reused across encryptions -- this breaks AES-GCM's security guarantee"
            );
        }
    }

    #[test]
    fn test_storage_roundtrip_non_utf8_bytes() {
        let enc = StorageEncryption::new_random();
        let raw_salt: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x80, 0x81];
        let stored = enc.encrypt_for_storage(raw_salt, b"salt:key").unwrap();
        let restored = enc.decrypt_from_storage(&stored, b"salt:key").unwrap();
        assert_eq!(restored, raw_salt);
    }

    /// A key provider that resolves to no usable key at all must make
    /// construction fail, not silently produce a `StorageEncryption` that
    /// can't actually encrypt anything (e.g. by skipping encryption).
    struct EmptyKeyProvider;
    impl KeyProvider for EmptyKeyProvider {
        fn load_keys(&self) -> Result<LoadedKeys> {
            Err(AuthError::config("no key configured (test)"))
        }
    }

    #[test]
    fn test_construction_fails_closed_with_no_key() {
        let result = StorageEncryption::new(&EmptyKeyProvider);
        assert!(
            result.is_err(),
            "StorageEncryption::new must fail, not silently construct an unusable/no-op encryptor"
        );
    }

    /// Key rotation: an envelope encrypted under an OLD key must still
    /// decrypt once the current key id has moved on, as long as the old
    /// key is still present in the loaded key set.
    struct TwoKeyProvider {
        current_id: String,
        old_key: [u8; 32],
        new_key: [u8; 32],
        old_id: String,
    }
    impl KeyProvider for TwoKeyProvider {
        fn load_keys(&self) -> Result<LoadedKeys> {
            let mut keys = HashMap::new();
            keys.insert(self.old_id.clone(), self.old_key);
            keys.insert(self.current_id.clone(), self.new_key);
            Ok(LoadedKeys {
                current_key_id: self.current_id.clone(),
                keys,
            })
        }
    }

    #[test]
    fn test_old_key_still_decrypts_after_rotation() {
        let old_provider_only = {
            let mut keys = HashMap::new();
            keys.insert("1".to_string(), [7u8; 32]);
            LoadedKeys {
                current_key_id: "1".to_string(),
                keys,
            }
        };
        struct OldOnly(LoadedKeys);
        impl KeyProvider for OldOnly {
            fn load_keys(&self) -> Result<LoadedKeys> {
                Ok(LoadedKeys {
                    current_key_id: self.0.current_key_id.clone(),
                    keys: self.0.keys.clone(),
                })
            }
        }
        let enc_before_rotation = StorageEncryption::new(&OldOnly(LoadedKeys {
            current_key_id: old_provider_only.current_key_id.clone(),
            keys: old_provider_only.keys.clone(),
        }))
        .unwrap();
        let old_envelope = enc_before_rotation
            .encrypt(b"written before rotation", b"some:key")
            .unwrap();
        assert_eq!(old_envelope.key_id, "1");

        // Now rotate: current key id moves to "2", but "1" is kept around.
        let provider = TwoKeyProvider {
            current_id: "2".to_string(),
            old_id: "1".to_string(),
            old_key: [7u8; 32],
            new_key: [9u8; 32],
        };
        let enc_after_rotation = StorageEncryption::new(&provider).unwrap();

        // New writes use the new key.
        let new_envelope = enc_after_rotation
            .encrypt(b"written after rotation", b"some:key")
            .unwrap();
        assert_eq!(new_envelope.key_id, "2");

        // The OLD envelope (key_id "1") must still decrypt.
        let decrypted_old = enc_after_rotation
            .decrypt(&old_envelope, b"some:key")
            .unwrap();
        assert_eq!(decrypted_old, b"written before rotation");
    }

    #[tokio::test]
    async fn test_list_kv_keys_passes_through_unencrypted() {
        let inner = MemoryStorage::new();
        inner
            .store_kv("prefix:a", b"ignored by this test", None)
            .await
            .unwrap();
        inner
            .store_kv("prefix:b", b"ignored by this test", None)
            .await
            .unwrap();
        let wrapped = EncryptedStorage::new(inner, StorageEncryption::new_random());

        let mut keys = wrapped.list_kv_keys("prefix:").await.unwrap();
        keys.sort();
        assert_eq!(
            keys,
            vec!["prefix:a".to_string(), "prefix:b".to_string()],
            "list_kv_keys must pass through to the inner backend, not use the trait's \
             empty-Vec default"
        );
    }

    #[tokio::test]
    async fn test_encrypted_storage_roundtrip() {
        let inner = MemoryStorage::new();
        let wrapped = EncryptedStorage::new(inner, StorageEncryption::new_random());

        wrapped
            .store_kv("user:alice:totp_secret", b"JBSWY3DPEHPK3PXP", None)
            .await
            .unwrap();
        let value = wrapped.get_kv("user:alice:totp_secret").await.unwrap();
        assert_eq!(value, Some(b"JBSWY3DPEHPK3PXP".to_vec()));
    }

    /// Proves the wrapper actually changes what's on disk/in the backend
    /// -- reading through the INNER storage directly (bypassing
    /// `EncryptedStorage`) must NOT show the plaintext.
    #[tokio::test]
    async fn test_encrypted_storage_actually_encrypts_the_underlying_value() {
        let wrapped = EncryptedStorage::new(MemoryStorage::new(), StorageEncryption::new_random());

        wrapped
            .store_kv("user:alice:totp_secret", b"JBSWY3DPEHPK3PXP", None)
            .await
            .unwrap();

        let inner = wrapped.into_inner();
        let raw = inner
            .get_kv("user:alice:totp_secret")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            raw,
            b"JBSWY3DPEHPK3PXP".to_vec(),
            "the underlying storage must not hold the plaintext value"
        );
        assert!(
            StorageEncryption::looks_like_envelope(&raw),
            "the underlying storage must hold a proper encrypted envelope"
        );
    }

    /// A value stored by some pre-encryption version of the framework (or
    /// while `storage_encryption.enabled = false`) must still be readable
    /// after encryption is turned on, not error out because it isn't a
    /// valid envelope.
    #[tokio::test]
    async fn test_reads_legacy_plaintext_without_error() {
        let inner = MemoryStorage::new();
        inner
            .store_kv("legacy:key", b"pre-existing plaintext value", None)
            .await
            .unwrap();
        let wrapped = EncryptedStorage::new(inner, StorageEncryption::new_random());

        let value = wrapped.get_kv("legacy:key").await.unwrap();
        assert_eq!(value, Some(b"pre-existing plaintext value".to_vec()));
    }

    #[tokio::test]
    async fn test_migration_dry_run_reports_without_writing() {
        let storage = MemoryStorage::new();
        storage
            .store_kv("secret:a", b"plaintext-a", None)
            .await
            .unwrap();
        storage
            .store_kv("secret:b", b"plaintext-b", None)
            .await
            .unwrap();
        let encryption = StorageEncryption::new_random();

        let report = migrate_kv_to_encrypted(&storage, &encryption, "secret:", true)
            .await
            .unwrap();

        assert!(report.dry_run);
        assert_eq!(report.scanned, 2);
        assert_eq!(report.encrypted, 2);
        assert_eq!(report.already_encrypted, 0);

        // Dry run must not have written anything.
        let still_plaintext = storage.get_kv("secret:a").await.unwrap().unwrap();
        assert_eq!(still_plaintext, b"plaintext-a".to_vec());
    }

    #[tokio::test]
    async fn test_migration_encrypts_plaintext_values() {
        let storage = MemoryStorage::new();
        storage
            .store_kv("secret:a", b"plaintext-a", None)
            .await
            .unwrap();
        let encryption = StorageEncryption::new_random();

        let report = migrate_kv_to_encrypted(&storage, &encryption, "secret:", false)
            .await
            .unwrap();
        assert_eq!(report.encrypted, 1);

        let raw = storage.get_kv("secret:a").await.unwrap().unwrap();
        assert!(StorageEncryption::looks_like_envelope(&raw));
        let decrypted = encryption.decrypt_from_storage(&raw, b"secret:a").unwrap();
        assert_eq!(decrypted, b"plaintext-a".to_vec());
    }

    /// Proves idempotency and resumability: running the migration a
    /// second time over a mix of already-migrated and still-plaintext
    /// keys (simulating an interrupted first run) must not re-encrypt
    /// (double-encrypt) the already-done ones, and must finish the rest.
    #[tokio::test]
    async fn test_migration_is_idempotent_and_resumable() {
        let storage = MemoryStorage::new();
        storage
            .store_kv("secret:a", b"plaintext-a", None)
            .await
            .unwrap();
        storage
            .store_kv("secret:b", b"plaintext-b", None)
            .await
            .unwrap();
        let encryption = StorageEncryption::new_random();

        // Simulate a first run that only got through "secret:a" before
        // being interrupted.
        let envelope_a = encryption
            .encrypt_for_storage(b"plaintext-a", b"secret:a")
            .unwrap();
        storage
            .store_kv("secret:a", &envelope_a, None)
            .await
            .unwrap();

        // Resume: should skip "secret:a" (already encrypted) and finish
        // "secret:b".
        let report = migrate_kv_to_encrypted(&storage, &encryption, "secret:", false)
            .await
            .unwrap();
        assert_eq!(report.scanned, 2);
        assert_eq!(report.already_encrypted, 1);
        assert_eq!(report.encrypted, 1);

        let raw_a_after = storage.get_kv("secret:a").await.unwrap().unwrap();
        assert_eq!(
            raw_a_after, envelope_a,
            "an already-encrypted value must be left byte-for-byte unchanged, not double-encrypted"
        );
        let raw_b_after = storage.get_kv("secret:b").await.unwrap().unwrap();
        assert!(StorageEncryption::looks_like_envelope(&raw_b_after));

        // Running it again changes nothing further.
        let report2 = migrate_kv_to_encrypted(&storage, &encryption, "secret:", false)
            .await
            .unwrap();
        assert_eq!(report2.already_encrypted, 2);
        assert_eq!(report2.encrypted, 0);
    }

    #[tokio::test]
    async fn test_migration_only_touches_matching_prefix() {
        let storage = MemoryStorage::new();
        storage
            .store_kv("secret:a", b"plaintext-a", None)
            .await
            .unwrap();
        storage
            .store_kv("other:b", b"plaintext-b", None)
            .await
            .unwrap();
        let encryption = StorageEncryption::new_random();

        let report = migrate_kv_to_encrypted(&storage, &encryption, "secret:", false)
            .await
            .unwrap();
        assert_eq!(report.scanned, 1);

        let other_untouched = storage.get_kv("other:b").await.unwrap().unwrap();
        assert_eq!(
            other_untouched,
            b"plaintext-b".to_vec(),
            "a key outside the given prefix must not be touched"
        );
    }
}
