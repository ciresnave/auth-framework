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
use zeroize::Zeroize;

/// Serializes every test anywhere in this crate's lib-unit-test binary
/// that reads or writes `AUTH_STORAGE_ENCRYPTION_KEY`/
/// `AUTH_STORAGE_ENCRYPTION_KEYS_FILE`, since those are process-global
/// state shared across all tests running in parallel threads within one
/// `cargo test --lib` invocation. Acquire this (and clean up the env var
/// via [`EncryptionEnvGuard`], not a bare `set_var`/`remove_var` pair) in
/// any test that touches those variables.
/// A `tokio::sync::Mutex`, not `std::sync::Mutex`, because several callers
/// (in `#[tokio::test]` functions) need to hold this guard across `.await`
/// points -- use `.lock().await` there, or `.blocking_lock()` in a plain
/// (non-async) `#[test]`.
#[cfg(test)]
pub(crate) static TEST_ENCRYPTION_ENV_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

/// RAII guard that sets `AUTH_STORAGE_ENCRYPTION_KEY` for the lifetime of
/// the guard and removes it on drop -- including on an early return or a
/// panic (e.g. from an `assert!`/`.unwrap()` failure), unlike a bare
/// `set_var` at the top of a test and a `remove_var` at the bottom, which
/// leaks the variable if the test fails before reaching that last line.
/// Callers should hold [`TEST_ENCRYPTION_ENV_LOCK`] for the guard's entire
/// lifetime.
#[cfg(test)]
pub(crate) struct EncryptionEnvGuard;

#[cfg(test)]
impl EncryptionEnvGuard {
    pub(crate) fn set(key: &str) -> Self {
        unsafe {
            std::env::set_var("AUTH_STORAGE_ENCRYPTION_KEY", key);
            std::env::remove_var("AUTH_STORAGE_ENCRYPTION_KEYS_FILE");
        }
        Self
    }
}

#[cfg(test)]
impl Drop for EncryptionEnvGuard {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var("AUTH_STORAGE_ENCRYPTION_KEY");
        }
    }
}

/// Current envelope format version. Bumped whenever the envelope's fields
/// or decryption rules change in a way that needs disambiguating from
/// older data still on disk.
const CURRENT_FORMAT_VERSION: u8 = 1;

fn default_format_version() -> u8 {
    // Envelopes serialized before this field existed (format version 0,
    // the original public `EncryptedStorage`: fields `data`/`nonce`/
    // `algorithm`/`key_derivation`, no `key_id`, no AAD at encryption
    // time) deserialize with this field absent -- serde DOES call this
    // function in that case (per `#[serde(default = "...")]`'s actual
    // behavior), which happens to return the same `0` the bare type
    // default would. It's spelled out explicitly, rather than relying on
    // `#[serde(default)]`'s type-default shorthand, so the "absent field
    // means format version 0" rule is visible at the field's definition
    // instead of implicit in `u8::default()`.
    0
}

/// Encrypted data container with metadata.
///
/// `key_id` makes this a versioned envelope: a value encrypted under one key
/// can still be decrypted after the *current* key rotates, as long as the
/// old key is still loadable (see [`KeyProvider`]). Writers always use the
/// current key; readers look up whichever key the envelope names.
///
/// `v` and `key_derivation` exist for backward compatibility with the
/// original, pre-this-redesign public `EncryptedStorage` (format version
/// 0): that format had no `key_id` and no AAD binding at encryption time.
/// An envelope with `v == 0` (including any envelope missing the `v` field
/// entirely, since `#[serde(default)]` fills it with `0`) is decrypted
/// against every loaded key with an empty AAD, matching the old behavior;
/// see [`StorageEncryption::decrypt`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Base64 encoded encrypted data
    pub data: String,
    /// Base64 encoded nonce/IV (96 bits, randomly generated per encryption)
    pub nonce: String,
    /// Algorithm identifier
    pub algorithm: String,
    /// Which key (by id) encrypted this value. Empty for format version 0
    /// (the original `EncryptedStorage`, which had no key-id concept).
    #[serde(default)]
    pub key_id: String,
    /// Envelope format version. `0` (including an absent field, which
    /// deserializes to `0`) is the original pre-redesign format; `1` is
    /// the current format (versioned `key_id`, AAD-bound encryption).
    #[serde(default = "default_format_version")]
    pub v: u8,
    /// Present only for format-version-0 compatibility (the original
    /// field name was `key_derivation`); current envelopes don't set it.
    #[serde(default)]
    pub key_derivation: String,
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
    /// All loadable keys, including the current one, by key id. A key id
    /// must not be empty -- [`StorageEncryption::new`] rejects any that
    /// are, since an empty id can't be told apart from format-version-0
    /// envelopes (which have no key id at all).
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
///   here. If set, this takes priority over the two env vars above. On
///   Unix, a keys file readable by group or other triggers a `tracing::warn!`
///   (best-effort; not enforced, and not checked at all on Windows).
pub struct EnvKeyProvider;

impl KeyProvider for EnvKeyProvider {
    fn load_keys(&self) -> Result<LoadedKeys> {
        if let Ok(path) = env::var("AUTH_STORAGE_ENCRYPTION_KEYS_FILE") {
            return Self::load_from_file(&path);
        }

        let mut key_data = env::var("AUTH_STORAGE_ENCRYPTION_KEY").map_err(|_| {
            AuthError::config(
                "No storage encryption key configured: set AUTH_STORAGE_ENCRYPTION_KEY \
                 (or AUTH_STORAGE_ENCRYPTION_KEYS_FILE for multi-key rotation). \
                 Refusing to start rather than silently storing data unencrypted.",
            )
        })?;
        let key_id = env::var("AUTH_STORAGE_ENCRYPTION_KEY_ID").unwrap_or_else(|_| "1".to_string());
        let key = decode_key(&key_data);
        key_data.zeroize();
        let key = key?;

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

        Self::warn_if_file_too_permissive(path);

        let mut contents = fs::read_to_string(path).map_err(|e| {
            AuthError::config(format!(
                "Failed to read AUTH_STORAGE_ENCRYPTION_KEYS_FILE '{path}': {e}"
            ))
        })?;
        let parsed: Result<KeysFile> = serde_json::from_str(&contents).map_err(|e| {
            AuthError::config(format!(
                "Failed to parse AUTH_STORAGE_ENCRYPTION_KEYS_FILE '{path}': {e}"
            ))
        });
        contents.zeroize();
        let parsed = parsed?;

        if !parsed.keys.contains_key(&parsed.current) {
            return Err(AuthError::config(format!(
                "AUTH_STORAGE_ENCRYPTION_KEYS_FILE '{path}': current key id '{}' \
                 is not present in 'keys'",
                parsed.current
            )));
        }

        let mut keys = HashMap::new();
        for (id, mut encoded) in parsed.keys {
            let key = decode_key(&encoded);
            encoded.zeroize();
            keys.insert(id, key?);
        }

        Ok(LoadedKeys {
            current_key_id: parsed.current,
            keys,
        })
    }

    /// Best-effort, Unix-only warning: a keys file readable by group or
    /// other defeats the point of a file-based key. Not enforced (never
    /// blocks startup) because permission semantics vary too much across
    /// deployment environments (containers, CI, Windows) to safely hard-fail.
    #[cfg(unix)]
    fn warn_if_file_too_permissive(path: &str) {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = path,
                    mode = format!("{mode:o}"),
                    "AUTH_STORAGE_ENCRYPTION_KEYS_FILE is readable by group or other -- \
                     restrict it to the owner only (chmod 600)."
                );
            }
        }
    }

    #[cfg(not(unix))]
    fn warn_if_file_too_permissive(_path: &str) {}
}

fn decode_key(encoded: &str) -> Result<[u8; 32]> {
    let mut key_bytes = BASE64
        .decode(encoded)
        .map_err(|_| AuthError::config("Invalid base64 in storage encryption key"))?;
    if key_bytes.len() != 32 {
        key_bytes.zeroize();
        return Err(AuthError::config(
            "Storage encryption key must be 32 bytes (256 bits) once base64-decoded",
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    key_bytes.zeroize();
    Ok(key)
}

/// Storage encryption manager using AES-256-GCM, with per-record random
/// nonces and associated data (AAD) binding each ciphertext to the storage
/// key it was stored under -- so a ciphertext copied from one record to
/// another fails to decrypt instead of silently "succeeding" with the
/// wrong value.
///
/// **Known limitation (replay of an older value under the same key):** AAD
/// binds a ciphertext to *which record* it belongs to, not to *when* it was
/// written. Someone who can both read an old ciphertext for a given key and
/// write to that same key can replay the old value -- AES-GCM's
/// authentication only proves "this is a genuine envelope for this record,"
/// not "this is the most recent one." Mitigating this needs a monotonic
/// counter or timestamp bound into the AAD, not done here (most KV-layer
/// values in this crate are replaced wholesale on every write, which bounds
/// but does not eliminate the exposure).
///
/// **Zeroization scope (accurate, not aspirational):** this module
/// zeroizes raw key material it owns as soon as it's done with it -- the
/// `[u8; 32]` key bytes in [`LoadedKeys`] (after the AES-GCM ciphers are
/// built), [`decode_key`]'s intermediate decoded `Vec<u8>`, and the
/// base64-encoded key strings/file contents read by [`EnvKeyProvider`].
/// It does **not** zeroize: any copy the standard library or `aes-gcm`
/// makes internally that this code doesn't control (notably `aes` 0.8.4's
/// own key-schedule storage inside the `Aes256Gcm` cipher object, which
/// has no zeroize support in the version this crate depends on), or a
/// plaintext value this module decrypts and hands back to its caller
/// (that's the actual return value the caller needs -- it isn't leftover
/// residue to clean up).
pub struct StorageEncryption {
    current_key_id: String,
    ciphers: HashMap<String, Aes256Gcm>,
}

impl StorageEncryption {
    /// Create a new encryption manager, loading keys from the given
    /// provider. Fails closed: if the provider can't load a usable key,
    /// this returns `Err` rather than any fallback.
    pub fn new(provider: &dyn KeyProvider) -> Result<Self> {
        let mut loaded = provider.load_keys()?;
        if loaded.current_key_id.is_empty() {
            return Err(AuthError::config(
                "Key provider's current_key_id must not be empty",
            ));
        }
        if loaded.keys.keys().any(|id| id.is_empty()) {
            return Err(AuthError::config(
                "Key provider returned a key with an empty id -- an empty id is reserved \
                 to mean \"format-version-0 envelope, no key id at all\"",
            ));
        }
        if !loaded.keys.contains_key(&loaded.current_key_id) {
            return Err(AuthError::config(format!(
                "Key provider's current_key_id '{}' is not among the keys it loaded",
                loaded.current_key_id
            )));
        }
        let ciphers = loaded
            .keys
            .iter()
            .map(|(id, key_bytes)| {
                let key = Key::<Aes256Gcm>::from_slice(key_bytes);
                (id.clone(), Aes256Gcm::new(key))
            })
            .collect();
        // The cipher objects above have their own internal copies of the
        // key material; zeroize the raw bytes we held so they don't sit
        // around in this struct any longer than necessary.
        for key_bytes in loaded.keys.values_mut() {
            key_bytes.zeroize();
        }
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
        key_bytes.zeroize();
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
        let encoded = BASE64.encode(key_bytes);
        key_bytes.zeroize();
        encoded
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

        // 96-bit nonce, freshly random every call. NIST SP 800-38D caps a
        // randomly generated 96-bit IV at 2^32 invocations under a single
        // key before the collision probability becomes unacceptable (the
        // "32-bit random IV construction" guidance) -- not the ~2^64/2
        // birthday bound a naive calculation might suggest. A given
        // deployment's key should be rotated well before approaching that
        // count; this crate does not currently track or enforce it.
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
            v: CURRENT_FORMAT_VERSION,
            key_derivation: String::new(),
        })
    }

    /// Decrypt an envelope. `aad` must match exactly what was passed to
    /// [`Self::encrypt`] (the storage key the envelope is stored under) --
    /// a mismatch (e.g. a ciphertext copied to a different record) fails
    /// decryption rather than succeeding with the wrong plaintext.
    ///
    /// A format-version-0 envelope (see [`EncryptedData`]) is decrypted
    /// with an empty AAD against every loaded key in turn, matching the
    /// original `EncryptedStorage`'s behavior (no AAD, no key id) --
    /// AES-GCM's authentication tag makes trying the wrong key safe (it
    /// just fails), so this cannot silently produce the wrong plaintext.
    pub fn decrypt(&self, encrypted: &EncryptedData, aad: &[u8]) -> Result<Vec<u8>> {
        if encrypted.algorithm != "AES-256-GCM" {
            return Err(AuthError::internal(format!(
                "Unsupported encryption algorithm: {}",
                encrypted.algorithm
            )));
        }

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

        if encrypted.v == 0 {
            // Format version 0 (the original EncryptedStorage): no key id,
            // no AAD. Try every loaded key; the auth tag rejects wrong ones.
            for cipher in self.ciphers.values() {
                if let Ok(plaintext) = cipher.decrypt(
                    nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: b"",
                    },
                ) {
                    return Ok(plaintext);
                }
            }
            return Err(AuthError::internal(
                "Failed to decrypt format-version-0 envelope with any loaded key",
            ));
        }

        let cipher = self.ciphers.get(&encrypted.key_id).ok_or_else(|| {
            AuthError::internal(format!(
                "No loaded key for key_id '{}' -- it may have been rotated out \
                 without being kept in the keys file for decrypt-only use",
                encrypted.key_id
            ))
        })?;

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

    /// Parses `data` as one of this module's own serialized envelopes --
    /// either the current format or the original format-version-0 shape
    /// (see [`EncryptedData`]) -- without attempting to decrypt it. `None`
    /// if `data` isn't valid UTF-8 JSON, or doesn't name the right
    /// algorithm.
    ///
    /// This is a **shape** check only. A value that parses here but fails
    /// to decrypt (wrong key, corrupted, or tampered with) is a hard error
    /// from [`Self::decrypt_from_storage`], never silently treated as
    /// plaintext.
    pub fn parse_envelope(data: &[u8]) -> Option<EncryptedData> {
        let encrypted = std::str::from_utf8(data)
            .ok()
            .and_then(|s| serde_json::from_str::<EncryptedData>(s).ok())?;
        if encrypted.algorithm == "AES-256-GCM" {
            Some(encrypted)
        } else {
            None
        }
    }

    /// Returns `true` if `data` parses as one of this module's own
    /// serialized envelopes. Used by [`migrate_kv_to_encrypted`] and
    /// [`EncryptedStorage::get_kv`] to decide whether a stored value
    /// should be decrypted at all.
    pub fn looks_like_envelope(data: &[u8]) -> bool {
        Self::parse_envelope(data).is_some()
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
    /// See [`Self::get_kv`]'s doc comment for exactly what this controls.
    allow_plaintext_reads: bool,
    /// See [`Self::get_kv`]'s doc comment for exactly what this controls.
    allow_legacy_v0: bool,
}

impl<T> EncryptedStorage<T> {
    /// `allow_plaintext_reads` should be `true` only transiently, while
    /// migrating an existing deployment's plaintext data (see
    /// [`migrate_kv_to_encrypted`]) -- it is what makes [`Self::get_kv`]
    /// tolerate a value that isn't a valid envelope instead of erroring.
    /// Leaving it `true` permanently means anyone who can write to the
    /// backing store can overwrite an encrypted value with chosen
    /// plaintext (or corrupt one) and have it accepted silently, which
    /// defeats the point of encrypting at rest. Pass `false` for normal
    /// operation.
    ///
    /// `allow_legacy_v0` should likewise be `true` only transiently, while
    /// migrating pre-existing format-version-0 data: a v0 envelope has no
    /// AAD binding it to its own storage key, so with this `true`, a
    /// writer who knows one record's v0 envelope can copy it onto a
    /// different record's key and it still decrypts -- the exact swap the
    /// current format's AAD exists to prevent. [`migrate_kv_to_encrypted`]
    /// upgrades every v0 envelope it finds to the current format
    /// regardless of this flag (it talks to the inner storage directly,
    /// bypassing this policy check), so this only needs to be `true` if
    /// something *other* than the migration tool needs to read v0 data
    /// through this wrapper before migration runs.
    pub fn new(
        storage: T,
        encryption: StorageEncryption,
        allow_plaintext_reads: bool,
        allow_legacy_v0: bool,
    ) -> Self {
        Self {
            inner: storage,
            encryption,
            allow_plaintext_reads,
            allow_legacy_v0,
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

    // Bulk methods — delegate directly to `inner`'s own overrides (if any)
    // instead of inheriting the `AuthStorage` trait's one-at-a-time default
    // loop, so a backend that implements real batching here keeps that
    // benefit even when wrapped. Token/session bulk methods are unaffected
    // by encryption (see the coverage note above) either way.
    async fn store_tokens_bulk(&self, tokens: &[AuthToken]) -> Result<()> {
        self.inner.store_tokens_bulk(tokens).await
    }

    async fn delete_tokens_bulk(&self, token_ids: &[String]) -> Result<()> {
        self.inner.delete_tokens_bulk(token_ids).await
    }

    async fn store_sessions_bulk(&self, sessions: &[(String, SessionData)]) -> Result<()> {
        self.inner.store_sessions_bulk(sessions).await
    }

    async fn delete_sessions_bulk(&self, session_ids: &[String]) -> Result<()> {
        self.inner.delete_sessions_bulk(session_ids).await
    }

    // Key-value methods — encrypted, with the storage key itself as AAD so
    // a ciphertext can't be swapped between records.
    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()> {
        let encrypted_value = self.encryption.encrypt_for_storage(value, key.as_bytes())?;
        self.inner.store_kv(key, &encrypted_value, ttl).await
    }

    /// Reads back a value stored by [`Self::store_kv`], decrypting it.
    ///
    /// A value that **parses as one of this module's envelopes**
    /// ([`StorageEncryption::looks_like_envelope`]) is always decrypted;
    /// a decryption failure (wrong key, corrupted, tampered) is a hard
    /// `Err`, never silently returned as-is.
    ///
    /// A value that does **not** parse as an envelope at all is ambiguous:
    /// it could be genuine pre-encryption plaintext, or it could be a
    /// plaintext value an attacker (or a bug) overwrote the encrypted one
    /// with. This method only tolerates that ambiguity -- returning the
    /// raw bytes as-is -- when `allow_plaintext_reads` is `true`. With it
    /// `false` (the default via the storage factory once migration is
    /// done), a non-envelope value is also a hard `Err`, so overwriting an
    /// encrypted record with plaintext cannot silently succeed.
    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let Some(raw) = self.inner.get_kv(key).await? else {
            return Ok(None);
        };

        if let Some(envelope) = StorageEncryption::parse_envelope(&raw) {
            if envelope.v == 0 && !self.allow_legacy_v0 {
                return Err(AuthError::internal(format!(
                    "Value for key '{key}' is a format-version-0 envelope (no AAD binding \
                     it to its own storage key), and storage_encryption.allow_legacy_v0 is \
                     false. Run the migration tool (`auth-framework-admin security \
                     encrypt-kv`) to upgrade it to the current format -- that does not \
                     require this flag -- or temporarily set \
                     storage_encryption.allow_legacy_v0 = true if something else needs to \
                     read it first."
                )));
            }
            let decrypted = self.encryption.decrypt(&envelope, key.as_bytes())?;
            return Ok(Some(decrypted));
        }

        if self.allow_plaintext_reads {
            return Ok(Some(raw));
        }

        Err(AuthError::internal(format!(
            "Value for key '{key}' is not a valid encrypted envelope, and \
             storage_encryption.allow_plaintext_reads is false. If this key genuinely \
             predates encryption being enabled, run the migration tool \
             (`auth-framework-admin security encrypt-kv`) or temporarily set \
             storage_encryption.allow_plaintext_reads = true while migrating."
        )))
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
    /// Keys that were already a current-format envelope -- left
    /// untouched.
    pub already_encrypted: u64,
    /// Keys that were a format-version-0 envelope (no AAD, no key id)
    /// and got rewritten under the current format (or would have, in a
    /// dry run). See [`migrate_kv_to_encrypted`]'s own docs for why this
    /// matters: a v0 envelope has no protection against being copied onto
    /// a different record's key, regardless of any config flag.
    pub upgraded_from_legacy: u64,
    /// Keys that were plaintext (not an envelope at all) and got
    /// encrypted (or would have, in a dry run).
    pub encrypted: u64,
    /// Keys that were read but had vanished by the time of the write-back
    /// (concurrent deletion) -- not an error, just skipped.
    pub vanished: u64,
}

/// Re-encrypts every already-plaintext value under `prefix` in the given
/// KV storage, in place.
///
/// - **Idempotent and resumable**: a value already in the *current*
///   envelope format is left untouched. A value in the original
///   format-version-0 shape (no AAD, no key id -- see [`EncryptedData`])
///   is decrypted and re-encrypted under the current format, regardless
///   of `storage_encryption.allow_legacy_v0` -- this is how a v0 envelope
///   stops being one, since nothing else in this crate ever upgrades it.
///   Re-running this function (e.g. after it was interrupted) only ever
///   touches the plaintext and v0 values still remaining -- there's no
///   separate resume cursor to manage.
/// - **Dry-run first**: pass `dry_run: true` to get an accurate
///   [`KvEncryptionMigrationReport`] without writing anything.
/// - **Never logs plaintext**: this function does not log key values at
///   any point, encrypted or not (only aggregate counts); callers should
///   preserve that if they add their own logging around it.
/// - **Not safe to run concurrently with live writes to the same keys**:
///   this does a read, then a write-back, with no compare-and-swap. If
///   something else writes a fresh value to a key between this function's
///   read and write, the write-back here overwrites it with the stale
///   value it read. Run this offline, or at least pause writers to the
///   given `prefix`, before running it against a live deployment.
///
/// `storage` and `encryption` are the same values the caller would pass to
/// [`EncryptedStorage::new`] -- this function talks to the *inner*,
/// unwrapped storage directly, since [`EncryptedStorage::get_kv`] would
/// already transparently decrypt (and thus hide which rows still need
/// migrating).
///
/// **Known limitation (TTL loss):** [`AuthStorage::get_kv`] doesn't return
/// a value's remaining TTL, so a migrated value is re-stored with no TTL
/// (it becomes non-expiring) even if the original had one. This is a real
/// risk for TTL'd data such as OAuth authorization codes, email-verification
/// tokens, MFA/SMS one-time codes, WebAuthn challenges, rate-limit windows,
/// or expiring API keys: migrating those under a prefix that includes them
/// makes them (and any lockout window keyed the same way) stop expiring.
/// Callers should scope `prefix` to durable-secret namespaces only (API
/// keys, TOTP secrets, client registries) and avoid migrating over the
/// entire KV keyspace in one call; the CLI (`security encrypt-kv`)
/// requires an explicit `--confirm` to use an empty prefix for a real
/// (non-dry-run) application for exactly this reason.
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

        if let Some(envelope) = StorageEncryption::parse_envelope(&raw) {
            if envelope.v >= CURRENT_FORMAT_VERSION {
                report.already_encrypted += 1;
                continue;
            }

            // Format-version-0 envelope: decrypt it (v0 has no AAD, so
            // the key passed here is ignored by `decrypt`'s v0 path --
            // see its own docs) and re-encrypt under the current format
            // with real AAD, regardless of `allow_legacy_v0` -- this
            // function is exactly how a v0 envelope stops being one.
            report.upgraded_from_legacy += 1;
            if !dry_run {
                let plaintext = encryption.decrypt(&envelope, key.as_bytes())?;
                let new_envelope = encryption.encrypt_for_storage(&plaintext, key.as_bytes())?;
                storage.store_kv(&key, &new_envelope, None).await?;
            }
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

    struct FixedKeyProvider(LoadedKeys);
    impl KeyProvider for FixedKeyProvider {
        fn load_keys(&self) -> Result<LoadedKeys> {
            Ok(LoadedKeys {
                current_key_id: self.0.current_key_id.clone(),
                keys: self.0.keys.clone(),
            })
        }
    }

    #[test]
    fn test_construction_rejects_empty_key_id() {
        // current_key_id is non-empty and present in the map (so the
        // separate, earlier checks for "current_key_id is empty" and
        // "current_key_id isn't in the map" don't fire first) -- this
        // specifically exercises the "no key in the map has an empty id"
        // check via a SECOND entry.
        let mut keys = HashMap::new();
        keys.insert("1".to_string(), [1u8; 32]);
        keys.insert(String::new(), [2u8; 32]);
        let result = StorageEncryption::new(&FixedKeyProvider(LoadedKeys {
            current_key_id: "1".to_string(),
            keys,
        }));
        assert!(
            result.is_err(),
            "an empty key id anywhere in the loaded key set must be rejected (it's reserved \
             for format-version-0 envelopes), even when current_key_id itself is valid"
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
        let mut keys = HashMap::new();
        keys.insert("1".to_string(), [7u8; 32]);
        let enc_before_rotation = StorageEncryption::new(&FixedKeyProvider(LoadedKeys {
            current_key_id: "1".to_string(),
            keys,
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

    /// Format-version-0 compatibility: an envelope shaped like the
    /// original (pre-redesign) `EncryptedStorage` produced -- no `key_id`,
    /// no `v`, no AAD at encryption time -- must still decrypt under the
    /// new `StorageEncryption`, since real deployments may already hold
    /// data in that shape.
    #[test]
    fn test_decrypts_format_version_0_envelope() {
        let mut keys = HashMap::new();
        keys.insert("1".to_string(), [3u8; 32]);
        let enc = StorageEncryption::new(&FixedKeyProvider(LoadedKeys {
            current_key_id: "1".to_string(),
            keys,
        }))
        .unwrap();

        // Hand-build a format-version-0 envelope the way the original
        // `EncryptedStorage::encrypt` did: no AAD, no key_id, no v.
        let cipher = {
            let key = Key::<Aes256Gcm>::from_slice(&[3u8; 32]);
            Aes256Gcm::new(key)
        };
        let nonce_bytes = [5u8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, b"legacy-format plaintext".as_ref())
            .unwrap();
        let legacy_json = format!(
            r#"{{"data":"{}","nonce":"{}","algorithm":"AES-256-GCM","key_derivation":"direct"}}"#,
            BASE64.encode(&ciphertext),
            BASE64.encode(nonce_bytes)
        );

        assert!(StorageEncryption::looks_like_envelope(
            legacy_json.as_bytes()
        ));
        let decrypted = enc
            .decrypt_from_storage(legacy_json.as_bytes(), b"irrelevant-for-v0")
            .unwrap();
        assert_eq!(decrypted, b"legacy-format plaintext".to_vec());
    }

    /// Negative case for the v0 downgrade attack: a GENUINE current-format
    /// (v1) envelope, with its `v` and `key_id` fields stripped (so it now
    /// parses as a v0-shaped envelope), must not be accepted as that
    /// record's value. It fails for two independent reasons here -- the
    /// policy check (`allow_legacy_v0: false` by default) rejects it before
    /// any decryption is attempted, and even without that check the
    /// ciphertext itself was sealed with a real (non-empty) AAD, so the v0
    /// path's empty-AAD decrypt attempt would fail the authentication tag
    /// anyway.
    #[tokio::test]
    async fn test_wrapper_rejects_v1_envelope_downgraded_to_look_like_v0() {
        let mut keys = HashMap::new();
        keys.insert("1".to_string(), [4u8; 32]);
        let encryption = StorageEncryption::new(&FixedKeyProvider(LoadedKeys {
            current_key_id: "1".to_string(),
            keys,
        }))
        .unwrap();

        let inner = MemoryStorage::new();
        let wrapped = EncryptedStorage::new(inner, encryption, false, false);

        wrapped
            .store_kv("user:alice:totp_secret", b"real secret", None)
            .await
            .unwrap();

        let inner = wrapped.into_inner();
        let real_envelope: EncryptedData = serde_json::from_slice(
            &inner
                .get_kv("user:alice:totp_secret")
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();

        // Strip the fields a v0 envelope never had, simulating an
        // attacker (or a bug) downgrading a real v1 envelope.
        let downgraded_json = serde_json::json!({
            "data": real_envelope.data,
            "nonce": real_envelope.nonce,
            "algorithm": real_envelope.algorithm,
        })
        .to_string();
        inner
            .store_kv("user:alice:totp_secret", downgraded_json.as_bytes(), None)
            .await
            .unwrap();

        let mut keys2 = HashMap::new();
        keys2.insert("1".to_string(), [4u8; 32]);
        let encryption2 = StorageEncryption::new(&FixedKeyProvider(LoadedKeys {
            current_key_id: "1".to_string(),
            keys: keys2,
        }))
        .unwrap();
        let wrapped = EncryptedStorage::new(inner, encryption2, false, false);

        let result = wrapped.get_kv("user:alice:totp_secret").await;
        assert!(
            result.is_err(),
            "a v1 envelope downgraded to look like v0 must not be accepted as the record's \
             value, with allow_legacy_v0 at its default (false)"
        );
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
        let wrapped = EncryptedStorage::new(inner, StorageEncryption::new_random(), false, false);

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
        let wrapped = EncryptedStorage::new(inner, StorageEncryption::new_random(), false, false);

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
        let wrapped = EncryptedStorage::new(
            MemoryStorage::new(),
            StorageEncryption::new_random(),
            false,
            false,
        );

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

    /// Proves the wrapper's own AAD wiring (not just `StorageEncryption`
    /// directly, which `test_decrypt_rejects_wrong_aad` already covers) --
    /// swapping two records' raw envelopes in the INNER backend must make
    /// both unreadable through the wrapper, because each envelope's AAD no
    /// longer matches the key it's stored under. If the wrapper passed a
    /// constant (e.g. empty) AAD instead of the real key, this swap would
    /// go undetected and both reads would "succeed" with the wrong value.
    #[tokio::test]
    async fn test_wrapper_rejects_ciphertext_swapped_between_records() {
        let mut keys = HashMap::new();
        keys.insert("1".to_string(), [11u8; 32]);
        let loaded = LoadedKeys {
            current_key_id: "1".to_string(),
            keys,
        };
        let encryption_for_wrapper = StorageEncryption::new(&FixedKeyProvider(LoadedKeys {
            current_key_id: loaded.current_key_id.clone(),
            keys: loaded.keys.clone(),
        }))
        .unwrap();
        // An independent `StorageEncryption` built from the SAME key, used
        // only to verify what AAD the wrapper actually used -- never to
        // produce the envelopes under test.
        let encryption_for_verification =
            StorageEncryption::new(&FixedKeyProvider(loaded)).unwrap();

        let inner = MemoryStorage::new();
        let wrapped = EncryptedStorage::new(inner, encryption_for_wrapper, false, false);

        wrapped
            .store_kv("user:alice:totp_secret", b"alice-secret", None)
            .await
            .unwrap();

        let inner = wrapped.into_inner();
        let raw = inner
            .get_kv("user:alice:totp_secret")
            .await
            .unwrap()
            .unwrap();

        // The wrapper must have used the storage key itself as AAD: decrypting
        // with that exact AAD must succeed...
        let decrypted = encryption_for_verification
            .decrypt(
                &serde_json::from_slice(&raw).unwrap(),
                b"user:alice:totp_secret",
            )
            .unwrap();
        assert_eq!(decrypted, b"alice-secret".to_vec());

        // ...and decrypting the SAME envelope under a DIFFERENT record's key
        // name must fail. If the wrapper instead used some constant AAD (the
        // exact mutation this test exists to catch), this swap-style check
        // would succeed instead of failing.
        let wrong_aad_result = encryption_for_verification.decrypt(
            &serde_json::from_slice(&raw).unwrap(),
            b"user:bob:totp_secret",
        );
        assert!(
            wrong_aad_result.is_err(),
            "the wrapper's envelope must not decrypt under a different record's key name -- \
             if it does, the wrapper is using a constant AAD instead of the real storage key"
        );
    }

    /// A value stored by some pre-encryption version of the framework (or
    /// while `storage_encryption.enabled = false`) is readable when
    /// `allow_plaintext_reads` is explicitly true (the migration-window
    /// setting).
    #[tokio::test]
    async fn test_reads_legacy_plaintext_when_allowed() {
        let inner = MemoryStorage::new();
        inner
            .store_kv("legacy:key", b"pre-existing plaintext value", None)
            .await
            .unwrap();
        let wrapped = EncryptedStorage::new(inner, StorageEncryption::new_random(), true, false);

        let value = wrapped.get_kv("legacy:key").await.unwrap();
        assert_eq!(value, Some(b"pre-existing plaintext value".to_vec()));
    }

    /// With `allow_plaintext_reads` false (the normal, post-migration
    /// setting), a value that isn't a valid envelope -- whether genuine
    /// untouched legacy plaintext, a corrupted envelope, or an attacker's
    /// overwrite -- must be a hard error, not silently accepted. This is
    /// the fix for the finding that an attacker able to write to the
    /// backing store could otherwise overwrite an encrypted secret with
    /// chosen plaintext and have it accepted forever.
    #[tokio::test]
    async fn test_rejects_non_envelope_value_when_plaintext_reads_disallowed() {
        let inner = MemoryStorage::new();
        inner
            .store_kv("user:alice:totp_secret", b"attacker-chosen-plaintext", None)
            .await
            .unwrap();
        let wrapped = EncryptedStorage::new(inner, StorageEncryption::new_random(), false, false);

        let result = wrapped.get_kv("user:alice:totp_secret").await;
        assert!(
            result.is_err(),
            "a non-envelope value must be rejected, not silently treated as plaintext, \
             when allow_plaintext_reads is false"
        );
    }

    /// The real fix for the v0-downgrade finding: a format-version-0
    /// envelope must be actively rewritten to the current format by
    /// migration (not just counted as "already encrypted" and left
    /// alone), since nothing else in this crate ever upgrades one.
    #[tokio::test]
    async fn test_migration_upgrades_v0_envelope_to_current_format() {
        let mut keys = HashMap::new();
        keys.insert("1".to_string(), [6u8; 32]);
        let encryption = StorageEncryption::new(&FixedKeyProvider(LoadedKeys {
            current_key_id: "1".to_string(),
            keys,
        }))
        .unwrap();

        // Hand-build a v0 envelope the way the original pre-redesign
        // `EncryptedStorage` did (no AAD, no key_id, no v).
        let cipher = {
            let key = Key::<Aes256Gcm>::from_slice(&[6u8; 32]);
            Aes256Gcm::new(key)
        };
        let nonce_bytes = [8u8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, b"v0 secret".as_ref()).unwrap();
        let v0_json = format!(
            r#"{{"data":"{}","nonce":"{}","algorithm":"AES-256-GCM","key_derivation":"direct"}}"#,
            BASE64.encode(&ciphertext),
            BASE64.encode(nonce_bytes)
        );

        let storage = MemoryStorage::new();
        storage
            .store_kv("secret:legacy", v0_json.as_bytes(), None)
            .await
            .unwrap();

        let report = migrate_kv_to_encrypted(&storage, &encryption, "secret:", false)
            .await
            .unwrap();
        assert_eq!(
            report.upgraded_from_legacy, 1,
            "a v0 envelope must be counted as upgraded, not already_encrypted"
        );
        assert_eq!(report.already_encrypted, 0);

        let raw_after = storage.get_kv("secret:legacy").await.unwrap().unwrap();
        let envelope_after: EncryptedData = serde_json::from_slice(&raw_after).unwrap();
        assert_eq!(
            envelope_after.v, CURRENT_FORMAT_VERSION,
            "the stored envelope must now be the current format, not still v0"
        );
        assert!(
            !envelope_after.key_id.is_empty(),
            "the upgraded envelope must have a real key_id"
        );

        // The upgraded envelope must decrypt correctly through the
        // normal (AAD-bound) path -- not just via the v0 fallback.
        let decrypted = encryption
            .decrypt(&envelope_after, b"secret:legacy")
            .unwrap();
        assert_eq!(decrypted, b"v0 secret".to_vec());

        // Idempotent: running it again finds nothing left to upgrade.
        let report2 = migrate_kv_to_encrypted(&storage, &encryption, "secret:", false)
            .await
            .unwrap();
        assert_eq!(report2.upgraded_from_legacy, 0);
        assert_eq!(report2.already_encrypted, 1);
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
