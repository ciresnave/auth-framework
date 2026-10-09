use crate::config::{StorageConfig, StorageEncryptionConfig};
use crate::errors::{AuthError, Result};
use crate::storage::encryption::{EncryptedStorage, StorageEncryption};
use crate::storage::{AuthStorage, MemoryStorage};
use std::sync::Arc;

/// Builds the configured storage backend and, unless explicitly disabled,
/// wraps it in [`EncryptedStorage`] so KV-layer values are encrypted at
/// rest. In-memory storage holds nothing across a restart, so "at rest"
/// encryption has no referent for it and is skipped regardless of
/// `encryption_config`. Postgres/Redis/SQLite actually persist, so they
/// get wrapped per the config, defaulting to on (board decision 124).
///
/// **This wrapping only applies to storage built by this function.**
/// `StorageConfig::Custom` is rejected outright (see
/// `build_storage_backend_inner`'s own doc) -- it is never silently left
/// unwrapped, because it never reaches a usable backend at all through
/// this path. Storage supplied directly via
/// `AuthFramework::new_with_storage`, `replace_storage`, or the builder's
/// `custom_storage` bypasses this function entirely and is **not**
/// auto-wrapped; callers doing that must wrap it themselves with
/// `EncryptedStorage::new` if they want it encrypted.
pub(crate) async fn build_storage_backend_with_encryption(
    config: &StorageConfig,
    pool_size: Option<u32>,
    encryption_config: &StorageEncryptionConfig,
) -> Result<Arc<dyn AuthStorage>> {
    let backend = build_storage_backend_inner(config, pool_size).await?;

    if matches!(config, StorageConfig::Memory) {
        return Ok(backend);
    }

    // A single env-var key cannot rotate: warn when it protects data that
    // is already encrypted (a changed key would orphan every envelope).
    if encryption_config.enabled
        && probe_is_cheap(config)
        && crate::storage::encryption::env_key_source_in_use()
    {
        match crate::storage::encryption::stored_envelopes_exist(backend.as_ref(), 100).await {
            Ok(true) => tracing::warn!(
                "Storage encryption uses the single AUTH_STORAGE_ENCRYPTION_KEY environment \
                 variable and encrypted values already exist: this key cannot rotate, and \
                 replacing it makes them undecryptable. Move to \
                 AUTH_STORAGE_ENCRYPTION_KEYS_FILE (current + old keys) before the first rotation."
            ),
            Ok(false) => {}
            Err(e) => tracing::debug!("could not probe storage for existing envelopes: {e}"),
        }
    }

    wrap_with_encryption_if_enabled(backend, encryption_config)
}

/// Listing every KV key is a single query on SQL backends but `KEYS` on Redis,
/// which is O(N) and blocks the server, so the startup probe skips Redis.
fn probe_is_cheap(config: &StorageConfig) -> bool {
    #[cfg(feature = "redis-storage")]
    if matches!(config, StorageConfig::Redis { .. }) {
        return false;
    }
    let _ = config;
    true
}

/// Checks storage supplied by the caller (`new_with_storage`,
/// `replace_storage`, the builder's `custom_storage`) against the encryption
/// config: such storage bypasses [`wrap_with_encryption_if_enabled`].
///
/// With encryption enabled and storage that is not an
/// [`EncryptedStorage`], KV values are NOT encrypted at rest even though the
/// config says they are. That is a warning by default and a startup error
/// when `require_wrapped_storage` is set. (In-memory storage supplied this
/// way is flagged too: the framework cannot tell it from a persistent one.)
pub(crate) fn check_overridden_storage(
    storage: &Arc<dyn AuthStorage>,
    encryption_config: &StorageEncryptionConfig,
) -> Result<()> {
    if !encryption_config.enabled || storage.encrypts_kv_at_rest() {
        return Ok(());
    }
    if encryption_config.require_wrapped_storage {
        return Err(AuthError::configuration(
            "storage_encryption.enabled is true and storage_encryption.require_wrapped_storage \
             is set, but the storage supplied via new_with_storage / replace_storage / \
             custom_storage is not an EncryptedStorage, so KV values would NOT be encrypted \
             at rest. Wrap it with EncryptedStorage::new, or set \
             storage_encryption.enabled = false to opt out explicitly.",
        ));
    }
    tracing::warn!(
        "storage_encryption.enabled is true, but the storage supplied via new_with_storage / \
         replace_storage / custom_storage is not an EncryptedStorage: KV values are NOT \
         encrypted at rest. Wrap it with EncryptedStorage::new, set \
         storage_encryption.enabled = false to opt out explicitly, or set \
         storage_encryption.require_wrapped_storage = true to make this an error."
    );
    Ok(())
}

/// Builds the configured storage backend WITHOUT wrapping it in
/// [`EncryptedStorage`], regardless of `StorageEncryptionConfig`.
///
/// This exists for [`crate::storage::encryption::migrate_kv_to_encrypted`]:
/// migration needs to see each row's *raw* bytes to decide whether it's
/// already an encrypted envelope, which the transparently-decrypting
/// wrapper would hide. Most callers want [`build_storage_backend_with_encryption`]
/// instead.
///
/// Currently only used by the admin CLI's `security encrypt-kv` command
/// (hence the `cli` feature gate); if another caller needs it, drop the
/// gate.
#[cfg(feature = "cli")]
pub(crate) async fn build_storage_backend_unencrypted(
    config: &StorageConfig,
    pool_size: Option<u32>,
) -> Result<Arc<dyn AuthStorage>> {
    build_storage_backend_inner(config, pool_size).await
}

/// Wraps `backend` in [`EncryptedStorage`] per `encryption_config`, or
/// returns it unwrapped if encryption is explicitly disabled. `pub(crate)`
/// (not private) so other storage-construction sites outside this module
/// -- currently `auth_modular::AuthFramework::new`'s own, separate Redis
/// construction path -- get the same wrapping behavior instead of silently
/// bypassing it.
pub(crate) fn wrap_with_encryption_if_enabled(
    backend: Arc<dyn AuthStorage>,
    encryption_config: &StorageEncryptionConfig,
) -> Result<Arc<dyn AuthStorage>> {
    if !encryption_config.enabled {
        tracing::warn!(
            "Storage encryption at rest is explicitly disabled (storage_encryption.enabled = false) -- \
             KV-layer values (API keys, TOTP secrets, OAuth2 client registries, etc.) will be stored in plaintext."
        );
        return Ok(backend);
    }

    // Fail closed: if encryption is on (the default) and no usable key
    // can be loaded, refuse to start rather than silently falling back to
    // plaintext storage.
    let encryption = StorageEncryption::from_env().map_err(|e| {
        AuthError::configuration(format!(
            "Storage encryption at rest is enabled (the default) but no encryption key could be \
             loaded: {e}. Either configure AUTH_STORAGE_ENCRYPTION_KEY / \
             AUTH_STORAGE_ENCRYPTION_KEYS_FILE, or set storage_encryption.enabled = false to \
             explicitly opt out (not recommended for any backend that persists data)."
        ))
    })?;

    Ok(Arc::new(EncryptedStorage::new(
        backend,
        encryption,
        encryption_config.allow_plaintext_reads,
        encryption_config.allow_legacy_v0,
    )))
}

async fn build_storage_backend_inner(
    config: &StorageConfig,
    _pool_size: Option<u32>,
) -> Result<Arc<dyn AuthStorage>> {
    match config {
        StorageConfig::Memory => Ok(Arc::new(MemoryStorage::new())),
        #[cfg(feature = "redis-storage")]
        StorageConfig::Redis { url, key_prefix } => {
            crate::storage::RedisStorage::new(url, key_prefix)
                .map(|storage| Arc::new(storage) as Arc<dyn AuthStorage>)
                .map_err(|e| {
                    AuthError::configuration(format!("Failed to create Redis storage: {e}"))
                })
        }
        #[cfg(feature = "postgres-storage")]
        StorageConfig::Postgres {
            connection_string,
            table_prefix: _,
        } => {
            use sqlx::postgres::PgPoolOptions;

            let pool = PgPoolOptions::new()
                .max_connections(_pool_size.unwrap_or(10))
                .connect(connection_string)
                .await
                .map_err(|e| {
                    AuthError::configuration(format!("Failed to connect PostgreSQL storage: {e}"))
                })?;

            let storage = crate::storage::postgres::PostgresStorage::new(pool);
            storage.migrate().await.map_err(|e| {
                AuthError::configuration(format!("Failed to initialize PostgreSQL storage: {e}"))
            })?;

            Ok(Arc::new(storage))
        }
        #[cfg(feature = "sqlite-storage")]
        StorageConfig::Sqlite { connection_string } => {
            use sqlx::sqlite::SqlitePoolOptions;

            let pool = SqlitePoolOptions::new()
                .max_connections(_pool_size.unwrap_or(10))
                .connect(connection_string)
                .await
                .map_err(|e| {
                    AuthError::configuration(format!("Failed to connect SQLite storage: {e}"))
                })?;

            let storage = crate::storage::sqlite::SqliteStorage::new(pool);
            storage.migrate().await.map_err(|e| {
                AuthError::configuration(format!("Failed to initialize SQLite storage: {e}"))
            })?;

            Ok(Arc::new(storage))
        }
        StorageConfig::Custom(name) => Err(AuthError::configuration(format!(
            "Custom storage backend '{name}' requires AuthFramework::new_with_storage() or replace_storage()",
        ))),
        #[allow(unreachable_patterns)]
        _ => Err(AuthError::configuration(
            "Requested storage backend is unavailable in this build. Enable the matching storage feature.",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use crate::storage::encryption::{
        EncryptionEnvGuard, StorageEncryption, TEST_ENCRYPTION_ENV_LOCK,
    };

    fn config(allow_plaintext_reads: bool, allow_legacy_v0: bool) -> StorageEncryptionConfig {
        StorageEncryptionConfig {
            enabled: true,
            allow_plaintext_reads,
            allow_legacy_v0,
            ..Default::default()
        }
    }

    /// Proves `wrap_with_encryption_if_enabled` actually threads
    /// `allow_plaintext_reads` from the config into the `EncryptedStorage`
    /// it builds, rather than accepting and silently ignoring it.
    #[tokio::test]
    async fn test_wrap_threads_allow_plaintext_reads_through() {
        let _lock = TEST_ENCRYPTION_ENV_LOCK.lock().await;
        let key = StorageEncryption::generate_key();
        let _guard = EncryptionEnvGuard::set(&key);

        let inner: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
        inner
            .store_kv("legacy:key", b"plaintext value", None)
            .await
            .unwrap();

        let wrapped_strict =
            wrap_with_encryption_if_enabled(inner.clone(), &config(false, false)).unwrap();
        assert!(
            wrapped_strict.get_kv("legacy:key").await.is_err(),
            "allow_plaintext_reads: false must reject a non-envelope value"
        );

        let wrapped_permissive =
            wrap_with_encryption_if_enabled(inner.clone(), &config(true, false)).unwrap();
        assert_eq!(
            wrapped_permissive.get_kv("legacy:key").await.unwrap(),
            Some(b"plaintext value".to_vec()),
            "allow_plaintext_reads: true must accept a non-envelope value"
        );
    }

    /// Proves `wrap_with_encryption_if_enabled` actually threads
    /// `allow_legacy_v0` through, using a hand-built format-version-0
    /// envelope (no `key_id`, no AAD) the same shape the original
    /// pre-redesign `EncryptedStorage` produced.
    #[tokio::test]
    async fn test_wrap_threads_allow_legacy_v0_through() {
        let _lock = TEST_ENCRYPTION_ENV_LOCK.lock().await;
        let key_bytes_b64 = StorageEncryption::generate_key();
        let _guard = EncryptionEnvGuard::set(&key_bytes_b64);

        // Build a v0 envelope using the SAME key just set in the env var,
        // by loading it back through the real provider.
        let encryption = StorageEncryption::from_env().unwrap();
        let v1_envelope = encryption
            .encrypt(b"legacy value", b"irrelevant-for-v0")
            .unwrap();
        // Downgrade it to a v0-shaped envelope: no key_id, v=0, and
        // re-seal the same plaintext with the empty-AAD v0 convention so
        // it is a GENUINE v0 envelope, not just a relabeled v1 one (a
        // relabeled v1 ciphertext would fail to decrypt under the v0
        // empty-AAD path regardless of this flag -- see the negative
        // test below for that case specifically).
        let _ = v1_envelope; // only needed the key; build v0 directly:
        let v0_json = {
            use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
            use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
            let raw_key = BASE64.decode(&key_bytes_b64).unwrap();
            let cipher = Aes256Gcm::new_from_slice(&raw_key).unwrap();
            let nonce_bytes = [9u8; 12];
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ciphertext = cipher.encrypt(nonce, b"legacy value".as_ref()).unwrap();
            format!(
                r#"{{"data":"{}","nonce":"{}","algorithm":"AES-256-GCM","key_derivation":"direct"}}"#,
                BASE64.encode(&ciphertext),
                BASE64.encode(nonce_bytes)
            )
        };

        let inner: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
        inner
            .store_kv("legacy:v0:key", v0_json.as_bytes(), None)
            .await
            .unwrap();

        let wrapped_strict =
            wrap_with_encryption_if_enabled(inner.clone(), &config(false, false)).unwrap();
        assert!(
            wrapped_strict.get_kv("legacy:v0:key").await.is_err(),
            "allow_legacy_v0: false must reject a format-version-0 envelope"
        );

        let wrapped_permissive =
            wrap_with_encryption_if_enabled(inner.clone(), &config(false, true)).unwrap();
        assert_eq!(
            wrapped_permissive.get_kv("legacy:v0:key").await.unwrap(),
            Some(b"legacy value".to_vec()),
            "allow_legacy_v0: true must decrypt a format-version-0 envelope"
        );
    }

    // ---- storage supplied by the caller bypasses the wrapping (M3) --------------

    fn cfg_with(enabled: bool, require_wrapped_storage: bool) -> StorageEncryptionConfig {
        StorageEncryptionConfig {
            enabled,
            require_wrapped_storage,
            ..Default::default()
        }
    }

    fn wrapped() -> Arc<dyn AuthStorage> {
        Arc::new(EncryptedStorage::new(
            MemoryStorage::new(),
            StorageEncryption::new_random(),
            false,
            false,
        ))
    }

    fn unwrapped() -> Arc<dyn AuthStorage> {
        Arc::new(MemoryStorage::new())
    }

    #[test]
    fn overridden_storage_check_matrix() {
        // Wrapped storage always passes.
        assert!(check_overridden_storage(&wrapped(), &cfg_with(true, true)).is_ok());
        // Unwrapped + encryption on + not required: warns, passes.
        assert!(check_overridden_storage(&unwrapped(), &cfg_with(true, false)).is_ok());
        // Unwrapped + encryption on + required: refused.
        assert!(check_overridden_storage(&unwrapped(), &cfg_with(true, true)).is_err());
        // Encryption explicitly off: nothing to check, even when "required".
        assert!(check_overridden_storage(&unwrapped(), &cfg_with(false, true)).is_ok());
    }
}
