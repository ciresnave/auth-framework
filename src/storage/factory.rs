use crate::config::{StorageConfig, StorageEncryptionConfig};
use crate::errors::{AuthError, Result};
use crate::storage::encryption::{EncryptedStorage, StorageEncryption};
use crate::storage::{AuthStorage, MemoryStorage};
use std::sync::Arc;

/// Builds the configured storage backend and, unless explicitly disabled,
/// wraps it in [`EncryptedStorage`] so KV-layer values are encrypted at
/// rest. In-memory storage holds nothing across a restart, so "at rest"
/// encryption has no referent for it and is skipped regardless of
/// `encryption_config`. Every other backend (Postgres/Redis/SQLite/
/// custom) actually persists, so it gets wrapped per the config,
/// defaulting to on (board decision 124).
pub(crate) async fn build_storage_backend_with_encryption(
    config: &StorageConfig,
    pool_size: Option<u32>,
    encryption_config: &StorageEncryptionConfig,
) -> Result<Arc<dyn AuthStorage>> {
    let backend = build_storage_backend_inner(config, pool_size).await?;

    if matches!(config, StorageConfig::Memory) {
        return Ok(backend);
    }

    wrap_with_encryption_if_enabled(backend, encryption_config)
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
pub async fn build_storage_backend_unencrypted(
    config: &StorageConfig,
    pool_size: Option<u32>,
) -> Result<Arc<dyn AuthStorage>> {
    build_storage_backend_inner(config, pool_size).await
}

fn wrap_with_encryption_if_enabled(
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

    Ok(Arc::new(EncryptedStorage::new(backend, encryption)))
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
