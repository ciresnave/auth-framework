use crate::config::StorageConfig;
use crate::errors::{AuthError, Result};
use crate::storage::{AuthStorage, MemoryStorage};
use std::sync::Arc;

pub(crate) async fn build_storage_backend(
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
