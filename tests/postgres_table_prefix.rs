//! `StorageConfig::Postgres { table_prefix }` must either be honoured or refused: a prefix that is
//! accepted and silently ignored lets two deployments that chose different prefixes share tables.

#![cfg(feature = "postgres-storage")]

use auth_framework::auth::AuthFramework;
use auth_framework::config::{AuthConfig, StorageConfig};
use sqlx::PgPool;

async fn tables_like(pool: &PgPool, pattern: &str) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT table_name::text FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name LIKE $1",
    )
    .bind(pattern)
    .fetch_all(pool)
    .await
    .expect("list tables")
}

#[tokio::test]
async fn a_custom_table_prefix_is_honoured_or_refused() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&url).await.expect("connect");

    let mut config =
        AuthConfig::new().secret("test-secret-key-with-sufficient-length-for-security");
    config.storage = StorageConfig::Postgres {
        connection_string: url.clone(),
        table_prefix: "zzp_".to_string(),
    };
    config.storage_encryption.enabled = false;

    let mut framework = AuthFramework::new(config);
    let initialised = framework.initialize().await;

    // Positive control: the same query finds the tables the backend does create.
    assert!(
        !tables_like(&pool, "kv\\_store").await.is_empty() || initialised.is_err(),
        "control: kv_store should exist once the backend initialised"
    );

    let prefixed = tables_like(&pool, "zzp\\_%").await;
    assert!(
        initialised.is_err() || !prefixed.is_empty(),
        "prefix 'zzp_' was accepted (initialize succeeded) but no table carries it: it was ignored"
    );
}

#[tokio::test]
async fn the_default_prefix_still_initialises() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&url).await.expect("connect");

    let mut config =
        AuthConfig::new().secret("test-secret-key-with-sufficient-length-for-security");
    config.storage = StorageConfig::Postgres {
        connection_string: url,
        table_prefix: "auth_".to_string(),
    };
    config.storage_encryption.enabled = false;

    let mut framework = AuthFramework::new(config);
    framework.initialize().await.expect("initialize");
    assert!(!tables_like(&pool, "kv\\_store").await.is_empty());
}
