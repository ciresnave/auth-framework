// Standard library imports for Rust 2024 edition
use std::{assert, option::Option::Some, string::ToString, sync::Arc};

use auth_framework::storage::MemoryStorage;
use auth_framework::{AuthConfig, AuthFramework};

#[tokio::test]
async fn build_with_custom_storage() {
    let mut config = AuthConfig::default();
    // Use a stronger secret to satisfy configuration validation
    let strong_secret = "Y3J5cHRvX3JhbmRvbV9zZWNyZXRfMTIzNDU2Nzg5MA==".to_string();
    config.security.secret_key = Some(strong_secret.clone());

    // Create an in-memory storage and pass it via the builder
    let storage = Arc::new(MemoryStorage::new());

    // 1) Builder.custom path
    let framework = AuthFramework::builder()
        .customize(|c| {
            c.secret = Some(strong_secret.clone());
            c
        })
        .with_storage()
        .custom(storage.clone())
        .done()
        .build()
        .await
        .expect("builder should succeed");

    // Framework should be initialized and able to return stats
    assert!(framework.get_stats().await.is_ok());

    // 2) new_with_storage convenience (non-initialized)
    let mut framework2 = AuthFramework::new_with_storage(config.clone(), storage.clone());
    // Not initialized yet: initialize() must be called
    assert!(framework2.initialize().await.is_ok());

    // 3) new_initialized_with_storage convenience (initialized)
    let framework3 = AuthFramework::new_initialized_with_storage(config, storage)
        .await
        .expect("should initialize with storage");

    assert!(framework3.get_stats().await.is_ok());
}
