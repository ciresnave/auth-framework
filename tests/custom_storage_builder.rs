use auth_framework::prelude::*;
use auth_framework::storage::MemoryStorage;
use std::sync::Arc;

#[tokio::test]
async fn build_with_custom_storage() {
    let mut config = AuthConfig::default();
    // Use a cryptographically strong-looking key (no common words) so the
    // pattern-detection check in validate_jwt_secret does not reject it.
    config.security.secret_key = Some("Xk9mQ3pL7vN2wA5rB8jH4cY6dF0eG1tZ".to_string().into());

    // Create an in-memory storage and pass it via the builder
    let storage = Arc::new(MemoryStorage::new());

    let framework = AuthFramework::builder()
        .customize(|c| {
            c.secret = Some("Xk9mQ3pL7vN2wA5rB8jH4cY6dF0eG1tZ".to_string());
            c
        })
        .with_storage()
        .custom(storage.clone())
        .done()
        .build()
        .await
        .expect("builder should succeed");

    // Framework should be initialized and use the storage we provided
    assert!(framework.get_stats().await.is_ok());
}
