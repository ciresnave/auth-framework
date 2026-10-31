//! The `AuthFramework` TOTP facade and `TotpManager` used directly must agree on where a secret
//! lives and how it is encoded: a secret made through one verifies through the other.
//!
//! Both are built over ONE `MemoryStorage`, so the storage key (`user:{id}:totp_secret`) and the
//! base32 encoding are exercised, not just a shared in-process object. Part of #116.

use auth_framework::auth_modular::mfa::totp::TotpManager;
use auth_framework::storage::{AuthStorage, MemoryStorage};
use auth_framework::{AuthConfig, AuthFramework};
use std::sync::Arc;

async fn framework_and_manager() -> (AuthFramework, TotpManager, Arc<dyn AuthStorage>) {
    let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
    let config = AuthConfig::new().secret("cross_verify_secret_key_32bytes!".to_string());
    let mut fw = AuthFramework::new_with_storage(config, storage.clone());
    fw.initialize().await.unwrap();
    let manager = TotpManager::new_plaintext(storage.clone());
    (fw, manager, storage)
}

#[tokio::test]
async fn facade_secret_verifies_through_totp_manager() {
    let (fw, manager, storage) = framework_and_manager().await;
    let secret = fw.generate_totp_secret("alice").await.unwrap();
    let stored = storage.get_kv("user:alice:totp_secret").await.unwrap();
    assert_eq!(
        stored.as_deref(),
        Some(secret.as_bytes()),
        "storage key/encoding drifted"
    );
    let code = fw.generate_totp_code(&secret).await.unwrap();
    assert!(manager.verify_code("alice", &code).await.unwrap());
}

#[tokio::test]
async fn totp_manager_secret_verifies_through_facade() {
    let (fw, manager, storage) = framework_and_manager().await;
    let secret = manager.generate_secret("bob").await.unwrap();
    let stored = storage.get_kv("user:bob:totp_secret").await.unwrap();
    assert_eq!(
        stored.as_deref(),
        Some(secret.as_bytes()),
        "storage key/encoding drifted"
    );
    let code = manager.generate_code(&secret).await.unwrap();
    assert!(fw.verify_totp_code("bob", &code).await.unwrap());
}

#[tokio::test]
async fn code_outside_the_skew_window_is_rejected_through_the_other_path() {
    let (fw, manager, _storage) = framework_and_manager().await;
    let secret = fw.generate_totp_secret("carol").await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    let mut near = Vec::new();
    for window in now - 2..=now + 2 {
        near.push(
            manager
                .generate_code_for_window(&secret, Some(window))
                .await
                .unwrap(),
        );
    }
    let wrong = (0..1_000_000u32)
        .map(|n| format!("{n:06}"))
        .find(|c| !near.contains(c))
        .unwrap();
    assert!(!manager.verify_code("carol", &wrong).await.unwrap());
    assert!(!fw.verify_totp_code("carol", &wrong).await.unwrap());
    // Positive control: the same user's current code does verify (once: codes are single-use).
    assert!(manager.verify_code("carol", &near[2]).await.unwrap());
}

#[tokio::test]
async fn user_without_a_secret_is_rejected_on_both_paths() {
    let (fw, manager, _storage) = framework_and_manager().await;
    assert!(!manager.verify_code("nobody", "123456").await.unwrap());
    assert!(!fw.verify_totp_code("nobody", "123456").await.unwrap());
}
