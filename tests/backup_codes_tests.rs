//! Backup codes are kept only as digests, in the one store the login flow reads.

use auth_framework::auth_modular::mfa::backup_codes::BackupCodesManager;
use auth_framework::storage::{AuthStorage, MemoryStorage};
use sha2::{Digest, Sha256};
use std::sync::Arc;

fn manager() -> (BackupCodesManager, Arc<dyn AuthStorage>) {
    let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
    (BackupCodesManager::new(storage.clone()), storage)
}

async fn raw(storage: &Arc<dyn AuthStorage>, key: &str) -> Option<String> {
    storage
        .get_kv(key)
        .await
        .unwrap()
        .map(|b| String::from_utf8(b).unwrap())
}

#[tokio::test]
async fn generated_codes_are_stored_only_as_digests_in_the_login_store() {
    let (mgr, storage) = manager();
    let codes = mgr.generate_codes("u1", 5).await.unwrap();
    assert_eq!(codes.len(), 5);
    for code in &codes {
        assert_eq!(code.len(), 12, "{code}");
    }
    let stored = raw(&storage, "mfa_backup_codes:u1")
        .await
        .expect("login store");
    for code in &codes {
        assert!(!stored.contains(code.as_str()), "plaintext at rest");
        assert!(stored.contains(&hex::encode(Sha256::digest(code.as_bytes()))));
    }
    assert!(raw(&storage, "user:u1:backup_codes").await.is_none());
}

#[tokio::test]
async fn a_code_works_once_through_either_verify_path_and_ignores_case_and_spaces() {
    let (mgr, _) = manager();
    let codes = mgr.generate_codes("u2", 3).await.unwrap();
    assert!(
        mgr.verify_login_code("u2", &format!(" {} ", codes[0].to_lowercase()))
            .await
            .unwrap()
    );
    assert!(!mgr.verify_code("u2", &codes[0]).await.unwrap());
    assert!(mgr.verify_code("u2", &codes[1]).await.unwrap());
    assert!(!mgr.verify_code("u2", "NOTACODE").await.unwrap());
    assert!(!mgr.verify_code("u2", "").await.unwrap());
    assert_eq!(mgr.get_remaining_count("u2").await.unwrap(), 1);
}

#[tokio::test]
async fn regenerating_invalidates_the_old_codes() {
    let (mgr, _) = manager();
    let old = mgr.generate_codes("u3", 2).await.unwrap();
    let new = mgr.regenerate_codes("u3", 2).await.unwrap();
    assert!(!mgr.verify_code("u3", &old[0]).await.unwrap());
    assert!(mgr.verify_code("u3", &new[0]).await.unwrap());
}

#[tokio::test]
async fn plaintext_codes_an_earlier_release_stored_are_hashed_on_first_use() {
    let (mgr, storage) = manager();
    let legacy = serde_json::to_vec(&["12345678", "87654321"]).unwrap();
    storage
        .store_kv("user:u4:backup_codes", &legacy, None)
        .await
        .unwrap();
    assert!(mgr.verify_code("u4", "12345678").await.unwrap());
    assert!(
        raw(&storage, "user:u4:backup_codes").await.is_none(),
        "legacy row kept"
    );
    let stored = raw(&storage, "mfa_backup_codes:u4").await.unwrap();
    assert!(!stored.contains("87654321"));
    assert!(mgr.verify_login_code("u4", "87654321").await.unwrap());
    assert!(!mgr.verify_code("u4", "12345678").await.unwrap());
}
