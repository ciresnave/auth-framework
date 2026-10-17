//! API keys carry a role, chosen at creation from a configurable set, and validation returns it.

use auth_framework::auth_modular::{UserInfo, UserManager};
use auth_framework::config::PasswordHashAlgorithm;
use auth_framework::storage::{AuthStorage, MemoryStorage};
use std::sync::Arc;

fn manager(storage: Arc<dyn AuthStorage>) -> UserManager {
    UserManager::new(storage, PasswordHashAlgorithm::Argon2)
}

fn roles_of(info: &UserInfo) -> Vec<String> {
    info.roles.iter().cloned().collect()
}

#[tokio::test]
async fn a_key_without_a_chosen_role_is_api_user() {
    let um = manager(Arc::new(MemoryStorage::new()));
    let key = um.create_api_key("alice", None).await.unwrap();
    let info = um.validate_api_key(&key).await.unwrap();
    assert_eq!(roles_of(&info), ["api_user"]);
}

#[tokio::test]
async fn a_key_carries_the_role_it_was_created_with() {
    let um = manager(Arc::new(MemoryStorage::new()));
    let admin = um
        .create_api_key_with_role("alice", "admin", None)
        .await
        .unwrap();
    let user = um
        .create_api_key_with_role("alice", "user", None)
        .await
        .unwrap();
    assert_eq!(
        roles_of(&um.validate_api_key(&admin).await.unwrap()),
        ["admin"]
    );
    assert_eq!(
        roles_of(&um.validate_api_key(&user).await.unwrap()),
        ["user"]
    );
}

#[tokio::test]
async fn the_role_is_stored_with_the_key_not_held_by_the_manager() {
    let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
    let key = manager(storage.clone())
        .create_api_key_with_role("alice", "admin", None)
        .await
        .unwrap();
    // A different manager over the same storage sees the same role.
    let info = manager(storage).validate_api_key(&key).await.unwrap();
    assert_eq!(roles_of(&info), ["admin"]);
}

#[tokio::test]
async fn a_row_written_before_roles_existed_reads_as_api_user() {
    let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
    let um = manager(storage.clone());
    // A pre-roles row as an older release stored it: the raw key as the row name, no role field.
    let old_row = serde_json::json!({
        "user_id": "alice",
        "created_at": chrono::Utc::now(),
        "expires_at": null,
    });
    storage
        .store_kv(
            "api_key:ak_old_release",
            old_row.to_string().as_bytes(),
            None,
        )
        .await
        .unwrap();
    let info = um.validate_api_key("ak_old_release").await.unwrap();
    assert_eq!(roles_of(&info), ["api_user"]);
}

#[tokio::test]
async fn an_unknown_role_is_refused_at_creation() {
    let um = manager(Arc::new(MemoryStorage::new()));
    for role in ["superuser", "Admin", "", " admin", "admin "] {
        assert!(
            um.create_api_key_with_role("alice", role, None)
                .await
                .is_err(),
            "role {role:?} must be refused"
        );
    }
}

#[tokio::test]
async fn the_allowed_set_is_configurable() {
    let um = manager(Arc::new(MemoryStorage::new()))
        .with_api_key_roles(vec!["reader".to_string(), "writer".to_string()]);
    let key = um
        .create_api_key_with_role("alice", "reader", None)
        .await
        .unwrap();
    assert_eq!(
        roles_of(&um.validate_api_key(&key).await.unwrap()),
        ["reader"]
    );
    assert!(
        um.create_api_key_with_role("alice", "admin", None)
            .await
            .is_err(),
        "a role outside the configured set is refused"
    );
}

#[tokio::test]
async fn a_stored_role_outside_the_set_fails_closed() {
    let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
    let key = manager(storage.clone())
        .create_api_key_with_role("alice", "admin", None)
        .await
        .unwrap();
    // The operator later narrows the set: the existing admin key must stop validating, not be
    // downgraded to another role and not keep admin.
    let narrowed = manager(storage).with_api_key_roles(vec!["user".to_string()]);
    assert!(narrowed.validate_api_key(&key).await.is_err());
}
