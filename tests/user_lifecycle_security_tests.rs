// SPDX-License-Identifier: MIT OR Apache-2.0
//! User Lifecycle Security Tests
//!
//! Verifies that critical user lifecycle events—deactivation, password change,
//! and account deletion—are correctly enforced at login time.

use auth_framework::{
    auth::{AuthFramework, AuthResult},
    authentication::credentials::Credential,
    config::AuthConfig,
};

fn make_framework() -> AuthFramework {
    let config = AuthConfig::new().secret("test_lifecycle_secret_key_32_bytes!".to_string());
    AuthFramework::new(config)
}

// ---------------------------------------------------------------------------
// Deactivated user is blocked from login
// ---------------------------------------------------------------------------

/// A user that has been deactivated via `set_user_active(false)` must not be
/// able to obtain a token through the password login route.
#[tokio::test]
async fn test_deactivated_user_cannot_login() {
    let mut fw = make_framework();
    fw.initialize().await.unwrap();

    let user_id = fw
        .register_user("deact_user", "deact@example.com", "SecurePass123!")
        .await
        .expect("registration should succeed");

    // Confirm the user can log in before deactivation.
    let pre = fw
        .authenticate(
            "password",
            Credential::password("deact_user", "SecurePass123!"),
        )
        .await
        .expect("authenticate call should not error");
    assert!(
        matches!(pre, AuthResult::Success(_)),
        "active user should be able to log in; got: {:?}",
        pre
    );

    // Deactivate the account.
    fw.set_user_active(&user_id, false)
        .await
        .expect("set_user_active should succeed");

    // Login must now fail.
    let post = fw
        .authenticate(
            "password",
            Credential::password("deact_user", "SecurePass123!"),
        )
        .await
        .expect("authenticate call should not error");
    assert!(
        matches!(post, AuthResult::Failure(_)),
        "deactivated user must not be able to log in; got: {:?}",
        post
    );
}

/// Re-activating a previously deactivated user must restore login capability.
#[tokio::test]
async fn test_reactivated_user_can_login_again() {
    let mut fw = make_framework();
    fw.initialize().await.unwrap();

    let user_id = fw
        .register_user("react_user", "react@example.com", "SecurePass123!")
        .await
        .expect("registration should succeed");

    fw.set_user_active(&user_id, false).await.unwrap();

    // Confirm blocked.
    let blocked = fw
        .authenticate(
            "password",
            Credential::password("react_user", "SecurePass123!"),
        )
        .await
        .unwrap();
    assert!(matches!(blocked, AuthResult::Failure(_)));

    // Re-activate.
    fw.set_user_active(&user_id, true).await.unwrap();

    // Login must succeed again.
    let restored = fw
        .authenticate(
            "password",
            Credential::password("react_user", "SecurePass123!"),
        )
        .await
        .unwrap();
    assert!(
        matches!(restored, AuthResult::Success(_)),
        "re-activated user should be able to log in"
    );
}

// ---------------------------------------------------------------------------
// Password change is reflected at login
// ---------------------------------------------------------------------------

/// After `update_user_password`, the old password must be rejected and the new
/// one accepted for subsequent logins.
#[tokio::test]
async fn test_password_change_blocks_old_password() {
    let mut fw = make_framework();
    fw.initialize().await.unwrap();

    fw.register_user("pw_change_user", "pwchange@example.com", "OldPass123!")
        .await
        .expect("registration should succeed");

    // Verify old password works.
    let before = fw
        .authenticate(
            "password",
            Credential::password("pw_change_user", "OldPass123!"),
        )
        .await
        .unwrap();
    assert!(
        matches!(before, AuthResult::Success(_)),
        "old password should work before change"
    );

    // Change password.
    fw.update_user_password("pw_change_user", "NewPass456!")
        .await
        .expect("update_user_password should succeed");

    // Old password must now be rejected.
    let old_attempt = fw
        .authenticate(
            "password",
            Credential::password("pw_change_user", "OldPass123!"),
        )
        .await
        .unwrap();
    assert!(
        matches!(old_attempt, AuthResult::Failure(_)),
        "old password should be rejected after change; got: {:?}",
        old_attempt
    );

    // New password must be accepted.
    let new_attempt = fw
        .authenticate(
            "password",
            Credential::password("pw_change_user", "NewPass456!"),
        )
        .await
        .unwrap();
    assert!(
        matches!(new_attempt, AuthResult::Success(_)),
        "new password should be accepted after change; got: {:?}",
        new_attempt
    );
}

// ---------------------------------------------------------------------------
// Deleted user is blocked from login
// ---------------------------------------------------------------------------

/// A user deleted via `delete_user` must no longer be able to log in.  
/// This verifies that `user:credentials:{username}` is cleaned up on deletion.
#[tokio::test]
async fn test_deleted_user_cannot_login() {
    let mut fw = make_framework();
    fw.initialize().await.unwrap();

    fw.register_user("del_user", "del@example.com", "SecurePass123!")
        .await
        .expect("registration should succeed");

    // Confirm login works before deletion.
    let pre = fw
        .authenticate(
            "password",
            Credential::password("del_user", "SecurePass123!"),
        )
        .await
        .unwrap();
    assert!(matches!(pre, AuthResult::Success(_)));

    // Delete the user.
    fw.delete_user("del_user")
        .await
        .expect("delete_user should succeed");

    // Login must now fail.
    let post = fw
        .authenticate(
            "password",
            Credential::password("del_user", "SecurePass123!"),
        )
        .await
        .unwrap();
    assert!(
        matches!(post, AuthResult::Failure(_)),
        "deleted user must not be able to log in; got: {:?}",
        post
    );
}

// ---------------------------------------------------------------------------
// Admin-created users can log in
// ---------------------------------------------------------------------------

/// Users created via the framework's `register_user` call (the admin path) must
/// be able to authenticate with the password login route, which reads from
/// `user:credentials:{username}`.
#[tokio::test]
async fn test_admin_created_user_can_login() {
    let mut fw = make_framework();
    fw.initialize().await.unwrap();

    // register_user is the call the admin API endpoint delegates to.
    fw.register_user(
        "admin_created",
        "admin_created@example.com",
        "SecurePass123!",
    )
    .await
    .expect("admin-path registration should succeed");

    let result = fw
        .authenticate(
            "password",
            Credential::password("admin_created", "SecurePass123!"),
        )
        .await
        .expect("authenticate should not error");

    assert!(
        matches!(result, AuthResult::Success(_)),
        "admin-created user should be able to log in; got: {:?}",
        result
    );
}
