//! A hand-built `AuthToken` must not authorise through the framework's public permission check.
use auth_framework::auth::AuthFramework;
use auth_framework::config::AuthConfig;
use auth_framework::permissions::{Permission, PermissionChecker};
use auth_framework::tokens::AuthToken;
use std::time::Duration;

fn forged() -> AuthToken {
    let mut t = AuthToken::new(
        "alice",
        "not-a-jwt-we-issued",
        Duration::from_secs(3600),
        "jwt",
    );
    t.scopes = vec!["read:docs".to_string()].into();
    t
}

#[tokio::test]
async fn framework_check_permission_refuses_a_forged_token() {
    let config = AuthConfig::new().secret("test-secret-key-with-sufficient-length-for-security");
    let mut fw = AuthFramework::new(config);
    fw.initialize().await.expect("initialize");
    fw.grant_permission("alice", "read", "docs")
        .await
        .expect("grant");

    let allowed = fw.check_permission(&forged(), "read", "docs").await;
    assert!(
        !matches!(allowed, Ok(true)),
        "forged token authorised: {allowed:?}"
    );
}

/// Control: the same forged token and the same grant ARE accepted by the lower-level checker, which
/// does not validate tokens. This shows the query above can return true, so its `false` means something.
#[test]
fn the_low_level_checker_accepts_the_same_forged_token() {
    let mut checker = PermissionChecker::new();
    checker.add_user_permission("alice", Permission::new("read", "docs"));
    #[allow(
        deprecated,
        reason = "the test calls the deprecated low-level checker to show it accepts the forged token"
    )]
    let allowed = checker
        .check_token_permission(&forged(), &Permission::new("read", "docs"))
        .unwrap();
    assert!(allowed);
}
