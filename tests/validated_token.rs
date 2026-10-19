//! `ValidatedToken` is proof that the framework validated a token, so a permission check on it
//! cannot be reached with a hand-built `AuthToken`.
use auth_framework::auth::AuthFramework;
use auth_framework::config::AuthConfig;
use auth_framework::methods::{AuthMethodEnum, JwtMethod};
use auth_framework::permissions::{Permission, PermissionChecker};
use auth_framework::tokens::AuthToken;
use std::time::Duration;

async fn framework() -> AuthFramework {
    let config = AuthConfig::new().secret("test-secret-key-with-sufficient-length-for-security");
    let mut fw = AuthFramework::new(config);
    fw.register_method("jwt", AuthMethodEnum::Jwt(JwtMethod::new()));
    fw.initialize().await.expect("initialize");
    fw
}

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
async fn a_forged_token_does_not_validate() {
    let fw = framework().await;
    assert!(fw.validated_token(&forged()).await.unwrap().is_none());
}

#[tokio::test]
async fn an_issued_token_validates_and_is_checked_against_grants() {
    let fw = framework().await;
    fw.grant_permission("alice", "read", "docs").await.unwrap();
    let issued = fw
        .create_auth_token("alice", vec!["read:docs".to_string()], "jwt", None)
        .await
        .unwrap();

    let proof = fw
        .validated_token(&issued)
        .await
        .unwrap()
        .expect("issued token validates");
    assert_eq!(proof.token().user_id, "alice");
    assert!(
        fw.check_validated_permission(&proof, "read", "docs")
            .await
            .unwrap()
    );
    // Control: the same proof is refused for something never granted.
    assert!(
        !fw.check_validated_permission(&proof, "write", "docs")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_revoked_token_no_longer_validates() {
    let fw = framework().await;
    let issued = fw
        .create_auth_token("alice", vec!["read:docs".to_string()], "jwt", None)
        .await
        .unwrap();
    assert!(fw.validated_token(&issued).await.unwrap().is_some());
    fw.revoke_token(&issued).await.unwrap();
    assert!(fw.validated_token(&issued).await.unwrap().is_none());
}

/// The checker accepts the witness only; scope and stored-grant rules are unchanged.
#[tokio::test]
async fn checker_requires_scope_and_grant() {
    let fw = framework().await;
    let issued = fw
        .create_auth_token("alice", vec!["read:docs".to_string()], "jwt", None)
        .await
        .unwrap();
    let proof = fw.validated_token(&issued).await.unwrap().unwrap();
    let mut checker = PermissionChecker::new();
    // Scope present, no stored grant: refused.
    assert!(!matches!(
        checker.check_validated_permission(&proof, &Permission::new("read", "docs")),
        Ok(true)
    ));
    checker.add_user_permission("alice", Permission::new("read", "docs"));
    assert!(
        checker
            .check_validated_permission(&proof, &Permission::new("read", "docs"))
            .unwrap()
    );
    // Grant present, scope absent: refused.
    checker.add_user_permission("alice", Permission::new("write", "docs"));
    assert!(
        !checker
            .check_validated_permission(&proof, &Permission::new("write", "docs"))
            .unwrap()
    );
}
