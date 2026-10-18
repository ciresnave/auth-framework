//! A key's role becomes the authenticated token's roles and scopes: the mapping is explicit and pinned.
//!
//! Authenticating with an API key copies the key's roles into the token's roles AND scopes, so a key
//! created with the role `admin` yields exactly the scope `admin`, which is what the crate's admin
//! checks look for. Creating such a key is the caller's authorization decision.

use auth_framework::{
    auth::{AuthFramework, AuthResult},
    auth_modular::user_manager::DEFAULT_API_KEY_ROLES,
    authentication::credentials::Credential,
    config::AuthConfig,
    tokens::AuthToken,
};

/// Every scope name the crate checks for, found by searching `src` for scope checks
/// (`has_scope("..")`, `scopes.contains("..")`). `admin` is the privileged one; `read` and `write`
/// are ordinary. If a new privileged scope name is added to the crate, add it here: the collision
/// test below then decides whether any API-key role can spell it.
const SCOPE_NAMES_THE_CRATE_CHECKS: [&str; 3] = ["admin", "read", "write"];

async fn framework() -> AuthFramework {
    let config = AuthConfig::new().secret("test-secret-key-with-sufficient-length-for-security");
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.expect("initialize");
    framework
}

async fn authenticate_with_role(framework: &AuthFramework, role: &str) -> AuthToken {
    let key = framework
        .create_api_key_with_role("alice", role, None)
        .await
        .expect("create key");
    match framework
        .authenticate("api_key", Credential::api_key(&key))
        .await
        .expect("authenticate")
    {
        AuthResult::Success(token) => *token,
        other => panic!("expected success, got {other:?}"),
    }
}

#[tokio::test]
async fn an_admin_key_yields_exactly_the_admin_scope_and_role() {
    let framework = framework().await;
    let token = authenticate_with_role(&framework, "admin").await;
    assert_eq!(token.scopes.0, ["admin"]);
    assert!(token.roles.contains("admin"));
}

#[tokio::test]
async fn a_user_key_does_not_get_the_admin_scope_or_role() {
    let framework = framework().await;
    let token = authenticate_with_role(&framework, "user").await;
    assert_eq!(token.scopes.0, ["user"]);
    assert!(!token.scopes.contains("admin"));
    assert!(!token.roles.contains("admin"));
}

#[tokio::test]
async fn a_plain_key_still_yields_api_user() {
    let framework = framework().await;
    let key = framework.create_api_key("alice", None).await.unwrap();
    let AuthResult::Success(token) = framework
        .authenticate("api_key", Credential::api_key(&key))
        .await
        .unwrap()
    else {
        panic!("expected success");
    };
    assert_eq!(token.scopes.0, ["api_user"]);
    assert!(!token.roles.contains("admin"));
}

#[test]
fn only_the_admin_role_spells_a_privileged_scope() {
    // The roles an API key can carry become scope names. The only one that may equal a scope
    // the crate checks is `admin`, deliberately; `user` and `api_user` must not collide with
    // `read`, `write` or any other scope name.
    let colliding: Vec<&str> = DEFAULT_API_KEY_ROLES
        .iter()
        .copied()
        .filter(|role| SCOPE_NAMES_THE_CRATE_CHECKS.contains(role))
        .collect();
    assert_eq!(colliding, ["admin"]);
}
