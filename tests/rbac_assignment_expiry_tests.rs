//! A role assignment that asks for an expiry is refused, because the role system keeps none and
//! the role would be granted for good. Without an expiry the assignment works as before.
#![cfg(all(feature = "enhanced-rbac", feature = "api-server"))]

use auth_framework::api::ApiState;
use auth_framework::api::rbac_endpoints::{
    AssignRoleRequest, BulkAssignRequest, BulkAssignment, assign_user_role, bulk_assign_roles,
};
use auth_framework::testing::helpers::create_test_token;
use auth_framework::{AuthConfig, AuthFramework};
use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use std::sync::Arc;

async fn state() -> ApiState {
    let config = AuthConfig::new().secret("test_rbac_expiry_secret_key_long_enough_for_jwt");
    let mut f = AuthFramework::new(config);
    f.initialize().await.unwrap();
    let state = ApiState::new(Arc::new(f)).await.unwrap();
    state
        .authorization_service
        .create_role("auditor", "reads audit logs", vec![], None)
        .await
        .unwrap();
    state
}

fn admin_token() -> auth_framework::tokens::AuthToken {
    create_test_token("rbac-admin").with_permissions(vec!["manage:user_roles".to_string()])
}

async fn roles_of(state: &ApiState, user: &str) -> Vec<String> {
    state
        .authorization_service
        .get_user_roles(user)
        .await
        .unwrap_or_default()
}

fn in_a_day() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::days(1)
}

#[tokio::test]
async fn an_assignment_with_an_expiry_is_refused_and_grants_nothing() {
    let state = state().await;
    let reply = assign_user_role(
        State(state.clone()),
        Extension(admin_token()),
        Path("temp-user".to_string()),
        Json(AssignRoleRequest {
            role_id: "auditor".to_string(),
            expires_at: Some(in_a_day()),
            reason: None,
        }),
    )
    .await
    .unwrap();
    assert!(!reply.0.success, "an expiring assignment must be refused");
    assert!(
        roles_of(&state, "temp-user").await.is_empty(),
        "nothing granted"
    );
}

#[tokio::test]
async fn an_assignment_without_an_expiry_still_works() {
    let state = state().await;
    let reply = assign_user_role(
        State(state.clone()),
        Extension(admin_token()),
        Path("perm-user".to_string()),
        Json(AssignRoleRequest {
            role_id: "auditor".to_string(),
            expires_at: None,
            reason: None,
        }),
    )
    .await
    .unwrap();
    assert!(reply.0.success);
    assert_eq!(
        roles_of(&state, "perm-user").await,
        vec!["auditor".to_string()]
    );
}

#[tokio::test]
async fn a_bulk_request_with_any_expiry_is_refused_before_granting_any_role() {
    let state = state().await;
    let reply = bulk_assign_roles(
        State(state.clone()),
        Extension(admin_token()),
        Json(BulkAssignRequest {
            assignments: vec![
                BulkAssignment {
                    user_id: "bulk-a".to_string(),
                    role_id: "auditor".to_string(),
                    expires_at: None,
                },
                BulkAssignment {
                    user_id: "bulk-b".to_string(),
                    role_id: "auditor".to_string(),
                    expires_at: Some(in_a_day()),
                },
            ],
        }),
    )
    .await
    .unwrap();
    assert!(!reply.0.success);
    assert!(
        roles_of(&state, "bulk-a").await.is_empty(),
        "no partial grant"
    );
    assert!(roles_of(&state, "bulk-b").await.is_empty());
}
