//! The OIDC provider's `OAuth2Server` records `client_credentials` grants in the framework's own
//! audit trail when it is given `AuthFramework::audit_storage()` (issue #91): queryable through
//! `AuthFramework::audit()`, and never carrying the client secret.

use auth_framework::audit::{AuditEventType, AuditQuery, EventOutcome};
use auth_framework::server::oauth::oauth2_server::TokenRequest;
use auth_framework::server::oidc::{OidcConfig, OidcProvider};
use auth_framework::storage::MemoryStorage;
use auth_framework::tokens::TokenManager;
use auth_framework::{AuthConfig, AuthFramework};
use std::sync::Arc;

const SECRET: &str = "oidc-cc-secret-0123456789-abcdefghij-KLMN";

async fn framework() -> AuthFramework {
    let mut fw = AuthFramework::new(
        AuthConfig::new()
            .secret("test_oidc_audit_wiring_secret_key_long_enough_for_jwt".to_string()),
    );
    fw.initialize().await.unwrap();
    fw
}

async fn provider() -> OidcProvider<MemoryStorage> {
    let token_manager = Arc::new(TokenManager::new_hmac(
        b"test_secret_key_32_bytes_long!!!!",
        "test_issuer",
        "test_audience",
    ));
    let provider = OidcProvider::new(
        OidcConfig::default(),
        token_manager,
        Arc::new(MemoryStorage::new()),
    )
    .await
    .unwrap();
    provider
        .oauth2_server()
        .register_confidential_client(
            "oidc-cc".to_string(),
            SECRET,
            vec!["https://app.example.com/cb".to_string()],
            vec!["read".to_string()],
            vec!["client_credentials".to_string()],
        )
        .await
        .unwrap();
    provider
}

async fn grants(fw: &AuthFramework) -> Vec<auth_framework::audit::AuditEvent> {
    fw.audit()
        .query_events(
            &AuditQuery::builder()
                .event_types(vec![AuditEventType::TokenIssued])
                .limit(100)
                .build(),
        )
        .await
        .unwrap()
}

fn request() -> TokenRequest {
    TokenRequest {
        scope: Some("read".to_string()),
        ..TokenRequest::client_credentials("oidc-cc", SECRET)
    }
}

#[tokio::test]
async fn the_oidc_providers_client_credentials_grant_lands_in_the_framework_audit_trail() {
    let fw = framework().await;
    let provider = provider().await.with_audit_storage(fw.audit_storage());

    let response = provider
        .oauth2_server()
        .token_exchange(request())
        .await
        .unwrap();

    let events = grants(&fw).await;
    assert_eq!(events.len(), 1, "one grant, one record");
    assert_eq!(events[0].outcome, EventOutcome::Success);
    assert_eq!(events[0].actor.actor_id, "oidc-cc");
    let dump = format!("{:?}", events[0]);
    assert!(!dump.contains(SECRET) && !dump.contains(&response.access_token));
}

#[tokio::test]
async fn without_with_audit_storage_the_provider_records_nothing() {
    // Control: the wiring is what puts the record in the trail.
    let fw = framework().await;
    let provider = provider().await;
    provider
        .oauth2_server()
        .token_exchange(request())
        .await
        .unwrap();
    assert!(grants(&fw).await.is_empty());
}
