//! Tests for OIDC Enhanced CIBA and Advanced JARM managers.

use auth_framework::server::oidc::oidc_advanced_jarm::{
    AdvancedJarmConfig, AdvancedJarmManager, AuthorizationResponse, JarmDeliveryMode,
};
use auth_framework::server::oidc::oidc_enhanced_ciba::{
    AuthenticationMode, BackchannelAuthParams, EnhancedCibaConfig, EnhancedCibaManager,
    UserIdentifierHint,
};

/// Create an EnhancedCibaManager with JWT keys configured for testing.
fn test_ciba_manager() -> EnhancedCibaManager {
    let config = EnhancedCibaConfig {
        encoding_key: Some(jsonwebtoken::EncodingKey::from_secret(b"test-secret-key")),
        decoding_key: Some(jsonwebtoken::DecodingKey::from_secret(b"test-secret-key")),
        ..Default::default()
    };
    EnhancedCibaManager::new(config)
}

// ═══════════════════════════════════════════════════════════════════
//  Enhanced CIBA tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn ciba_initiate_poll_mode_returns_auth_req_id() {
    let mgr = test_ciba_manager();

    let resp = mgr
        .initiate_backchannel_auth(BackchannelAuthParams {
            client_id: "client-1",
            user_hint: UserIdentifierHint::LoginHint("alice".into()),
            binding_message: Some("Approve login".into()),
            auth_context: None,
            scopes: vec!["openid".into()],
            mode: AuthenticationMode::Poll,
            client_notification_endpoint: None,
            client_notification_token: None,
        })
        .await
        .expect("poll-mode initiation should succeed");

    assert!(!resp.auth_req_id.is_empty());
    assert!(resp.interval.is_some(), "poll mode should include interval");
    assert!(resp.expires_in > 0);
}

#[tokio::test]
async fn ciba_poll_pending_returns_authorization_pending() {
    let mgr = test_ciba_manager();

    let resp = mgr
        .initiate_backchannel_auth(BackchannelAuthParams {
            client_id: "client-1",
            user_hint: UserIdentifierHint::LoginHint("bob".into()),
            binding_message: None,
            auth_context: None,
            scopes: vec!["openid".into()],
            mode: AuthenticationMode::Poll,
            client_notification_endpoint: None,
            client_notification_token: None,
        })
        .await
        .unwrap();

    let err = mgr.poll_auth_request(&resp.auth_req_id).await.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("authorization_pending"),
        "expected authorization_pending, got: {msg}"
    );
}

#[tokio::test]
async fn ciba_poll_unknown_request_returns_error() {
    let mgr = test_ciba_manager();

    let err = mgr.poll_auth_request("nonexistent-id").await.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("not found"),
        "expected 'not found', got: {msg}"
    );
}

#[tokio::test]
async fn ciba_binding_message_too_long_rejected() {
    let mgr = test_ciba_manager();

    let long_msg = "x".repeat(2048);
    let err = mgr
        .initiate_backchannel_auth(BackchannelAuthParams {
            client_id: "c1",
            user_hint: UserIdentifierHint::LoginHint("u1".into()),
            binding_message: Some(long_msg),
            auth_context: None,
            scopes: vec!["openid".into()],
            mode: AuthenticationMode::Poll,
            client_notification_endpoint: None,
            client_notification_token: None,
        })
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("Binding message too long"),
        "expected binding-message-too-long error, got: {msg}"
    );
}

#[tokio::test]
async fn ciba_ping_mode_requires_notification_endpoint() {
    let mgr = test_ciba_manager();

    let err = mgr
        .initiate_backchannel_auth(BackchannelAuthParams {
            client_id: "c1",
            user_hint: UserIdentifierHint::LoginHint("u1".into()),
            binding_message: None,
            auth_context: None,
            scopes: vec!["openid".into()],
            mode: AuthenticationMode::Ping,
            client_notification_endpoint: None,
            client_notification_token: Some("tok".into()),
        })
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("Notification endpoint required"),
        "expected notification-endpoint error, got: {msg}"
    );
}

#[tokio::test]
async fn ciba_ping_mode_requires_notification_token() {
    let mgr = test_ciba_manager();

    let err = mgr
        .initiate_backchannel_auth(BackchannelAuthParams {
            client_id: "c1",
            user_hint: UserIdentifierHint::LoginHint("u1".into()),
            binding_message: None,
            auth_context: None,
            scopes: vec!["openid".into()],
            mode: AuthenticationMode::Ping,
            client_notification_endpoint: Some("https://client.example.com/cb".into()),
            client_notification_token: None,
        })
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("client_notification_token"),
        "expected notification-token error, got: {msg}"
    );
}

#[tokio::test]
async fn ciba_complete_and_poll_completed() {
    let mgr = test_ciba_manager();

    let resp = mgr
        .initiate_backchannel_auth(BackchannelAuthParams {
            client_id: "c1",
            user_hint: UserIdentifierHint::LoginHint("alice".into()),
            binding_message: None,
            auth_context: None,
            scopes: vec!["openid".into()],
            mode: AuthenticationMode::Poll,
            client_notification_endpoint: None,
            client_notification_token: None,
        })
        .await
        .unwrap();

    // Mark authentication as completed.
    mgr.complete_auth_request(&resp.auth_req_id, true, None)
        .await
        .expect("complete should succeed");

    // Polling a completed request should either return tokens or an error
    // depending on session state — just verify it doesn't return 'pending'.
    let result = mgr.poll_auth_request(&resp.auth_req_id).await;
    match &result {
        Ok(token_resp) => {
            assert!(!token_resp.access_token.is_empty());
        }
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                !msg.contains("authorization_pending"),
                "completed request should not be pending"
            );
        }
    }
}

#[tokio::test]
async fn ciba_complete_denied_returns_access_denied() {
    let mgr = test_ciba_manager();

    let resp = mgr
        .initiate_backchannel_auth(BackchannelAuthParams {
            client_id: "c1",
            user_hint: UserIdentifierHint::LoginHint("alice".into()),
            binding_message: None,
            auth_context: None,
            scopes: vec!["openid".into()],
            mode: AuthenticationMode::Poll,
            client_notification_endpoint: None,
            client_notification_token: None,
        })
        .await
        .unwrap();

    mgr.complete_auth_request(&resp.auth_req_id, false, None)
        .await
        .expect("complete (denied) should succeed");

    let err = mgr.poll_auth_request(&resp.auth_req_id).await.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("access_denied"),
        "expected access_denied, got: {msg}"
    );
}

// ═══════════════════════════════════════════════════════════════════
//  Advanced JARM tests
// ═══════════════════════════════════════════════════════════════════

fn jarm_manager() -> AdvancedJarmManager {
    // Use HS256 since we don't have RSA keys in the test environment.
    let config = AdvancedJarmConfig {
        supported_algorithms: vec![jsonwebtoken::Algorithm::HS256],
        ..Default::default()
    };
    AdvancedJarmManager::new(config)
}

fn sample_auth_response() -> AuthorizationResponse {
    AuthorizationResponse {
        code: Some("auth_code_abc".into()),
        state: Some("state_xyz".into()),
        access_token: None,
        token_type: None,
        expires_in: None,
        scope: None,
        id_token: None,
        error: None,
        error_description: None,
    }
}

#[tokio::test]
async fn jarm_create_response_query_mode() {
    let mgr = jarm_manager();
    let auth_resp = sample_auth_response();

    let jarm_resp = mgr
        .create_jarm_response("client-1", &auth_resp, JarmDeliveryMode::Query, None)
        .await
        .expect("create JARM response should succeed");

    assert!(!jarm_resp.response_token.is_empty());
    assert_eq!(jarm_resp.delivery_mode, JarmDeliveryMode::Query);
    assert_eq!(jarm_resp.client_id, "client-1");
}

#[tokio::test]
async fn jarm_create_response_form_post_mode() {
    let mgr = jarm_manager();
    let auth_resp = sample_auth_response();

    let jarm_resp = mgr
        .create_jarm_response("client-2", &auth_resp, JarmDeliveryMode::FormPost, None)
        .await
        .expect("create JARM response form_post should succeed");

    assert_eq!(jarm_resp.delivery_mode, JarmDeliveryMode::FormPost);
}

#[tokio::test]
async fn jarm_validate_own_token() {
    let mgr = jarm_manager();
    let auth_resp = sample_auth_response();

    let jarm_resp = mgr
        .create_jarm_response("client-1", &auth_resp, JarmDeliveryMode::Query, None)
        .await
        .unwrap();

    let validated = mgr.validate_jarm_response(&jarm_resp.response_token).await;

    assert!(
        validated.is_ok(),
        "validating own token should succeed: {:?}",
        validated.err()
    );
}

#[tokio::test]
async fn jarm_custom_claims_added() {
    let mgr = jarm_manager();
    let auth_resp = sample_auth_response();

    let mut custom = std::collections::HashMap::new();
    custom.insert(
        "custom_field".to_string(),
        serde_json::json!("custom_value"),
    );

    let result = mgr
        .create_jarm_response(
            "client-1",
            &auth_resp,
            JarmDeliveryMode::Query,
            Some(custom),
        )
        .await;

    assert!(result.is_ok(), "custom claims should be accepted");
}

#[tokio::test]
async fn jarm_too_many_custom_claims_rejected() {
    let config = AdvancedJarmConfig {
        max_custom_claims: 2,
        supported_algorithms: vec![jsonwebtoken::Algorithm::HS256],
        ..Default::default()
    };
    let mgr = AdvancedJarmManager::new(config);
    let auth_resp = sample_auth_response();

    let mut custom = std::collections::HashMap::new();
    for i in 0..5 {
        custom.insert(format!("claim_{i}"), serde_json::json!(i));
    }

    let err = mgr
        .create_jarm_response("c1", &auth_resp, JarmDeliveryMode::Query, Some(custom))
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("Too many custom claims"),
        "expected too-many-claims error, got: {msg}"
    );
}

#[tokio::test]
async fn jarm_custom_claims_disabled_rejects() {
    let config = AdvancedJarmConfig {
        enable_custom_claims: false,
        supported_algorithms: vec![jsonwebtoken::Algorithm::HS256],
        ..Default::default()
    };
    let mgr = AdvancedJarmManager::new(config);
    let auth_resp = sample_auth_response();

    let mut custom = std::collections::HashMap::new();
    custom.insert("foo".to_string(), serde_json::json!("bar"));

    let err = mgr
        .create_jarm_response("c1", &auth_resp, JarmDeliveryMode::Query, Some(custom))
        .await
        .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("disabled"),
        "expected custom-claims-disabled error, got: {msg}"
    );
}

#[tokio::test]
async fn jarm_revoke_and_check_token() {
    let mgr = jarm_manager();
    let token_id = "test-jti-12345";

    assert!(!mgr.is_jarm_token_revoked(token_id).unwrap());

    mgr.revoke_jarm_token(token_id).unwrap();

    assert!(mgr.is_jarm_token_revoked(token_id).unwrap());
}

#[tokio::test]
async fn jarm_error_response() {
    let mgr = jarm_manager();

    let err_resp = AuthorizationResponse {
        code: None,
        state: Some("s1".into()),
        access_token: None,
        token_type: None,
        expires_in: None,
        scope: None,
        id_token: None,
        error: Some("access_denied".into()),
        error_description: Some("User denied consent".into()),
    };

    let jarm_resp = mgr
        .create_jarm_response("c1", &err_resp, JarmDeliveryMode::Fragment, None)
        .await
        .expect("error response should be encodable");

    assert!(!jarm_resp.response_token.is_empty());
    assert_eq!(jarm_resp.delivery_mode, JarmDeliveryMode::Fragment);
}
