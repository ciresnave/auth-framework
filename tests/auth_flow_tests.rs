// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for password change, token refresh, and account lockout flows.

#[cfg(all(test, feature = "api-server"))]
mod auth_flow_tests {
    use auth_framework::api::ApiState;
    use auth_framework::api::users::{self, ChangePasswordRequest};
    use auth_framework::authentication::credentials::Credential;
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Json;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
    use std::sync::Arc;

    async fn setup_api_state() -> ApiState {
        let config = AuthConfig::new()
            .secret("test_auth_flow_secret_key_that_is_long_enough_for_jwt".to_string());
        let mut auth_framework = AuthFramework::new(config);
        auth_framework.initialize().await.unwrap();
        ApiState::new(Arc::new(auth_framework)).await.unwrap()
    }

    async fn register_and_auth(state: &ApiState, suffix: &str) -> (String, HeaderMap) {
        let username = format!("flow_user_{}", suffix);
        let email = format!("{}@test.example.com", username);

        let user_id = state
            .auth_framework
            .register_user(&username, &email, "SecurePass123!")
            .await
            .expect("user registration should succeed");

        let token = state
            .auth_framework
            .token_manager()
            .create_auth_token(
                &user_id,
                vec!["read".to_string(), "write".to_string()],
                "test",
                None,
            )
            .expect("token creation should succeed");

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token.access_token))
                .expect("valid header value"),
        );
        (user_id, headers)
    }

    // ── T1: Password change flow tests ──────────────────────────────────

    #[tokio::test]
    async fn test_change_password_success() {
        let state = setup_api_state().await;
        let (_user_id, headers) = register_and_auth(&state, "chpw_ok").await;

        let resp = users::change_password(
            State(state.clone()),
            headers,
            Json(ChangePasswordRequest {
                current_password: "SecurePass123!".to_string(),
                new_password: "NewSecureP@ss456!".to_string(),
            }),
        )
        .await;

        assert!(
            resp.success,
            "password change should succeed: {:?}",
            resp.error
        );
    }

    #[tokio::test]
    async fn test_change_password_wrong_current() {
        let state = setup_api_state().await;
        let (_user_id, headers) = register_and_auth(&state, "chpw_wrong").await;

        let resp = users::change_password(
            State(state.clone()),
            headers,
            Json(ChangePasswordRequest {
                current_password: "WrongPassword999!".to_string(),
                new_password: "NewSecureP@ss456!".to_string(),
            }),
        )
        .await;

        assert!(
            !resp.success,
            "password change with wrong current should fail"
        );
    }

    #[tokio::test]
    async fn test_change_password_empty_fields() {
        let state = setup_api_state().await;
        let (_user_id, headers) = register_and_auth(&state, "chpw_empty").await;

        let resp = users::change_password(
            State(state.clone()),
            headers,
            Json(ChangePasswordRequest {
                current_password: "".to_string(),
                new_password: "".to_string(),
            }),
        )
        .await;

        assert!(
            !resp.success,
            "password change with empty fields should fail"
        );
    }

    #[tokio::test]
    async fn test_change_password_unauthenticated() {
        let state = setup_api_state().await;
        let headers = HeaderMap::new(); // no auth header

        let resp = users::change_password(
            State(state.clone()),
            headers,
            Json(ChangePasswordRequest {
                current_password: "SecurePass123!".to_string(),
                new_password: "NewSecureP@ss456!".to_string(),
            }),
        )
        .await;

        assert!(!resp.success, "unauthenticated password change should fail");
    }

    // ── T2: Token refresh flow tests ────────────────────────────────────

    #[tokio::test]
    async fn test_refresh_token_roundtrip() {
        let state = setup_api_state().await;
        let (user_id, _headers) = register_and_auth(&state, "refresh_ok").await;

        // Store a refresh token
        let refresh_token = uuid::Uuid::new_v4().to_string().replace("-", "");
        let refresh_data = serde_json::json!({
            "user_id": user_id,
            "scopes": "openid profile email",
        });
        let refresh_key = format!("oauth2_refresh_token:{}", refresh_token);
        state
            .auth_framework
            .storage()
            .store_kv(
                &refresh_key,
                serde_json::to_string(&refresh_data).unwrap().as_bytes(),
                Some(std::time::Duration::from_secs(3600)),
            )
            .await
            .unwrap();

        // Exchange the refresh token
        use auth_framework::server::oauth::oauth2_server::TokenRequest;
        let req = TokenRequest::refresh(refresh_token.clone());

        let resp = auth_framework::api::oauth2::token(State(state.clone()), Json(req)).await;
        assert!(
            resp.success,
            "refresh grant should succeed: {:?}",
            resp.error
        );
        assert!(resp.data.is_some());
        let data = resp.data.unwrap();
        assert!(!data.access_token.is_empty());
        assert!(
            data.refresh_token.is_some(),
            "rotation should issue new refresh token"
        );

        // Old refresh token should be consumed (deleted)
        let old = state
            .auth_framework
            .storage()
            .get_kv(&refresh_key)
            .await
            .unwrap();
        assert!(
            old.is_none(),
            "old refresh token should be deleted after rotation"
        );
    }

    #[tokio::test]
    async fn test_refresh_token_reuse_rejected() {
        let state = setup_api_state().await;
        let (user_id, _headers) = register_and_auth(&state, "refresh_reuse").await;

        let refresh_token = uuid::Uuid::new_v4().to_string().replace("-", "");
        let refresh_data = serde_json::json!({
            "user_id": user_id,
            "scopes": "openid",
        });
        let refresh_key = format!("oauth2_refresh_token:{}", refresh_token);
        state
            .auth_framework
            .storage()
            .store_kv(
                &refresh_key,
                serde_json::to_string(&refresh_data).unwrap().as_bytes(),
                Some(std::time::Duration::from_secs(3600)),
            )
            .await
            .unwrap();

        use auth_framework::server::oauth::oauth2_server::TokenRequest;
        let make_req = || TokenRequest::refresh(refresh_token.clone());

        // First use succeeds
        let resp1 =
            auth_framework::api::oauth2::token(State(state.clone()), Json(make_req())).await;
        assert!(resp1.success, "first refresh should succeed");

        // Second use should fail (single-use rotation)
        let resp2 =
            auth_framework::api::oauth2::token(State(state.clone()), Json(make_req())).await;
        assert!(!resp2.success, "reused refresh token should be rejected");
    }

    #[tokio::test]
    async fn test_refresh_token_missing() {
        let state = setup_api_state().await;
        use auth_framework::server::oauth::oauth2_server::TokenRequest;

        let req = TokenRequest {
            grant_type: "refresh_token".to_string(),
            ..Default::default()
        };

        let resp = auth_framework::api::oauth2::token(State(state.clone()), Json(req)).await;
        assert!(!resp.success, "missing refresh_token should fail");
    }

    #[tokio::test]
    async fn test_refresh_token_invalid() {
        let state = setup_api_state().await;
        use auth_framework::server::oauth::oauth2_server::TokenRequest;

        let req = TokenRequest::refresh("nonexistent_token_value");

        let resp = auth_framework::api::oauth2::token(State(state.clone()), Json(req)).await;
        assert!(!resp.success, "invalid refresh_token should fail");
    }

    // ── T3: Account lockout config tests ────────────────────────────────

    #[test]
    fn test_lockout_config_defaults() {
        let config = auth_framework::security::LockoutConfig::default();
        assert!(!config.enabled, "lockout should be disabled by default");
        assert_eq!(config.max_failed_attempts, 0);
        assert_eq!(config.lockout_duration_seconds, 0);
    }

    #[test]
    fn test_lockout_config_custom() {
        let config = auth_framework::security::LockoutConfig {
            enabled: true,
            max_failed_attempts: 5,
            lockout_duration_seconds: 300,
            progressive_lockout: true,
            max_lockout_duration_seconds: 3600,
        };
        assert!(config.enabled);
        assert_eq!(config.max_failed_attempts, 5);
        assert!(config.progressive_lockout);
    }

    #[test]
    fn test_lockout_config_serialization_roundtrip() {
        let config = auth_framework::security::LockoutConfig {
            enabled: true,
            max_failed_attempts: 10,
            lockout_duration_seconds: 600,
            progressive_lockout: false,
            max_lockout_duration_seconds: 7200,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: auth_framework::security::LockoutConfig =
            serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.enabled, config.enabled);
        assert_eq!(deserialized.max_failed_attempts, config.max_failed_attempts);
        assert_eq!(
            deserialized.lockout_duration_seconds,
            config.lockout_duration_seconds
        );
        assert_eq!(deserialized.progressive_lockout, config.progressive_lockout);
        assert_eq!(
            deserialized.max_lockout_duration_seconds,
            config.max_lockout_duration_seconds
        );
    }

    #[tokio::test]
    async fn test_failed_login_does_not_lockout_without_config() {
        let state = setup_api_state().await;

        // Register a user
        state
            .auth_framework
            .register_user("lockout_user", "lockout@test.com", "SecurePass123!")
            .await
            .unwrap();

        // Multiple failed login attempts should not lock the account
        // (lockout is not enabled by default)
        for _ in 0..10 {
            let _ = state
                .auth_framework
                .authenticate(
                    "password",
                    Credential::password("lockout_user", "WrongPassword!"),
                )
                .await;
        }

        // Should still be able to authenticate with correct password
        let result = state
            .auth_framework
            .authenticate(
                "password",
                Credential::password("lockout_user", "SecurePass123!"),
            )
            .await;
        assert!(
            result.is_ok(),
            "correct password should work after failed attempts when lockout is disabled"
        );
    }
}
