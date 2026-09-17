//! OAuth2 Integration Test
//!
//! This test demonstrates the complete OAuth2 authorization server flow
//! including authorization code generation, PKCE validation, token exchange,
//! and UserInfo retrieval.

#[cfg(all(test, feature = "api-server"))]
mod oauth2_integration_tests {
    use auth_framework::api::ApiState;
    use auth_framework::api::oauth2::{self, AuthorizeRequest, RevokeRequest, TokenRequest};
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Json;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    use std::sync::Arc;

    async fn setup_auth_framework() -> Arc<AuthFramework> {
        let config = AuthConfig::new()
            .secret("test_oauth2_secret_key_that_is_long_enough_for_secure_operation".to_string());

        let mut auth_framework = AuthFramework::new(config);
        auth_framework.initialize().await.unwrap();
        Arc::new(auth_framework)
    }

    async fn setup_api_state() -> ApiState {
        let auth_framework = setup_auth_framework().await;
        let state = ApiState::new(auth_framework).await.unwrap();

        // Register test clients so the authorize endpoint can validate them
        let callback = "http://localhost:3000/callback";
        for client_id in &[
            "test_client",
            "test_client_pkce",
            "test_client_invalid_pkce",
        ] {
            let client_data = serde_json::json!({ "redirect_uris": [callback] });
            let key = format!("oauth2_client:{}", client_id);
            state
                .auth_framework
                .storage()
                .store_kv(&key, client_data.to_string().as_bytes(), None)
                .await
                .unwrap();
        }
        state
    }

    /// Create a test user and return an `Authorization: Bearer` `HeaderMap` that
    /// the updated `authorize` endpoint requires as proof of user identity.
    async fn make_auth_headers(state: &ApiState) -> HeaderMap {
        use axum::http::{HeaderValue, header::AUTHORIZATION};
        // Use a timestamp-based suffix to avoid conflicts between concurrently-
        // running tests.
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let username = format!("test_oauth_user_{}", suffix);
        let email = format!("{}@test.example.com", username);

        let user_id = state
            .auth_framework
            .register_user(&username, &email, "SecurePass123!")
            .await
            .expect("test user registration should succeed");

        let token = state
            .auth_framework
            .token_manager()
            .create_auth_token(
                &user_id,
                vec!["openid".to_string(), "profile".to_string()],
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
        headers
    }

    #[tokio::test]
    async fn test_oauth2_authorization_endpoint() {
        let state = setup_api_state().await;

        // Test valid authorization request
        let auth_request = AuthorizeRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "http://localhost:3000/callback".to_string(),
            scope: Some("openid profile email".to_string()),
            state: Some("xyz123".to_string()),
            code_challenge: Some("test_challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
            resource: None,
        };

        let auth_headers = make_auth_headers(&state).await;
        let response = oauth2::authorize(State(state.clone()), auth_headers, Query(auth_request))
            .await
            .into_response();

        // Authorize endpoint returns a redirect on success
        assert!(
            response.status().is_redirection(),
            "Expected redirect, got {:?}",
            response.status()
        );
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("code="));
        // state=xyz123 — all alphanum so URL-encoding leaves it unchanged
        assert!(location.contains("state=xyz123"));
    }

    /// Verify that state parameters containing URL-unsafe characters (`&`, `=`, space)
    /// are percent-encoded in the redirect URI, preventing redirect injection.
    #[tokio::test]
    async fn test_oauth2_state_encoding_with_special_chars() {
        let state = setup_api_state().await;

        let auth_request = AuthorizeRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "http://localhost:3000/callback".to_string(),
            scope: Some("openid".to_string()),
            state: Some("a&b=c d".to_string()),
            code_challenge: Some("test_challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
            resource: None,
        };

        let auth_headers = make_auth_headers(&state).await;
        let response = oauth2::authorize(State(state.clone()), auth_headers, Query(auth_request))
            .await
            .into_response();

        assert!(
            response.status().is_redirection(),
            "Expected redirect, got {:?}",
            response.status()
        );
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();

        // The raw injection characters must NOT appear unencoded in the Location header.
        assert!(
            !location.contains("&b=c"),
            "State '&' was not percent-encoded: {location}"
        );
        // Verify that the encoded representation IS present.
        assert!(
            location.contains("a%26b%3Dc"),
            "State parameter was not percent-encoded correctly: {location}"
        );
    }

    #[tokio::test]
    async fn test_oauth2_authorization_invalid_response_type() {
        let state = setup_api_state().await;

        // Test invalid response_type
        let auth_request = AuthorizeRequest {
            response_type: "token".to_string(), // Invalid
            client_id: "test_client".to_string(),
            redirect_uri: "http://localhost:3000/callback".to_string(),
            scope: None,
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            resource: None,
        };

        let response = oauth2::authorize(State(state), HeaderMap::new(), Query(auth_request))
            .await
            .into_response();

        // Should fail with 400 Bad Request
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_oauth2_token_endpoint_authorization_code() {
        let state = setup_api_state().await;

        // First, create an authorization code by calling authorize endpoint
        let auth_request = AuthorizeRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "http://localhost:3000/callback".to_string(),
            scope: Some("openid profile".to_string()),
            state: Some("test_state".to_string()),
            code_challenge: Some("test_challenge".to_string()),
            code_challenge_method: Some("plain".to_string()),
            nonce: None,
            resource: None,
        };

        let auth_headers = make_auth_headers(&state).await;
        let auth_response =
            oauth2::authorize(State(state.clone()), auth_headers, Query(auth_request))
                .await
                .into_response();

        assert!(
            auth_response.status().is_redirection(),
            "Expected redirect on successful authorize"
        );

        // Extract authorization code from the Location header
        let auth_url = auth_response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let code = auth_url
            .split("code=")
            .nth(1)
            .unwrap()
            .split("&")
            .next()
            .unwrap();

        // Now test token exchange
        let token_request = TokenRequest::authorization_code(code)
            .redirect_uri("http://localhost:3000/callback")
            .client_id("test_client")
            .code_verifier("test_challenge"); // For PKCE

        let token_response = oauth2::token(State(state), Json(token_request)).await;

        // Should be successful
        assert!(token_response.success);

        if let Some(data) = token_response.data {
            assert!(!data.access_token.is_empty());
            assert_eq!(data.token_type, "Bearer");
            assert_eq!(data.expires_in, 3600);
            // Refresh token may or may not be present depending on configuration
            assert!(data.scope.is_some());
        }
    }

    #[tokio::test]
    async fn test_oauth2_userinfo_endpoint() {
        let state = setup_api_state().await;

        // Register a real user so storage has the profile data that the
        // UserInfo endpoint needs.  register_user takes &self, so it works
        // fine on the Arc<AuthFramework> returned by setup_api_state().
        let user_id = state
            .auth_framework
            .register_user(
                "oauth2_userinfo_test",
                "oauth2_userinfo_test@example.com",
                "SecurePass123!",
            )
            .await
            .expect("test user registration should succeed");

        // Create an access token whose `sub` claim is the newly registered user.
        let token = state
            .auth_framework
            .token_manager()
            .create_auth_token(
                &user_id,
                vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ],
                "oauth2",
                None,
            )
            .unwrap();

        // Call the UserInfo endpoint.
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {}", token.access_token)).unwrap(),
        );

        let userinfo_response = oauth2::userinfo(State(state), headers).await;

        assert!(
            userinfo_response.success,
            "UserInfo endpoint should return success"
        );

        let data = userinfo_response
            .data
            .expect("UserInfo response should contain data");
        assert_eq!(data.sub, user_id, "sub claim must match registered user id");
        assert_eq!(
            data.name,
            Some("oauth2_userinfo_test".to_string()),
            "name should be the registered username"
        );
        assert_eq!(
            data.email,
            Some("oauth2_userinfo_test@example.com".to_string()),
            "email should match the registered email"
        );
        assert!(data.updated_at.is_some(), "updated_at should be set");
    }

    #[tokio::test]
    async fn test_oauth2_revoke_endpoint() {
        let state = setup_api_state().await;

        let revoke_request = RevokeRequest {
            token: "test_token_to_revoke".to_string(),
            token_type_hint: Some("access_token".to_string()),
        };

        let revoke_response = oauth2::revoke(State(state), Json(revoke_request)).await;

        // Should be successful
        assert!(revoke_response.success);
    }

    #[tokio::test]
    async fn test_oauth2_pkce_s256_validation() {
        let state = setup_api_state().await;

        // Test S256 PKCE flow
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; // S256 hash of verifier

        // First, create authorization code with S256 challenge
        let auth_request = AuthorizeRequest {
            response_type: "code".to_string(),
            client_id: "test_client_pkce".to_string(),
            redirect_uri: "http://localhost:3000/callback".to_string(),
            scope: Some("openid".to_string()),
            state: None,
            code_challenge: Some(expected_challenge.to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
            resource: None,
        };

        let auth_headers = make_auth_headers(&state).await;
        let auth_response =
            oauth2::authorize(State(state.clone()), auth_headers, Query(auth_request))
                .await
                .into_response();

        assert!(
            auth_response.status().is_redirection(),
            "Expected redirect on successful PKCE authorize"
        );

        // Extract authorization code
        let auth_url = auth_response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let code = auth_url
            .split("code=")
            .nth(1)
            .unwrap()
            .split("&")
            .next()
            .unwrap();

        // Test token exchange with correct code_verifier
        let token_request = TokenRequest::authorization_code(code)
            .redirect_uri("http://localhost:3000/callback")
            .client_id("test_client_pkce")
            .code_verifier(code_verifier);

        let token_response = oauth2::token(State(state), Json(token_request)).await;

        // Should be successful with correct PKCE verification
        assert!(token_response.success);
    }

    #[tokio::test]
    async fn test_oauth2_invalid_pkce_fails() {
        let state = setup_api_state().await;

        // First, create authorization code with challenge
        let auth_request = AuthorizeRequest {
            response_type: "code".to_string(),
            client_id: "test_client_invalid_pkce".to_string(),
            redirect_uri: "http://localhost:3000/callback".to_string(),
            scope: Some("openid".to_string()),
            state: None,
            code_challenge: Some("valid_challenge".to_string()),
            code_challenge_method: Some("plain".to_string()),
            nonce: None,
            resource: None,
        };

        let auth_headers = make_auth_headers(&state).await;
        let auth_response =
            oauth2::authorize(State(state.clone()), auth_headers, Query(auth_request))
                .await
                .into_response();

        assert!(
            auth_response.status().is_redirection(),
            "Expected redirect on authorize"
        );

        // Extract authorization code
        let auth_url = auth_response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let code = auth_url
            .split("code=")
            .nth(1)
            .unwrap()
            .split("&")
            .next()
            .unwrap();

        // Test token exchange with wrong code_verifier
        let token_request = TokenRequest::authorization_code(code)
            .redirect_uri("http://localhost:3000/callback")
            .client_id("test_client_invalid_pkce")
            .code_verifier("wrong_verifier");

        let token_response = oauth2::token(State(state), Json(token_request)).await;

        // Should fail due to PKCE mismatch
        assert!(!token_response.success);
    }
}
