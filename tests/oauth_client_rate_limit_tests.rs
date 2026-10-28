//! An authenticated OAuth2 client is rate limited by its own identity, not only by the address
//! it comes from (issue #92). The router-wide limiter is keyed on the caller's address; the
//! handlers called directly here never see an address, so what limits these calls is the
//! per-client bucket. Failed authentication does not count against the client it names.

#[cfg(all(test, feature = "axum-integration"))]
mod client_rate_limit_tests {
    use auth_framework::api::ApiState;
    use auth_framework::api::oauth_advanced::{IntrospectRequest, introspect_token};
    use auth_framework::distributed::rate_limiting::{DistributedRateLimiter, RateLimitConfig};
    use auth_framework::server::oauth::oauth2_server::TokenRequest;
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Form;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION};
    use base64::Engine;
    use std::sync::Arc;
    use std::time::Duration;

    const ALLOWANCE: u32 = 3;

    async fn state() -> ApiState {
        let config = AuthConfig::new()
            .secret("test_client_rate_limit_secret_key_long_enough_for_jwt".to_string());
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();
        let mut state = ApiState::new(Arc::new(framework)).await.unwrap();
        let mut limits = RateLimitConfig::balanced();
        limits.max_requests = ALLOWANCE;
        limits.window_duration = Duration::from_secs(60);
        limits.burst_allowance = None;
        limits.penalty_duration = None;
        limits.adaptive = false;
        state.rate_limiter = Arc::new(DistributedRateLimiter::new(limits).await.unwrap());
        for (id, secret) in [("limited-a", "secret-a"), ("limited-b", "secret-b")] {
            state
                .auth_framework
                .storage()
                .store_kv(
                    &format!("oauth2_client:{id}"),
                    serde_json::json!({"client_id": id, "client_secret": secret})
                        .to_string()
                        .as_bytes(),
                    None,
                )
                .await
                .unwrap();
        }
        state
    }

    /// `Ok(())` if the introspection endpoint let the client in, else the HTTP status.
    async fn introspect(state: &ApiState, id: &str, secret: &str) -> Result<(), StatusCode> {
        let mut headers = HeaderMap::new();
        let basic = base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {basic}")).unwrap(),
        );
        introspect_token(
            State(state.clone()),
            headers,
            Form(IntrospectRequest {
                token: "not-a-token".to_string(),
                token_type_hint: None,
                client_id: None,
                client_secret: None,
            }),
        )
        .await
        .map(|_| ())
        .map_err(|(status, _)| status)
    }

    #[tokio::test]
    async fn an_authenticated_client_is_limited_by_its_own_identity() {
        let state = state().await;
        for i in 0..ALLOWANCE {
            assert_eq!(
                introspect(&state, "limited-a", "secret-a").await,
                Ok(()),
                "request {i} is within the allowance"
            );
        }
        assert_eq!(
            introspect(&state, "limited-a", "secret-a").await,
            Err(StatusCode::TOO_MANY_REQUESTS),
            "the next request is over it"
        );
        // Another client has its own bucket.
        assert_eq!(introspect(&state, "limited-b", "secret-b").await, Ok(()));
    }

    #[tokio::test]
    async fn failed_attempts_do_not_count_against_the_client_they_name() {
        let state = state().await;
        for _ in 0..(ALLOWANCE * 4) {
            assert_eq!(
                introspect(&state, "limited-b", "wrong").await,
                Err(StatusCode::UNAUTHORIZED)
            );
        }
        for i in 0..ALLOWANCE {
            assert_eq!(
                introspect(&state, "limited-b", "secret-b").await,
                Ok(()),
                "request {i}: the real client still has its whole allowance"
            );
        }
    }

    #[tokio::test]
    async fn the_token_endpoint_limits_an_authenticated_client_too() {
        let state = state().await;
        let exchange = || async {
            auth_framework::api::oauth2::token(
                State(state.clone()),
                axum::Json(TokenRequest {
                    grant_type: "authorization_code".to_string(),
                    code: Some("no-such-code".to_string()),
                    client_id: Some("limited-a".to_string()),
                    client_secret: Some("secret-a".to_string()),
                    redirect_uri: Some("https://app.example.com/cb".to_string()),
                    ..Default::default()
                }),
            )
            .await
        };
        let code_of = |r: &auth_framework::api::ApiResponse<_>| {
            r.error.as_ref().map(|e| e.code.clone()).unwrap_or_default()
        };
        for i in 0..ALLOWANCE {
            let resp = exchange().await;
            assert_eq!(
                code_of(&resp),
                "invalid_grant",
                "request {i} passes client authentication"
            );
        }
        assert_eq!(code_of(&exchange().await), "rate_limit_exceeded");
    }
}
