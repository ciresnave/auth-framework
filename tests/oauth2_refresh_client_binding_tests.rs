//! A refresh token that carries a `client_id` is redeemable ONLY by that client
//! (RFC 6749 §6 / §10.4): a confidential client must authenticate and the
//! authenticated client must be the one the token was issued to; a public
//! client must present a matching `client_id`. No "check it only if present".

#[cfg(all(test, feature = "api-server"))]
mod refresh_client_binding_tests {
    use auth_framework::api::ApiState;
    use auth_framework::server::oauth::oauth2_server::TokenRequest;
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Json;
    use axum::extract::State;
    use std::sync::Arc;

    async fn state() -> ApiState {
        let config = AuthConfig::new()
            .secret("test_refresh_binding_secret_key_that_is_long_enough_for_jwt".to_string());
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();
        ApiState::new(Arc::new(framework)).await.unwrap()
    }

    async fn put(state: &ApiState, key: &str, value: serde_json::Value) {
        state
            .auth_framework
            .storage()
            .store_kv(
                key,
                value.to_string().as_bytes(),
                Some(std::time::Duration::from_secs(3600)),
            )
            .await
            .unwrap();
    }

    /// Registers a confidential client (has a secret) or a public one (none).
    async fn register_client(state: &ApiState, client_id: &str, secret: Option<&str>) {
        let mut record = serde_json::json!({
            "client_id": client_id,
            "redirect_uris": ["https://app.example.com/cb"],
        });
        if let Some(secret) = secret {
            record["client_secret"] = serde_json::json!(secret);
        }
        put(state, &format!("oauth2_client:{client_id}"), record).await;
    }

    /// Stores a refresh token issued to `client_id` (or to nobody).
    async fn issue_refresh_token(state: &ApiState, client_id: Option<&str>) -> String {
        let user_id = state
            .auth_framework
            .register_user(
                &format!("rb_{}", uuid::Uuid::new_v4().simple()),
                &format!("{}@test.example.com", uuid::Uuid::new_v4().simple()),
                "SecurePass123!",
            )
            .await
            .unwrap();
        let token = uuid::Uuid::new_v4().simple().to_string();
        let mut record = serde_json::json!({"user_id": user_id, "scopes": "openid"});
        if let Some(client_id) = client_id {
            record["client_id"] = serde_json::json!(client_id);
        }
        put(state, &format!("oauth2_refresh_token:{token}"), record).await;
        token
    }

    fn request(token: &str, client_id: Option<&str>, secret: Option<&str>) -> TokenRequest {
        TokenRequest {
            grant_type: "refresh_token".to_string(),
            refresh_token: Some(token.to_string()),
            client_id: client_id.map(String::from),
            client_secret: secret.map(String::from),
            ..Default::default()
        }
    }

    async fn redeem(
        state: &ApiState,
        req: TokenRequest,
    ) -> auth_framework::api::ApiResponse<auth_framework::api::oauth2::TokenResponse> {
        auth_framework::api::oauth2::token(State(state.clone()), Json(req)).await
    }

    fn error_code<T>(resp: &auth_framework::api::ApiResponse<T>) -> String {
        resp.error
            .as_ref()
            .map(|e| e.code.clone())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn confidential_client_must_authenticate() {
        let state = state().await;
        register_client(&state, "conf-1", Some("s3cret")).await;
        let token = issue_refresh_token(&state, Some("conf-1")).await;

        let no_credentials = redeem(&state, request(&token, None, None)).await;
        assert!(!no_credentials.success, "no credentials must be refused");
        assert_eq!(error_code(&no_credentials), "invalid_client");

        let id_only = redeem(&state, request(&token, Some("conf-1"), None)).await;
        assert!(
            !id_only.success,
            "client_id without a secret must be refused"
        );
        assert_eq!(error_code(&id_only), "invalid_client");

        let wrong_secret = redeem(&state, request(&token, Some("conf-1"), Some("nope"))).await;
        assert!(!wrong_secret.success);
        assert_eq!(error_code(&wrong_secret), "invalid_client");
    }

    #[tokio::test]
    async fn confidential_client_with_valid_credentials_redeems_and_keeps_the_binding() {
        let state = state().await;
        register_client(&state, "conf-1", Some("s3cret")).await;
        let token = issue_refresh_token(&state, Some("conf-1")).await;

        let ok = redeem(&state, request(&token, Some("conf-1"), Some("s3cret"))).await;
        assert!(ok.success, "{:?}", ok.error);
        let rotated = ok.data.unwrap().refresh_token.unwrap();

        // The rotated token is still bound to conf-1.
        let stolen = redeem(&state, request(&rotated, None, None)).await;
        assert!(!stolen.success, "rotated token must stay bound");
        let again = redeem(&state, request(&rotated, Some("conf-1"), Some("s3cret"))).await;
        assert!(again.success, "{:?}", again.error);
    }

    #[tokio::test]
    async fn another_authenticated_client_cannot_redeem_the_token() {
        let state = state().await;
        register_client(&state, "conf-1", Some("s3cret-1")).await;
        register_client(&state, "conf-2", Some("s3cret-2")).await;
        let token = issue_refresh_token(&state, Some("conf-1")).await;

        let thief = redeem(&state, request(&token, Some("conf-2"), Some("s3cret-2"))).await;
        assert!(!thief.success, "conf-2 holds a token issued to conf-1");
        assert_eq!(error_code(&thief), "invalid_grant");
    }

    #[tokio::test]
    async fn public_client_must_present_the_matching_client_id() {
        let state = state().await;
        register_client(&state, "pub-1", None).await;
        register_client(&state, "pub-2", None).await;
        let token = issue_refresh_token(&state, Some("pub-1")).await;

        let missing = redeem(&state, request(&token, None, None)).await;
        assert!(!missing.success, "a missing client_id must be refused");
        assert_eq!(error_code(&missing), "invalid_grant");

        let other = redeem(&state, request(&token, Some("pub-2"), None)).await;
        assert!(!other.success, "a different client_id must be refused");
        assert_eq!(error_code(&other), "invalid_grant");

        let ok = redeem(&state, request(&token, Some("pub-1"), None)).await;
        assert!(ok.success, "{:?}", ok.error);
    }

    /// A refused attempt must not burn the token: otherwise anyone who
    /// merely sees a refresh token could lock its owner out.
    #[tokio::test]
    async fn a_refused_attempt_does_not_consume_the_token() {
        let state = state().await;
        register_client(&state, "pub-1", None).await;
        let token = issue_refresh_token(&state, Some("pub-1")).await;

        let refused = redeem(&state, request(&token, Some("someone-else"), None)).await;
        assert!(!refused.success);

        let ok = redeem(&state, request(&token, Some("pub-1"), None)).await;
        assert!(
            ok.success,
            "the rightful client can still redeem: {:?}",
            ok.error
        );
    }

    #[tokio::test]
    async fn token_bound_to_an_unregistered_client_fails_closed() {
        let state = state().await;
        let token = issue_refresh_token(&state, Some("ghost-client")).await;
        let resp = redeem(&state, request(&token, Some("ghost-client"), None)).await;
        assert!(
            !resp.success,
            "a client that no longer exists cannot redeem"
        );
        assert_eq!(error_code(&resp), "invalid_grant");
    }

    /// Tokens issued without any client (e.g. by older versions) keep working.
    #[tokio::test]
    async fn token_without_a_client_id_is_unchanged() {
        let state = state().await;
        let token = issue_refresh_token(&state, None).await;
        let resp = redeem(&state, request(&token, None, None)).await;
        assert!(resp.success, "{:?}", resp.error);
    }

    #[tokio::test]
    async fn presenting_unknown_or_secretless_clients_against_a_confidential_token() {
        let state = state().await;
        register_client(&state, "conf-1", Some("s3cret")).await;
        register_client(&state, "pub-1", None).await;
        let token = issue_refresh_token(&state, Some("conf-1")).await;

        // An unregistered client cannot authenticate.
        let unknown = redeem(&state, request(&token, Some("nobody"), Some("x"))).await;
        assert!(!unknown.success);
        assert_eq!(error_code(&unknown), "invalid_client");

        // A registered PUBLIC client has no secret to authenticate with.
        let public = redeem(&state, request(&token, Some("pub-1"), Some("anything"))).await;
        assert!(!public.success);
        assert_eq!(error_code(&public), "invalid_client");

        // An empty client_id / empty secret authenticate nobody.
        let empty_id = redeem(&state, request(&token, Some(""), Some("s3cret"))).await;
        assert!(!empty_id.success);
        let empty_secret = redeem(&state, request(&token, Some("conf-1"), Some(""))).await;
        assert!(!empty_secret.success);
        assert_eq!(error_code(&empty_secret), "invalid_client");

        // None of the refusals consumed the token.
        let ok = redeem(&state, request(&token, Some("conf-1"), Some("s3cret"))).await;
        assert!(ok.success, "{:?}", ok.error);
    }

    #[tokio::test]
    async fn a_secret_does_not_make_a_public_client_confidential() {
        let state = state().await;
        register_client(&state, "pub-1", None).await;
        let token = issue_refresh_token(&state, Some("pub-1")).await;
        // The secret is ignored; the matching client_id is what counts.
        let ok = redeem(&state, request(&token, Some("pub-1"), Some("ignored"))).await;
        assert!(ok.success, "{:?}", ok.error);
    }

    #[tokio::test]
    async fn a_stored_client_id_of_the_wrong_type_fails_closed() {
        let state = state().await;
        let user_id = state
            .auth_framework
            .register_user(
                &format!("rb_{}", uuid::Uuid::new_v4().simple()),
                &format!("{}@test.example.com", uuid::Uuid::new_v4().simple()),
                "SecurePass123!",
            )
            .await
            .unwrap();
        let token = uuid::Uuid::new_v4().simple().to_string();
        put(
            &state,
            &format!("oauth2_refresh_token:{token}"),
            serde_json::json!({"user_id": user_id, "scopes": "openid", "client_id": 42}),
        )
        .await;
        let resp = redeem(&state, request(&token, None, None)).await;
        assert!(!resp.success, "a malformed binding must not be skipped");
        assert_eq!(error_code(&resp), "invalid_grant");
    }
}
