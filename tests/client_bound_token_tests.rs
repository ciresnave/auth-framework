//! A token issued to an OAuth client on a user's behalf is a delegated-access token: it
//! works at the OAuth resource endpoints and at routes that opt in to delegated access, but
//! not as a user session (profile, admin, ...) and not at the default extractors.

#[cfg(all(test, feature = "axum-integration"))]
mod client_bound_token_tests {
    use auth_framework::api::oauth2::{token, userinfo, users_me};
    use auth_framework::api::users::get_profile;
    use auth_framework::api::{ApiState, validate_api_token};
    use auth_framework::integrations::axum::{AuthenticatedUser, DelegatedUser};
    use auth_framework::server::oauth::oauth2_server::TokenRequest;
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Json;
    use axum::Router;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header::AUTHORIZATION};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    const REDIRECT: &str = "https://app.example.com/cb";
    const VERIFIER: &str = "a-sufficiently-long-code-verifier-0123456789-abcdefghij";

    struct Env {
        state: ApiState,
        fw: Arc<AuthFramework>,
        user: String,
    }

    async fn env() -> Env {
        let config = AuthConfig::new()
            .secret("test_client_bound_secret_key_that_is_long_enough_for_jwt".to_string())
            .token_lifetime(Duration::from_secs(3600));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        let fw = Arc::new(f);
        let state = ApiState::new(fw.clone()).await.unwrap();
        let name = format!("cb_{}", uuid::Uuid::new_v4().simple());
        let user = fw
            .register_user(
                &name,
                &format!("{name}@test.example.com"),
                "SecurePass123!x",
            )
            .await
            .unwrap();
        fw.storage()
            .store_kv(
                "oauth2_client:c1",
                serde_json::json!({"client_id": "c1", "redirect_uris": [REDIRECT], "scope": "openid profile"})
                    .to_string()
                    .as_bytes(),
                None,
            )
            .await
            .unwrap();
        Env { state, fw, user }
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    }

    /// An access token obtained through the real authorization-code grant.
    async fn client_token(env: &Env) -> String {
        let code = format!("ac_cb_{}", uuid::Uuid::new_v4().simple());
        env.fw
            .storage()
            .store_kv(
                &format!("oauth2_code:{code}"),
                serde_json::json!({
                    "client_id": "c1", "redirect_uri": REDIRECT, "user_id": env.user, "scope": "openid",
                    "code_challenge": URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
                    "code_challenge_method": "S256",
                })
                .to_string()
                .as_bytes(),
                Some(Duration::from_secs(600)),
            )
            .await
            .unwrap();
        let resp = token(
            State(env.state.clone()),
            Json(TokenRequest {
                grant_type: "authorization_code".into(),
                code: Some(code),
                client_id: Some("c1".into()),
                redirect_uri: Some(REDIRECT.into()),
                code_verifier: Some(VERIFIER.into()),
                ..Default::default()
            }),
        )
        .await;
        assert!(resp.success, "{:?}", resp.error);
        serde_json::to_value(resp.data.unwrap()).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// A session token (no client): what login issues.
    fn session_token(env: &Env) -> String {
        env.fw
            .token_manager()
            .create_jwt_token(
                &env.user,
                vec!["read".into()],
                Some(Duration::from_secs(600)),
            )
            .unwrap()
    }

    #[tokio::test]
    async fn oauth_grants_issue_client_bound_tokens() {
        let env = env().await;
        let access = client_token(&env).await;
        let claims = env.fw.token_manager().validate_jwt_token(&access).unwrap();
        assert_eq!(claims.client_id.as_deref(), Some("c1"));

        // and so does the OAuth refresh grant
        env.fw
            .storage()
            .store_kv(
                "oauth2_refresh_token:rt_cb",
                serde_json::json!({"user_id": env.user, "client_id": "c1", "scopes": "openid"})
                    .to_string()
                    .as_bytes(),
                None,
            )
            .await
            .unwrap();
        let resp = token(
            State(env.state.clone()),
            Json(TokenRequest {
                grant_type: "refresh_token".into(),
                refresh_token: Some("rt_cb".into()),
                client_id: Some("c1".into()),
                ..Default::default()
            }),
        )
        .await;
        assert!(resp.success, "{:?}", resp.error);
        let refreshed = serde_json::to_value(resp.data.unwrap()).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let claims = env
            .fw
            .token_manager()
            .validate_jwt_token(&refreshed)
            .unwrap();
        assert_eq!(claims.client_id.as_deref(), Some("c1"));
    }

    #[tokio::test]
    async fn a_client_bound_token_is_not_a_user_session() {
        let env = env().await;
        let delegated = client_token(&env).await;

        // first-party session endpoints refuse it ...
        assert!(validate_api_token(&env.fw, &delegated).await.is_err());
        let profile = get_profile(State(env.state.clone()), bearer(&delegated)).await;
        assert!(
            !profile.success,
            "profile must not open to a client-bound token"
        );

        // ... and accept a session token (control)
        let session = session_token(&env);
        assert!(validate_api_token(&env.fw, &session).await.is_ok());
        let profile = get_profile(State(env.state.clone()), bearer(&session)).await;
        assert!(profile.success, "{:?}", profile.error);
    }

    #[tokio::test]
    async fn a_client_bound_token_cannot_authorize_codes() {
        use auth_framework::api::oauth2::authorize;
        use auth_framework::server::oauth::oauth2_server::AuthorizationRequest;
        use axum::extract::Query;
        let env = env().await;
        let delegated = client_token(&env).await;
        let req = AuthorizationRequest::new("c1", "code", REDIRECT).pkce(
            URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
            "S256",
        );
        let resp = authorize(State(env.state.clone()), bearer(&delegated), Query(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // control: a session token can
        let req = AuthorizationRequest::new("c1", "code", REDIRECT).pkce(
            URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
            "S256",
        );
        let ok = authorize(
            State(env.state.clone()),
            bearer(&session_token(&env)),
            Query(req),
        )
        .await
        .into_response();
        assert!(ok.status().is_redirection(), "{}", ok.status());
    }

    #[tokio::test]
    async fn refreshing_a_client_bound_token_keeps_it_client_bound() {
        let env = env().await;
        let token = env
            .fw
            .token_manager()
            .create_client_auth_token(&env.user, vec!["openid".to_string()], "oauth2", "c1", None)
            .unwrap();
        let again = env.fw.token_manager().refresh_token(&token).unwrap();
        assert_eq!(again.client_id.as_deref(), Some("c1"));
        let claims = env
            .fw
            .token_manager()
            .validate_jwt_token(&again.access_token)
            .unwrap();
        assert!(claims.is_client_bound());
    }

    #[tokio::test]
    async fn oauth_resource_endpoints_accept_a_client_bound_token() {
        let env = env().await;
        let delegated = client_token(&env).await;
        let info = userinfo(State(env.state.clone()), bearer(&delegated)).await;
        assert!(info.success, "{:?}", info.error);
        let me = users_me(State(env.state.clone()), bearer(&delegated))
            .await
            .into_response();
        assert_eq!(me.status(), StatusCode::OK);
    }

    fn app(fw: Arc<AuthFramework>) -> Router {
        Router::new()
            .route(
                "/session",
                get(|u: AuthenticatedUser| async move { u.user_id }),
            )
            .route(
                "/delegated",
                get(|d: DelegatedUser| async move {
                    d.0.token.client_id.unwrap_or_else(|| "none".to_string())
                }),
            )
            .with_state(fw)
    }

    async fn call(app: &Router, path: &str, token: &str) -> (StatusCode, String) {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    #[tokio::test]
    async fn default_extractors_refuse_client_bound_tokens_and_the_opt_in_accepts_them() {
        let env = env().await;
        let app = app(env.fw.clone());
        let delegated = client_token(&env).await;
        let session = session_token(&env);

        assert_eq!(
            call(&app, "/session", &delegated).await.0,
            StatusCode::UNAUTHORIZED
        );
        let (status, body) = call(&app, "/delegated", &delegated).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "c1", "the client id is visible to the route");

        // a pre-upgrade / session token (no client_id) works on both
        assert_eq!(call(&app, "/session", &session).await.0, StatusCode::OK);
        let (status, body) = call(&app, "/delegated", &session).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "none");
    }

    #[tokio::test]
    async fn jwt_credentials_refuse_client_bound_tokens() {
        use auth_framework::auth::AuthResult;
        use auth_framework::authentication::credentials::Credential;
        let env = env().await;
        let delegated = client_token(&env).await;
        let session = session_token(&env);
        let ok = env
            .fw
            .authenticate("jwt", Credential::Jwt { token: session })
            .await;
        assert!(matches!(ok, Ok(AuthResult::Success(_))));
        let refused = env
            .fw
            .authenticate("jwt", Credential::Jwt { token: delegated })
            .await;
        assert!(
            matches!(refused, Ok(AuthResult::Failure(_)) | Err(_)),
            "a client-bound token must not authenticate as a session"
        );
    }
}
