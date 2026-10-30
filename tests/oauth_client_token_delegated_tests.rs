//! A token issued to an OAuth client on a user's behalf is delegated access, not the user's own
//! session; and a client is granted only the scopes it is registered for.

#[cfg(all(test, feature = "api-server"))]
mod oauth_client_token_delegated_tests {
    use auth_framework::api::oauth2::{authorize, token, userinfo};
    use auth_framework::api::users::get_profile;
    use auth_framework::api::{ApiState, validate_api_token};
    use auth_framework::server::oauth::oauth2_server::{AuthorizationRequest, TokenRequest};
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Json;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
    use axum::response::IntoResponse;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use std::time::Duration;

    const REDIRECT: &str = "https://app.example.com/cb";
    const VERIFIER: &str = "a-sufficiently-long-code-verifier-0123456789-abcdefghij";

    struct Env {
        fw: Arc<AuthFramework>,
        state: ApiState,
        user: String,
    }

    /// A user and a public client `c1` registered for exactly `openid`.
    async fn env() -> Env {
        let config = AuthConfig::new()
            .secret("test_client_token_delegated_secret_key_long_enough_for_jwt".to_string())
            .token_lifetime(Duration::from_secs(3600));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        let fw = Arc::new(f);
        let state = ApiState::new(fw.clone()).await.unwrap();
        let name = format!("cd_{}", uuid::Uuid::new_v4().simple());
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
                serde_json::json!({"client_id": "c1", "redirect_uris": [REDIRECT], "scope": "openid"})
                    .to_string()
                    .as_bytes(),
                None,
            )
            .await
            .unwrap();
        Env { fw, state, user }
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    }

    fn challenge() -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
    }

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

    /// An access token obtained through the real authorization-code grant.
    async fn client_token(env: &Env) -> String {
        let code = format!("ac_cd_{}", uuid::Uuid::new_v4().simple());
        env.fw
            .storage()
            .store_kv(
                &format!("oauth2_code:{code}"),
                serde_json::json!({
                    "client_id": "c1", "redirect_uri": REDIRECT, "user_id": env.user,
                    "scope": "openid", "code_challenge": challenge(),
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

    #[tokio::test]
    async fn a_client_token_is_not_a_user_session() {
        let env = env().await;
        let delegated = client_token(&env).await;
        let claims = env
            .fw
            .token_manager()
            .validate_jwt_token(&delegated)
            .unwrap();
        assert_eq!(claims.client_id.as_deref(), Some("c1"));

        assert!(validate_api_token(&env.fw, &delegated).await.is_err());
        let profile = get_profile(State(env.state.clone()), bearer(&delegated)).await;
        assert!(!profile.success, "profile must not open to a client token");

        // Controls: a session token still opens both, and the client token still reaches userinfo.
        let session = session_token(&env);
        assert!(validate_api_token(&env.fw, &session).await.is_ok());
        let profile = get_profile(State(env.state.clone()), bearer(&session)).await;
        assert!(profile.success, "{:?}", profile.error);
        let info = userinfo(State(env.state.clone()), bearer(&delegated)).await;
        assert!(info.success, "{:?}", info.error);
    }

    #[tokio::test]
    async fn the_refresh_grant_keeps_a_token_client_bound() {
        let env = env().await;
        env.fw
            .storage()
            .store_kv(
                "oauth2_refresh_token:rt_cd",
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
                refresh_token: Some("rt_cd".into()),
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
        assert!(validate_api_token(&env.fw, &refreshed).await.is_err());
    }

    async fn authorize_status(env: &Env, scope: Option<&str>) -> (u16, Option<String>) {
        let mut req = AuthorizationRequest::new("c1", "code", REDIRECT).pkce(challenge(), "S256");
        if let Some(s) = scope {
            req = req.scope(s);
        }
        let resp = authorize(
            State(env.state.clone()),
            bearer(&session_token(env)),
            Query(req),
        )
        .await
        .into_response();
        let status = resp.status().as_u16();
        let granted = resp
            .headers()
            .get("location")
            .and_then(|l| l.to_str().ok())
            .and_then(|l| url::Url::parse(l).ok())
            .and_then(|u| {
                u.query_pairs()
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.to_string())
            });
        (status, granted)
    }

    #[tokio::test]
    async fn an_unregistered_scope_is_refused() {
        let env = env().await;
        let (status, code) = authorize_status(&env, Some("openid admin:all")).await;
        assert_eq!(status, 400, "an unregistered scope must be refused");
        assert!(code.is_none());

        // Controls: the registered scope, and no scope at all, are granted.
        let (status, code) = authorize_status(&env, Some("openid")).await;
        assert!(status == 302 || status == 303, "{status}");
        let code = code.expect("a code for the registered scope");
        let stored = env
            .fw
            .storage()
            .get_kv(&format!("oauth2_code:{code}"))
            .await
            .unwrap()
            .unwrap();
        let stored: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert_eq!(stored["scope"], "openid");
        let (status, code) = authorize_status(&env, None).await;
        assert!(status == 302 || status == 303, "{status}");
        assert!(code.is_some());
    }

    #[tokio::test]
    async fn a_code_with_an_unregistered_scope_is_clamped_at_the_token_endpoint() {
        let env = env().await;
        let code = format!("ac_cd_{}", uuid::Uuid::new_v4().simple());
        env.fw
            .storage()
            .store_kv(
                &format!("oauth2_code:{code}"),
                serde_json::json!({
                    "client_id": "c1", "redirect_uri": REDIRECT, "user_id": env.user,
                    "scope": "openid admin:all", "code_challenge": challenge(),
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
        let v = serde_json::to_value(resp.data.unwrap()).unwrap();
        let access = v["access_token"].as_str().unwrap();
        let claims = env.fw.token_manager().validate_jwt_token(access).unwrap();
        assert_eq!(claims.scope, "openid");
    }
}
