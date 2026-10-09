//! A client can be granted only the scopes it is registered for, and `/auth/refresh`
//! accepts only genuine refresh tokens (never an access token that merely mentions
//! "refresh" in its scope).

#[cfg(all(test, feature = "api-server"))]
mod oauth2_scope_and_refresh_tests {
    use auth_framework::api::auth::{LoginRequest, RefreshRequest, login, refresh_token};
    use auth_framework::api::oauth2::{authorize, token};
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
    const PASSWORD: &str = "SecurePass123!x";

    async fn framework() -> Arc<AuthFramework> {
        let config = AuthConfig::new()
            .secret("test_scope_refresh_secret_key_that_is_long_enough_for_jwt".to_string())
            .token_lifetime(Duration::from_secs(3600))
            .refresh_token_lifetime(Duration::from_secs(86400));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        Arc::new(f)
    }

    async fn put(f: &AuthFramework, key: &str, value: serde_json::Value) {
        f.storage()
            .store_kv(
                key,
                value.to_string().as_bytes(),
                Some(Duration::from_secs(600)),
            )
            .await
            .unwrap();
    }

    /// A public client registered for exactly `scope` (space separated).
    async fn register(f: &AuthFramework, client_id: &str, scope: &str) {
        put(
            f,
            &format!("oauth2_client:{client_id}"),
            serde_json::json!({
                "client_id": client_id,
                "redirect_uris": [REDIRECT],
                "scope": scope,
            }),
        )
        .await;
    }

    struct User {
        id: String,
        username: String,
    }

    async fn user(f: &AuthFramework) -> User {
        let username = format!("sr_{}", uuid::Uuid::new_v4().simple());
        let id = f
            .register_user(&username, &format!("{username}@test.example.com"), PASSWORD)
            .await
            .unwrap();
        User { id, username }
    }

    fn bearer_for(f: &AuthFramework, uid: &str, scopes: &[&str]) -> (String, HeaderMap) {
        let jwt = f
            .token_manager()
            .create_jwt_token(
                uid,
                scopes.iter().map(|s| s.to_string()).collect(),
                Some(Duration::from_secs(600)),
            )
            .unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {jwt}")).unwrap(),
        );
        (jwt, h)
    }

    fn challenge() -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
    }

    /// Call /oauth/authorize; returns (status, code if redirected, error code if refused).
    async fn do_authorize(
        state: &ApiState,
        headers: HeaderMap,
        client_id: &str,
        scope: Option<&str>,
    ) -> (u16, Option<String>, Option<String>) {
        let mut req =
            AuthorizationRequest::new(client_id, "code", REDIRECT).pkce(challenge(), "S256");
        if let Some(s) = scope {
            req = req.scope(s);
        }
        let resp = authorize(State(state.clone()), headers, Query(req))
            .await
            .into_response();
        let status = resp.status().as_u16();
        if resp.status().is_redirection() {
            let loc = resp.headers()["location"].to_str().unwrap().to_string();
            let code = url::Url::parse(&loc)
                .unwrap()
                .query_pairs()
                .find(|(k, _)| k == "code")
                .map(|(_, v)| v.to_string());
            return (status, code, None);
        }
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        (status, None, body["error"].as_str().map(String::from))
    }

    async fn redeem(state: &ApiState, client_id: &str, code: &str) -> Option<String> {
        let resp = token(
            State(state.clone()),
            Json(TokenRequest {
                grant_type: "authorization_code".into(),
                code: Some(code.into()),
                client_id: Some(client_id.into()),
                redirect_uri: Some(REDIRECT.into()),
                code_verifier: Some(VERIFIER.into()),
                ..Default::default()
            }),
        )
        .await;
        resp.data.map(|d| {
            serde_json::to_value(d).unwrap()["access_token"]
                .as_str()
                .unwrap()
                .to_string()
        })
    }

    #[tokio::test]
    async fn a_scope_outside_the_clients_registration_is_refused() {
        let f = framework().await;
        let state = ApiState::new(f.clone()).await.unwrap();
        register(&f, "narrow", "openid").await;
        let u = user(&f).await;
        let (_, headers) = bearer_for(&f, &u.id, &["user"]);

        for requested in ["refresh", "openid refresh", "openid admin", "profile"] {
            let (status, code, err) =
                do_authorize(&state, headers.clone(), "narrow", Some(requested)).await;
            assert_eq!(status, 400, "{requested}: {err:?}");
            assert!(code.is_none(), "{requested} must not yield a code");
            assert_eq!(err.as_deref(), Some("invalid_scope"), "{requested}");
        }
    }

    #[tokio::test]
    async fn a_registered_scope_and_the_default_are_granted() {
        let f = framework().await;
        let state = ApiState::new(f.clone()).await.unwrap();
        register(&f, "narrow", "openid").await;
        let u = user(&f).await;
        let (_, headers) = bearer_for(&f, &u.id, &["user"]);

        let (status, code, _) =
            do_authorize(&state, headers.clone(), "narrow", Some("openid")).await;
        assert!(status == 302 || status == 303 || status == 307, "{status}");
        let stored = f
            .storage()
            .get_kv(&format!("oauth2_code:{}", code.unwrap()))
            .await
            .unwrap()
            .unwrap();
        let stored: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert_eq!(stored["scope"], "openid");

        // No scope requested: the client gets what it is registered for, nothing more.
        let (_, code, _) = do_authorize(&state, headers, "narrow", None).await;
        let stored = f
            .storage()
            .get_kv(&format!("oauth2_code:{}", code.unwrap()))
            .await
            .unwrap()
            .unwrap();
        let stored: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert_eq!(stored["scope"], "openid");
    }

    #[tokio::test]
    async fn the_token_endpoint_clamps_a_code_to_the_clients_registration() {
        let f = framework().await;
        let state = ApiState::new(f.clone()).await.unwrap();
        register(&f, "narrow", "openid").await;
        let u = user(&f).await;
        // a code carrying more than the client may hold (e.g. issued before scopes were enforced)
        put(
            &f,
            "oauth2_code:ac_overbroad",
            serde_json::json!({
                "client_id": "narrow", "redirect_uri": REDIRECT, "user_id": u.id,
                "scope": "openid refresh admin",
                "code_challenge": challenge(), "code_challenge_method": "S256",
            }),
        )
        .await;
        let access = redeem(&state, "narrow", "ac_overbroad")
            .await
            .expect("redeems");
        let claims = f.token_manager().validate_jwt_token(&access).unwrap();
        assert_eq!(claims.scope, "openid");
    }

    #[tokio::test]
    async fn refresh_rejects_an_oauth_access_token_whatever_its_scope() {
        let f = framework().await;
        let state = ApiState::new(f.clone()).await.unwrap();
        // permissive registration so the OAuth token can legitimately carry the word
        register(&f, "wide", "openid refresh token_refresh_manager").await;
        let u = user(&f).await;
        put(
            &f,
            &format!("user_permissions:{}", u.id),
            serde_json::json!(["read", "write", "admin"]),
        )
        .await;
        for scope in ["refresh", "openid refresh", "token_refresh_manager"] {
            put(
                &f,
                &format!("oauth2_code:ac_word_{}", scope.replace(' ', "_")),
                serde_json::json!({
                    "client_id": "wide", "redirect_uri": REDIRECT, "user_id": u.id,
                    "scope": scope,
                    "code_challenge": challenge(), "code_challenge_method": "S256",
                }),
            )
            .await;
            let access = redeem(
                &state,
                "wide",
                &format!("ac_word_{}", scope.replace(' ', "_")),
            )
            .await
            .expect("redeems");
            let r = refresh_token(
                State(state.clone()),
                Json(RefreshRequest {
                    refresh_token: access,
                }),
            )
            .await;
            assert!(
                !r.success,
                "an access token with scope {scope:?} must not refresh"
            );
        }
    }

    #[tokio::test]
    async fn registrations_are_read_in_every_shape_and_empty_means_nothing() {
        let f = framework().await;
        let state = ApiState::new(f.clone()).await.unwrap();
        let u = user(&f).await;
        let (_, headers) = bearer_for(&f, &u.id, &["user"]);

        // `scopes` list shape
        put(
            &f,
            "oauth2_client:listy",
            serde_json::json!({
                "client_id": "listy", "redirect_uris": [REDIRECT], "scopes": ["openid", "profile"]
            }),
        )
        .await;
        let (s, code, _) =
            do_authorize(&state, headers.clone(), "listy", Some("openid profile")).await;
        assert!((300..400).contains(&s) && code.is_some(), "{s}");
        let (s, _, err) = do_authorize(&state, headers.clone(), "listy", Some("email")).await;
        assert_eq!((s, err.as_deref()), (400, Some("invalid_scope")));

        // a registration that names an empty scope is granted nothing
        register(&f, "empty", "").await;
        for requested in [None, Some("openid")] {
            let (s, code, err) = do_authorize(&state, headers.clone(), "empty", requested).await;
            assert_eq!(
                (s, err.as_deref()),
                (400, Some("invalid_scope")),
                "{requested:?}"
            );
            assert!(code.is_none());
        }

        // duplicates are collapsed
        register(&f, "dup", "openid profile").await;
        let (_, code, _) = do_authorize(
            &state,
            headers,
            "dup",
            Some("openid profile openid profile"),
        )
        .await;
        let stored = f
            .storage()
            .get_kv(&format!("oauth2_code:{}", code.unwrap()))
            .await
            .unwrap()
            .unwrap();
        let stored: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert_eq!(stored["scope"], "openid profile");
    }

    #[tokio::test]
    async fn the_refresh_grant_never_exceeds_the_current_registration() {
        let f = framework().await;
        let state = ApiState::new(f.clone()).await.unwrap();
        register(&f, "narrow", "openid").await;
        let u = user(&f).await;
        // a stored refresh record that carries more than the client may hold
        put(
            &f,
            "oauth2_refresh_token:rt_overbroad",
            serde_json::json!({
                "user_id": u.id, "client_id": "narrow", "scopes": "openid admin refresh"
            }),
        )
        .await;
        let resp = token(
            State(state.clone()),
            Json(TokenRequest {
                grant_type: "refresh_token".into(),
                refresh_token: Some("rt_overbroad".into()),
                client_id: Some("narrow".into()),
                ..Default::default()
            }),
        )
        .await;
        assert!(resp.success, "{:?}", resp.error);
        let access = serde_json::to_value(resp.data.unwrap()).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            f.token_manager().validate_jwt_token(&access).unwrap().scope,
            "openid"
        );
    }

    #[tokio::test]
    async fn refresh_rejects_an_access_token_with_a_role_that_contains_the_word() {
        let f = framework().await;
        let state = ApiState::new(f.clone()).await.unwrap();
        let u = user(&f).await;
        let (jwt, _) = bearer_for(&f, &u.id, &["token_refresh_manager"]);
        let r = refresh_token(State(state), Json(RefreshRequest { refresh_token: jwt })).await;
        assert!(!r.success);
        assert_eq!(r.error.unwrap().code, "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn a_genuine_refresh_token_still_refreshes_and_is_not_an_access_token() {
        let f = framework().await;
        let state = ApiState::new(f.clone()).await.unwrap();
        let u = user(&f).await;
        let resp = login(
            State(state.clone()),
            HeaderMap::new(),
            Json(LoginRequest {
                username: u.username.clone(),
                password: PASSWORD.to_string(),
                challenge_id: None,
                mfa_code: None,
                remember_me: false,
            }),
        )
        .await;
        assert!(resp.success, "{:?}", resp.error);
        let login = resp.data.unwrap();

        let ok = refresh_token(
            State(state.clone()),
            Json(RefreshRequest {
                refresh_token: login.refresh_token.clone(),
            }),
        )
        .await;
        assert!(ok.success, "{:?}", ok.error);

        // the access token is not a refresh token ...
        let bad = refresh_token(
            State(state.clone()),
            Json(RefreshRequest {
                refresh_token: login.access_token.clone(),
            }),
        )
        .await;
        assert!(!bad.success);
        // ... and the refresh token is not an access token
        assert!(validate_api_token(&f, &login.refresh_token).await.is_err());
        assert!(validate_api_token(&f, &login.access_token).await.is_ok());
    }
}
