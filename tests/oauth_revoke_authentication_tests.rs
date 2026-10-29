//! `/oauth/revoke` acts only on tokens this server issued, and a refresh token issued to an OAuth
//! client is revoked only by that client (RFC 7009 sections 2.1 and 2.2).

#[cfg(all(test, feature = "axum-integration"))]
mod revoke_authentication_tests {
    use auth_framework::api::ApiState;
    use auth_framework::api::oauth2::{RevokeRequest, revoke};
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
    use base64::Engine;
    use std::sync::Arc;
    use std::time::Duration;

    struct Env {
        state: ApiState,
        fw: Arc<AuthFramework>,
        user: String,
    }

    async fn put(fw: &AuthFramework, key: &str, value: serde_json::Value) {
        fw.storage()
            .store_kv(key, value.to_string().as_bytes(), None)
            .await
            .unwrap();
    }

    async fn env() -> Env {
        let config = AuthConfig::new()
            .secret("test_revoke_authentication_secret_key_long_enough".to_string())
            .token_lifetime(Duration::from_secs(300));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        let fw = Arc::new(f);
        let state = ApiState::new(fw.clone()).await.unwrap();
        let name = format!("rv_{}", uuid::Uuid::new_v4().simple());
        let user = fw
            .register_user(
                &name,
                &format!("{name}@test.example.com"),
                "SecurePass123!x",
            )
            .await
            .unwrap();
        put(
            &fw,
            "oauth2_client:rv-conf",
            serde_json::json!({"client_id": "rv-conf", "client_secret": "rv-conf-secret"}),
        )
        .await;
        put(
            &fw,
            "oauth2_client:rv-pub",
            serde_json::json!({"client_id": "rv-pub"}),
        )
        .await;
        Env { state, fw, user }
    }

    fn request(token: &str, id: Option<&str>, secret: Option<&str>) -> RevokeRequest {
        RevokeRequest {
            token: token.to_string(),
            token_type_hint: None,
            client_id: id.map(String::from),
            client_secret: secret.map(String::from),
        }
    }

    async fn call(
        env: &Env,
        headers: HeaderMap,
        req: RevokeRequest,
    ) -> auth_framework::api::ApiResponse<serde_json::Value> {
        revoke(State(env.state.clone()), headers, axum::Json(req)).await
    }

    async fn marker(env: &Env, token: &str) -> bool {
        env.fw
            .storage()
            .get_kv(&format!("oauth2_revoked_token:{token}"))
            .await
            .unwrap()
            .is_some()
    }

    /// A refresh token issued to `client`: an opaque token with a stored record. (JWTs carry no
    /// client on this line.)
    async fn client_token(env: &Env, client: &str) -> String {
        let token = format!("rt-{}", uuid::Uuid::new_v4().simple());
        put(
            &env.fw,
            &format!("oauth2_refresh_token:{token}"),
            serde_json::json!({"user_id": env.user, "client_id": client, "scopes": "read"}),
        )
        .await;
        token
    }

    /// A flood of requests with strings that are not tokens must not grow storage.
    #[tokio::test]
    async fn strings_that_are_not_tokens_leave_no_marker() {
        let env = env().await;
        let junk: Vec<String> = (0..200)
            .map(|i| format!("not-a-token-{i}-{}", "x".repeat(64)))
            .collect();
        for token in &junk {
            let resp = call(&env, HeaderMap::new(), request(token, None, None)).await;
            assert!(resp.success, "an unknown token still answers success");
        }
        let mut stored = 0;
        for token in &junk {
            if marker(&env, token).await {
                stored += 1;
            }
        }
        eprintln!("revocation markers stored for 200 junk strings: {stored}");
        assert_eq!(stored, 0, "{stored} of 200 junk strings left a marker");
    }

    /// An oversized string is refused before it can become a storage key.
    #[tokio::test]
    async fn an_oversized_token_is_refused_and_leaves_no_marker() {
        let env = env().await;
        let big = "a".repeat(8193);
        let resp = call(&env, HeaderMap::new(), request(&big, None, None)).await;
        assert!(!resp.success);
        assert_eq!(
            resp.error.as_ref().map(|e| e.code.as_str()),
            Some("invalid_request")
        );
        assert!(!marker(&env, &big).await);
        // Control: the boundary itself is accepted (as a no-op, it is not a token).
        let edge = "a".repeat(8192);
        assert!(
            call(&env, HeaderMap::new(), request(&edge, None, None))
                .await
                .success
        );
    }

    /// A JWT signed by someone else is not a token we issued.
    #[tokio::test]
    async fn a_foreign_jwt_is_a_no_op() {
        let env = env().await;
        let other = AuthFramework::new(
            AuthConfig::new().secret("a_different_secret_key_that_is_long_enough_xx".to_string()),
        );
        let foreign = other
            .token_manager()
            .create_jwt_token(
                &env.user,
                vec!["read".into()],
                Some(Duration::from_secs(300)),
            )
            .unwrap();
        // Control: a JWT of our own does validate.
        let ours = env
            .fw
            .token_manager()
            .create_jwt_token(
                &env.user,
                vec!["read".into()],
                Some(Duration::from_secs(300)),
            )
            .unwrap();
        assert!(env.fw.token_manager().validate_jwt_token(&ours).is_ok());
        assert!(env.fw.token_manager().validate_jwt_token(&foreign).is_err());

        let resp = call(&env, HeaderMap::new(), request(&foreign, None, None)).await;
        assert!(resp.success, "answers like success (RFC 7009 2.2)");
        assert!(!marker(&env, &foreign).await, "and stores nothing");
    }

    /// A refresh token of a client whose record is gone cannot be revoked by anyone: the
    /// request fails closed rather than acting without knowing who the owner is.
    #[tokio::test]
    async fn a_token_of_a_deleted_client_fails_closed() {
        let env = env().await;
        let token = client_token(&env, "rv-gone").await;
        let resp = call(
            &env,
            HeaderMap::new(),
            request(&token, Some("rv-gone"), None),
        )
        .await;
        assert_eq!(
            resp.error.as_ref().map(|e| e.code.as_str()),
            Some("invalid_client")
        );
        assert!(!marker(&env, &token).await);
    }

    /// Control: a first-party token (no client) is still revoked by whoever holds it.
    #[tokio::test]
    async fn a_token_with_no_client_is_revoked_by_its_holder() {
        let env = env().await;
        let jwt = env
            .fw
            .token_manager()
            .create_jwt_token(
                &env.user,
                vec!["read".into()],
                Some(Duration::from_secs(300)),
            )
            .unwrap();
        let resp = call(&env, HeaderMap::new(), request(&jwt, None, None)).await;
        assert!(resp.success);
        assert!(marker(&env, &jwt).await);
        let claims = env.fw.token_manager().validate_jwt_token(&jwt).unwrap();
        assert!(
            env.fw
                .storage()
                .get_kv(&format!("revoked_token:{}", claims.jti))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_confidential_clients_token_needs_that_clients_secret() {
        let env = env().await;
        let jwt = client_token(&env, "rv-conf").await;

        // No credentials, wrong secret, another client's id: refused, nothing stored.
        for (label, req) in [
            ("none", request(&jwt, None, None)),
            ("wrong secret", request(&jwt, Some("rv-conf"), Some("nope"))),
            ("id only", request(&jwt, Some("rv-conf"), None)),
            ("other client", request(&jwt, Some("rv-pub"), None)),
        ] {
            let resp = call(&env, HeaderMap::new(), req).await;
            assert!(!resp.success, "{label} must be refused");
            assert_eq!(
                resp.error.as_ref().map(|e| e.code.as_str()),
                Some("invalid_client"),
                "{label}"
            );
            assert!(!marker(&env, &jwt).await, "{label} stored a marker");
        }

        // The right secret in the body revokes it.
        let resp = call(
            &env,
            HeaderMap::new(),
            request(&jwt, Some("rv-conf"), Some("rv-conf-secret")),
        )
        .await;
        assert!(resp.success);
        assert!(marker(&env, &jwt).await);

        // HTTP Basic works too.
        let second = client_token(&env, "rv-conf").await;
        let mut headers = HeaderMap::new();
        let basic = base64::engine::general_purpose::STANDARD.encode("rv-conf:rv-conf-secret");
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {basic}")).unwrap(),
        );
        let resp = call(&env, headers, request(&second, None, None)).await;
        assert!(resp.success);
        assert!(marker(&env, &second).await);
    }

    #[tokio::test]
    async fn a_public_clients_token_is_revoked_by_naming_the_client() {
        let env = env().await;
        let jwt = client_token(&env, "rv-pub").await;

        let resp = call(&env, HeaderMap::new(), request(&jwt, None, None)).await;
        assert!(!resp.success, "no client named");
        let resp = call(
            &env,
            HeaderMap::new(),
            request(&jwt, Some("rv-conf"), Some("rv-conf-secret")),
        )
        .await;
        assert!(!resp.success, "another client cannot revoke it");
        assert!(!marker(&env, &jwt).await);

        let resp = call(&env, HeaderMap::new(), request(&jwt, Some("rv-pub"), None)).await;
        assert!(resp.success);
        assert!(marker(&env, &jwt).await);
    }
}
