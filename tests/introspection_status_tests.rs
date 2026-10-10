//! `/oauth/introspect` reports a token as active only if it could actually be used: its
//! account is live, and a refresh token is neither spent nor in a revoked chain.

#[cfg(all(test, feature = "axum-integration"))]
mod introspection_status_tests {
    use auth_framework::api::ApiState;
    use auth_framework::api::oauth_advanced::{IntrospectRequest, introspect_token};
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Form;
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

    async fn env() -> Env {
        let config = AuthConfig::new()
            .secret("test_introspection_status_secret_key_long_enough_jwt".to_string())
            .token_lifetime(Duration::from_secs(300))
            .refresh_token_lifetime(Duration::from_secs(3600));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        let fw = Arc::new(f);
        let state = ApiState::new(fw.clone()).await.unwrap();
        let name = format!("is_{}", uuid::Uuid::new_v4().simple());
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
                "oauth2_client:rs",
                serde_json::json!({"client_id": "rs", "client_secret": "rs-secret"})
                    .to_string()
                    .as_bytes(),
                None,
            )
            .await
            .unwrap();
        Env { state, fw, user }
    }

    async fn introspect(env: &Env, token: &str) -> serde_json::Value {
        let mut headers = HeaderMap::new();
        let basic = base64::engine::general_purpose::STANDARD.encode("rs:rs-secret");
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {basic}")).unwrap(),
        );
        let resp = introspect_token(
            State(env.state.clone()),
            headers,
            Form(IntrospectRequest {
                token: token.to_string(),
                token_type_hint: None,
                client_id: None,
                client_secret: None,
            }),
        )
        .await
        .expect("introspection answers");
        serde_json::to_value(&resp.0).unwrap()
    }

    #[tokio::test]
    async fn a_live_access_token_is_active_and_a_deactivated_accounts_is_not() {
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
        let live = introspect(&env, &jwt).await;
        assert_eq!(live["active"], true, "{live}");

        let key = format!("user:{}", env.user);
        let mut rec: serde_json::Value =
            serde_json::from_slice(&env.fw.storage().get_kv(&key).await.unwrap().unwrap()).unwrap();
        rec["active"] = serde_json::json!(false);
        env.fw
            .storage()
            .store_kv(&key, rec.to_string().as_bytes(), None)
            .await
            .unwrap();
        let dead = introspect(&env, &jwt).await;
        assert_eq!(dead["active"], false, "{dead}");
    }

    #[tokio::test]
    async fn a_refresh_token_is_active_until_it_is_spent() {
        let env = env().await;
        let rt = env
            .fw
            .token_manager()
            .create_refresh_jwt_token(&env.user, Some(Duration::from_secs(600)))
            .unwrap();
        let before = introspect(&env, &rt).await;
        assert_eq!(before["active"], true, "{before}");
        assert_eq!(before["token_type"], "refresh_token", "{before}");

        env.fw.redeem_refresh_jwt(&rt).await.unwrap();
        let after = introspect(&env, &rt).await;
        assert_eq!(
            after["active"], false,
            "a spent refresh token is not active: {after}"
        );
    }

    #[tokio::test]
    async fn a_refresh_token_in_a_revoked_chain_is_not_active() {
        let env = env().await;
        let rt1 = env
            .fw
            .token_manager()
            .create_refresh_jwt_token(&env.user, Some(Duration::from_secs(600)))
            .unwrap();
        let rt2 = env
            .fw
            .redeem_refresh_jwt(&rt1)
            .await
            .unwrap()
            .new_refresh_token;
        assert_eq!(introspect(&env, &rt2).await["active"], true);
        // replaying rt1 revokes the chain
        assert!(env.fw.redeem_refresh_jwt(&rt1).await.is_err());
        assert_eq!(introspect(&env, &rt2).await["active"], false);
    }
}
