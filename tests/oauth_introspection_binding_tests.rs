//! `/oauth/introspect` reports a token that was issued to an OAuth client only to that client
//! (RFC 7662 section 4: the server decides which callers may learn about which tokens). Another
//! authenticated client gets `active: false` and nothing else. A token that carries no client
//! (a first-party token) is still introspectable by any authenticated client: the framework has
//! no resource-server role to restrict it to yet.

#[cfg(all(test, feature = "axum-integration"))]
mod introspection_binding_tests {
    use auth_framework::api::ApiState;
    use auth_framework::api::oauth_advanced::{
        IntrospectRequest, IntrospectResponse, introspect_token,
    };
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Form;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
    use base64::Engine;
    use std::sync::Arc;
    use std::time::Duration;

    const SECRET: &str = "test_introspection_binding_secret_key_long_enough";

    struct Env {
        state: ApiState,
        fw: Arc<AuthFramework>,
    }

    async fn env() -> Env {
        let config = AuthConfig::new()
            .secret(SECRET.to_string())
            .token_lifetime(Duration::from_secs(300));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        let fw = Arc::new(f);
        let state = ApiState::new(fw.clone()).await.unwrap();
        for (id, secret) in [("ib-a", "secret-a"), ("ib-b", "secret-b")] {
            fw.storage()
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
        Env { state, fw }
    }

    async fn introspect(env: &Env, caller: (&str, &str), token: &str) -> IntrospectResponse {
        let mut headers = HeaderMap::new();
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", caller.0, caller.1));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {basic}")).unwrap(),
        );
        let response = introspect_token(
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
        .unwrap_or_else(|(status, _)| panic!("introspection refused the caller: {status}"));
        response.0
    }

    /// A JWT for `user`. This line mints no client-bound JWT, so a bound one is made by taking
    /// a token of our own, setting its client claim and signing it with the same secret.
    fn token_of(env: &Env, user: &str, client: Option<&str>) -> String {
        let manager = env.fw.token_manager();
        let jwt = manager
            .create_jwt_token(user, vec!["read".into()], Some(Duration::from_secs(300)))
            .unwrap();
        let Some(client) = client else {
            return jwt;
        };
        let mut claims = manager.validate_jwt_token(&jwt).unwrap();
        claims.client_id = Some(client.to_string());
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn the_client_a_token_was_issued_to_sees_it_active() {
        let env = env().await;
        let jwt = token_of(&env, "alice", Some("ib-a"));
        let answer = introspect(&env, ("ib-a", "secret-a"), &jwt).await;
        assert!(answer.active);
        assert_eq!(answer.client_id.as_deref(), Some("ib-a"));
        assert_eq!(answer.sub.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn another_client_learns_nothing_about_it() {
        let env = env().await;
        let jwt = token_of(&env, "alice", Some("ib-a"));
        let answer = introspect(&env, ("ib-b", "secret-b"), &jwt).await;
        assert!(!answer.active, "another client must not see the token");
        assert!(answer.sub.is_none() && answer.scope.is_none() && answer.client_id.is_none());
        assert!(answer.jti.is_none() && answer.username.is_none() && answer.exp.is_none());
    }

    /// The limit: a token with no client is introspectable by any authenticated client.
    #[tokio::test]
    async fn a_first_party_token_is_still_introspectable_by_an_authenticated_client() {
        let env = env().await;
        let jwt = token_of(&env, "alice", None);
        let answer = introspect(&env, ("ib-b", "secret-b"), &jwt).await;
        assert!(answer.active);
        assert_eq!(answer.sub.as_deref(), Some("alice"));
    }
}
