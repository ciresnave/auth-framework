//! A client registered without a secret has nothing to authenticate with, so it cannot call
//! `/oauth/introspect` (RFC 7662 section 2.1): neither Basic `client_id:` nor a POST body with
//! an empty `client_secret` gets in, while a client with a secret still does.

#[cfg(all(test, feature = "axum-integration"))]
mod secretless_client_tests {
    use auth_framework::api::ApiState;
    use auth_framework::api::oauth_advanced::{IntrospectRequest, introspect_token};
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Form;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION};
    use base64::Engine;
    use std::sync::Arc;

    async fn state() -> ApiState {
        let config = AuthConfig::new()
            .secret("test_secretless_introspection_secret_key_long_enough".to_string());
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();
        let state = ApiState::new(Arc::new(framework)).await.unwrap();
        for record in [
            serde_json::json!({"client_id": "public-client", "redirect_uris": ["https://a.example/cb"]}),
            serde_json::json!({"client_id": "empty-secret", "client_secret": ""}),
            serde_json::json!({"client_id": "conf-client", "client_secret": "conf-secret"}),
        ] {
            let id = record["client_id"].as_str().unwrap().to_string();
            state
                .auth_framework
                .storage()
                .store_kv(
                    &format!("oauth2_client:{id}"),
                    record.to_string().as_bytes(),
                    None,
                )
                .await
                .unwrap();
        }
        state
    }

    fn basic(client_id: &str, secret: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        headers
    }

    fn body(client: Option<(&str, &str)>) -> Form<IntrospectRequest> {
        Form(IntrospectRequest {
            token: "not-a-token".to_string(),
            token_type_hint: None,
            client_id: client.map(|(id, _)| id.to_string()),
            client_secret: client.map(|(_, secret)| secret.to_string()),
        })
    }

    #[tokio::test]
    async fn a_client_without_a_secret_cannot_introspect() {
        let state = state().await;
        for id in ["public-client", "empty-secret"] {
            let by_basic = introspect_token(State(state.clone()), basic(id, ""), body(None)).await;
            let (status, _) = by_basic.expect_err("an empty secret must not authenticate");
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{id}: Basic");

            let by_body =
                introspect_token(State(state.clone()), HeaderMap::new(), body(Some((id, ""))))
                    .await;
            let (status, _) = by_body.expect_err("an empty secret must not authenticate");
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{id}: body");
        }
    }

    #[tokio::test]
    async fn a_client_with_a_secret_still_introspects() {
        let state = state().await;
        assert!(
            introspect_token(
                State(state.clone()),
                basic("conf-client", "conf-secret"),
                body(None)
            )
            .await
            .is_ok()
        );
        assert!(
            introspect_token(State(state.clone()), basic("conf-client", ""), body(None))
                .await
                .is_err()
        );
        assert!(
            introspect_token(
                State(state),
                HeaderMap::new(),
                body(Some(("conf-client", "wrong")))
            )
            .await
            .is_err()
        );
    }
}
