//! A client's secret is stored only as a hash (issue #90): dynamic registration writes
//! `client_secret_hash` and no plaintext, a hashed client authenticates with its secret and
//! no other, and a record that still holds a plain `client_secret` keeps working and is
//! rewritten with a hash the first time its client authenticates.

#[cfg(all(test, feature = "axum-integration"))]
mod client_secret_hash_tests {
    use auth_framework::api::ApiState;
    use auth_framework::api::oauth_advanced::{IntrospectRequest, introspect_token};
    use auth_framework::api::oauth2::{ClientRegistrationRequest, register_client};
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Form;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION};
    use axum::response::IntoResponse;
    use base64::Engine;
    use std::sync::Arc;
    use std::time::Duration;

    const IAT: &str = "initial-access-token-for-the-secret-hash-tests";

    async fn state() -> ApiState {
        let config = AuthConfig::new()
            .secret("test_client_secret_hash_secret_key_long_enough_for_jwt".to_string());
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();
        let state = ApiState::new(Arc::new(framework)).await.unwrap();
        state
            .auth_framework
            .storage()
            .store_kv("oauth2_initial_access_token", IAT.as_bytes(), None)
            .await
            .unwrap();
        state
    }

    /// Register a client through the API; returns `(client_id, client_secret)`.
    async fn register(state: &ApiState) -> (String, String) {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {IAT}")).unwrap(),
        );
        let response = register_client(
            State(state.clone()),
            headers,
            axum::Json(ClientRegistrationRequest {
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_name: Some("secret-hash-test".to_string()),
                token_endpoint_auth_method: None,
                grant_types: None,
                response_types: None,
                scope: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (
            json["client_id"].as_str().unwrap().to_string(),
            json["client_secret"].as_str().unwrap().to_string(),
        )
    }

    async fn record(state: &ApiState, client_id: &str) -> serde_json::Value {
        let bytes = state
            .auth_framework
            .storage()
            .get_kv(&format!("oauth2_client:{client_id}"))
            .await
            .unwrap()
            .expect("client record");
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Authenticate to the introspection endpoint as the client; `true` if it was accepted.
    async fn authenticates(state: &ApiState, client_id: &str, secret: &str) -> bool {
        let mut headers = HeaderMap::new();
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
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
        .is_ok()
    }

    #[tokio::test]
    async fn registration_stores_a_hash_and_no_plaintext() {
        let state = state().await;
        let (client_id, secret) = register(&state).await;

        let stored = record(&state, &client_id).await;
        assert!(
            stored.get("client_secret").is_none(),
            "the plain secret must not be stored: {stored}"
        );
        let hash = stored["client_secret_hash"].as_str().expect("a hash");
        assert!(hash.starts_with("$argon2id$"), "{hash}");
        assert!(!stored.to_string().contains(&secret));

        assert!(authenticates(&state, &client_id, &secret).await);
        assert!(!authenticates(&state, &client_id, "not-the-secret").await);
        assert!(!authenticates(&state, &client_id, "").await);
    }

    #[tokio::test]
    async fn a_plain_secret_record_still_authenticates_and_is_upgraded_once() {
        let state = state().await;
        let key = "oauth2_client:legacy-client";
        state
            .auth_framework
            .storage()
            .store_kv(
                key,
                serde_json::json!({
                    "client_id": "legacy-client",
                    "client_secret": "legacy-secret",
                    "redirect_uris": ["https://app.example.com/cb"],
                })
                .to_string()
                .as_bytes(),
                Some(Duration::from_secs(600)),
            )
            .await
            .unwrap();

        // A wrong secret changes nothing.
        assert!(!authenticates(&state, "legacy-client", "wrong").await);
        assert_eq!(
            record(&state, "legacy-client").await["client_secret"],
            "legacy-secret"
        );

        // The right secret authenticates and the record is rewritten.
        assert!(authenticates(&state, "legacy-client", "legacy-secret").await);
        let upgraded = record(&state, "legacy-client").await;
        assert!(upgraded.get("client_secret").is_none(), "{upgraded}");
        assert!(
            upgraded["client_secret_hash"]
                .as_str()
                .is_some_and(|h| h.starts_with("$argon2id$")),
            "{upgraded}"
        );
        assert_eq!(upgraded["redirect_uris"][0], "https://app.example.com/cb");

        // The hashed record keeps working, and still refuses a wrong secret.
        assert!(authenticates(&state, "legacy-client", "legacy-secret").await);
        assert!(!authenticates(&state, "legacy-client", "wrong").await);
        assert!(!authenticates(&state, "legacy-client", "").await);
    }

    /// A client whose record holds only a hash is still confidential at the token endpoint: it is
    /// not mistaken for a public client, and a missing or wrong secret is `invalid_client`.
    #[tokio::test]
    async fn a_hashed_client_is_confidential_at_the_token_endpoint() {
        use auth_framework::server::oauth::oauth2_server::TokenRequest;

        let state = state().await;
        let (client_id, secret) = register(&state).await;

        let exchange = |secret: Option<String>| {
            let state = state.clone();
            let client_id = client_id.clone();
            async move {
                auth_framework::api::oauth2::token(
                    State(state),
                    axum::Json(TokenRequest {
                        grant_type: "authorization_code".to_string(),
                        code: Some("no-such-code".to_string()),
                        client_id: Some(client_id),
                        client_secret: secret,
                        redirect_uri: Some("https://app.example.com/cb".to_string()),
                        ..Default::default()
                    }),
                )
                .await
            }
        };
        let code_of = |resp: &auth_framework::api::ApiResponse<_>| {
            resp.error
                .as_ref()
                .map(|e| e.code.clone())
                .unwrap_or_default()
        };

        for presented in [
            None,
            Some("not-the-secret".to_string()),
            Some(String::new()),
        ] {
            let resp = exchange(presented).await;
            assert!(!resp.success);
            assert_eq!(code_of(&resp), "invalid_client");
        }
        // The right secret gets past client authentication; the code itself does not exist.
        let resp = exchange(Some(secret)).await;
        assert!(!resp.success);
        assert_eq!(code_of(&resp), "invalid_grant");
    }
}
