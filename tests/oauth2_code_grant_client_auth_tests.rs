//! The authorization_code grant authenticates the client (RFC 6749 §4.1.3, §3.2.1):
//! a confidential client must present its registered secret, a code issued to one
//! client cannot be redeemed by another, and a public client is identified by a
//! registered client_id and must use PKCE.

#[cfg(all(test, feature = "api-server"))]
mod code_grant_client_auth_tests {
    use auth_framework::api::ApiState;
    use auth_framework::server::oauth::oauth2_server::TokenRequest;
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Json;
    use axum::extract::State;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    const REDIRECT: &str = "https://app.example.com/cb";
    const VERIFIER: &str = "a-sufficiently-long-code-verifier-0123456789-abcdefghij";

    async fn state() -> ApiState {
        let config = AuthConfig::new()
            .secret("test_code_grant_secret_key_that_is_long_enough_for_jwt".to_string());
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
                Some(std::time::Duration::from_secs(600)),
            )
            .await
            .unwrap();
    }

    async fn register_client(state: &ApiState, client_id: &str, secret: Option<&str>) {
        let mut record = serde_json::json!({
            "client_id": client_id,
            "redirect_uris": [REDIRECT],
        });
        if let Some(secret) = secret {
            record["client_secret"] = serde_json::json!(secret);
        }
        put(state, &format!("oauth2_client:{client_id}"), record).await;
    }

    /// Plants an authorization code issued to `client_id`, with or without a PKCE challenge.
    async fn issue_code(state: &ApiState, client_id: &str, with_pkce: bool) -> String {
        let user_id = state
            .auth_framework
            .register_user(
                &format!("cg_{}", uuid::Uuid::new_v4().simple()),
                &format!("{}@test.example.com", uuid::Uuid::new_v4().simple()),
                "SecurePass123!",
            )
            .await
            .unwrap();
        let code = uuid::Uuid::new_v4().simple().to_string();
        let mut record = serde_json::json!({
            "client_id": client_id,
            "user_id": user_id,
            "redirect_uri": REDIRECT,
            "scope": "openid",
        });
        if with_pkce {
            record["code_challenge"] =
                serde_json::json!(URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())));
            record["code_challenge_method"] = serde_json::json!("S256");
        }
        put(state, &format!("oauth2_code:{code}"), record).await;
        code
    }

    fn request(
        code: &str,
        client_id: &str,
        secret: Option<&str>,
        verifier: Option<&str>,
    ) -> TokenRequest {
        TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code.to_string()),
            client_id: Some(client_id.to_string()),
            client_secret: secret.map(String::from),
            redirect_uri: Some(REDIRECT.to_string()),
            code_verifier: verifier.map(String::from),
            ..Default::default()
        }
    }

    async fn exchange(
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
    async fn confidential_client_must_present_its_secret() {
        let state = state().await;
        register_client(&state, "conf-1", Some("s3cret")).await;

        for (label, secret) in [
            ("missing", None),
            ("wrong", Some("nope")),
            ("empty", Some("")),
        ] {
            let code = issue_code(&state, "conf-1", true).await;
            let resp = exchange(&state, request(&code, "conf-1", secret, Some(VERIFIER))).await;
            assert!(!resp.success, "{label} secret must be refused");
            assert_eq!(error_code(&resp), "invalid_client", "{label} secret");
        }
    }

    #[tokio::test]
    async fn confidential_client_with_its_secret_redeems_with_and_without_pkce() {
        let state = state().await;
        register_client(&state, "conf-1", Some("s3cret")).await;

        let with_pkce = issue_code(&state, "conf-1", true).await;
        let ok = exchange(
            &state,
            request(&with_pkce, "conf-1", Some("s3cret"), Some(VERIFIER)),
        )
        .await;
        assert!(ok.success, "{:?}", ok.error);

        let without_pkce = issue_code(&state, "conf-1", false).await;
        let ok = exchange(
            &state,
            request(&without_pkce, "conf-1", Some("s3cret"), None),
        )
        .await;
        assert!(ok.success, "{:?}", ok.error);
    }

    #[tokio::test]
    async fn a_code_issued_to_another_client_is_refused_and_not_burned() {
        let state = state().await;
        register_client(&state, "conf-1", Some("s3cret-1")).await;
        register_client(&state, "conf-2", Some("s3cret-2")).await;
        let code = issue_code(&state, "conf-1", true).await;

        // conf-2 authenticates correctly but the code is not its own.
        let thief = exchange(
            &state,
            request(&code, "conf-2", Some("s3cret-2"), Some(VERIFIER)),
        )
        .await;
        assert!(!thief.success);
        assert_eq!(error_code(&thief), "invalid_grant");

        // The refusal did not consume the code: its rightful client still redeems it.
        let ok = exchange(
            &state,
            request(&code, "conf-1", Some("s3cret-1"), Some(VERIFIER)),
        )
        .await;
        assert!(ok.success, "{:?}", ok.error);
    }

    #[tokio::test]
    async fn a_failed_client_authentication_does_not_burn_the_code() {
        let state = state().await;
        register_client(&state, "conf-1", Some("s3cret")).await;
        let code = issue_code(&state, "conf-1", true).await;

        let bad = exchange(
            &state,
            request(&code, "conf-1", Some("guess"), Some(VERIFIER)),
        )
        .await;
        assert!(!bad.success);
        let ok = exchange(
            &state,
            request(&code, "conf-1", Some("s3cret"), Some(VERIFIER)),
        )
        .await;
        assert!(ok.success, "{:?}", ok.error);
    }

    #[tokio::test]
    async fn public_clients_are_unchanged_pkce_still_required() {
        let state = state().await;
        register_client(&state, "pub-1", None).await;

        let code = issue_code(&state, "pub-1", true).await;
        let ok = exchange(&state, request(&code, "pub-1", None, Some(VERIFIER))).await;
        assert!(ok.success, "{:?}", ok.error);

        let wrong_verifier = issue_code(&state, "pub-1", true).await;
        let resp = exchange(
            &state,
            request(
                &wrong_verifier,
                "pub-1",
                None,
                Some("not-the-verifier-0123456789-0123456789-0123456789"),
            ),
        )
        .await;
        assert!(!resp.success);
        assert_eq!(error_code(&resp), "invalid_grant");

        let no_pkce = issue_code(&state, "pub-1", false).await;
        let resp = exchange(&state, request(&no_pkce, "pub-1", None, None)).await;
        assert!(
            !resp.success,
            "a public client without PKCE must be refused"
        );
        assert_eq!(error_code(&resp), "invalid_request");
    }

    /// Presenting a secret must not let a PUBLIC client skip PKCE: whether a client is
    /// public comes from its registration, not from what the request carries.
    #[tokio::test]
    async fn a_made_up_secret_does_not_exempt_a_public_client_from_pkce() {
        let state = state().await;
        register_client(&state, "pub-1", None).await;
        let code = issue_code(&state, "pub-1", false).await;
        let resp = exchange(&state, request(&code, "pub-1", Some("anything"), None)).await;
        assert!(
            !resp.success,
            "a public client cannot opt out of PKCE with a secret"
        );
        assert_eq!(error_code(&resp), "invalid_request");
    }

    #[tokio::test]
    async fn an_unregistered_client_cannot_redeem_a_code() {
        let state = state().await;
        // A code that names a client with no registration (e.g. deleted since).
        let code = issue_code(&state, "ghost", true).await;
        let resp = exchange(&state, request(&code, "ghost", None, Some(VERIFIER))).await;
        assert!(!resp.success);
        assert_eq!(error_code(&resp), "invalid_client");
    }
}
