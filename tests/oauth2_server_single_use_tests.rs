//! `OAuth2Server` redeems an authorization code, and rotates a refresh token, exactly once even
//! when many requests present the same value at the same time (RFC 6749 sections 4.1.2 and 10.4).

use auth_framework::oauth2_server::{
    AuthorizationRequest, OAuth2Config, OAuth2Server, TokenRequest,
};
use auth_framework::tokens::TokenManager;
use auth_framework::user_context::UserContext;
use std::sync::Arc;

const REDIRECT: &str = "https://app.example.com/cb";
const VERIFIER: &str = "a-sufficiently-long-code-verifier-0123456789-abcdefghij";

async fn server() -> Arc<OAuth2Server> {
    let token_manager = Arc::new(TokenManager::new_hmac(
        b"test_secret_key_32_bytes_long!!!!",
        "test_issuer",
        "test_audience",
    ));
    let server = OAuth2Server::new(OAuth2Config::default(), token_manager)
        .await
        .unwrap();
    server
        .register_public_client(
            "pub-1".to_string(),
            vec![REDIRECT.to_string()],
            vec!["read".to_string()],
            vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
        )
        .await
        .unwrap();
    Arc::new(server)
}

async fn code(server: &OAuth2Server) -> (String, String) {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(VERIFIER.as_bytes()));
    let user = UserContext::new("u1".to_string(), "u1".to_string(), None)
        .with_scopes(vec!["read".to_string()]);
    let issued = server
        .create_authorization_code(
            AuthorizationRequest {
                client_id: "pub-1".to_string(),
                response_type: "code".to_string(),
                redirect_uri: REDIRECT.to_string(),
                scope: Some("read".to_string()),
                state: None,
                code_challenge: Some(challenge),
                code_challenge_method: Some("S256".to_string()),
                nonce: None,
            },
            user,
        )
        .await
        .unwrap();
    (issued.code.clone(), VERIFIER.to_string())
}

fn code_request(code: &str, verifier: &str) -> TokenRequest {
    TokenRequest {
        grant_type: "authorization_code".to_string(),
        client_id: "pub-1".to_string(),
        code: Some(code.to_string()),
        redirect_uri: Some(REDIRECT.to_string()),
        code_verifier: Some(verifier.to_string()),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_redemptions_of_one_code_succeed_once() {
    let server = server().await;
    for round in 0..8 {
        let (code, verifier) = code(&server).await;
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let server = server.clone();
            let request = code_request(&code, &verifier);
            tasks.push(tokio::spawn(async move {
                server.token_exchange(request).await.is_ok()
            }));
        }
        let mut ok = 0;
        for t in tasks {
            if t.await.unwrap() {
                ok += 1;
            }
        }
        assert_eq!(ok, 1, "round {round}: {ok} redemptions succeeded");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_redemptions_of_one_refresh_token_succeed_once() {
    let server = server().await;
    for round in 0..8 {
        let (code, verifier) = code(&server).await;
        let first = server
            .token_exchange(code_request(&code, &verifier))
            .await
            .unwrap();
        let refresh = first.refresh_token.expect("a refresh token is issued");
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let server = server.clone();
            let refresh = refresh.clone();
            tasks.push(tokio::spawn(async move {
                server
                    .token_exchange(TokenRequest {
                        grant_type: "refresh_token".to_string(),
                        client_id: "pub-1".to_string(),
                        refresh_token: Some(refresh),
                        ..Default::default()
                    })
                    .await
                    .is_ok()
            }));
        }
        let mut ok = 0;
        for t in tasks {
            if t.await.unwrap() {
                ok += 1;
            }
        }
        assert_eq!(ok, 1, "round {round}: {ok} redemptions succeeded");
    }
}
