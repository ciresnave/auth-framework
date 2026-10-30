//! A user-bound access token issued by `OAuth2Server` carries its client and is not accepted as
//! the user's own session by an `AuthFramework` whose TokenManager shares the signing secret,
//! issuer and audience.
#![cfg(feature = "api-server")]

use auth_framework::api::validate_api_token;
use auth_framework::oauth2_server::{
    AuthorizationRequest, OAuth2Config, OAuth2Server, TokenRequest,
};
use auth_framework::tokens::TokenManager;
use auth_framework::user_context::UserContext;
use auth_framework::{AuthConfig, AuthFramework};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const REDIRECT: &str = "https://app.example.com/cb";
const VERIFIER: &str = "a-sufficiently-long-code-verifier-0123456789-abcdefghij";
const SECRET: &str = "Zq8vL2nXp7TgR4wYb9HcJ6mDs3KfA1eU";

async fn framework_and_server() -> (AuthFramework, OAuth2Server) {
    let mut fw = AuthFramework::new(AuthConfig::new().secret(SECRET.to_string()));
    fw.initialize().await.unwrap();
    // The integrator builds the library server's TokenManager from the same secret.
    let tm = Arc::new(TokenManager::new_hmac(
        SECRET.as_bytes(),
        "auth-framework",
        "auth-framework",
    ));
    let server = OAuth2Server::new(OAuth2Config::default(), tm)
        .await
        .unwrap();
    server
        .register_public_client(
            "pub-1".to_string(),
            vec![REDIRECT.to_string()],
            vec!["read".to_string()],
            vec!["authorization_code".to_string()],
        )
        .await
        .unwrap();
    (fw, server)
}

async fn client_access_token(server: &OAuth2Server) -> String {
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
    server
        .token_exchange(TokenRequest {
            grant_type: "authorization_code".to_string(),
            client_id: "pub-1".to_string(),
            code: Some(issued.code.clone()),
            redirect_uri: Some(REDIRECT.to_string()),
            code_verifier: Some(VERIFIER.to_string()),
            ..Default::default()
        })
        .await
        .unwrap()
        .access_token
}

#[tokio::test]
async fn a_library_client_token_is_not_the_api_session() {
    let (fw, server) = framework_and_server().await;
    let access = client_access_token(&server).await;

    let claims = fw.token_manager().validate_jwt_token(&access).unwrap();
    assert_eq!(claims.client_id.as_deref(), Some("pub-1"));
    assert!(validate_api_token(&fw, &access).await.is_err());

    // Control: a session token minted by the framework is still accepted.
    let session = fw
        .token_manager()
        .create_jwt_token("u1", vec!["read".to_string()], None)
        .unwrap();
    assert!(validate_api_token(&fw, &session).await.is_ok());
}
