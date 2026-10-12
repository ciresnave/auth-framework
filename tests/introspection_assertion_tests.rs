//! At the token introspection endpoint a client "assertion" must not be a JWT the SERVER itself
//! signed. The JWT client-authentication arm validated the assertion with the server's own token
//! manager and then compared `sub` with the client id, so any server-issued token whose subject was
//! the client id (a client_credentials access token, for one) authenticated as that client.
//! Private regression test; the file is copied into tests/ of the line under test.

use auth_framework::server::token_exchange::token_introspection::{
    ClientAuthMethod, IntrospectionClientCredentials, TokenIntrospectionConfig,
    TokenIntrospectionRequest, TokenIntrospectionService,
};
use auth_framework::storage::MemoryStorage;
use auth_framework::tokens::TokenManager;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const ISSUER: &str = "https://auth.example.com";

fn service() -> (TokenIntrospectionService, Arc<TokenManager>) {
    let manager = Arc::new(TokenManager::new_hmac(
        b"introspection-assertion-test-secret-32-bytes!",
        ISSUER,
        ISSUER,
    ));
    let config = TokenIntrospectionConfig {
        issuer: ISSUER.to_string(),
        ..TokenIntrospectionConfig::default()
    };
    let svc = TokenIntrospectionService::new(
        config,
        Arc::new(MemoryStorage::new()),
        manager.clone(),
        None,
    );
    (svc, manager)
}

fn request() -> TokenIntrospectionRequest {
    TokenIntrospectionRequest {
        token: "some-other-token".to_string(),
        token_type_hint: None,
        additional_params: HashMap::new(),
    }
}

#[tokio::test]
async fn a_server_signed_token_naming_the_client_is_not_a_client_assertion() {
    let (svc, manager) = service();
    // What a client_credentials access token of client "client-x" looks like: subject = client id,
    // audience = the issuer.
    let token = manager
        .create_jwt_token(
            "client-x",
            vec!["read".to_string()],
            Some(Duration::from_secs(600)),
        )
        .unwrap();

    for method in [
        ClientAuthMethod::ClientSecretJwt,
        ClientAuthMethod::PrivateKeyJwt,
    ] {
        let creds = IntrospectionClientCredentials {
            client_id: "client-x".to_string(),
            client_secret: None,
            client_assertion: Some(token.clone()),
            auth_method: method.clone(),
        };
        let result = svc.introspect_token(request(), Some(creds)).await;
        assert!(
            result.is_err(),
            "{method:?}: a server-signed access token authenticated as the client"
        );
    }
}

#[tokio::test]
async fn the_other_client_authentication_failures_are_still_failures() {
    // control: the endpoint refuses a missing assertion and an unknown secret, so the test above
    // fails because of the assertion arm and not because everything is refused.
    let (svc, _) = service();
    let no_assertion = IntrospectionClientCredentials {
        client_id: "client-x".to_string(),
        client_secret: None,
        client_assertion: None,
        auth_method: ClientAuthMethod::PrivateKeyJwt,
    };
    assert!(
        svc.introspect_token(request(), Some(no_assertion))
            .await
            .is_err()
    );
    let unauthenticated = svc.introspect_token(request(), None).await;
    assert!(unauthenticated.is_err());
}
