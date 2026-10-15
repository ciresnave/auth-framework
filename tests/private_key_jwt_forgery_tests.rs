//! `private_key_jwt` client authentication must verify the assertion against the registered
//! PUBLIC key. It used to derive an HMAC secret from the public JWK members themselves
//! (`rsa_private_key_jwt_n:{n}_e:{e}`), so anyone who could read the client's public key could
//! mint an assertion that verified.

use auth_framework::security::secure_jwt::{SecureJwtConfig, SecureJwtValidator};
use auth_framework::server::jwt::private_key_jwt::{ClientJwtConfig, PrivateKeyJwtManager};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

const N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS";
const E: &str = "AQAB";
const CLIENT: &str = "forged_client";

#[allow(clippy::field_reassign_with_default)] // each override stays on its own line so the diff against Default is readable
fn manager() -> PrivateKeyJwtManager {
    // A deployment that accepts HS256 assertions for this client: the enhanced validator is told
    // to expect the client id as issuer (the default issuer allow-list would refuse every client).
    let mut config = SecureJwtConfig::default();
    config.required_issuers = std::iter::once(CLIENT.to_string()).collect();
    config.allowed_algorithms = vec![Algorithm::HS256];
    let validator = SecureJwtValidator::new(config).unwrap();
    PrivateKeyJwtManager::new(validator)
}

/// An assertion for `CLIENT` signed HS256 with a secret anyone can compute from the public JWK.
fn forged_assertion() -> String {
    let now = Utc::now();
    let claims = serde_json::json!({
        "iss": CLIENT,
        "sub": CLIENT,
        "aud": CLIENT,
        "jti": uuid::Uuid::new_v4().to_string(),
        "exp": (now + Duration::minutes(5)).timestamp(),
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "scope": "openid",
        "typ": "access",
    });
    let secret = format!("rsa_private_key_jwt_n:{N}_e:{E}");
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

#[tokio::test]
async fn an_assertion_forged_from_the_public_jwk_does_not_authenticate() {
    let mgr = manager();
    let jwk = serde_json::json!({ "kty": "RSA", "n": N, "e": E });
    // The configuration that made the forgery work: HS256 allowed for a public-key client.
    let config = ClientJwtConfig::builder(CLIENT, jwk)
        .algorithms(vec![Algorithm::HS256])
        .audience(CLIENT)
        .build();

    // Either registration refuses the configuration (the fix) or, if it is accepted, the forged
    // assertion must not authenticate. It must never authenticate.
    if mgr.register_client(config).await.is_ok() {
        let result = mgr.authenticate_client(&forged_assertion()).await.unwrap();
        assert!(
            !result.authenticated,
            "an assertion signed with a secret derived from the PUBLIC key authenticated"
        );
    }
}
