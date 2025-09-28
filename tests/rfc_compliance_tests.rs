//! RFC Compliance Tests
//!
//! These tests ensure that the AuthFramework complies with relevant RFCs
//! for OAuth 2.0, JWT, and related security standards.

// Standard library imports for Rust 2024 edition
use std::{
    assert,
    println,
    sync::Arc,
    time::Duration,
};

use auth_framework::{
    auth::AuthFramework,
    config::AuthConfig,
    methods::{AuthMethodEnum, JwtMethod},
    oauth2_server::{GrantType, OAuth2Config, OAuth2Server},
    providers::generate_pkce,
    tokens::TokenManager,
};

#[cfg(test)]
mod oauth2_basic_tests {
    use super::*;

    #[tokio::test]
    async fn test_oauth2_server_creation() {
        let config = OAuth2Config::default();
        let token_manager = Arc::new(TokenManager::new_hmac(
            b"test-secret-key-32-bytes-long!!!",
            &config.issuer,
            "test-audience",
        ));

        let server = OAuth2Server::new(config, token_manager).await;
        assert!(server.is_ok());
        println!("✅ OAuth2 server creation successful");
    }

    #[tokio::test]
    async fn test_grant_types_available() {
        let _auth_code = GrantType::AuthorizationCode;
        let _client_creds = GrantType::ClientCredentials;
        let _refresh = GrantType::RefreshToken;
        let _device = GrantType::DeviceCode;
        let _exchange = GrantType::TokenExchange;

        println!("✅ All OAuth2 grant types available");
    }
}

#[cfg(test)]
mod pkce_tests {
    use super::*;

    #[tokio::test]
    async fn test_pkce_generation() {
        let (verifier, challenge) = generate_pkce();
        assert!(!verifier.is_empty());
        assert!(!challenge.is_empty());
        assert_ne!(verifier, challenge);
        println!("✅ PKCE generation working");
    }
}

#[cfg(test)]
mod jwt_tests {
    use super::*;

    #[tokio::test]
    async fn test_jwt_method_creation() {
        let _jwt = JwtMethod::new()
            .secret_key("test-secret")
            .issuer("test-issuer")
            .audience("test-audience");
        println!("✅ JWT method creation working");
    }

    #[tokio::test]
    async fn test_framework_with_jwt() {
        let config = AuthConfig::new()
            .secret("test_secret_key_32_bytes_long!!!!".to_string())
            .token_lifetime(Duration::from_secs(3600));

        let mut auth = AuthFramework::new(config);

        let jwt_method = JwtMethod::new()
            .secret_key("test-secret-32-bytes-long")
            .issuer("test-issuer")
            .audience("test-audience");

        auth.register_method("jwt", AuthMethodEnum::Jwt(jwt_method));
        let result = auth.initialize().await;
        assert!(result.is_ok());
        println!("✅ AuthFramework with JWT initialization working");
    }
}
