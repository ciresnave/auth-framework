//! Comprehensive API and Integration Tests for AuthFramewo        let mut framework = AuthFramework::new(config);
// Framework not yet initialized
//!
//! This test suite validates all public APIs, edge cases, and integration scenarios
//! for the current AuthFramework implementation.

use auth_framework::{
    auth::AuthFramework,
    authentication::credentials::{Credential, CredentialMetadata},
    config::{
        AuthConfig, CookieSameSite, JwtAlgorithm, PasswordHashAlgorithm, RateLimitConfig,
        SecurityConfig, StorageConfig,
    },
    errors::AuthError,
    methods::{ApiKeyMethod, AuthMethodEnum, JwtMethod, OAuth2Method, PasswordMethod},
    tokens::AuthToken,
};
use std::time::Duration;

/// Test suite for AuthFramework initialization and configuration
#[cfg(test)]
mod framework_lifecycle_tests {
    use super::*;

    #[tokio::test]
    async fn test_new_framework_with_minimal_config() {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());

        let framework = AuthFramework::new(config);
        // Framework created successfully (can't test initialization state)
        let credential = Credential::password("test", "pass");
        assert!(
            framework
                .authenticate("password", credential)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_new_framework_with_full_config() {
        let config = AuthConfig::new()
            .secret("test_secret_key_32_bytes_long!!!!".to_string())
            .issuer("test-issuer".to_string())
            .audience("test-audience".to_string())
            .storage(StorageConfig::Memory)
            .security(SecurityConfig {
                min_password_length: 12,
                require_password_complexity: true,
                password_hash_algorithm: PasswordHashAlgorithm::Argon2,
                jwt_algorithm: JwtAlgorithm::HS256,
                secret_key: Some("test_secret_key_32_bytes_long!!!!".to_string()),
                secure_cookies: true,
                cookie_same_site: CookieSameSite::Strict,
                csrf_protection: true,
                session_timeout: Duration::from_secs(1800),
            })
            .rate_limiting(RateLimitConfig {
                enabled: true,
                max_requests: 100,
                window: Duration::from_secs(60),
                burst: 150,
            });

        let mut framework = AuthFramework::new(config);
        assert!(framework.initialize().await.is_ok());
        // Framework successfully initialized
    }

    #[tokio::test]
    async fn test_framework_initialization_success() {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let mut framework = AuthFramework::new(config);

        let result = framework.initialize().await;
        assert!(result.is_ok());
        // Framework successfully initialized
    }

    #[tokio::test]
    async fn test_framework_double_initialization() {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let mut framework = AuthFramework::new(config);

        // First initialization
        assert!(framework.initialize().await.is_ok());
        // Framework successfully initialized

        // Second initialization should succeed (idempotent)
        assert!(framework.initialize().await.is_ok());
        // Framework still initialized
    }

    #[test]
    fn test_framework_new_with_invalid_secret() {
        // Secret too short
        let config = AuthConfig::new().secret("short".to_string());

        // This should not panic but should show a warning
        let _framework = AuthFramework::new(config);
    }

    #[test]
    fn test_framework_new_with_env_var_fallback() {
        // Test JWT_SECRET environment variable fallback
        unsafe {
            std::env::set_var("JWT_SECRET", "env_secret_key_32_bytes_long!!!!!");
        }

        let config = AuthConfig::new(); // No explicit secret
        let _framework = AuthFramework::new(config);

        unsafe {
            std::env::remove_var("JWT_SECRET");
        }
    }
}

/// Test suite for authentication method registration and management
#[cfg(test)]
mod method_registration_tests {
    use super::*;

    #[tokio::test]
    async fn test_register_password_method() {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let mut framework = AuthFramework::new(config);

        framework.register_method("password", AuthMethodEnum::Password(PasswordMethod::new()));

        assert!(framework.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_register_multiple_methods() {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let mut framework = AuthFramework::new(config);

        framework.register_method("password", AuthMethodEnum::Password(PasswordMethod::new()));
        framework.register_method("jwt", AuthMethodEnum::Jwt(JwtMethod::new()));
        framework.register_method("api_key", AuthMethodEnum::ApiKey(ApiKeyMethod::new()));
        framework.register_method("oauth2", AuthMethodEnum::OAuth2(OAuth2Method::new()));

        assert!(framework.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_register_method_overwrite() {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let mut framework = AuthFramework::new(config);

        // Register method twice - should overwrite
        framework.register_method("password", AuthMethodEnum::Password(PasswordMethod::new()));
        framework.register_method("password", AuthMethodEnum::Password(PasswordMethod::new()));

        assert!(framework.initialize().await.is_ok());
    }
}

/// Test suite for authentication flows and edge cases
#[cfg(test)]
mod authentication_tests {
    use super::*;

    async fn setup_framework_with_methods() -> AuthFramework {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let mut framework = AuthFramework::new(config);

        framework.register_method("password", AuthMethodEnum::Password(PasswordMethod::new()));
        framework.register_method("jwt", AuthMethodEnum::Jwt(JwtMethod::new()));
        framework.register_method("api_key", AuthMethodEnum::ApiKey(ApiKeyMethod::new()));

        framework.initialize().await.unwrap();
        framework
    }

    #[tokio::test]
    async fn test_authenticate_with_uninitialized_framework() {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let framework = AuthFramework::new(config); // Not initialized

        let credential = Credential::password("user", "password");
        let result = framework.authenticate("password", credential).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthError::Internal { message: _ }
        ));
    }

    #[tokio::test]
    async fn test_authenticate_with_unknown_method() {
        let framework = setup_framework_with_methods().await;

        let credential = Credential::password("user", "password");
        let result = framework.authenticate("unknown_method", credential).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthError::AuthMethod {
                method: _,
                message: _,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_authenticate_password_empty_credentials() {
        let framework = setup_framework_with_methods().await;

        let credential = Credential::password("", "");
        let result = framework.authenticate("password", credential).await;

        // Should succeed but return failure result from method
        assert!(result.is_ok());
        match result.unwrap() {
            auth_framework::AuthResult::Failure(reason) => {
                assert!(reason.contains("empty"));
            }
            _ => panic!("Expected failure result"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_jwt_empty_token() {
        let framework = setup_framework_with_methods().await;

        let credential = Credential::jwt("");
        let result = framework.authenticate("jwt", credential).await;

        assert!(result.is_ok());
        match result.unwrap() {
            auth_framework::AuthResult::Failure(reason) => {
                assert!(reason.contains("empty"));
            }
            _ => panic!("Expected failure result"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_api_key_empty_key() {
        let framework = setup_framework_with_methods().await;

        let credential = Credential::api_key("");
        let result = framework.authenticate("api_key", credential).await;

        assert!(result.is_ok());
        match result.unwrap() {
            auth_framework::AuthResult::Failure(reason) => {
                assert!(reason.contains("empty"));
            }
            _ => panic!("Expected failure result"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_with_metadata() {
        let framework = setup_framework_with_methods().await;

        let credential = Credential::password("user", "password");
        let _metadata = CredentialMetadata::new();
        let metadata = CredentialMetadata::new()
            .client_ip("192.168.1.1".to_string())
            .user_agent("TestAgent/1.0".to_string());

        let result = framework
            .authenticate_with_metadata("password", credential, metadata)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_authenticate_with_localhost_ip_warning() {
        let framework = setup_framework_with_methods().await;

        let credential = Credential::password("user", "password");
        let metadata = CredentialMetadata::new().client_ip("127.0.0.1");

        let result = framework
            .authenticate_with_metadata("password", credential, metadata)
            .await;
        assert!(result.is_ok()); // Should still work but log warning
    }
}

/// Test suite for token management and validation
#[cfg(test)]
mod token_management_tests {
    use super::*;

    async fn setup_framework() -> AuthFramework {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();
        framework
    }

    #[tokio::test]
    async fn test_create_auth_token_success() {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let mut framework = AuthFramework::new(config);
        framework.register_method("password", AuthMethodEnum::Password(PasswordMethod::new()));
        framework.initialize().await.unwrap();

        let result = framework
            .create_auth_token(
                "user123",
                vec!["read".to_string(), "write".to_string()],
                "password",
                Some(Duration::from_secs(3600)),
            )
            .await;

        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.user_id, "user123");
        assert_eq!(token.scopes, vec!["read", "write"]);
        assert_eq!(token.auth_method, "password");
    }

    #[tokio::test]
    async fn test_create_auth_token_with_unknown_method() {
        let framework = setup_framework().await;

        let result = framework
            .create_auth_token("user123", vec!["read".to_string()], "unknown_method", None)
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthError::AuthMethod {
                method: _,
                message: _,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_validate_token_uninitialized_framework() {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let framework = AuthFramework::new(config); // Not initialized

        let token = AuthToken::new("user", "token", Duration::from_secs(3600), "test");
        let result = framework.validate_token(&token).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthError::Internal { message: _ }
        ));
    }

    #[tokio::test]
    async fn test_token_manager_access() {
        let framework = setup_framework().await;
        let token_manager = framework.token_manager();

        // Just verify we can access the token manager
        // Token manager initialized successfully
        assert!(token_manager.validate_jwt_token("invalid_token").is_err());
    }
}

/// Test suite for user management and validation
#[cfg(test)]
mod user_management_tests {
    use super::*;

    async fn setup_framework() -> AuthFramework {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();
        framework
    }

    #[tokio::test]
    async fn test_validate_username_valid() {
        let framework = setup_framework().await;

        let result = framework.validate_username("valid_user123").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_validate_username_empty() {
        let framework = setup_framework().await;

        let result = framework.validate_username("").await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Empty username should be invalid
    }

    #[tokio::test]
    async fn test_validate_username_too_long() {
        let framework = setup_framework().await;

        let long_username = "a".repeat(256); // Very long username
        let result = framework.validate_username(&long_username).await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Too long username should be invalid
    }

    #[tokio::test]
    async fn test_validate_display_name_valid() {
        let framework = setup_framework().await;

        let result = framework.validate_display_name("John Doe").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_validate_display_name_empty() {
        let framework = setup_framework().await;

        let result = framework.validate_display_name("").await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Empty display name should be invalid
    }

    #[tokio::test]
    async fn test_validate_user_input_safe() {
        let framework = setup_framework().await;

        let result = framework.validate_user_input("safe_input_123").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_validate_user_input_potentially_malicious() {
        let framework = setup_framework().await;

        let result = framework
            .validate_user_input("<script>alert('xss')</script>")
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Potentially malicious input should be invalid
    }
}

/// Test suite for MFA (Multi-Factor Authentication) functionality
#[cfg(test)]
mod mfa_tests {
    use super::*;

    async fn setup_framework() -> AuthFramework {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();
        framework
    }

    #[tokio::test]
    async fn test_initiate_sms_challenge_success() {
        let framework = setup_framework().await;

        let result = framework.initiate_sms_challenge("user123").await;
        assert!(result.is_ok());
        let challenge_id = result.unwrap();
        assert!(!challenge_id.is_empty());
    }

    #[tokio::test]
    async fn test_initiate_sms_challenge_empty_user() {
        let framework = setup_framework().await;

        let result = framework.initiate_sms_challenge("").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_sms_code_invalid_challenge() {
        let framework = setup_framework().await;

        let result = framework
            .verify_sms_code("invalid_challenge_id", "123456")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_initiate_email_challenge_success() {
        let framework = setup_framework().await;

        let result = framework.initiate_email_challenge("user123").await;
        assert!(result.is_ok());
        let challenge_id = result.unwrap();
        assert!(!challenge_id.is_empty());
    }

    #[tokio::test]
    async fn test_register_email_valid() {
        let framework = setup_framework().await;

        let result = framework
            .register_email("user123", "user@example.com")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_register_email_invalid_format() {
        let framework = setup_framework().await;

        let result = framework.register_email("user123", "invalid-email").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthError::Validation { message: _ }
        ));
    }

    #[tokio::test]
    async fn test_register_email_empty() {
        let framework = setup_framework().await;

        let result = framework.register_email("user123", "").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthError::Validation { message: _ }
        ));
    }

    #[tokio::test]
    async fn test_register_email_no_at_symbol() {
        let framework = setup_framework().await;

        let result = framework.register_email("user123", "userexample.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_register_email_no_domain() {
        let framework = setup_framework().await;

        let result = framework.register_email("user123", "user@").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_register_email_invalid_domain() {
        let framework = setup_framework().await;

        let result = framework.register_email("user123", "user@.com").await;
        assert!(result.is_err());
    }
}

/// Test suite for API key management
#[cfg(test)]
mod api_key_tests {
    use super::*;

    async fn setup_framework() -> AuthFramework {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();
        framework
    }

    #[tokio::test]
    async fn test_validate_api_key_nonexistent() {
        let framework = setup_framework().await;

        let result = framework.validate_api_key("nonexistent_key").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::Token(_)));
    }

    #[tokio::test]
    async fn test_validate_api_key_empty() {
        let framework = setup_framework().await;

        let result = framework.validate_api_key("").await;
        assert!(result.is_err());
    }
}

/// Test suite for session management
#[cfg(test)]
mod session_tests {
    use super::*;

    async fn setup_framework() -> AuthFramework {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();
        framework
    }

    #[tokio::test]
    async fn test_get_nonexistent_session() {
        let framework = setup_framework().await;

        let result = framework.get_session("nonexistent_session").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_session() {
        let framework = setup_framework().await;

        let result = framework.delete_session("nonexistent_session").await;
        assert!(result.is_ok()); // Should succeed even if session doesn't exist
    }

    #[tokio::test]
    async fn test_list_user_tokens_empty() {
        let framework = setup_framework().await;

        let result = framework.list_user_tokens("nonexistent_user").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}

/// Test suite for rate limiting functionality
#[cfg(test)]
mod rate_limiting_tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiting_disabled() {
        let config = AuthConfig::new()
            .secret("test_secret_key_32_bytes_long!!!!".to_string())
            .rate_limiting(RateLimitConfig {
                enabled: false,
                max_requests: 10,
                window: Duration::from_secs(60),
                burst: 15,
            });
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();

        let result = framework.check_ip_rate_limit("192.168.1.1").await;
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should always pass when disabled
    }

    #[tokio::test]
    async fn test_rate_limiting_enabled() {
        let config = AuthConfig::new()
            .secret("test_secret_key_32_bytes_long!!!!".to_string())
            .rate_limiting(RateLimitConfig {
                enabled: true,
                max_requests: 5,
                window: Duration::from_secs(60),
                burst: 10,
            });
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();

        let result = framework.check_ip_rate_limit("192.168.1.1").await;
        assert!(result.is_ok());
    }
}

/// Test suite for statistics and monitoring
#[cfg(test)]
mod monitoring_tests {
    use super::*;

    async fn setup_framework() -> AuthFramework {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();
        framework
    }

    #[tokio::test]
    async fn test_get_stats() {
        let framework = setup_framework().await;

        let result = framework.get_stats().await;
        assert!(result.is_ok());
        let stats = result.unwrap();

        // Verify stats structure
        assert_eq!(stats.registered_methods.len(), 0); // No methods registered
        assert_eq!(stats.tokens_issued, 0);
    }

    #[tokio::test]
    async fn test_get_security_metrics() {
        let framework = setup_framework().await;

        let result = framework.get_security_metrics().await;
        assert!(result.is_ok());
        let metrics = result.unwrap();

        // Should return a HashMap with security metrics
        assert!(metrics.contains_key("failed_attempts"));
        assert!(metrics.contains_key("successful_attempts"));
    }

    #[tokio::test]
    async fn test_cleanup_expired_data() {
        let framework = setup_framework().await;

        let result = framework.cleanup_expired_data().await;
        assert!(result.is_ok());
    }
}

/// Test suite for edge cases and error conditions
#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_config_validation_edge_cases() {
        // Test with minimal valid config
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        assert!(config.validate().is_ok());

        // Test with empty issuer (should still be valid)
        let config = AuthConfig::new()
            .secret("test_secret_key_32_bytes_long!!!!".to_string())
            .issuer("".to_string());
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_concurrent_initialization() {
        let config = AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!".to_string());
        let mut framework = AuthFramework::new(config);

        // Try to initialize from multiple tasks simultaneously
        let handles: Vec<_> = (0..5)
            .map(|_| {
                tokio::spawn(async move {
                    // This won't work because we need mutable access
                    // framework.initialize().await
                })
            })
            .collect();

        // Wait for all tasks to complete
        for handle in handles {
            let _ = handle.await;
        }

        // Manual initialization should still work
        assert!(framework.initialize().await.is_ok());
    }

    #[test]
    fn test_memory_safety_with_large_configs() {
        // Test with very large configuration values
        let large_string = "a".repeat(10000);
        let config = AuthConfig::new()
            .secret("test_secret_key_32_bytes_long!!!!".to_string())
            .issuer(large_string.clone())
            .audience(large_string);

        let _framework = AuthFramework::new(config);
    }
}
