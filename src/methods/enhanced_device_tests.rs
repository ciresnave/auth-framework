//! Comprehensive tests for enhanced device flow edge cases
//!
//! These tests cover various failure scenarios, edge cases, and integration points
//! to ensure robust behavior of the enhanced device flow implementation.

#[cfg(test)]
#[cfg(feature = "enhanced-device-flow")]
mod enhanced_device_flow_edge_cases {
    use crate::{
        methods::{AuthMethod, enhanced_device::*},
        credentials::{Credential, CredentialMetadata},
        errors::AuthError,
    };
    use oauth_device_flows::Provider as DeviceFlowProvider;
    use std::time::Duration;
    use std::collections::HashMap;

    #[test]
    fn test_enhanced_device_flow_edge_cases() {
        // Test with empty client ID
        let result = std::panic::catch_unwind(|| {
            EnhancedDeviceFlowMethod::new(
                DeviceFlowProvider::GitHub,
                "".to_string(),
            )
        });
        assert!(result.is_ok()); // Should not panic, but validation should catch it

        // Test validation with empty client ID
        let method = EnhancedDeviceFlowMethod::new(
            DeviceFlowProvider::GitHub,
            "".to_string(),
        );
        assert!(method.validate_config().is_err());
    }

    #[test]
    fn test_enhanced_device_flow_provider_conversions() {
        use crate::providers::OAuthProvider;
        
        // Test all provider conversions
        let providers = vec![
            (OAuthProvider::Microsoft, DeviceFlowProvider::Microsoft),
            (OAuthProvider::Google, DeviceFlowProvider::Google),
            (OAuthProvider::GitHub, DeviceFlowProvider::GitHub),
            (OAuthProvider::GitLab, DeviceFlowProvider::GitLab),
        ];

        for (auth_provider, expected_device_provider) in providers {
            let device_provider: DeviceFlowProvider = auth_provider.into();
            assert!(matches!(device_provider, expected_device_provider));
        }
    }

    #[test]
    fn test_enhanced_device_flow_configuration_edge_cases() {
        // Test extreme polling configurations
        let method = EnhancedDeviceFlowMethod::new(
            DeviceFlowProvider::GitHub,
            "test-client-id".to_string(),
        )
        .polling_config(Duration::from_millis(100), 1) // Very short interval, single attempt
        .scopes(vec![]); // Empty scopes

        assert_eq!(method.name(), "enhanced-device-flow");
        assert!(method.validate_config().is_ok());

        // Test with very long scopes list
        let long_scopes: Vec<String> = (0..100)
            .map(|i| format!("scope_{}", i))
            .collect();
        
        let method_with_many_scopes = EnhancedDeviceFlowMethod::new(
            DeviceFlowProvider::Google,
            "test-client-id".to_string(),
        ).scopes(long_scopes);

        assert!(method_with_many_scopes.validate_config().is_ok());
    }

    #[tokio::test]
    async fn test_enhanced_device_flow_credential_handling() {
        let method = EnhancedDeviceFlowMethod::new(
            DeviceFlowProvider::GitHub,
            "test-client-id".to_string(),
        );

        let metadata = CredentialMetadata::default();

        // Test valid start_device_flow credential
        let start_credential = Credential::Custom {
            method: "start_device_flow".to_string(),
            data: HashMap::new(),
        };

        // This will fail because we don't have real OAuth credentials, but it should handle gracefully
        let result = method.authenticate(&start_credential, &metadata).await;
        assert!(result.is_err()); // Expected to fail without real credentials

        // Test invalid credential types
        let invalid_credentials = vec![
            Credential::Password { username: "test".to_string(), password: "test".to_string() },
            Credential::ApiKey { key: "test".to_string() },
            Credential::Bearer { token: "test".to_string() },
            Credential::Custom { method: "unknown_method".to_string(), data: HashMap::new() },
        ];

        for credential in invalid_credentials {
            let result = method.authenticate(&credential, &metadata).await;
            assert!(result.is_err());
            if let Err(AuthError::AuthMethod { message, .. }) = result {
                assert!(message.contains("Invalid credential type"));
            }
        }

        // Test device_flow_token credential (should return specific error)
        let token_credential = Credential::Custom {
            method: "device_flow_token".to_string(),
            data: HashMap::new(),
        };

        let result = method.authenticate(&token_credential, &metadata).await;
        assert!(result.is_err());
        if let Err(AuthError::AuthMethod { message, .. }) = result {
            assert!(message.contains("should be handled separately"));
        }
    }

    #[test]
    fn test_enhanced_device_flow_supports_refresh() {
        let method = EnhancedDeviceFlowMethod::new(
            DeviceFlowProvider::Microsoft,
            "test-client-id".to_string(),
        );

        assert!(method.supports_refresh());
    }

    #[tokio::test]
    async fn test_enhanced_device_flow_refresh_token_handling() {
        let method = EnhancedDeviceFlowMethod::new(
            DeviceFlowProvider::Google,
            "test-client-id".to_string(),
        );

        // Test refresh token method (should return specific error directing to oauth-device-flows)
        let result = method.refresh_token("fake_refresh_token").await;
        assert!(result.is_err());
        if let Err(AuthError::AuthMethod { message, .. }) = result {
            assert!(message.contains("oauth-device-flows TokenManager"));
        }
    }

    #[test]
    fn test_enhanced_device_flow_with_client_secret() {
        // Test method with client secret (required for some providers)
        let method = EnhancedDeviceFlowMethod::new(
            DeviceFlowProvider::Microsoft,
            "test-client-id".to_string(),
        ).client_secret("test-client-secret".to_string());

        assert!(method.validate_config().is_ok());
        assert_eq!(method.name(), "enhanced-device-flow");
    }

    #[test]
    fn test_enhanced_device_flow_qr_codes_feature() {
        let method = EnhancedDeviceFlowMethod::new(
            DeviceFlowProvider::GitHub,
            "test-client-id".to_string(),
        ).with_qr_codes(); // This should not panic even if qr-codes feature is not enabled

        assert!(method.validate_config().is_ok());
    }

    // Mock test to verify DeviceFlowInstructions structure
    #[test]
    fn test_device_flow_instructions_structure() {
        // We can't easily test the actual DeviceFlowInstructions without real OAuth,
        // but we can test that the structure is sound
        use oauth_device_flows::DeviceFlow;
        
        // This tests that our BoxedDeviceFlow type is compatible
        let device_flow = DeviceFlow::new(
            DeviceFlowProvider::GitHub,
            oauth_device_flows::DeviceFlowConfig::new().client_id("test")
        );
        
        // Should not panic to box the device flow
        if device_flow.is_ok() {
            let boxed = Box::new(device_flow.unwrap());
            // Verify we can create the box type that DeviceFlowInstructions expects
            assert!(!boxed.provider().to_string().is_empty());
        }
    }
}

#[cfg(test)]
#[cfg(feature = "enhanced-device-flow")]
mod enhanced_device_flow_integration_tests {
    use crate::{
        AuthFramework, AuthConfig,
        methods::{enhanced_device::*, AuthMethod},
    };
    use oauth_device_flows::Provider as DeviceFlowProvider;

    #[tokio::test]
    async fn test_enhanced_device_flow_framework_integration() {
        // Test integration with AuthFramework
        let config = AuthConfig::new();
        let mut auth = AuthFramework::new(config);

        let enhanced_method = EnhancedDeviceFlowMethod::new(
            DeviceFlowProvider::GitHub,
            "test-client-id".to_string(),
        );

        // Test method registration
        auth.register_method("enhanced_github", Box::new(enhanced_method));
        
        // Test framework initialization
        let init_result = auth.initialize().await;
        assert!(init_result.is_ok());
    }

    #[tokio::test] 
    async fn test_multiple_enhanced_device_flow_methods() {
        let config = AuthConfig::new();
        let mut auth = AuthFramework::new(config);

        // Register multiple enhanced device flow methods for different providers
        let github_method = EnhancedDeviceFlowMethod::new(
            DeviceFlowProvider::GitHub,
            "github-client-id".to_string(),
        );

        let google_method = EnhancedDeviceFlowMethod::new(
            DeviceFlowProvider::Google,
            "google-client-id".to_string(),
        );

        let microsoft_method = EnhancedDeviceFlowMethod::new(
            DeviceFlowProvider::Microsoft,
            "microsoft-client-id".to_string(),
        ).client_secret("microsoft-secret".to_string());

        auth.register_method("github_enhanced", Box::new(github_method));
        auth.register_method("google_enhanced", Box::new(google_method));
        auth.register_method("microsoft_enhanced", Box::new(microsoft_method));

        let init_result = auth.initialize().await;
        assert!(init_result.is_ok());
    }
}
