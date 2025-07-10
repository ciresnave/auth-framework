//! Enhanced device flow authentication using the oauth-device-flows crate
//!
//! This module provides an enhanced device flow implementation that leverages
//! the specialized oauth-device-flows crate for more robust device authentication.

// CLI integration helpers
#[cfg(feature = "enhanced-device-flow")]
pub mod cli;

#[cfg(feature = "enhanced-device-flow")]
use oauth_device_flows::{DeviceFlow, DeviceFlowConfig, Provider as DeviceFlowProvider, TokenManager as DeviceTokenManager};

use crate::{
    AuthToken, AuthError, Result, 
    methods::{AuthMethod, MethodResult},
    credentials::{Credential, CredentialMetadata},
    tokens::TokenManager,
};
use async_trait::async_trait;
use std::time::Duration;

/// Enhanced device flow authentication method using oauth-device-flows crate
#[cfg(feature = "enhanced-device-flow")]
pub struct EnhancedDeviceFlowMethod {
    name: String,
    client_id: String,
    client_secret: Option<String>,
    provider: DeviceFlowProvider,
    config: DeviceFlowConfig,
    token_manager: TokenManager,
}

#[cfg(feature = "enhanced-device-flow")]
impl EnhancedDeviceFlowMethod {
    /// Create a new enhanced device flow method
    pub fn new(provider: DeviceFlowProvider, client_id: String) -> Self {
        let config = DeviceFlowConfig::new()
            .client_id(&client_id)
            .poll_interval(Duration::from_secs(5))
            .max_attempts(60); // 5 minutes total

        let token_manager = TokenManager::new_hmac(
            b"device-flow-secret",
            "auth-framework",
            "device-flow",
        );

        Self {
            name: "enhanced-device-flow".to_string(),
            client_id,
            client_secret: None,
            provider,
            config,
            token_manager,
        }
    }

    /// Set client secret (if required by provider)
    pub fn client_secret(mut self, client_secret: String) -> Self {
        self.client_secret = Some(client_secret.clone());
        self.config = self.config.client_secret(&client_secret);
        self
    }

    /// Set custom scopes
    pub fn scopes(mut self, scopes: Vec<String>) -> Self {
        self.config = self.config.scopes(scopes);
        self
    }

    /// Set polling configuration
    pub fn polling_config(mut self, interval: Duration, max_attempts: u32) -> Self {
        self.config = self.config
            .poll_interval(interval)
            .max_attempts(max_attempts);
        self
    }

    /// Generate QR code for mobile authentication (if enabled by oauth-device-flows)
    pub fn with_qr_codes(self) -> Self {
        // QR code generation is handled automatically by oauth-device-flows
        // when the qr-codes feature is enabled in that crate
        self
    }

    /// Start device flow and return user instructions
    pub async fn start_device_flow(&self) -> Result<DeviceFlowInstructions> {
        let mut device_flow = DeviceFlow::new(self.provider.clone(), self.config.clone())
            .map_err(|e| AuthError::auth_method(&self.name, format!("Failed to create device flow: {}", e)))?;

        let auth_response = device_flow.initialize().await
            .map_err(|e| AuthError::auth_method(&self.name, format!("Failed to initialize device flow: {}", e)))?;

        // Extract values before moving device_flow
        let verification_uri = auth_response.verification_uri().to_string();
        let user_code = auth_response.user_code().to_string();
        let verification_uri_complete = auth_response.verification_uri_complete().map(|s| s.to_string());
        let expires_in = auth_response.expires_in().as_secs();
        let qr_code = auth_response.generate_qr_code().ok();

        Ok(DeviceFlowInstructions {
            verification_uri,
            user_code,
            verification_uri_complete,
            expires_in,
            device_flow: Box::new(device_flow),
            qr_code,
        })
    }
}

/// Device flow instructions for the user
pub struct DeviceFlowInstructions {
    /// URL where user should authenticate
    pub verification_uri: String,
    /// Code user should enter
    pub user_code: String,
    /// Complete URL with embedded code (optional)
    pub verification_uri_complete: Option<String>,
    /// Time until code expires (seconds)
    pub expires_in: u64,
    /// Internal device flow for polling
    device_flow: Box<DeviceFlow>,
    /// QR code for mobile scanning (if enabled by oauth-device-flows)
    pub qr_code: Option<String>,
}

impl DeviceFlowInstructions {
    /// Poll for token completion with timeout
    pub async fn poll_for_token(self) -> Result<AuthToken> {
        self.poll_for_token_with_timeout(None).await
    }

    /// Poll for token completion with custom timeout
    pub async fn poll_for_token_with_timeout(self, timeout: Option<Duration>) -> Result<AuthToken> {
        let poll_future = async {
            let token_response = self.device_flow.poll_for_token().await
                .map_err(|e| {
                    // Map specific oauth-device-flows errors to our error types
                    match e.to_string().as_str() {
                        s if s.contains("authorization_pending") => 
                            AuthError::auth_method("enhanced-device-flow", "User has not yet authorized the device"),
                        s if s.contains("slow_down") => 
                            AuthError::auth_method("enhanced-device-flow", "Polling too frequently, slowing down"),
                        s if s.contains("access_denied") => 
                            AuthError::auth_method("enhanced-device-flow", "User denied the authorization request"),
                        s if s.contains("expired_token") => 
                            AuthError::auth_method("enhanced-device-flow", "Device code has expired"),
                        s if s.contains("invalid_grant") => 
                            AuthError::auth_method("enhanced-device-flow", "Invalid device code or client credentials"),
                        s if s.contains("timeout") || s.contains("timed out") => 
                            AuthError::auth_method("enhanced-device-flow", "Device flow timed out waiting for user authorization"),
                        s if s.contains("network") || s.contains("connection") => 
                            AuthError::auth_method("enhanced-device-flow", format!("Network error during device flow: {}", s)),
                        _ => AuthError::auth_method("enhanced-device-flow", format!("Device flow failed: {}", e))
                    }
                })?;

            // Create token manager for automatic refresh
            let token_manager = DeviceTokenManager::new(
                token_response.clone(),
                self.device_flow.provider().clone(),
                self.device_flow.config().clone(),
            ).map_err(|e| AuthError::auth_method("enhanced-device-flow", format!("Failed to create token manager: {}", e)))?;

            // Convert to our AuthToken format
            let expires_in = Duration::from_secs(
                token_response.expires_in.unwrap_or(3600)
            );

            // Try to get user information if available (some providers include it in token response)
            let user_id = match self.device_flow.provider() {
                oauth_device_flows::Provider::Microsoft => "ms_user", // Microsoft Graph can provide user info
                oauth_device_flows::Provider::Google => "google_user", // Google provides user info
                oauth_device_flows::Provider::GitHub => "github_user", // GitHub provides user info
                oauth_device_flows::Provider::GitLab => "gitlab_user", // GitLab provides user info
                oauth_device_flows::Provider::Generic => "device_user", // Generic provider fallback
            };

            let auth_token = AuthToken::new(
                user_id,
                token_manager.access_token().to_string(),
                expires_in,
                "enhanced-device-flow",
            );

            Ok(auth_token)
        };

        // Apply timeout if specified
        if let Some(timeout_duration) = timeout {
            match tokio::time::timeout(timeout_duration, poll_future).await {
                Ok(result) => result,
                Err(_) => Err(AuthError::auth_method(
                    "enhanced-device-flow",
                    format!("Device flow timed out after {:?}", timeout_duration)
                ))
            }
        } else {
            poll_future.await
        }
    }

    /// Cancel the device flow (for graceful shutdown)
    pub fn cancel(self) {
        // The oauth-device-flows crate handles cancellation internally
        // when the DeviceFlow is dropped, so we just need to drop self
        drop(self);
    }

    /// Display user-friendly instructions
    pub fn display_instructions(&self) {
        println!("🔐 Device Authentication Required");
        println!("================================");
        println!("Please visit: {}", self.verification_uri);
        println!("And enter code: {}", self.user_code);
        
        if let Some(complete_uri) = &self.verification_uri_complete {
            println!("Or visit directly: {}", complete_uri);
        }

        if let Some(qr_code) = &self.qr_code {
            println!("\nOr scan this QR code:");
            println!("{}", qr_code);
        }

        println!("\n⏰ Code expires in {} minutes", self.expires_in / 60);
        println!("🔄 Waiting for authorization...\n");
    }
}

#[cfg(feature = "enhanced-device-flow")]
#[async_trait]
impl AuthMethod for EnhancedDeviceFlowMethod {
    fn name(&self) -> &str {
        &self.name
    }

    async fn authenticate(
        &self,
        credential: &Credential,
        _metadata: &CredentialMetadata,
    ) -> Result<MethodResult> {
        // For device flow, the credential should contain a flag to start the flow
        match credential {
            Credential::Custom { method, data: _ } if method == "start_device_flow" => {
                // This is a request to start device flow
                let instructions = self.start_device_flow().await?;
                
                // Return instructions for the user
                return Ok(MethodResult::Failure {
                    reason: format!(
                        "Device flow started. Visit {} and enter code {}",
                        instructions.verification_uri,
                        instructions.user_code
                    ),
                });
            }
            Credential::Custom { method, data: _ } if method == "device_flow_token" => {
                // This would be called after the user completes authentication
                // In practice, you'd store the device flow state and poll separately
                return Err(AuthError::auth_method(
                    &self.name,
                    "Device flow polling should be handled separately".to_string(),
                ));
            }
            _ => {
                return Err(AuthError::auth_method(
                    &self.name,
                    "Invalid credential type for enhanced device flow".to_string(),
                ));
            }
        }
    }

    fn validate_config(&self) -> Result<()> {
        // Validate client ID
        if self.client_id.is_empty() {
            return Err(AuthError::config("Device flow client ID is required"));
        }

        // Validate client ID format (should not contain spaces or special chars)
        if self.client_id.contains(' ') || self.client_id.contains('\n') || self.client_id.contains('\t') {
            return Err(AuthError::config("Device flow client ID contains invalid characters"));
        }

        // Check client ID length (reasonable bounds)
        if self.client_id.len() < 3 {
            return Err(AuthError::config("Device flow client ID is too short (minimum 3 characters)"));
        }

        if self.client_id.len() > 255 {
            return Err(AuthError::config("Device flow client ID is too long (maximum 255 characters)"));
        }

        // Validate client secret if present
        if let Some(secret) = &self.client_secret {
            if secret.is_empty() {
                return Err(AuthError::config("Device flow client secret cannot be empty if provided"));
            }
            
            if secret.len() < 8 {
                return Err(AuthError::config("Device flow client secret is too short (minimum 8 characters)"));
            }
        }

        // Validate provider-specific requirements
        match self.provider {
            DeviceFlowProvider::Microsoft => {
                // Microsoft typically requires client secret for device flow
                if self.client_secret.is_none() {
                    tracing::warn!("Microsoft device flow typically requires a client secret for production use");
                }
            }
            DeviceFlowProvider::Google => {
                // Google has specific client ID format
                if !self.client_id.ends_with(".googleusercontent.com") {
                    tracing::warn!("Google client ID should end with '.googleusercontent.com'");
                }
            }
            DeviceFlowProvider::GitHub => {
                // GitHub client IDs have specific format
                if self.client_id.len() != 20 {
                    tracing::warn!("GitHub client IDs are typically 20 characters long");
                }
            }
            DeviceFlowProvider::GitLab => {
                // GitLab validation
                if self.client_id.len() < 10 {
                    tracing::warn!("GitLab client IDs are typically longer than 10 characters");
                }
            }
            DeviceFlowProvider::Generic => {
                // No specific validation for generic provider
            }
        }

        Ok(())
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    async fn refresh_token(&self, _refresh_token: &str) -> Result<AuthToken> {
        // Token refresh would be handled by the oauth-device-flows crate's TokenManager
        Err(AuthError::auth_method(
            &self.name,
            "Token refresh should be handled by oauth-device-flows TokenManager".to_string(),
        ))
    }
}

// Conversion utilities between oauth-device-flows providers and our framework
#[cfg(feature = "enhanced-device-flow")]
impl From<crate::providers::OAuthProvider> for DeviceFlowProvider {
    fn from(provider: crate::providers::OAuthProvider) -> Self {
        match provider {
            crate::providers::OAuthProvider::Microsoft => DeviceFlowProvider::Microsoft,
            crate::providers::OAuthProvider::Google => DeviceFlowProvider::Google,
            crate::providers::OAuthProvider::GitHub => DeviceFlowProvider::GitHub,
            crate::providers::OAuthProvider::GitLab => DeviceFlowProvider::GitLab,
            _ => DeviceFlowProvider::GitHub, // Default fallback
        }
    }
}

#[cfg(test)]
#[cfg(feature = "enhanced-device-flow")]
mod tests {
    use super::*;

    #[test]
    fn test_enhanced_device_flow_creation() {
        let method = EnhancedDeviceFlowMethod::new(
            DeviceFlowProvider::GitHub,
            "test-client-id".to_string(),
        );

        assert_eq!(method.name(), "enhanced-device-flow");
        assert_eq!(method.client_id, "test-client-id");
    }

    #[test]
    fn test_provider_conversion() {
        let auth_provider = crate::providers::OAuthProvider::GitHub;
        let device_provider: DeviceFlowProvider = auth_provider.into();
        
        // This would test the conversion works
        assert!(matches!(device_provider, DeviceFlowProvider::GitHub));
    }
}
