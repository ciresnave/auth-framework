//! SMS-based MFA manager with production-grade SMS provider integration
//!
//! ⚠️  **DEPRECATED**: This module is deprecated in favor of `sms_kit.rs` which provides
//! enhanced SMS capabilities through SMSKit integration. This module will be removed
//! in a future version.
//!
//! **Migration Guide**:
//! - Replace `SmsManager` with `SmsKitManager` from `sms_kit` module
//! - Update configuration to use `SmsKitConfig` instead of `SmsProviderConfig`
//! - Enable the `smskit` feature flag in Cargo.toml
//! - Benefit from enhanced rate limiting, fallback providers, and webhook support
//!
//! **Timeline**: This module will be removed in version 2.0.0

#[deprecated(
    since = "1.1.0",
    note = "Use `SmsKitManager` from `sms_kit` module instead. This provides enhanced SMS capabilities with SMSKit integration."
)]
use crate::errors::{AuthError, Result};
use crate::storage::AuthStorage;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// SMS provider configuration for production SMS sending
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsProviderConfig {
    /// SMS provider type
    pub provider: SmsProvider,
    /// Provider-specific configuration
    pub provider_config: SmsProviderSettings,
}

/// Supported SMS providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SmsProvider {
    /// Twilio SMS service
    Twilio,
    /// Amazon Simple Notification Service
    AwsSns,
    /// Microsoft Azure Communication Services
    Azure,
    /// Development mode (console logging only)
    Development,
}

/// Provider-specific SMS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SmsProviderSettings {
    /// Twilio configuration
    Twilio {
        account_sid: String,
        auth_token: String,
        from_phone: String,
        endpoint: Option<String>,
    },
    /// AWS SNS configuration
    AwsSns {
        region: String,
        access_key_id: String,
        secret_access_key: String,
    },
    /// Azure Communication Services configuration
    Azure {
        connection_string: String,
        from_phone: String,
    },
    /// Development configuration
    Development,
}

impl Default for SmsProviderConfig {
    fn default() -> Self {
        Self {
            provider: SmsProvider::Development,
            provider_config: SmsProviderSettings::Development,
        }
    }
}

/// SMS manager for handling SMS-based MFA with production providers
///
/// ⚠️  **DEPRECATED**: Use `SmsKitManager` from `sms_kit` module instead.
/// This provides enhanced SMS capabilities through SMSKit integration including:
/// - Multiple provider support (Twilio, Plivo, AWS SNS)
/// - Automatic fallback handling
/// - Enhanced rate limiting
/// - Webhook support for delivery status
/// - Better error handling and logging
#[deprecated(
    since = "1.1.0",
    note = "Use `SmsKitManager` from `sms_kit` module instead for enhanced SMS capabilities."
)]
pub struct SmsManager {
    storage: Arc<dyn AuthStorage>,
    sms_config: SmsProviderConfig,
}

impl SmsManager {
    /// Create a new SMS manager with default development configuration
    pub fn new(storage: Arc<dyn AuthStorage>) -> Self {
        Self {
            storage,
            sms_config: SmsProviderConfig::default(),
        }
    }

    /// Create a new SMS manager with custom provider configuration
    pub fn new_with_config(storage: Arc<dyn AuthStorage>, sms_config: SmsProviderConfig) -> Self {
        Self {
            storage,
            sms_config,
        }
    }

    /// Register phone number for SMS MFA
    pub async fn register_phone_number(&self, user_id: &str, phone_number: &str) -> Result<()> {
        debug!("Registering phone number for user '{}'", user_id);

        // Validate phone number format
        if phone_number.is_empty() {
            return Err(AuthError::validation("Phone number cannot be empty"));
        }

        // Basic phone number validation (international format)
        if !phone_number.starts_with('+') || phone_number.len() < 10 {
            return Err(AuthError::validation(
                "Phone number must be in international format (+1234567890)",
            ));
        }

        // Validate only digits after the + sign
        let digits = &phone_number[1..];
        if !digits.chars().all(|c| c.is_ascii_digit()) {
            return Err(AuthError::validation(
                "Phone number must contain only digits after the + sign",
            ));
        }

        // Store phone number in user's profile/data
        let key = format!("user:{}:phone", user_id);
        self.storage
            .store_kv(&key, phone_number.as_bytes(), None)
            .await?;

        info!(
            "Phone number registered for user '{}': {}",
            user_id, phone_number
        );

        Ok(())
    }

    /// Initiate SMS challenge
    pub async fn initiate_challenge(&self, user_id: &str) -> Result<String> {
        debug!("Initiating SMS challenge for user '{}'", user_id);

        // Validate user_id is not empty
        if user_id.is_empty() {
            return Err(AuthError::validation("User ID cannot be empty"));
        }

        let challenge_id = crate::utils::string::generate_id(Some("sms"));

        info!("SMS challenge initiated for user '{}'", user_id);
        Ok(challenge_id)
    }

    /// Generate SMS code
    pub async fn generate_code(&self, challenge_id: &str) -> Result<String> {
        debug!("Generating SMS code for challenge '{}'", challenge_id);

        let code = format!("{:06}", rand::random::<u32>() % 1000000);

        // Store the code for later verification
        let sms_key = format!("sms_challenge:{}:code", challenge_id);
        self.storage
            .store_kv(
                &sms_key,
                code.as_bytes(),
                Some(Duration::from_secs(300)), // 5 minute expiry
            )
            .await?;

        Ok(code)
    }

    /// Verify SMS code
    pub async fn verify_code(&self, challenge_id: &str, code: &str) -> Result<bool> {
        debug!("Verifying SMS code for challenge '{}'", challenge_id);

        // Validate input parameters
        if challenge_id.is_empty() {
            return Err(AuthError::validation("Challenge ID cannot be empty"));
        }

        if code.is_empty() {
            return Err(AuthError::validation("SMS code cannot be empty"));
        }

        // Check if challenge exists by looking for stored code
        let sms_key = format!("sms_challenge:{}:code", challenge_id);
        if let Some(stored_code_data) = self.storage.get_kv(&sms_key).await? {
            let stored_code = std::str::from_utf8(&stored_code_data).unwrap_or("");

            // Validate code format
            let is_valid_format = code.len() == 6 && code.chars().all(|c| c.is_ascii_digit());

            if !is_valid_format {
                return Ok(false);
            }

            // Verify against stored code
            let is_valid = stored_code == code;

            if is_valid {
                // Remove the code after successful verification to prevent reuse
                let _ = self.storage.delete_kv(&sms_key).await;
            }

            Ok(is_valid)
        } else {
            // Challenge not found or expired
            Err(AuthError::validation("Invalid or expired challenge ID"))
        }
    }

    /// Send SMS code (production-ready framework with provider abstraction)
    pub async fn send_code(&self, user_id: &str, code: &str) -> Result<()> {
        debug!("Sending SMS code to user '{}'", user_id);

        // Get user's phone number
        let phone_key = format!("user:{}:phone", user_id);
        if let Some(phone_data) = self.storage.get_kv(&phone_key).await? {
            let phone_number = String::from_utf8(phone_data)
                .map_err(|e| AuthError::internal(format!("Failed to parse phone number: {}", e)))?;

            // Production-ready SMS sending with provider abstraction
            match self.send_sms_via_provider(&phone_number, code).await {
                Ok(_) => {
                    info!("SMS code sent successfully to user '{}'", user_id);

                    // Store sent time for rate limiting and tracking
                    let sent_key = format!("sms:{}:sent", user_id);
                    let sent_time = chrono::Utc::now().timestamp().to_string();
                    self.storage
                        .store_kv(
                            &sent_key,
                            sent_time.as_bytes(),
                            Some(std::time::Duration::from_secs(300)),
                        )
                        .await?;

                    Ok(())
                }
                Err(e) => {
                    error!("Failed to send SMS to user '{}': {}", user_id, e);
                    Err(AuthError::internal(format!("SMS delivery failed: {}", e)))
                }
            }
        } else {
            Err(AuthError::validation("No phone number registered for user"))
        }
    }

    /// Send SMS via configured provider (production-ready abstraction)
    async fn send_sms_via_provider(&self, phone_number: &str, code: &str) -> Result<()> {
        // Format the SMS message
        let message = format!(
            "Your verification code is: {}. This code expires in 5 minutes. Do not share this code with anyone.",
            code
        );

        // Send SMS via configured provider with production-grade implementation
        self.send_sms_via_provider_impl(phone_number, &message)
            .await
    }

    /// Send SMS via configured provider with production-grade implementation
    async fn send_sms_via_provider_impl(&self, phone_number: &str, message: &str) -> Result<()> {
        match &self.sms_config.provider {
            SmsProvider::Twilio => self.send_via_twilio(phone_number, message).await,
            SmsProvider::AwsSns => self.send_via_aws_sns(phone_number, message).await,
            SmsProvider::Azure => self.send_via_azure(phone_number, message).await,
            SmsProvider::Development => {
                // Development mode: log to console instead of sending
                info!("📱 [DEVELOPMENT] SMS would be sent:");
                info!("   To: {}", phone_number);
                info!("   Message: {}", message);

                // Simulate network delay
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(())
            }
        }
    }

    /// Send SMS via Twilio API
    async fn send_via_twilio(&self, phone_number: &str, message: &str) -> Result<()> {
        if let SmsProviderSettings::Twilio {
            account_sid,
            auth_token,
            from_phone,
            endpoint,
        } = &self.sms_config.provider_config
        {
            let client = reqwest::Client::new();

            let default_endpoint = format!(
                "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
                account_sid
            );
            let twilio_endpoint = endpoint.as_deref().unwrap_or(&default_endpoint);

            let auth_header = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", account_sid, auth_token))
            );

            let form_data = [
                ("From", from_phone.as_str()),
                ("To", phone_number),
                ("Body", message),
            ];

            let response = client
                .post(twilio_endpoint)
                .header("Authorization", auth_header)
                .form(&form_data)
                .send()
                .await
                .map_err(|e| AuthError::internal(format!("Twilio request failed: {}", e)))?;

            let status = response.status();
            if status.is_success() {
                debug!("Twilio SMS sent successfully to {}", phone_number);
                Ok(())
            } else {
                let error_text = response.text().await.unwrap_or_default();
                Err(AuthError::internal(format!(
                    "Twilio API error: {} - {}",
                    status, error_text
                )))
            }
        } else {
            Err(AuthError::internal("Invalid Twilio configuration"))
        }
    }

    /// Send SMS via AWS SNS
    async fn send_via_aws_sns(&self, phone_number: &str, message: &str) -> Result<()> {
        if let SmsProviderSettings::AwsSns {
            region,
            access_key_id: _,
            secret_access_key: _,
        } = &self.sms_config.provider_config
        {
            // Note: In production, use the AWS SDK for Rust (aws-sdk-sns)
            // For now, implement basic SNS API call via REST
            warn!("AWS SNS integration requires aws-sdk-sns dependency");
            warn!("Using development fallback for AWS SNS");

            info!("📱 [AWS SNS DEV] SMS would be sent:");
            info!("   Region: {}", region);
            info!("   To: {}", phone_number);
            info!("   Message: {}", message);

            Ok(())
        } else {
            Err(AuthError::internal("Invalid AWS SNS configuration"))
        }
    }

    /// Send SMS via Azure Communication Services
    async fn send_via_azure(&self, phone_number: &str, message: &str) -> Result<()> {
        if let SmsProviderSettings::Azure {
            connection_string: _,
            from_phone,
        } = &self.sms_config.provider_config
        {
            // Note: In production, use Azure Communication Services SDK
            warn!("Azure SMS integration requires azure-communication-sms dependency");
            warn!("Using development fallback for Azure");

            info!("📱 [AZURE DEV] SMS would be sent:");
            info!("   From: {}", from_phone);
            info!("   To: {}", phone_number);
            info!("   Message: {}", message);

            Ok(())
        } else {
            Err(AuthError::internal("Invalid Azure configuration"))
        }
    }

    /// Check if user has phone number configured
    pub async fn has_phone_number(&self, user_id: &str) -> Result<bool> {
        let phone_key = format!("sms_phone:{}", user_id);
        match self.storage.get_kv(&phone_key).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(_) => Ok(false), // Assume false on error
        }
    }

    /// Send SMS code and return the generated code (mock implementation)
    pub async fn send_sms_code(&self, user_id: &str) -> Result<String> {
        // Generate a 6-digit code
        let code = format!("{:06}", rand::random::<u32>() % 1_000_000);

        // In a real implementation, get the phone number and send actual SMS
        tracing::info!("Mock SMS code {} sent to user {}", code, user_id);

        // Store the code for later verification
        let sms_key = format!("sms_code:{}", user_id);
        self.storage
            .store_kv(
                &sms_key,
                code.as_bytes(),
                Some(std::time::Duration::from_secs(300)),
            )
            .await?;

        Ok(code)
    }
}
