//! Next-generation SMS MFA manager powered by SMSKit

use crate::errors::{AuthError, Result};
use crate::storage::AuthStorage;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// SMSKit configuration for AuthFramework
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsKitConfig {
    /// Primary SMS provider
    pub provider: SmsKitProvider,
    /// Provider-specific configuration
    pub config: SmsKitProviderConfig,
    /// Fallback provider (optional)
    pub fallback_provider: Option<SmsKitProvider>,
    /// Fallback configuration (optional)
    pub fallback_config: Option<SmsKitProviderConfig>,
    /// Webhook configuration for delivery status
    pub webhook_config: Option<WebhookConfig>,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitConfig,
}

impl Default for SmsKitConfig {
    fn default() -> Self {
        Self {
            provider: SmsKitProvider::Development,
            config: SmsKitProviderConfig::Development,
            fallback_provider: None,
            fallback_config: None,
            webhook_config: None,
            rate_limiting: RateLimitConfig::default(),
        }
    }
}

/// Supported SMSKit providers
///
/// `Plivo` requires the `smskit` feature flag and its `sms-plivo` SDK crate.
/// When selected without the feature enabled, `send_sms_with_fallback`
/// returns a descriptive error at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SmsKitProvider {
    Twilio,
    /// Requires `smskit` feature and `sms-plivo` crate.
    Plivo,
    Development,
}

/// Provider-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SmsKitProviderConfig {
    Twilio {
        account_sid: String,
        auth_token: String,
        from_number: String,
        webhook_url: Option<String>,
    },
    Plivo {
        auth_id: String,
        auth_token: String,
        from_number: String,
        webhook_url: Option<String>,
    },
    Development,
}

/// Webhook configuration for SMS delivery status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub endpoint_url: String,
    pub webhook_secret: String,
    pub track_delivery: bool,
    pub track_clicks: bool,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub max_per_hour: u32,
    pub max_per_day: u32,
    pub cooldown_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_per_hour: 10,
            max_per_day: 20,
            cooldown_seconds: 60,
        }
    }
}

/// Enhanced SMS manager powered by SMSKit
pub struct SmsKitManager {
    storage: Arc<dyn AuthStorage>,
    config: SmsKitConfig,
}

impl SmsKitManager {
    /// Create a new SMSKit manager with default configuration
    pub fn new(storage: Arc<dyn AuthStorage>) -> Self {
        Self {
            storage,
            config: SmsKitConfig::default(),
        }
    }

    /// Create a new SMSKit manager with custom configuration
    pub fn new_with_config(storage: Arc<dyn AuthStorage>, config: SmsKitConfig) -> Result<Self> {
        let manager = Self { storage, config };
        Ok(manager)
    }

    /// Register phone number for SMS MFA
    pub async fn register_phone_number(&self, user_id: &str, phone_number: &str) -> Result<()> {
        debug!("Registering phone number for user '{}' via SMSKit", user_id);

        if phone_number.is_empty() {
            return Err(AuthError::validation("Phone number cannot be empty"));
        }

        if !phone_number.starts_with('+') || phone_number.len() < 10 {
            return Err(AuthError::validation(
                "Phone number must be in international format (+1234567890)",
            ));
        }

        let digits = &phone_number[1..];
        if !digits.chars().all(|c| c.is_ascii_digit()) {
            return Err(AuthError::validation(
                "Phone number must contain only digits after the + sign",
            ));
        }

        if digits.len() > 15 || digits.len() < 7 {
            return Err(AuthError::validation(
                "Phone number must be between 7 and 15 digits (E.164 format)",
            ));
        }

        let key = format!("user:{}:phone", user_id);
        self.storage
            .store_kv(&key, phone_number.as_bytes(), None)
            .await?;

        info!(
            "Phone number registered for user '{}': {} (SMSKit enabled)",
            user_id, phone_number
        );

        Ok(())
    }

    /// Initiate SMS challenge with rate limiting
    pub async fn initiate_challenge(&self, user_id: &str) -> Result<String> {
        debug!("Initiating SMS challenge for user '{}' via SMSKit", user_id);

        if user_id.is_empty() {
            return Err(AuthError::validation("User ID cannot be empty"));
        }

        self.check_rate_limits(user_id).await?;

        let challenge_id = crate::utils::string::generate_id(Some("smskit"));

        info!("SMS challenge initiated for user '{}' via SMSKit", user_id);
        Ok(challenge_id)
    }

    async fn check_rate_limits(&self, user_id: &str) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let hour_ago = now - 3600;
        let day_ago = now - 86400;

        let hourly_key = format!("smskit:{}:hourly", user_id);
        let hourly_count = self.get_sms_count(&hourly_key, hour_ago).await?;
        if hourly_count >= self.config.rate_limiting.max_per_hour {
            return Err(AuthError::rate_limited("SMS hourly limit exceeded"));
        }

        let daily_key = format!("smskit:{}:daily", user_id);
        let daily_count = self.get_sms_count(&daily_key, day_ago).await?;
        if daily_count >= self.config.rate_limiting.max_per_day {
            return Err(AuthError::rate_limited("SMS daily limit exceeded"));
        }

        let last_sent_key = format!("smskit:{}:last_sent", user_id);
        if let Some(last_sent_data) = self.storage.get_kv(&last_sent_key).await?
            && let Ok(last_sent_str) = std::str::from_utf8(&last_sent_data)
            && let Ok(last_sent) = last_sent_str.parse::<i64>()
        {
            let elapsed = now - last_sent;
            if elapsed < self.config.rate_limiting.cooldown_seconds as i64 {
                let remaining = self.config.rate_limiting.cooldown_seconds as i64 - elapsed;
                return Err(AuthError::rate_limited(format!(
                    "SMS cooldown active. Please wait {} seconds",
                    remaining
                )));
            }
        }

        Ok(())
    }

    async fn get_sms_count(&self, key: &str, _since: i64) -> Result<u32> {
        if let Some(count_data) = self.storage.get_kv(key).await?
            && let Ok(count_str) = std::str::from_utf8(&count_data)
            && let Ok(count) = count_str.parse::<u32>()
        {
            return Ok(count);
        }
        Ok(0)
    }

    /// Generate SMS verification code
    pub async fn generate_code(&self, challenge_id: &str) -> Result<String> {
        debug!(
            "Generating SMS code for challenge '{}' via SMSKit",
            challenge_id
        );

        let rng = ring::rand::SystemRandom::new();
        let mut buf = [0u8; 4];
        rng.fill(&mut buf).expect("system RNG failure");
        let val = u32::from_le_bytes(buf) % 1_000_000;
        let code = format!("{:06}", val);

        let sms_key = format!("smskit_challenge:{}:code", challenge_id);
        self.storage
            .store_kv(&sms_key, code.as_bytes(), Some(Duration::from_secs(300)))
            .await?;

        Ok(code)
    }

    /// Verify SMS code
    pub async fn verify_code(&self, challenge_id: &str, code: &str) -> Result<bool> {
        debug!(
            "Verifying SMS code for challenge '{}' via SMSKit",
            challenge_id
        );

        if challenge_id.is_empty() {
            return Err(AuthError::validation("Challenge ID cannot be empty"));
        }

        if code.is_empty() {
            return Err(AuthError::validation("SMS code cannot be empty"));
        }

        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Ok(false);
        }

        let sms_key = format!("smskit_challenge:{}:code", challenge_id);
        if let Some(stored_code_data) = self.storage.get_kv(&sms_key).await? {
            let stored_code = std::str::from_utf8(&stored_code_data).unwrap_or("");
            let is_valid: bool = stored_code.as_bytes().ct_eq(code.as_bytes()).into();

            if is_valid {
                let _ = self.storage.delete_kv(&sms_key).await;
            }

            Ok(is_valid)
        } else {
            Err(AuthError::validation("Invalid or expired challenge ID"))
        }
    }

    /// Send SMS code using SMSKit with fallback support
    pub async fn send_code(&self, user_id: &str, code: &str) -> Result<()> {
        debug!("Sending SMS code to user '{}' via SMSKit", user_id);

        let phone_key = format!("user:{}:phone", user_id);
        let phone_number = if let Some(phone_data) = self.storage.get_kv(&phone_key).await? {
            String::from_utf8(phone_data)
                .map_err(|e| AuthError::internal(format!("Failed to parse phone number: {}", e)))?
        } else {
            return Err(AuthError::validation("No phone number registered for user"));
        };

        self.check_rate_limits(user_id).await?;

        let message = format!(
            "Your verification code is: {}. This code expires in 5 minutes. Do not share this code with anyone.",
            code
        );

        match self.send_sms_with_fallback(&phone_number, &message).await {
            Ok(message_id) => {
                info!(
                    "SMS code sent successfully to user '{}' (Message ID: {})",
                    user_id, message_id
                );
                self.update_rate_limits(user_id).await?;
                Ok(())
            }
            Err(e) => {
                error!("Failed to send SMS to user '{}': {}", user_id, e);
                Err(e)
            }
        }
    }

    async fn send_sms_with_fallback(&self, phone_number: &str, message: &str) -> Result<String> {
        let result = match &self.config.provider {
            SmsKitProvider::Twilio => self.send_via_twilio(phone_number, message).await,
            SmsKitProvider::Plivo => self.send_via_plivo(phone_number, message).await,
            SmsKitProvider::Development => {
                info!("📱 [SMSKit Development] SMS sent to: {}", phone_number);
                info!("   Message: {}", message);
                Ok(format!("dev_msg_{}", chrono::Utc::now().timestamp()))
            }
        };

        // On failure, try fallback provider if configured
        match result {
            Ok(msg_id) => Ok(msg_id),
            Err(primary_err) => {
                if let Some(fallback_provider) = &self.config.fallback_provider {
                    warn!(
                        "Primary SMS provider failed ({}), trying fallback: {:?}",
                        primary_err, fallback_provider
                    );
                    match fallback_provider {
                        SmsKitProvider::Development => {
                            info!(
                                "📱 [SMSKit Development Fallback] SMS sent to: {}",
                                phone_number
                            );
                            info!("   Message: {}", message);
                            Ok(format!(
                                "dev_fallback_msg_{}",
                                chrono::Utc::now().timestamp()
                            ))
                        }
                        _ => Err(primary_err),
                    }
                } else {
                    Err(primary_err)
                }
            }
        }
    }

    /// Send SMS via Twilio using sms-twilio crate
    #[cfg(feature = "smskit")]
    async fn send_via_twilio(&self, phone_number: &str, message: &str) -> Result<String> {
        use sms_core::SmsClient;

        let (client, from_number) = if let SmsKitProviderConfig::Twilio {
            account_sid,
            auth_token,
            from_number,
            ..
        } = &self.config.config
        {
            if account_sid.is_empty() || auth_token.is_empty() || from_number.is_empty() {
                return Err(AuthError::internal("Twilio credentials are incomplete"));
            }
            (
                sms_twilio::TwilioClient::new(account_sid, auth_token),
                from_number.clone(),
            )
        } else {
            let from_number = std::env::var("TWILIO_FROM_NUMBER").map_err(|_| {
                AuthError::internal("Twilio from number not configured: set TWILIO_FROM_NUMBER")
            })?;
            let c = sms_twilio::TwilioClient::from_env()
                .map_err(|e| AuthError::internal(format!("Twilio env config failed: {}", e)))?;
            (c, from_number)
        };

        let request = sms_core::SendRequest {
            to: phone_number,
            from: &from_number,
            text: message,
        };

        let response = client
            .send(request)
            .await
            .map_err(|e| AuthError::internal(format!("Twilio SMS send failed: {}", e)))?;

        debug!("Twilio SMS sent successfully, ID: {}", response.id);
        Ok(response.id)
    }

    #[cfg(not(feature = "smskit"))]
    async fn send_via_twilio(&self, _phone_number: &str, _message: &str) -> Result<String> {
        Err(AuthError::internal(
            "Twilio SMS requires the 'smskit' feature flag to be enabled",
        ))
    }

    /// Send SMS via Plivo using sms-plivo crate
    #[cfg(feature = "smskit")]
    async fn send_via_plivo(&self, phone_number: &str, message: &str) -> Result<String> {
        use sms_core::SmsClient;

        let (client, from_number) = if let SmsKitProviderConfig::Plivo {
            auth_id,
            auth_token,
            from_number,
            ..
        } = &self.config.config
        {
            if auth_id.is_empty() || auth_token.is_empty() || from_number.is_empty() {
                return Err(AuthError::internal("Plivo credentials are incomplete"));
            }
            (
                sms_plivo::PlivoClient::new(auth_id, auth_token),
                from_number.clone(),
            )
        } else {
            let from_number = std::env::var("PLIVO_FROM_NUMBER").map_err(|_| {
                AuthError::internal("Plivo from number not configured: set PLIVO_FROM_NUMBER")
            })?;
            let c = sms_plivo::PlivoClient::from_env()
                .map_err(|e| AuthError::internal(format!("Plivo env config failed: {}", e)))?;
            (c, from_number)
        };

        let request = sms_core::SendRequest {
            to: phone_number,
            from: &from_number,
            text: message,
        };

        let response = client
            .send(request)
            .await
            .map_err(|e| AuthError::internal(format!("Plivo SMS send failed: {}", e)))?;

        debug!("Plivo SMS sent successfully, ID: {}", response.id);
        Ok(response.id)
    }

    #[cfg(not(feature = "smskit"))]
    async fn send_via_plivo(&self, _phone_number: &str, _message: &str) -> Result<String> {
        Err(AuthError::internal(
            "Plivo SMS requires the 'smskit' feature flag to be enabled",
        ))
    }

    async fn update_rate_limits(&self, user_id: &str) -> Result<()> {
        let now = chrono::Utc::now().timestamp();

        let hourly_key = format!("smskit:{}:hourly", user_id);
        let hourly_count = self.get_sms_count(&hourly_key, now - 3600).await? + 1;
        self.storage
            .store_kv(
                &hourly_key,
                hourly_count.to_string().as_bytes(),
                Some(Duration::from_secs(3600)),
            )
            .await?;

        let daily_key = format!("smskit:{}:daily", user_id);
        let daily_count = self.get_sms_count(&daily_key, now - 86400).await? + 1;
        self.storage
            .store_kv(
                &daily_key,
                daily_count.to_string().as_bytes(),
                Some(Duration::from_secs(86400)),
            )
            .await?;

        let last_sent_key = format!("smskit:{}:last_sent", user_id);
        self.storage
            .store_kv(
                &last_sent_key,
                now.to_string().as_bytes(),
                Some(Duration::from_secs(
                    self.config.rate_limiting.cooldown_seconds,
                )),
            )
            .await?;

        Ok(())
    }

    /// Get user's phone number
    pub async fn get_user_phone(&self, user_id: &str) -> Result<Option<String>> {
        let phone_key = format!("user:{}:phone", user_id);

        if let Some(phone_data) = self.storage.get_kv(&phone_key).await? {
            Ok(Some(String::from_utf8(phone_data).map_err(|e| {
                AuthError::internal(format!("Failed to parse phone number: {}", e))
            })?))
        } else {
            Ok(None)
        }
    }

    /// Check if user has phone number configured
    pub async fn has_phone_number(&self, user_id: &str) -> Result<bool> {
        let key = format!("user:{}:phone", user_id);
        match self.storage.get_kv(&key).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(_) => Ok(false), // Assume false on error
        }
    }

    /// Send verification code and return the generated code
    pub async fn send_verification_code(&self, user_id: &str) -> Result<String> {
        // Generate a 6-digit code
        let code = format!("{:06}", rand::random::<u32>() % 1_000_000);

        // Send the code via SMS
        self.send_code(user_id, &code).await?;

        // Store the code for later verification
        let code_key = format!("sms_verification:{}:{}", user_id, Uuid::new_v4());
        self.storage
            .store_kv(
                &code_key,
                code.as_bytes(),
                Some(std::time::Duration::from_secs(300)),
            )
            .await?;

        Ok(code)
    }
}
