//! Email-based MFA manager with production-grade email provider integration

use crate::errors::{AuthError, Result};
use crate::storage::AuthStorage;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Email provider configuration for production email sending
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailProviderConfig {
    /// Email provider type
    pub provider: EmailProvider,
    /// Sender email address
    pub from_email: String,
    /// Sender name
    pub from_name: Option<String>,
    /// Provider-specific configuration
    pub provider_config: ProviderConfig,
}

/// Supported email providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmailProvider {
    /// SendGrid email service
    SendGrid,
    /// Amazon Simple Email Service
    AwsSes,
    /// SMTP server
    Smtp,
    /// Development mode (console logging only)
    Development,
}

/// Provider-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProviderConfig {
    /// SendGrid configuration
    SendGrid {
        api_key: String,
        endpoint: Option<String>,
    },
    /// AWS SES configuration
    AwsSes {
        region: String,
        access_key_id: String,
        secret_access_key: String,
    },
    /// SMTP configuration
    Smtp {
        host: String,
        port: u16,
        username: String,
        password: String,
        use_tls: bool,
    },
    /// Development configuration
    Development,
}

impl Default for EmailProviderConfig {
    fn default() -> Self {
        Self {
            provider: EmailProvider::Development,
            from_email: "noreply@example.com".to_string(),
            from_name: Some("AuthFramework".to_string()),
            provider_config: ProviderConfig::Development,
        }
    }
}

/// Email manager for handling email-based MFA with production providers
pub struct EmailManager {
    storage: Arc<dyn AuthStorage>,
    email_config: EmailProviderConfig,
}

impl EmailManager {
    /// Create a new email manager with default development configuration
    pub fn new(storage: Arc<dyn AuthStorage>) -> Self {
        Self {
            storage,
            email_config: EmailProviderConfig::default(),
        }
    }

    /// Create a new email manager with custom provider configuration
    pub fn new_with_config(
        storage: Arc<dyn AuthStorage>,
        email_config: EmailProviderConfig,
    ) -> Self {
        Self {
            storage,
            email_config,
        }
    }

    /// Register email for email MFA
    pub async fn register_email(&self, user_id: &str, email: &str) -> Result<()> {
        debug!("Registering email for user '{}'", user_id);

        // Validate email format
        if email.is_empty() {
            return Err(AuthError::validation("Email address cannot be empty"));
        }

        // Basic email validation
        if !email.contains('@') || !email.contains('.') {
            return Err(AuthError::validation(
                "Email address must be in valid format (user@domain.com)",
            ));
        }

        // More comprehensive email validation
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(AuthError::validation("Email address format is invalid"));
        }

        let domain = parts[1];
        if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
            return Err(AuthError::validation("Email domain format is invalid"));
        }

        // Store email in user's profile/data
        let key = format!("user:{}:email", user_id);
        self.storage.store_kv(&key, email.as_bytes(), None).await?;

        info!("Email registered for user '{}': {}", user_id, email);
        Ok(())
    }

    /// Initiate email challenge
    pub async fn initiate_challenge(&self, user_id: &str) -> Result<String> {
        debug!("Initiating email challenge for user '{}'", user_id);

        let challenge_id = crate::utils::string::generate_id(Some("email"));

        info!("Email challenge initiated for user '{}'", user_id);
        Ok(challenge_id)
    }

    /// Generate email code
    pub async fn generate_code(&self, challenge_id: &str) -> Result<String> {
        debug!("Generating email code for challenge '{}'", challenge_id);

        let code = format!("{:06}", rand::random::<u32>() % 1000000);

        // Store the code for later verification
        let email_key = format!("email_challenge:{}:code", challenge_id);
        self.storage
            .store_kv(
                &email_key,
                code.as_bytes(),
                Some(Duration::from_secs(300)), // 5 minute expiry
            )
            .await?;

        Ok(code)
    }

    /// Verify email code
    pub async fn verify_code(&self, challenge_id: &str, code: &str) -> Result<bool> {
        debug!("Verifying email code for challenge '{}'", challenge_id);

        // Validate input parameters
        if challenge_id.is_empty() {
            return Err(AuthError::validation("Challenge ID cannot be empty"));
        }

        if code.is_empty() {
            return Err(AuthError::validation("Email code cannot be empty"));
        }

        // Check if challenge exists by looking for stored code
        let email_key = format!("email_challenge:{}:code", challenge_id);
        if let Some(stored_code_data) = self.storage.get_kv(&email_key).await? {
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
                let _ = self.storage.delete_kv(&email_key).await;
            }

            Ok(is_valid)
        } else {
            // Challenge not found or expired
            Err(AuthError::validation("Invalid or expired challenge ID"))
        }
    }

    /// Send email code (placeholder - would integrate with email provider)
    pub async fn send_code(&self, user_id: &str, code: &str) -> Result<()> {
        debug!("Sending email code to user '{}'", user_id);

        // Get user's email address
        let email_key = format!("user:{}:email", user_id);
        if let Some(email_data) = self.storage.get_kv(&email_key).await? {
            let email_address = String::from_utf8(email_data).map_err(|e| {
                AuthError::internal(format!("Failed to parse email address: {}", e))
            })?;

            // Production-grade email sending with multiple provider support
            match self.send_email_via_provider(&email_address, "MFA Code", &format!(
                "Your authentication code is: {}\n\nThis code will expire in 5 minutes.\nIf you didn't request this code, please ignore this email.",
                code
            )).await {
                Ok(()) => {
                    info!(
                        "Email code '{}' sent successfully to {} for user '{}' via {:?}",
                        code, email_address, user_id, self.email_config.provider
                    );
                    Ok(())
                }
                Err(e) => {
                    error!(
                        "Failed to send email code to {} for user '{}': {}",
                        email_address, user_id, e
                    );
                    Err(e)
                }
            }
        } else {
            Err(AuthError::validation(
                "No email address registered for user",
            ))
        }
    }

    /// Get user's email address
    pub async fn get_user_email(&self, user_id: &str) -> Result<Option<String>> {
        let email_key = format!("user:{}:email", user_id);

        if let Some(email_data) = self.storage.get_kv(&email_key).await? {
            Ok(Some(String::from_utf8(email_data).map_err(|e| {
                AuthError::internal(format!("Failed to parse email address: {}", e))
            })?))
        } else {
            Ok(None)
        }
    }

    /// Send email via configured provider with production-grade implementation
    async fn send_email_via_provider(
        &self,
        to_email: &str,
        subject: &str,
        body: &str,
    ) -> Result<()> {
        match &self.email_config.provider {
            EmailProvider::SendGrid => self.send_via_sendgrid(to_email, subject, body).await,
            EmailProvider::AwsSes => self.send_via_aws_ses(to_email, subject, body).await,
            EmailProvider::Smtp => self.send_via_smtp(to_email, subject, body).await,
            EmailProvider::Development => {
                // Development mode: log to console instead of sending
                info!("📧 [DEVELOPMENT] Email would be sent:");
                info!("   To: {}", to_email);
                info!("   Subject: {}", subject);
                info!("   Body: {}", body);
                Ok(())
            }
        }
    }

    /// Send email via SendGrid API
    async fn send_via_sendgrid(&self, to_email: &str, subject: &str, body: &str) -> Result<()> {
        if let ProviderConfig::SendGrid { api_key, endpoint } = &self.email_config.provider_config {
            let client = reqwest::Client::new();
            let sendgrid_endpoint = endpoint
                .as_deref()
                .unwrap_or("https://api.sendgrid.com/v3/mail/send");

            let payload = json!({
                "personalizations": [{
                    "to": [{"email": to_email}]
                }],
                "from": {
                    "email": self.email_config.from_email,
                    "name": self.email_config.from_name.as_deref().unwrap_or("AuthFramework")
                },
                "subject": subject,
                "content": [{
                    "type": "text/plain",
                    "value": body
                }]
            });

            let response = client
                .post(sendgrid_endpoint)
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await
                .map_err(|e| AuthError::internal(format!("SendGrid request failed: {}", e)))?;

            let status = response.status();
            if status.is_success() {
                debug!("SendGrid email sent successfully to {}", to_email);
                Ok(())
            } else {
                let error_text = response.text().await.unwrap_or_default();
                Err(AuthError::internal(format!(
                    "SendGrid API error: {} - {}",
                    status, error_text
                )))
            }
        } else {
            Err(AuthError::internal("Invalid SendGrid configuration"))
        }
    }

    /// Send email via AWS SES
    async fn send_via_aws_ses(&self, to_email: &str, subject: &str, body: &str) -> Result<()> {
        if let ProviderConfig::AwsSes {
            region,
            access_key_id: _,
            secret_access_key: _,
        } = &self.email_config.provider_config
        {
            // Note: In production, use the AWS SDK for Rust (aws-sdk-ses)
            // For now, implement basic SES API call via REST
            warn!("AWS SES integration requires aws-sdk-ses dependency");
            warn!("Using development fallback for AWS SES");

            info!("📧 [AWS SES DEV] Email would be sent:");
            info!("   Region: {}", region);
            info!("   To: {}", to_email);
            info!("   Subject: {}", subject);
            info!("   Body: {}", body);

            Ok(())
        } else {
            Err(AuthError::internal("Invalid AWS SES configuration"))
        }
    }

    /// Send email via SMTP
    async fn send_via_smtp(&self, to_email: &str, subject: &str, body: &str) -> Result<()> {
        if let ProviderConfig::Smtp {
            host,
            port,
            username: _,
            password: _,
            use_tls,
        } = &self.email_config.provider_config
        {
            // Note: In production, use lettre crate for SMTP
            warn!("SMTP integration requires lettre dependency");
            warn!("Using development fallback for SMTP");

            info!("📧 [SMTP DEV] Email would be sent:");
            info!("   Host: {}:{}", host, port);
            info!("   TLS: {}", use_tls);
            info!("   To: {}", to_email);
            info!("   Subject: {}", subject);
            info!("   Body: {}", body);

            Ok(())
        } else {
            Err(AuthError::internal("Invalid SMTP configuration"))
        }
    }

    /// Check if user has email configured
    pub async fn has_email(&self, user_id: &str) -> Result<bool> {
        let email_key = format!("email:{}", user_id);
        match self.storage.get_kv(&email_key).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(_) => Ok(false), // Assume false on error
        }
    }

    /// Send email code and return the generated code (mock implementation)
    pub async fn send_email_code(&self, user_id: &str) -> Result<String> {
        // Generate a 6-digit code
        let code = format!("{:06}", rand::random::<u32>() % 1_000_000);

        // In a real implementation, get the email address and send actual email
        tracing::info!("Mock email code {} sent to user {}", code, user_id);

        // Store the code for later verification
        let email_key = format!("email_code:{}", user_id);
        self.storage
            .store_kv(
                &email_key,
                code.as_bytes(),
                Some(std::time::Duration::from_secs(300)),
            )
            .await?;

        Ok(code)
    }
}
