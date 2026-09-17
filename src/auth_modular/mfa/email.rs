//! Email-based MFA manager with production-grade email provider integration

use crate::errors::{AuthError, Result};
use crate::storage::AuthStorage;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tracing::{debug, error, info};

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
///
/// `AwsSes` requires the `aws-sdk-ses` crate (not compiled in by default).
/// When selected without the dependency, `send_email_via_provider` returns a
/// descriptive error at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmailProvider {
    /// SendGrid email service
    SendGrid,
    /// Amazon Simple Email Service.
    /// Requires the `aws-sdk-ses` crate (not included by default).
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

            // Verify against stored code (constant-time to prevent timing attacks)
            let is_valid: bool = stored_code.as_bytes().ct_eq(code.as_bytes()).into();

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

    /// Send email verification code to the user via the configured email provider
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

    /// Send email via AWS SES using the SendEmail REST API (v2)
    async fn send_via_aws_ses(&self, to_email: &str, subject: &str, body: &str) -> Result<()> {
        if let ProviderConfig::AwsSes {
            region,
            access_key_id,
            secret_access_key,
        } = &self.email_config.provider_config
        {
            let from_email = &self.email_config.from_email;
            let from_name = self
                .email_config
                .from_name
                .as_deref()
                .unwrap_or("AuthFramework");

            let host = format!("email.{}.amazonaws.com", region);
            let url = format!("https://{}/v2/email/outbound-emails", host);
            let now = chrono::Utc::now();
            let date_stamp = now.format("%Y%m%d").to_string();
            let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

            let payload = serde_json::json!({
                "Content": {
                    "Simple": {
                        "Subject": { "Data": subject, "Charset": "UTF-8" },
                        "Body": { "Text": { "Data": body, "Charset": "UTF-8" } }
                    }
                },
                "Destination": {
                    "ToAddresses": [to_email]
                },
                "FromEmailAddress": format!("{} <{}>", from_name, from_email)
            });
            let payload_bytes = serde_json::to_vec(&payload).map_err(|e| {
                AuthError::internal(format!("SES payload serialization failed: {}", e))
            })?;

            // AWS Signature Version 4
            let payload_hash = ses_sha256_hex(&payload_bytes);
            let canonical_headers = format!(
                "content-type:application/json\nhost:{}\nx-amz-date:{}\n",
                host, amz_date
            );
            let signed_headers = "content-type;host;x-amz-date";
            let canonical_request = format!(
                "POST\n/v2/email/outbound-emails\n\n{}\n{}\n{}",
                canonical_headers, signed_headers, payload_hash
            );

            let credential_scope = format!("{}/{}/ses/aws4_request", date_stamp, region);
            let string_to_sign = format!(
                "AWS4-HMAC-SHA256\n{}\n{}\n{}",
                amz_date,
                credential_scope,
                ses_sha256_hex(canonical_request.as_bytes())
            );

            let signing_key =
                ses_sigv4_key(secret_access_key.as_bytes(), &date_stamp, region, "ses");
            let signature = ses_hmac_sha256_hex(&signing_key, string_to_sign.as_bytes());

            let authorization = format!(
                "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
                access_key_id, credential_scope, signed_headers, signature
            );

            let client = reqwest::Client::new();
            let resp = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("x-amz-date", &amz_date)
                .header("Authorization", &authorization)
                .body(payload_bytes)
                .send()
                .await
                .map_err(|e| AuthError::internal(format!("AWS SES request failed: {}", e)))?;

            let status = resp.status();
            if status.is_success() {
                debug!("AWS SES email sent successfully to {}", to_email);
                Ok(())
            } else {
                let error_text = resp.text().await.unwrap_or_default();
                Err(AuthError::internal(format!(
                    "AWS SES error ({}): {}",
                    status, error_text
                )))
            }
        } else {
            Err(AuthError::internal("Invalid AWS SES configuration"))
        }
    }

    /// Send email via SMTP using lettre
    async fn send_via_smtp(&self, to_email: &str, subject: &str, body: &str) -> Result<()> {
        if let ProviderConfig::Smtp {
            host,
            port,
            username,
            password,
            use_tls,
        } = &self.email_config.provider_config
        {
            use lettre::{
                Message, SmtpTransport, Transport, transport::smtp::authentication::Credentials,
            };

            let from_address = self.email_config.from_email.clone();
            let from_name = self
                .email_config
                .from_name
                .clone()
                .unwrap_or_else(|| "AuthFramework".to_string());

            let email = Message::builder()
                .from(
                    format!("{} <{}>", from_name, from_address)
                        .parse()
                        .map_err(|e| AuthError::internal(format!("Invalid from address: {}", e)))?,
                )
                .to(to_email
                    .parse()
                    .map_err(|e| AuthError::internal(format!("Invalid to address: {}", e)))?)
                .subject(subject)
                .body(body.to_string())
                .map_err(|e| AuthError::internal(format!("Failed to build email: {}", e)))?;

            let creds = Credentials::new(username.clone(), password.clone());

            let host = host.clone();
            let port = *port;
            let use_tls = *use_tls;

            // lettre's SmtpTransport is sync; run in a blocking task to avoid
            // blocking the async runtime.
            let result = tokio::task::spawn_blocking(move || {
                let transport = if use_tls {
                    SmtpTransport::relay(&host)
                        .map_err(|e| AuthError::internal(format!("SMTP relay error: {}", e)))?
                        .port(port)
                        .credentials(creds)
                        .build()
                } else {
                    SmtpTransport::builder_dangerous(&host)
                        .port(port)
                        .credentials(creds)
                        .build()
                };

                transport
                    .send(&email)
                    .map_err(|e| AuthError::internal(format!("SMTP send failed: {}", e)))
            })
            .await
            .map_err(|e| AuthError::internal(format!("SMTP task join error: {}", e)))?;

            result?;
            debug!("SMTP email sent successfully to {}", to_email);
            Ok(())
        } else {
            Err(AuthError::internal("Invalid SMTP configuration"))
        }
    }

    /// Check if user has email configured
    pub async fn has_email(&self, user_id: &str) -> Result<bool> {
        let email_key = format!("user:{}:email", user_id);
        match self.storage.get_kv(&email_key).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(_) => Ok(false), // Assume false on error
        }
    }

    /// Send email code and return the generated code
    pub async fn send_email_code(&self, user_id: &str) -> Result<String> {
        // Generate a 6-digit code
        let code = format!("{:06}", rand::random::<u32>() % 1_000_000);

        // Send the code via the configured email provider
        self.send_code(user_id, &code).await?;

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

// ── AWS SigV4 helpers for SES ───────────────────────────────────────────────

fn ses_sha256_hex(data: &[u8]) -> String {
    use ring::digest;
    let d = digest::digest(&digest::SHA256, data);
    hex::encode(d.as_ref())
}

fn ses_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use ring::hmac;
    let s_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&s_key, data).as_ref().to_vec()
}

fn ses_hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    hex::encode(ses_hmac_sha256(key, data))
}

fn ses_sigv4_key(secret: &[u8], date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = ses_hmac_sha256(&[b"AWS4", secret].concat(), date_stamp.as_bytes());
    let k_region = ses_hmac_sha256(&k_date, region.as_bytes());
    let k_service = ses_hmac_sha256(&k_region, service.as_bytes());
    ses_hmac_sha256(&k_service, b"aws4_request")
}
