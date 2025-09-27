//! Multi-Factor Authentication (MFA) implementation.
//!
//! This module provides comprehensive MFA support including TOTP, SMS, email,
//! backup codes, and WebAuthn for enhanced security.

use crate::errors::{AuthError, Result};
use crate::security::MfaConfig;
use async_trait::async_trait;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{Sha1, totp};

/// MFA method types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MfaMethodType {
    Totp,
    Sms,
    Email,
    WebAuthn,
    BackupCodes,
}

/// MFA challenge that must be completed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaChallenge {
    /// Unique challenge ID
    pub id: String,
    /// User ID this challenge belongs to
    pub user_id: String,
    /// Type of MFA method
    pub method_type: MfaMethodType,
    /// Challenge data (varies by method type)
    pub challenge_data: MfaChallengeData,
    /// When the challenge was created
    pub created_at: SystemTime,
    /// When the challenge expires
    pub expires_at: SystemTime,
    /// Number of attempts made
    pub attempts: u32,
    /// Maximum allowed attempts
    pub max_attempts: u32,
}

/// Challenge data specific to each MFA method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaChallengeData {
    Totp {
        /// Current time window
        time_window: u64,
    },
    Sms {
        /// Phone number (masked)
        phone_number: String,
        /// Generated code
        code: String,
    },
    Email {
        /// Email address (masked)
        email: String,
        /// Generated code
        code: String,
    },
    WebAuthn {
        /// Challenge bytes
        challenge: Vec<u8>,
        /// Allowed credential IDs
        allowed_credentials: Vec<String>,
    },
    BackupCodes {
        /// Remaining backup codes count
        remaining_codes: u32,
    },
}

/// MFA method configuration for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMfaMethod {
    /// Unique method ID
    pub id: String,
    /// User ID
    pub user_id: String,
    /// Method type
    pub method_type: MfaMethodType,
    /// Method-specific data
    pub method_data: MfaMethodData,
    /// Display name for the method
    pub display_name: String,
    /// Whether this is the primary method
    pub is_primary: bool,
    /// Whether this method is enabled
    pub is_enabled: bool,
    /// When the method was created
    pub created_at: SystemTime,
    /// When the method was last used
    pub last_used_at: Option<SystemTime>,
}

/// Method-specific configuration data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaMethodData {
    Totp {
        /// Base32-encoded secret key
        secret_key: String,
        /// QR code URL for setup
        qr_code_url: String,
    },
    Sms {
        /// Phone number
        phone_number: String,
        /// Whether phone number is verified
        is_verified: bool,
    },
    Email {
        /// Email address
        email: String,
        /// Whether email is verified
        is_verified: bool,
    },
    WebAuthn {
        /// Credential ID
        credential_id: String,
        /// Public key
        public_key: Vec<u8>,
        /// Counter for replay protection
        counter: u32,
    },
    BackupCodes {
        /// List of backup codes (hashed)
        codes: Vec<String>,
        /// Number of codes used
        used_count: u32,
    },
}

/// MFA verification result
#[derive(Debug, Clone)]
pub struct MfaVerificationResult {
    /// Whether verification succeeded
    pub success: bool,
    /// Method that was used
    pub method_type: MfaMethodType,
    /// Remaining attempts (if failed)
    pub remaining_attempts: Option<u32>,
    /// Error message (if failed)
    pub error_message: Option<String>,
}

/// TOTP (Time-based One-Time Password) implementation
pub struct TotpProvider {
    config: crate::security::TotpConfig,
}

impl TotpProvider {
    pub fn new(config: crate::security::TotpConfig) -> Self {
        Self { config }
    }

    /// Generate a new TOTP secret using cryptographically secure random
    pub fn generate_secret(&self) -> crate::Result<String> {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut secret = [0u8; 20];
        rng.fill(&mut secret).map_err(|_| {
            crate::errors::AuthError::crypto("Failed to generate secure TOTP secret".to_string())
        })?;
        Ok(base32::encode(
            base32::Alphabet::Rfc4648 { padding: true },
            &secret,
        ))
    }

    /// Generate QR code URL for TOTP setup
    pub fn generate_qr_code_url(&self, secret: &str, user_identifier: &str) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&digits={}&period={}",
            urlencoding::encode(&self.config.issuer),
            urlencoding::encode(user_identifier),
            secret,
            urlencoding::encode(&self.config.issuer),
            self.config.digits,
            self.config.period
        )
    }

    /// Generate TOTP code for the current time window
    pub fn generate_code(&self, secret: &str, time_step: Option<u64>) -> Result<String> {
        if secret.trim().is_empty() {
            return Err(AuthError::validation("TOTP secret cannot be empty"));
        }

        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, secret)
            .ok_or_else(|| AuthError::validation("Invalid TOTP secret"))?;

        let time_step = time_step.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                / self.config.period
        });

        // Convert time step to Unix timestamp for totp-lite
        // totp-lite expects Unix timestamp, not time step
        let unix_timestamp = time_step.checked_mul(self.config.period).ok_or_else(|| {
            AuthError::InvalidInput("Time step too large for conversion".to_string())
        })?;

        // Use totp-lite for proper TOTP generation
        let totp_value = totp::<Sha1>(&secret_bytes, unix_timestamp);

        // totp-lite returns variable length string, parse and format according to config
        let parsed_value: u32 = totp_value
            .parse()
            .map_err(|_| AuthError::validation("TOTP generation error"))?;

        // Format to the specified number of digits
        Ok(format!(
            "{:0width$}",
            parsed_value % 10_u32.pow(self.config.digits.into()),
            width = self.config.digits as usize
        ))
    }

    /// Verify TOTP code with time window tolerance
    pub fn verify_code(&self, secret: &str, code: &str, time_window: Option<u64>) -> Result<bool> {
        // First validate the secret by trying to decode it
        let _secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, secret)
            .ok_or_else(|| AuthError::validation("Invalid TOTP secret"))?;

        let current_time_step = if let Some(time) = time_window {
            time / self.config.period
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                / self.config.period
        };

        // Check current time step and ±1 time step for clock skew tolerance
        for step_offset in [-1i64, 0, 1] {
            let time_step_i64 = current_time_step as i64 + step_offset;
            // Skip negative time steps to avoid u64 overflow
            if time_step_i64 < 0 {
                continue;
            }
            let time_step = time_step_i64 as u64;
            let expected_code = self.generate_code(secret, Some(time_step))?;
            if expected_code == code {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Verify TOTP code with configurable time window
    pub fn verify_totp(&self, secret: &str, token: &str, window: u8) -> Result<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthError::validation("System time error"))?
            .as_secs()
            / self.config.period;

        // Check within the specified time window using constant-time comparison
        use subtle::ConstantTimeEq;

        for i in 0..=window {
            // Check current and positive offset
            if i == 0 {
                if let Ok(expected_code) = self.generate_code(secret, Some(now))
                    && expected_code.as_bytes().ct_eq(token.as_bytes()).into()
                {
                    return Ok(true);
                }
            } else {
                // Check both positive and negative offsets
                for offset in [i as i64, -(i as i64)] {
                    let time_step_i64 = now as i64 + offset;
                    // Skip negative time steps to avoid u64 overflow
                    if time_step_i64 < 0 {
                        continue;
                    }
                    let time_step = time_step_i64 as u64;
                    if let Ok(expected_code) = self.generate_code(secret, Some(time_step))
                        && expected_code.as_bytes().ct_eq(token.as_bytes()).into()
                    {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
}

/// SMS provider for sending verification codes
#[async_trait]
pub trait SmsProvider: Send + Sync {
    async fn send_code(&self, phone_number: &str, code: &str) -> Result<()>;
}

/// Email provider for sending verification codes
#[async_trait]
pub trait EmailProvider: Send + Sync {
    async fn send_code(&self, email: &str, code: &str) -> Result<()>;
}

/// Backup codes provider
pub struct BackupCodesProvider;

impl BackupCodesProvider {
    /// Generate backup codes
    pub fn generate_codes(count: u8) -> Vec<String> {
        let mut rng = rand::rng();
        (0..count)
            .map(|_| {
                format!(
                    "{:04}-{:04}",
                    rng.random_range(1000..9999),
                    rng.random_range(1000..9999)
                )
            })
            .collect()
    }

    /// Hash backup codes for storage
    pub fn hash_codes(codes: &[String]) -> Result<Vec<String>> {
        codes
            .iter()
            .map(|code| {
                // In production, use a proper password hashing function
                Ok(format!("hashed_{}", code))
            })
            .collect()
    }

    /// Verify backup code
    pub fn verify_code(hashed_codes: &[String], provided_code: &str) -> bool {
        let expected_hash = format!("hashed_{}", provided_code);
        hashed_codes.contains(&expected_hash)
    }
}

/// MFA storage trait
#[async_trait]
pub trait MfaStorage: Send + Sync {
    /// Store user MFA method
    async fn store_mfa_method(&self, method: &UserMfaMethod) -> Result<()>;

    /// Get user's MFA methods
    async fn get_user_mfa_methods(&self, user_id: &str) -> Result<Vec<UserMfaMethod>>;

    /// Update MFA method
    async fn update_mfa_method(&self, method: &UserMfaMethod) -> Result<()>;

    /// Delete MFA method
    async fn delete_mfa_method(&self, method_id: &str) -> Result<()>;

    /// Store MFA challenge
    async fn store_mfa_challenge(&self, challenge: &MfaChallenge) -> Result<()>;

    /// Get MFA challenge
    async fn get_mfa_challenge(&self, challenge_id: &str) -> Result<Option<MfaChallenge>>;

    /// Update MFA challenge (for attempt counting)
    async fn update_mfa_challenge(&self, challenge: &MfaChallenge) -> Result<()>;

    /// Delete MFA challenge
    async fn delete_mfa_challenge(&self, challenge_id: &str) -> Result<()>;

    /// Clean up expired challenges
    async fn cleanup_expired_challenges(&self) -> Result<()>;
}

/// MFA manager for handling multi-factor authentication
pub struct MfaManager<S: MfaStorage> {
    storage: S,
    config: MfaConfig,
    totp_provider: TotpProvider,
    sms_provider: Option<Box<dyn SmsProvider>>,
    email_provider: Option<Box<dyn EmailProvider>>,
}

impl<S: MfaStorage> MfaManager<S> {
    /// Create a new MFA manager
    pub fn new(storage: S, config: MfaConfig) -> Self {
        let totp_provider = TotpProvider::new(config.totp_config.clone());

        Self {
            storage,
            config,
            totp_provider,
            sms_provider: None,
            email_provider: None,
        }
    }

    /// Set SMS provider
    pub fn with_sms_provider(mut self, provider: Box<dyn SmsProvider>) -> Self {
        self.sms_provider = Some(provider);
        self
    }

    /// Set email provider
    pub fn with_email_provider(mut self, provider: Box<dyn EmailProvider>) -> Self {
        self.email_provider = Some(provider);
        self
    }

    /// Setup TOTP for a user
    pub async fn setup_totp(&self, user_id: &str, user_identifier: &str) -> Result<UserMfaMethod> {
        let secret = self.totp_provider.generate_secret()?;
        let qr_code_url = self
            .totp_provider
            .generate_qr_code_url(&secret, user_identifier);

        let method = UserMfaMethod {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            method_type: MfaMethodType::Totp,
            method_data: MfaMethodData::Totp {
                secret_key: secret,
                qr_code_url,
            },
            display_name: "Authenticator App".to_string(),
            is_primary: false,
            is_enabled: false, // Will be enabled after verification
            created_at: SystemTime::now(),
            last_used_at: None,
        };

        self.storage.store_mfa_method(&method).await?;
        Ok(method)
    }

    /// Setup SMS MFA for a user
    pub async fn setup_sms(&self, user_id: &str, phone_number: &str) -> Result<UserMfaMethod> {
        let method = UserMfaMethod {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            method_type: MfaMethodType::Sms,
            method_data: MfaMethodData::Sms {
                phone_number: phone_number.to_string(),
                is_verified: false,
            },
            display_name: format!("SMS to {}", mask_phone_number(phone_number)),
            is_primary: false,
            is_enabled: false,
            created_at: SystemTime::now(),
            last_used_at: None,
        };

        self.storage.store_mfa_method(&method).await?;
        Ok(method)
    }

    /// Generate backup codes for a user
    pub async fn generate_backup_codes(
        &self,
        user_id: &str,
    ) -> Result<(UserMfaMethod, Vec<String>)> {
        let codes = BackupCodesProvider::generate_codes(10);
        let hashed_codes = BackupCodesProvider::hash_codes(&codes)?;

        let method = UserMfaMethod {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            method_type: MfaMethodType::BackupCodes,
            method_data: MfaMethodData::BackupCodes {
                codes: hashed_codes,
                used_count: 0,
            },
            display_name: "Backup Codes".to_string(),
            is_primary: false,
            is_enabled: true,
            created_at: SystemTime::now(),
            last_used_at: None,
        };

        self.storage.store_mfa_method(&method).await?;
        Ok((method, codes))
    }

    /// Create MFA challenge for user
    pub async fn create_challenge(
        &self,
        user_id: &str,
        method_type: MfaMethodType,
    ) -> Result<MfaChallenge> {
        let user_methods = self.storage.get_user_mfa_methods(user_id).await?;
        let method = user_methods
            .iter()
            .find(|m| m.method_type == method_type && m.is_enabled)
            .ok_or_else(|| AuthError::validation("MFA method not found or not enabled"))?;

        let challenge_data = match &method.method_data {
            MfaMethodData::Totp { .. } => MfaChallengeData::Totp {
                time_window: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    / self.config.totp_config.period,
            },
            MfaMethodData::Sms { phone_number, .. } => {
                let code = generate_numeric_code(6);
                if let Some(sms_provider) = &self.sms_provider {
                    sms_provider.send_code(phone_number, &code).await?;
                }
                MfaChallengeData::Sms {
                    phone_number: mask_phone_number(phone_number),
                    code,
                }
            }
            MfaMethodData::Email { email, .. } => {
                let code = generate_numeric_code(6);
                if let Some(email_provider) = &self.email_provider {
                    email_provider.send_code(email, &code).await?;
                }
                MfaChallengeData::Email {
                    email: mask_email(email),
                    code,
                }
            }
            MfaMethodData::BackupCodes { .. } => {
                MfaChallengeData::BackupCodes { remaining_codes: 8 } // Default backup codes count
            }
            _ => return Err(AuthError::validation("Unsupported MFA method type")),
        };

        let challenge = MfaChallenge {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            method_type,
            challenge_data,
            created_at: SystemTime::now(),
            expires_at: SystemTime::now() + std::time::Duration::from_secs(300), // 5 minutes
            attempts: 0,
            max_attempts: 3,
        };

        self.storage.store_mfa_challenge(&challenge).await?;
        Ok(challenge)
    }

    /// Verify MFA challenge
    pub async fn verify_challenge(
        &self,
        challenge_id: &str,
        response: &str,
    ) -> Result<MfaVerificationResult> {
        let mut challenge = self
            .storage
            .get_mfa_challenge(challenge_id)
            .await?
            .ok_or_else(|| AuthError::validation("MFA challenge not found"))?;

        // Check if challenge has expired
        if SystemTime::now() > challenge.expires_at {
            self.storage.delete_mfa_challenge(challenge_id).await?;
            return Ok(MfaVerificationResult {
                success: false,
                method_type: challenge.method_type,
                remaining_attempts: None,
                error_message: Some("Challenge has expired".to_string()),
            });
        }

        // Check if max attempts exceeded
        if challenge.attempts >= challenge.max_attempts {
            self.storage.delete_mfa_challenge(challenge_id).await?;
            return Ok(MfaVerificationResult {
                success: false,
                method_type: challenge.method_type,
                remaining_attempts: Some(0),
                error_message: Some("Maximum attempts exceeded".to_string()),
            });
        }

        challenge.attempts += 1;

        let success = match &challenge.challenge_data {
            MfaChallengeData::Totp { time_window } => {
                let user_methods = self
                    .storage
                    .get_user_mfa_methods(&challenge.user_id)
                    .await?;
                if let Some(method) = user_methods
                    .iter()
                    .find(|m| m.method_type == MfaMethodType::Totp)
                {
                    if let MfaMethodData::Totp { secret_key, .. } = &method.method_data {
                        self.totp_provider
                            .verify_code(secret_key, response, Some(*time_window))?
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            MfaChallengeData::Sms { code, .. } => code == response,
            MfaChallengeData::Email { code, .. } => code == response,
            MfaChallengeData::BackupCodes { .. } => {
                let user_methods = self
                    .storage
                    .get_user_mfa_methods(&challenge.user_id)
                    .await?;
                if let Some(method) = user_methods
                    .iter()
                    .find(|m| m.method_type == MfaMethodType::BackupCodes)
                {
                    if let MfaMethodData::BackupCodes { codes, .. } = &method.method_data {
                        BackupCodesProvider::verify_code(codes, response)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        };

        if success {
            self.storage.delete_mfa_challenge(challenge_id).await?;
            Ok(MfaVerificationResult {
                success: true,
                method_type: challenge.method_type,
                remaining_attempts: None,
                error_message: None,
            })
        } else {
            let remaining = challenge.max_attempts.saturating_sub(challenge.attempts);
            self.storage.update_mfa_challenge(&challenge).await?;

            Ok(MfaVerificationResult {
                success: false,
                method_type: challenge.method_type,
                remaining_attempts: Some(remaining),
                error_message: Some("Invalid code".to_string()),
            })
        }
    }

    /// Check if user has MFA enabled
    pub async fn has_mfa_enabled(&self, user_id: &str) -> Result<bool> {
        let methods = self.storage.get_user_mfa_methods(user_id).await?;
        Ok(methods.iter().any(|m| m.is_enabled))
    }

    /// Get user's enabled MFA methods
    pub async fn get_enabled_methods(&self, user_id: &str) -> Result<Vec<MfaMethodType>> {
        let methods = self.storage.get_user_mfa_methods(user_id).await?;
        Ok(methods
            .iter()
            .filter(|m| m.is_enabled)
            .map(|m| m.method_type.clone())
            .collect())
    }
}

/// Generate a numeric code of specified length
fn generate_numeric_code(length: u8) -> String {
    let mut rng = rand::rng();
    (0..length)
        .map(|_| rng.random_range(0..10).to_string())
        .collect()
}

/// Mask phone number for display
fn mask_phone_number(phone: &str) -> String {
    if phone.len() > 4 {
        format!("***-***-{}", &phone[phone.len() - 4..])
    } else {
        "***-***-****".to_string()
    }
}

/// Mask email address for display
fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let (local, domain) = email.split_at(at_pos);
        if local.len() > 2 {
            format!("{}***{}", &local[0..1], &domain)
        } else {
            format!("***{}", domain)
        }
    } else {
        "***@***.***".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation() {
        let config = crate::security::TotpConfig::default();
        let provider = TotpProvider::new(config);

        let secret = provider.generate_secret().unwrap();
        assert!(!secret.is_empty());

        let code = provider.generate_code(&secret, Some(1)).unwrap();
        assert_eq!(code.len(), 6);

        // Verify the same code
        assert!(provider.verify_code(&secret, &code, Some(1)).unwrap());

        // Verify wrong code
        assert!(!provider.verify_code(&secret, "000000", Some(1)).unwrap());
    }

    #[test]
    fn test_backup_codes() {
        let codes = BackupCodesProvider::generate_codes(5);
        assert_eq!(codes.len(), 5);

        let hashed = BackupCodesProvider::hash_codes(&codes).unwrap();
        assert_eq!(hashed.len(), 5);

        // Should verify correctly
        assert!(BackupCodesProvider::verify_code(&hashed, &codes[0]));

        // Should not verify wrong code
        assert!(!BackupCodesProvider::verify_code(&hashed, "1234-5678"));
    }

    #[test]
    fn test_masking() {
        assert_eq!(mask_phone_number("+1234567890"), "***-***-7890");
        assert_eq!(mask_email("user@example.com"), "u***@example.com");
    }
}
