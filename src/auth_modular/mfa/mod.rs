//! Multi-Factor Authentication management module.

pub mod backup_codes;
pub mod email;
pub mod sms_kit;
pub mod totp;

use crate::errors::Result;
use crate::methods::MfaChallenge;
use crate::storage::AuthStorage;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::debug;

type EmergencyBypassHmac = Hmac<Sha256>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct EmergencyBypassClaims {
    admin_user_id: String,
    target_user_id: String,
    iat: i64,
    exp: i64,
    jti: String,
}

pub use backup_codes::BackupCodesManager;
pub use email::EmailManager;
pub use totp::TotpManager;

// Export SMSKit manager as the primary SMS interface
pub use sms_kit::{
    RateLimitConfig as SmsKitRateLimitConfig, SmsKitConfig, SmsKitManager, SmsKitProvider,
    SmsKitProviderConfig, WebhookConfig,
};

// Re-export as SmsManager for backward compatibility
pub use sms_kit::SmsKitManager as SmsManager;

/// Centralized multi-factor authentication (MFA) manager.
///
/// `MfaManager` coordinates all MFA operations across different authentication
/// factors including TOTP, SMS, email, and backup codes. It provides a unified
/// interface for MFA setup, challenge generation, and verification while
/// supporting multiple MFA methods simultaneously.
///
/// # Supported MFA Methods
///
/// - **TOTP (Time-based OTP)**: RFC 6238 compliant authenticator apps
/// - **SMS**: Text message-based verification codes
/// - **Email**: Email-based verification codes
/// - **Backup Codes**: Single-use recovery codes
///
/// # Multi-Method Support
///
/// Users can enable multiple MFA methods simultaneously, providing flexibility
/// and redundancy. The manager handles method coordination and fallback scenarios.
///
/// # Security Features
///
/// - **Challenge Expiration**: Time-limited challenges prevent replay attacks
/// - **Rate Limiting**: Prevents brute force attacks on MFA codes
/// - **Secure Code Generation**: Cryptographically secure random code generation
/// - **Method Validation**: Validates MFA setup before enabling
/// - **Audit Logging**: Comprehensive logging of all MFA operations
///
/// # Cross-Method Operations
///
/// The manager supports advanced scenarios like:
/// - Method fallback when primary method fails
/// - Cross-method challenge validation
/// - Method strength assessment
/// - Risk-based MFA requirements
///
/// # Example
///
/// ```rust,no_run
/// use auth_framework::auth_modular::mfa::MfaManager;
/// use std::sync::Arc;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let storage: Arc<dyn auth_framework::storage::AuthStorage> = unimplemented!();
/// // Create MFA manager with storage backend
/// let mfa_manager = MfaManager::new(storage);
///
/// // Generate a TOTP secret for a user (store it and show QR code to the user)
/// let secret = mfa_manager.totp.generate_secret("user123").await?;
///
/// // Verify a TOTP code during an authentication attempt
/// let is_valid = mfa_manager.totp.verify_code("user123", "123456").await?;
/// # Ok(())
/// # }
/// ```
///
/// # Thread Safety
///
/// The MFA manager is designed for concurrent use and safely coordinates
/// access to underlying MFA method implementations.
///
/// # Storage Integration
///
/// Integrates with the framework's storage system to persist:
/// - User MFA method configurations
/// - Active challenges
/// - Usage statistics and audit logs
/// - Backup codes and secrets
pub struct MfaManager {
    /// TOTP manager
    pub totp: TotpManager,

    /// SMS manager (using SMSKit)
    pub sms: SmsKitManager,

    /// Email manager
    pub email: EmailManager,

    /// Backup codes manager
    pub backup_codes: BackupCodesManager,

    /// Active MFA challenges
    challenges: Arc<RwLock<HashMap<String, MfaChallenge>>>,

    /// Storage backend for direct manager operations and fallback scenarios
    storage: Arc<dyn AuthStorage>,
}

impl MfaManager {
    /// Create a new MFA manager
    pub fn new(storage: Arc<dyn AuthStorage>) -> Self {
        Self {
            totp: TotpManager::new(storage.clone()),
            sms: SmsKitManager::new(storage.clone()),
            email: EmailManager::new(storage.clone()),
            backup_codes: BackupCodesManager::new(storage.clone()),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            storage,
        }
    }

    /// Create a new MFA manager with SMSKit configuration
    pub fn new_with_smskit_config(
        storage: Arc<dyn AuthStorage>,
        smskit_config: SmsKitConfig,
    ) -> Result<Self> {
        Ok(Self {
            totp: TotpManager::new(storage.clone()),
            sms: SmsKitManager::new_with_config(storage.clone(), smskit_config)?,
            email: EmailManager::new(storage.clone()),
            backup_codes: BackupCodesManager::new(storage.clone()),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            storage,
        })
    }

    /// Store an MFA challenge
    pub async fn store_challenge(&self, challenge: MfaChallenge) -> Result<()> {
        debug!("Storing MFA challenge '{}'", challenge.id);

        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge.id.clone(), challenge);

        Ok(())
    }

    /// Guard the global challenge budget and store the challenge.
    ///
    /// Returns an error if more than 10 000 challenges are pending; otherwise
    /// delegates to [`Self::store_challenge`].
    pub async fn guard_and_store(&self, challenge: MfaChallenge) -> Result<()> {
        const MAX_TOTAL_CHALLENGES: usize = 10_000;
        if self.get_active_challenge_count().await >= MAX_TOTAL_CHALLENGES {
            tracing::warn!("Maximum MFA challenges ({}) exceeded", MAX_TOTAL_CHALLENGES);
            return Err(crate::errors::AuthError::rate_limit(
                "Too many pending MFA challenges. Please try again later.",
            ));
        }
        self.store_challenge(challenge).await
    }

    /// Get an MFA challenge
    pub async fn get_challenge(&self, challenge_id: &str) -> Result<Option<MfaChallenge>> {
        let challenges = self.challenges.read().await;
        Ok(challenges.get(challenge_id).cloned())
    }

    /// Remove an MFA challenge
    pub async fn remove_challenge(&self, challenge_id: &str) -> Result<()> {
        debug!("Removing MFA challenge '{}'", challenge_id);

        let mut challenges = self.challenges.write().await;
        challenges.remove(challenge_id);

        Ok(())
    }

    /// Clean up expired challenges
    pub async fn cleanup_expired_challenges(&self) -> Result<()> {
        debug!("Cleaning up expired MFA challenges");

        let mut challenges = self.challenges.write().await;
        let now = chrono::Utc::now();
        challenges.retain(|_, challenge| challenge.expires_at > now);

        Ok(())
    }

    /// Get count of active challenges
    pub async fn get_active_challenge_count(&self) -> usize {
        self.challenges.read().await.len()
    }

    /// Verify a code against the given MFA challenge, dispatching to the appropriate sub-manager.
    pub async fn verify_challenge_code(
        &self,
        challenge: &crate::methods::MfaChallenge,
        code: &str,
    ) -> Result<bool> {
        use crate::security::secure_utils::constant_time_compare;

        if challenge.is_expired() {
            return Ok(false);
        }

        match &challenge.mfa_type {
            crate::methods::MfaType::Totp => {
                self.totp.verify_login_code(&challenge.user_id, code).await
            }
            crate::methods::MfaType::Sms { .. } => {
                if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
                    return Ok(false);
                }
                let sms_key = format!("smskit_challenge:{}:code", challenge.id);
                match self.storage.get_kv(&sms_key).await? {
                    Some(stored) => {
                        let stored_code = std::str::from_utf8(&stored).unwrap_or("");
                        Ok(constant_time_compare(
                            stored_code.as_bytes(),
                            code.as_bytes(),
                        ))
                    }
                    None => Ok(false),
                }
            }
            crate::methods::MfaType::Email { .. } => {
                if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
                    return Ok(false);
                }
                let email_key = format!("email_challenge:{}:code", challenge.id);
                match self.storage.get_kv(&email_key).await? {
                    Some(stored) => {
                        let stored_code = std::str::from_utf8(&stored).unwrap_or("");
                        Ok(constant_time_compare(
                            stored_code.as_bytes(),
                            code.as_bytes(),
                        ))
                    }
                    None => Ok(false),
                }
            }
            crate::methods::MfaType::BackupCode => {
                self.backup_codes
                    .verify_login_code(&challenge.user_id, code)
                    .await
            }
            crate::methods::MfaType::MultiMethod => {
                if self
                    .totp
                    .verify_login_code(&challenge.user_id, code)
                    .await?
                {
                    return Ok(true);
                }
                self.backup_codes
                    .verify_login_code(&challenge.user_id, code)
                    .await
            }
            _ => Ok(false),
        }
    }

    /// MFA CROSS-METHOD OPERATIONS: Step-up authentication with multiple factors
    pub async fn initiate_step_up_authentication(
        &self,
        user_id: &str,
        required_methods: &[MfaMethod],
        risk_level: RiskLevel,
    ) -> Result<CrossMethodChallenge> {
        tracing::info!(
            "Initiating step-up authentication for user: {} with risk level: {:?}",
            user_id,
            risk_level
        );

        // Determine required methods based on risk level
        let adaptive_methods = self
            .adapt_required_methods(required_methods, risk_level.clone())
            .await?;

        // Generate challenge ID
        let challenge_id = uuid::Uuid::new_v4().to_string();

        // Create individual challenges for each method
        let mut method_challenges = HashMap::new();
        let mut completion_status = HashMap::new();

        for method in &adaptive_methods {
            let method_challenge = match method {
                MfaMethod::Totp => {
                    completion_status.insert(method.clone(), false);
                    self.create_totp_challenge(user_id, &challenge_id).await?
                }
                MfaMethod::Sms => {
                    completion_status.insert(method.clone(), false);
                    self.create_sms_challenge(user_id, &challenge_id).await?
                }
                MfaMethod::Email => {
                    completion_status.insert(method.clone(), false);
                    self.create_email_challenge(user_id, &challenge_id).await?
                }
                MfaMethod::BackupCode => {
                    completion_status.insert(method.clone(), false);
                    MethodChallenge::BackupCode {
                        challenge_id: format!("{}-backup", challenge_id),
                        instructions: "Enter one of your backup codes".to_string(),
                    }
                }
            };

            method_challenges.insert(method.clone(), method_challenge);
        }

        let cross_method_challenge = CrossMethodChallenge {
            id: challenge_id,
            user_id: user_id.to_string(),
            required_methods: adaptive_methods.clone(),
            method_challenges,
            completion_status,
            risk_level,
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            created_at: chrono::Utc::now(),
        };

        // Store the cross-method challenge
        {
            let mut challenges = self.challenges.write().await;
            challenges.insert(
                cross_method_challenge.id.clone(),
                MfaChallenge {
                    id: cross_method_challenge.id.clone(),
                    mfa_type: crate::methods::MfaType::MultiMethod,
                    user_id: user_id.to_string(),
                    expires_at: cross_method_challenge.expires_at,
                    created_at: chrono::Utc::now(),
                    attempts: 0,
                    max_attempts: 3,
                    code_hash: None,
                    message: Some("Complete all required authentication methods".to_string()),
                    data: {
                        let mut data = HashMap::new();
                        data.insert(
                            "cross_method_data".to_string(),
                            serde_json::to_value(&cross_method_challenge)?,
                        );
                        data
                    },
                },
            );
        }

        tracing::info!(
            "Step-up authentication initiated with {} methods",
            adaptive_methods.len()
        );
        Ok(cross_method_challenge)
    }

    /// Complete a specific method within a cross-method challenge
    pub async fn complete_cross_method_step(
        &self,
        challenge_id: &str,
        method: MfaMethod,
        response: &str,
    ) -> Result<CrossMethodCompletionResult> {
        tracing::debug!(
            "Completing cross-method step: {:?} for challenge: {}",
            method,
            challenge_id
        );

        // Retrieve and update the cross-method challenge
        let mut cross_challenge = self.get_cross_method_challenge(challenge_id).await?;

        if cross_challenge.completion_status.get(&method) == Some(&true) {
            return Ok(CrossMethodCompletionResult {
                method,
                success: true,
                remaining_methods: self.get_remaining_methods(&cross_challenge),
                all_completed: false,
                error: Some("Method already completed".to_string()),
            });
        }

        // Verify the specific method response
        let verification_result = match method {
            MfaMethod::Totp => {
                self.totp
                    .verify_code(&cross_challenge.user_id, response)
                    .await
            }
            MfaMethod::Sms => {
                self.sms
                    .verify_code(&cross_challenge.user_id, response)
                    .await
            }
            MfaMethod::Email => {
                self.email
                    .verify_code(&cross_challenge.user_id, response)
                    .await
            }
            MfaMethod::BackupCode => {
                self.backup_codes
                    .verify_code(&cross_challenge.user_id, response)
                    .await
            }
        };

        // `verify_code` returns Ok(false) for a wrong code, so `is_ok()` is NOT success.
        let success = matches!(verification_result, Ok(true));

        if success {
            // Mark method as completed
            cross_challenge
                .completion_status
                .insert(method.clone(), true);

            // Update stored challenge
            self.update_cross_method_challenge(&cross_challenge).await?;

            tracing::info!("Cross-method step completed successfully: {:?}", method);
        } else {
            tracing::warn!(
                "Cross-method step failed: {:?} - {:?}",
                method,
                verification_result
            );
        }

        let remaining_methods = self.get_remaining_methods(&cross_challenge);
        let all_completed = remaining_methods.is_empty();

        if all_completed {
            tracing::info!(
                "All cross-method authentication steps completed for challenge: {}",
                challenge_id
            );
            // Clean up the challenge
            self.remove_challenge(challenge_id).await?;
        }

        Ok(CrossMethodCompletionResult {
            method,
            success,
            remaining_methods,
            all_completed,
            error: if success {
                None
            } else {
                Some(match &verification_result {
                    Ok(_) => "Verification failed: invalid code".to_string(),
                    Err(e) => format!("Verification failed: {:?}", e),
                })
            },
        })
    }

    /// Get available MFA methods for a user
    pub async fn get_available_methods(&self, user_id: &str) -> Result<Vec<MfaMethod>> {
        tracing::debug!("Getting available MFA methods for user: {}", user_id);

        let mut available_methods = Vec::new();

        // Check TOTP availability
        if self.totp.has_totp_secret(user_id).await.unwrap_or(false) {
            available_methods.push(MfaMethod::Totp);
        }

        // Check SMS availability
        if self.sms.has_phone_number(user_id).await.unwrap_or(false) {
            available_methods.push(MfaMethod::Sms);
        }

        // Check email availability
        if self.email.has_email(user_id).await.unwrap_or(false) {
            available_methods.push(MfaMethod::Email);
        }

        // Check backup codes availability
        if self
            .backup_codes
            .has_backup_codes(user_id)
            .await
            .unwrap_or(false)
        {
            available_methods.push(MfaMethod::BackupCode);
        }

        tracing::debug!(
            "Available methods for user {}: {:?}",
            user_id,
            available_methods
        );
        Ok(available_methods)
    }

    /// Perform method fallback when primary method fails
    pub async fn perform_method_fallback(
        &self,
        user_id: &str,
        failed_method: MfaMethod,
        fallback_order: &[MfaMethod],
    ) -> Result<MethodFallbackResult> {
        tracing::info!(
            "Performing method fallback for user: {} after failed method: {:?}",
            user_id,
            failed_method
        );

        let available_methods = self.get_available_methods(user_id).await?;

        // Find the first available fallback method
        for fallback_method in fallback_order {
            if available_methods.contains(fallback_method) && fallback_method != &failed_method {
                // Create challenge for fallback method
                let fallback_challenge = match fallback_method {
                    MfaMethod::Totp => self.create_totp_challenge(user_id, "fallback").await?,
                    MfaMethod::Sms => self.create_sms_challenge(user_id, "fallback").await?,
                    MfaMethod::Email => self.create_email_challenge(user_id, "fallback").await?,
                    MfaMethod::BackupCode => MethodChallenge::BackupCode {
                        challenge_id: "fallback-backup".to_string(),
                        instructions: "Enter one of your backup codes".to_string(),
                    },
                };

                tracing::info!(
                    "Fallback method activated: {:?} for user: {}",
                    fallback_method,
                    user_id
                );

                return Ok(MethodFallbackResult {
                    fallback_method: fallback_method.clone(),
                    challenge: fallback_challenge,
                    remaining_fallbacks: fallback_order
                        .iter()
                        .skip_while(|&m| m != fallback_method)
                        .skip(1)
                        .filter(|&m| available_methods.contains(m))
                        .cloned()
                        .collect(),
                });
            }
        }

        Err(crate::errors::AuthError::validation(
            "No fallback methods available",
        ))
    }

    /// Adaptive MFA: Adjust required methods based on risk level
    async fn adapt_required_methods(
        &self,
        base_methods: &[MfaMethod],
        risk_level: RiskLevel,
    ) -> Result<Vec<MfaMethod>> {
        let mut adapted_methods = base_methods.to_vec();

        match risk_level {
            RiskLevel::Low => {
                // Low risk: single factor is sufficient
                adapted_methods.truncate(1);
            }
            RiskLevel::Medium => {
                // Medium risk: use base methods as-is
                // No changes needed
            }
            RiskLevel::High => {
                // High risk: require additional verification
                if !adapted_methods.contains(&MfaMethod::Email) {
                    adapted_methods.push(MfaMethod::Email);
                }
                if !adapted_methods.contains(&MfaMethod::Sms) {
                    adapted_methods.push(MfaMethod::Sms);
                }
            }
            RiskLevel::Critical => {
                // Critical risk: require all available methods
                adapted_methods = vec![MfaMethod::Totp, MfaMethod::Sms, MfaMethod::Email];
            }
        }

        Ok(adapted_methods)
    }

    /// Helper methods for cross-method operations
    async fn get_cross_method_challenge(&self, challenge_id: &str) -> Result<CrossMethodChallenge> {
        let challenges = self.challenges.read().await;
        let challenge = challenges
            .get(challenge_id)
            .ok_or_else(|| crate::errors::AuthError::validation("Challenge not found"))?;

        let cross_challenge: CrossMethodChallenge =
            if let Some(cross_method_value) = challenge.data.get("cross_method_data") {
                serde_json::from_value(cross_method_value.clone())?
            } else {
                return Err(crate::errors::AuthError::validation(
                    "Invalid cross-method challenge data",
                ));
            };
        Ok(cross_challenge)
    }

    async fn update_cross_method_challenge(
        &self,
        cross_challenge: &CrossMethodChallenge,
    ) -> Result<()> {
        let mut challenges = self.challenges.write().await;
        if let Some(challenge) = challenges.get_mut(&cross_challenge.id) {
            challenge.data.insert(
                "cross_method_data".to_string(),
                serde_json::to_value(cross_challenge)?,
            );
        }
        Ok(())
    }

    fn get_remaining_methods(&self, cross_challenge: &CrossMethodChallenge) -> Vec<MfaMethod> {
        cross_challenge
            .completion_status
            .iter()
            .filter_map(|(method, &completed)| {
                if !completed {
                    Some(method.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Create individual method challenges
    async fn create_totp_challenge(
        &self,
        _user_id: &str,
        challenge_prefix: &str,
    ) -> Result<MethodChallenge> {
        Ok(MethodChallenge::Totp {
            challenge_id: format!("{}-totp", challenge_prefix),
            instructions: "Enter the 6-digit code from your authenticator app".to_string(),
        })
    }

    async fn create_sms_challenge(
        &self,
        user_id: &str,
        challenge_prefix: &str,
    ) -> Result<MethodChallenge> {
        let _code = self.sms.send_verification_code(user_id).await?;
        Ok(MethodChallenge::Sms {
            challenge_id: format!("{}-sms", challenge_prefix),
            instructions: "Enter the verification code sent to your phone".to_string(),
            phone_hint: self
                .get_phone_hint(user_id)
                .await
                .unwrap_or_else(|_| "***-***-****".to_string()),
        })
    }

    async fn create_email_challenge(
        &self,
        user_id: &str,
        challenge_prefix: &str,
    ) -> Result<MethodChallenge> {
        let _code = self.email.send_email_code(user_id).await?;
        Ok(MethodChallenge::Email {
            challenge_id: format!("{}-email", challenge_prefix),
            instructions: "Enter the verification code sent to your email".to_string(),
            email_hint: self
                .get_email_hint(user_id)
                .await
                .unwrap_or_else(|_| "****@****.com".to_string()),
        })
    }

    async fn get_phone_hint(&self, user_id: &str) -> Result<String> {
        // Try to look up the user's phone number from storage
        if let Ok(Some(data)) = self
            .storage
            .get_kv(&format!("user_phone:{}", user_id))
            .await
        {
            if let Ok(phone) = String::from_utf8(data) {
                if phone.len() >= 4 {
                    return Ok(format!("***-***-{}", &phone[phone.len() - 4..]));
                }
            }
        }
        // Fallback: no phone data in storage
        Ok("Phone on file".to_string())
    }

    async fn get_email_hint(&self, user_id: &str) -> Result<String> {
        // Try to look up the user's email from storage
        if let Ok(Some(data)) = self
            .storage
            .get_kv(&format!("user_email:{}", user_id))
            .await
        {
            if let Ok(email) = String::from_utf8(data) {
                if let Some(at_pos) = email.find('@') {
                    let prefix_len = at_pos.min(2);
                    return Ok(format!(
                        "{}****@****{}",
                        &email[..prefix_len],
                        &email[at_pos..]
                    ));
                }
            }
        }
        // Fallback: no email data in storage
        Ok(format!("{}****@****.com", &user_id[..user_id.len().min(2)]))
    }

    fn emergency_bypass_secret() -> Result<Vec<u8>> {
        let secret = std::env::var("AUTHFRAMEWORK_EMERGENCY_BYPASS_SECRET").map_err(|_| {
            crate::errors::AuthError::config(
                "Emergency MFA bypass is disabled until AUTHFRAMEWORK_EMERGENCY_BYPASS_SECRET is configured",
            )
        })?;

        if secret.len() < 32 {
            return Err(crate::errors::AuthError::config(
                "AUTHFRAMEWORK_EMERGENCY_BYPASS_SECRET must be at least 32 bytes long",
            ));
        }

        Ok(secret.into_bytes())
    }

    fn sign_emergency_bypass_payload(secret: &[u8], payload: &str) -> Result<String> {
        let mut mac = EmergencyBypassHmac::new_from_slice(secret).map_err(|_| {
            crate::errors::AuthError::config("Invalid emergency bypass signing key")
        })?;
        mac.update(payload.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn verify_emergency_bypass_token(secret: &[u8], token: &str) -> Result<EmergencyBypassClaims> {
        let (payload_b64, signature_hex) = token.split_once('.').ok_or_else(|| {
            crate::errors::AuthError::validation("Invalid emergency bypass token format")
        })?;

        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| {
                crate::errors::AuthError::validation("Invalid emergency bypass token encoding")
            })?;
        let payload = String::from_utf8(payload_bytes).map_err(|_| {
            crate::errors::AuthError::validation("Invalid emergency bypass token payload")
        })?;

        let expected_signature = Self::sign_emergency_bypass_payload(secret, &payload)?;
        if !crate::security::secure_utils::constant_time_compare(
            expected_signature.as_bytes(),
            signature_hex.as_bytes(),
        ) {
            return Err(crate::errors::AuthError::validation(
                "Emergency bypass token signature verification failed",
            ));
        }

        let claims: EmergencyBypassClaims = serde_json::from_str(&payload).map_err(|_| {
            crate::errors::AuthError::validation("Invalid emergency bypass token claims")
        })?;

        let now = chrono::Utc::now().timestamp();
        if now >= claims.exp {
            return Err(crate::errors::AuthError::validation(
                "Emergency bypass token has expired",
            ));
        }

        Ok(claims)
    }

    async fn user_has_admin_role(&self, user_id: &str) -> Result<bool> {
        let user_key = format!("user:{}", user_id);
        let Some(user_data) = self.storage.get_kv(&user_key).await? else {
            return Ok(false);
        };

        let profile: serde_json::Value = serde_json::from_slice(&user_data).map_err(|e| {
            crate::errors::AuthError::internal(format!(
                "Failed to parse stored user profile for emergency bypass validation: {}",
                e
            ))
        })?;

        Ok(profile
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|roles| roles.iter().any(|role| role.as_str() == Some("admin")))
            .unwrap_or(false))
    }

    /// Generate a signed emergency MFA bypass token for a specific target user.
    pub async fn generate_emergency_bypass_token(
        &self,
        admin_user_id: &str,
        target_user_id: &str,
        lifetime: Duration,
    ) -> Result<String> {
        if !self.user_has_admin_role(admin_user_id).await? {
            return Err(crate::errors::AuthError::Permission(
                crate::errors::PermissionError::Denied {
                    action: "generate emergency MFA bypass token".to_string(),
                    resource: admin_user_id.to_string(),
                    message:
                        "Admin privileges are required to generate an emergency MFA bypass token"
                            .to_string(),
                },
            ));
        }

        let secret = Self::emergency_bypass_secret()?;
        let now = chrono::Utc::now().timestamp();
        let exp = now
            + i64::try_from(lifetime.as_secs()).map_err(|_| {
                crate::errors::AuthError::validation(
                    "Emergency bypass token lifetime exceeds supported range",
                )
            })?;

        let claims = EmergencyBypassClaims {
            admin_user_id: admin_user_id.to_string(),
            target_user_id: target_user_id.to_string(),
            iat: now,
            exp,
            jti: uuid::Uuid::new_v4().to_string(),
        };
        let payload = serde_json::to_string(&claims)
            .map_err(|e| crate::errors::AuthError::internal(e.to_string()))?;
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signature = Self::sign_emergency_bypass_payload(&secret, &payload)?;
        Ok(format!("{}.{}", payload_b64, signature))
    }

    /// Emergency MFA bypass using direct storage access
    /// This method provides a way to recover when all MFA methods fail
    pub async fn emergency_mfa_bypass(&self, user_id: &str, admin_token: &str) -> Result<bool> {
        tracing::warn!("Emergency MFA bypass requested for user: {}", user_id);

        let secret = Self::emergency_bypass_secret()?;
        let claims = match Self::verify_emergency_bypass_token(&secret, admin_token) {
            Ok(claims) => claims,
            Err(e) => {
                tracing::error!(error = %e, "Invalid emergency MFA bypass token");
                return Ok(false);
            }
        };

        if claims.target_user_id != user_id {
            tracing::error!(
                target = %claims.target_user_id,
                requested = %user_id,
                "Emergency MFA bypass token target user mismatch"
            );
            return Ok(false);
        }

        if !self.user_has_admin_role(&claims.admin_user_id).await? {
            tracing::error!(
                admin_user_id = %claims.admin_user_id,
                "Emergency MFA bypass denied because issuing admin no longer has admin role"
            );
            return Ok(false);
        }

        tracing::info!(
            admin_user_id = %claims.admin_user_id,
            target_user_id = %claims.target_user_id,
            "Emergency MFA bypass granted"
        );

        let bypass_key = format!("mfa_bypass:{}:{}", user_id, chrono::Utc::now().timestamp());
        let bypass_data = serde_json::json!({
            "admin_user_id": claims.admin_user_id,
            "target_user_id": claims.target_user_id,
            "issued_at": claims.iat,
            "expires_at": claims.exp,
            "jti": claims.jti,
            "bypassed_at": chrono::Utc::now().to_rfc3339(),
        })
        .to_string();
        self.storage
            .store_kv(
                &bypass_key,
                bypass_data.as_bytes(),
                Some(Duration::from_secs(86400)),
            )
            .await?;

        Ok(true)
    }
}

/// MFA method types
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MfaMethod {
    Totp,
    Sms,
    Email,
    BackupCode,
}

/// Risk levels for adaptive MFA
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Cross-method challenge combining multiple MFA factors
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrossMethodChallenge {
    pub id: String,
    pub user_id: String,
    pub required_methods: Vec<MfaMethod>,
    pub method_challenges: HashMap<MfaMethod, MethodChallenge>,
    pub completion_status: HashMap<MfaMethod, bool>,
    pub risk_level: RiskLevel,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Individual method challenge
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum MethodChallenge {
    Totp {
        challenge_id: String,
        instructions: String,
    },
    Sms {
        challenge_id: String,
        instructions: String,
        phone_hint: String,
    },
    Email {
        challenge_id: String,
        instructions: String,
        email_hint: String,
    },
    BackupCode {
        challenge_id: String,
        instructions: String,
    },
}

/// Result of cross-method completion attempt
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrossMethodCompletionResult {
    pub method: MfaMethod,
    pub success: bool,
    pub remaining_methods: Vec<MfaMethod>,
    pub all_completed: bool,
    pub error: Option<String>,
}

/// Result of method fallback operation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MethodFallbackResult {
    pub fallback_method: MfaMethod,
    pub challenge: MethodChallenge,
    pub remaining_fallbacks: Vec<MfaMethod>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    fn make_mfa() -> MfaManager {
        MfaManager::new(Arc::new(MemoryStorage::new()))
    }

    fn make_challenge(user_id: &str) -> MfaChallenge {
        use crate::methods::{MfaChallenge, MfaType};
        MfaChallenge {
            id: format!("chal_{}", uuid::Uuid::new_v4()),
            mfa_type: MfaType::Totp,
            user_id: user_id.to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            attempts: 0,
            max_attempts: 3,
            code_hash: None,
            message: None,
            data: HashMap::new(),
        }
    }

    // ── store / get / remove challenge ──────────────────────────────────

    #[tokio::test]
    async fn test_store_and_get_challenge() {
        let mfa = make_mfa();
        let chal = make_challenge("u1");
        let id = chal.id.clone();
        mfa.store_challenge(chal).await.unwrap();
        let retrieved = mfa.get_challenge(&id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "u1");
    }

    #[tokio::test]
    async fn test_remove_challenge() {
        let mfa = make_mfa();
        let chal = make_challenge("u2");
        let id = chal.id.clone();
        mfa.store_challenge(chal).await.unwrap();
        mfa.remove_challenge(&id).await.unwrap();
        assert!(mfa.get_challenge(&id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_get_challenge_nonexistent() {
        let mfa = make_mfa();
        assert!(mfa.get_challenge("ghost").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_get_active_challenge_count() {
        let mfa = make_mfa();
        assert_eq!(mfa.get_active_challenge_count().await, 0);
        mfa.store_challenge(make_challenge("u3")).await.unwrap();
        assert_eq!(mfa.get_active_challenge_count().await, 1);
    }

    #[tokio::test]
    async fn test_cleanup_expired_challenges() {
        let mfa = make_mfa();
        let mut chal = make_challenge("u4");
        chal.expires_at = chrono::Utc::now() - chrono::Duration::minutes(1);
        mfa.store_challenge(chal).await.unwrap();
        mfa.cleanup_expired_challenges().await.unwrap();
        assert_eq!(mfa.get_active_challenge_count().await, 0);
    }

    #[tokio::test]
    async fn test_guard_and_store_succeeds() {
        let mfa = make_mfa();
        let chal = make_challenge("guard_user");
        mfa.guard_and_store(chal).await.unwrap();
        assert_eq!(mfa.get_active_challenge_count().await, 1);
    }

    // ── get_available_methods ───────────────────────────────────────────

    #[tokio::test]
    async fn test_get_available_methods_none() {
        let mfa = make_mfa();
        let methods = mfa.get_available_methods("nobody").await.unwrap();
        // Only backup codes might be default-available or might be empty
        // Either way this shouldn't error
        assert!(methods.len() <= 4);
    }

    #[tokio::test]
    async fn test_get_available_methods_with_totp() {
        let mfa = make_mfa();
        let _secret = mfa.totp.generate_secret("totp_user").await.unwrap();
        let methods = mfa.get_available_methods("totp_user").await.unwrap();
        assert!(methods.contains(&MfaMethod::Totp));
    }

    #[tokio::test]
    async fn test_perform_method_fallback_uses_api_enrolled_totp() {
        let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
        let mfa = MfaManager::new(storage.clone());
        let api_secret = base32::encode(base32::Alphabet::Rfc4648 { padding: true }, &[42; 20]);

        storage
            .store_kv("mfa_secret:api_totp_user", api_secret.as_bytes(), None)
            .await
            .unwrap();

        let fallback = mfa
            .perform_method_fallback("api_totp_user", MfaMethod::Email, &[MfaMethod::Totp])
            .await
            .unwrap();

        assert_eq!(fallback.fallback_method, MfaMethod::Totp);
        assert!(matches!(fallback.challenge, MethodChallenge::Totp { .. }));
    }

    // ── step-up authentication ──────────────────────────────────────────

    #[tokio::test]
    async fn test_cross_method_step_accepts_valid_code() {
        let mfa = make_mfa();
        let secret = mfa.totp.generate_secret("ok_user").await.unwrap();
        let cross = mfa
            .initiate_step_up_authentication("ok_user", &[MfaMethod::Totp], RiskLevel::Medium)
            .await
            .unwrap();
        let code = mfa.totp.generate_code(&secret).await.unwrap();
        let res = mfa
            .complete_cross_method_step(&cross.id, MfaMethod::Totp, &code)
            .await
            .unwrap();
        assert!(
            res.success,
            "a valid TOTP code must complete the step (error={:?})",
            res.error
        );
    }

    #[tokio::test]
    async fn test_cross_method_step_rejects_invalid_code() {
        let mfa = make_mfa();
        let _secret = mfa.totp.generate_secret("bypass_user").await.unwrap();
        let cross = mfa
            .initiate_step_up_authentication("bypass_user", &[MfaMethod::Totp], RiskLevel::Medium)
            .await
            .unwrap();
        // Malformed on purpose: TOTP verify_code returns Ok(false) for any non-6-char code,
        // so this is deterministic and cannot collide with a real TOTP value.
        let res = mfa
            .complete_cross_method_step(&cross.id, MfaMethod::Totp, "garbage")
            .await
            .unwrap();
        assert!(
            !res.success,
            "an invalid TOTP code must NOT complete a step-up MFA step (success={})",
            res.success
        );
    }

    #[tokio::test]
    async fn test_initiate_step_up_authentication() {
        let mfa = make_mfa();
        // Setup TOTP for user
        let _secret = mfa.totp.generate_secret("step_user").await.unwrap();

        let cross = mfa
            .initiate_step_up_authentication("step_user", &[MfaMethod::Totp], RiskLevel::Medium)
            .await
            .unwrap();
        assert_eq!(cross.user_id, "step_user");
        assert_eq!(cross.risk_level, RiskLevel::Medium);
    }

    /// Helper to create an admin user profile in storage so `user_has_admin_role` passes.
    async fn setup_admin(storage: &Arc<dyn AuthStorage>, user_id: &str) {
        let profile = serde_json::json!({
            "user_id": user_id,
            "username": user_id,
            "roles": ["admin"]
        });
        let key = format!("user:{}", user_id);
        storage
            .store_kv(&key, profile.to_string().as_bytes(), None)
            .await
            .unwrap();
    }

    // ── emergency bypass ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_generate_and_use_emergency_bypass() {
        let _env = crate::testing::test_infrastructure::TestEnvironmentGuard::new()
            .with_custom_var(
                "AUTHFRAMEWORK_EMERGENCY_BYPASS_SECRET",
                "this-is-a-very-long-test-secret-that-is-at-least-32-bytes",
            );
        let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
        let mfa = MfaManager::new(storage.clone());
        setup_admin(&storage, "admin1").await;
        let token = mfa
            .generate_emergency_bypass_token("admin1", "target1", Duration::from_secs(300))
            .await
            .unwrap();
        assert!(!token.is_empty());
        let result = mfa.emergency_mfa_bypass("target1", &token).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_emergency_bypass_wrong_user() {
        let _env = crate::testing::test_infrastructure::TestEnvironmentGuard::new()
            .with_custom_var(
                "AUTHFRAMEWORK_EMERGENCY_BYPASS_SECRET",
                "this-is-a-very-long-test-secret-that-is-at-least-32-bytes",
            );
        let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
        let mfa = MfaManager::new(storage.clone());
        setup_admin(&storage, "admin1").await;
        let token = mfa
            .generate_emergency_bypass_token("admin1", "target1", Duration::from_secs(300))
            .await
            .unwrap();
        let result = mfa
            .emergency_mfa_bypass("wrong_user", &token)
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_emergency_bypass_invalid_token() {
        let mfa = make_mfa();
        let result = mfa.emergency_mfa_bypass("user1", "bogus_token").await;
        // Should return Ok(false) or Err — either way not Ok(true)
        assert!(!result.unwrap_or(false));
    }

    #[tokio::test]
    async fn test_emergency_bypass_non_admin_rejected() {
        let _env = crate::testing::test_infrastructure::TestEnvironmentGuard::new()
            .with_custom_var(
                "AUTHFRAMEWORK_EMERGENCY_BYPASS_SECRET",
                "this-is-a-very-long-test-secret-that-is-at-least-32-bytes",
            );
        let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
        let mfa = MfaManager::new(storage.clone());
        // Don't set up admin — should fail
        let result = mfa
            .generate_emergency_bypass_token("notadmin", "target1", Duration::from_secs(300))
            .await;
        assert!(result.is_err());
    }

    // ── TOTP sub-module ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_totp_generate_secret() {
        let mfa = make_mfa();
        let secret = mfa.totp.generate_secret("totp1").await.unwrap();
        assert!(!secret.is_empty());
        assert!(mfa.totp.has_totp_secret("totp1").await.unwrap());
    }

    #[tokio::test]
    async fn test_totp_generate_code() {
        let mfa = make_mfa();
        let secret = mfa.totp.generate_secret("totp2").await.unwrap();
        let code = mfa.totp.generate_code(&secret).await.unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[tokio::test]
    async fn test_totp_verify_code_success() {
        let mfa = make_mfa();
        let secret = mfa.totp.generate_secret("totp3").await.unwrap();
        let code = mfa.totp.generate_code(&secret).await.unwrap();
        assert!(mfa.totp.verify_code("totp3", &code).await.unwrap());
    }

    #[tokio::test]
    async fn test_totp_verify_code_wrong() {
        let mfa = make_mfa();
        let _secret = mfa.totp.generate_secret("totp4").await.unwrap();
        assert!(
            !mfa.totp
                .verify_code("totp4", "000000")
                .await
                .unwrap_or(true)
        );
    }

    #[tokio::test]
    async fn test_totp_has_no_secret() {
        let mfa = make_mfa();
        assert!(!mfa.totp.has_totp_secret("nobody").await.unwrap());
    }

    #[tokio::test]
    async fn test_totp_generate_qr_code() {
        let mfa = make_mfa();
        let secret = mfa.totp.generate_secret("totp5").await.unwrap();
        let qr = mfa
            .totp
            .generate_qr_code("totp5", "AuthFramework", &secret)
            .await
            .unwrap();
        assert!(qr.contains("otpauth://"));
    }

    // ── Backup codes sub-module ─────────────────────────────────────────

    #[tokio::test]
    async fn test_backup_codes_generate() {
        let mfa = make_mfa();
        let codes = mfa.backup_codes.generate_codes("bc1", 10).await.unwrap();
        assert_eq!(codes.len(), 10);
    }

    #[tokio::test]
    async fn test_backup_codes_verify() {
        let mfa = make_mfa();
        let codes = mfa.backup_codes.generate_codes("bc2", 5).await.unwrap();
        let code = codes[0].clone();
        assert!(mfa.backup_codes.verify_code("bc2", &code).await.unwrap());
        // Code should be consumed — second verify should fail
        assert!(!mfa.backup_codes.verify_code("bc2", &code).await.unwrap());
    }

    #[tokio::test]
    async fn test_backup_codes_remaining_count() {
        let mfa = make_mfa();
        mfa.backup_codes.generate_codes("bc3", 5).await.unwrap();
        assert_eq!(
            mfa.backup_codes.get_remaining_count("bc3").await.unwrap(),
            5
        );
    }

    #[tokio::test]
    async fn test_backup_codes_verify_wrong_code() {
        let mfa = make_mfa();
        mfa.backup_codes.generate_codes("bc4", 5).await.unwrap();
        assert!(
            !mfa.backup_codes
                .verify_code("bc4", "WRONGCODE")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_backup_codes_regenerate() {
        let mfa = make_mfa();
        let old = mfa.backup_codes.generate_codes("bc5", 5).await.unwrap();
        let new = mfa.backup_codes.regenerate_codes("bc5", 5).await.unwrap();
        assert_ne!(old, new);
    }

    #[tokio::test]
    async fn test_backup_codes_has_codes() {
        let mfa = make_mfa();
        assert!(!mfa.backup_codes.has_backup_codes("nobody").await.unwrap());
        mfa.backup_codes.generate_codes("bc6", 3).await.unwrap();
        assert!(mfa.backup_codes.has_backup_codes("bc6").await.unwrap());
    }

    // ── Email MFA sub-module ────────────────────────────────────────────

    #[tokio::test]
    async fn test_email_register_and_has_email() {
        let mfa = make_mfa();
        assert!(!mfa.email.has_email("em1").await.unwrap());
        mfa.email
            .register_email("em1", "test@example.com")
            .await
            .unwrap();
        assert!(mfa.email.has_email("em1").await.unwrap());
    }

    #[tokio::test]
    async fn test_email_get_user_email() {
        let mfa = make_mfa();
        mfa.email
            .register_email("em2", "em2@example.com")
            .await
            .unwrap();
        let email = mfa.email.get_user_email("em2").await.unwrap();
        assert_eq!(email.as_deref(), Some("em2@example.com"));
    }

    #[tokio::test]
    async fn test_email_get_user_email_none() {
        let mfa = make_mfa();
        let email = mfa.email.get_user_email("nobody").await.unwrap();
        assert!(email.is_none());
    }

    #[tokio::test]
    async fn test_email_initiate_challenge() {
        let mfa = make_mfa();
        mfa.email
            .register_email("em3", "em3@example.com")
            .await
            .unwrap();
        let challenge_id = mfa.email.initiate_challenge("em3").await.unwrap();
        assert!(!challenge_id.is_empty());
    }

    #[tokio::test]
    async fn test_email_generate_and_verify_code() {
        let mfa = make_mfa();
        mfa.email
            .register_email("em4", "em4@example.com")
            .await
            .unwrap();
        let cid = mfa.email.initiate_challenge("em4").await.unwrap();
        let code = mfa.email.generate_code(&cid).await.unwrap();
        assert!(mfa.email.verify_code(&cid, &code).await.unwrap());
    }

    #[tokio::test]
    async fn test_email_verify_wrong_code() {
        let mfa = make_mfa();
        mfa.email
            .register_email("em5", "em5@example.com")
            .await
            .unwrap();
        let cid = mfa.email.initiate_challenge("em5").await.unwrap();
        let _code = mfa.email.generate_code(&cid).await.unwrap();
        assert!(!mfa.email.verify_code(&cid, "000000").await.unwrap());
    }

    // ── SMS MFA sub-module ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_sms_register_and_has_phone() {
        let mfa = make_mfa();
        assert!(!mfa.sms.has_phone_number("sms1").await.unwrap());
        mfa.sms
            .register_phone_number("sms1", "+1234567890")
            .await
            .unwrap();
        assert!(mfa.sms.has_phone_number("sms1").await.unwrap());
    }

    #[tokio::test]
    async fn test_sms_get_user_phone() {
        let mfa = make_mfa();
        mfa.sms
            .register_phone_number("sms2", "+9876543210")
            .await
            .unwrap();
        let phone = mfa.sms.get_user_phone("sms2").await.unwrap();
        assert_eq!(phone.as_deref(), Some("+9876543210"));
    }

    #[tokio::test]
    async fn test_sms_get_user_phone_none() {
        let mfa = make_mfa();
        let phone = mfa.sms.get_user_phone("nobody").await.unwrap();
        assert!(phone.is_none());
    }

    #[tokio::test]
    async fn test_sms_initiate_challenge() {
        let mfa = make_mfa();
        mfa.sms
            .register_phone_number("sms3", "+1111111111")
            .await
            .unwrap();
        let cid = mfa.sms.initiate_challenge("sms3").await.unwrap();
        assert!(!cid.is_empty());
    }

    #[tokio::test]
    async fn test_sms_generate_and_verify_code() {
        let mfa = make_mfa();
        mfa.sms
            .register_phone_number("sms4", "+2222222222")
            .await
            .unwrap();
        let cid = mfa.sms.initiate_challenge("sms4").await.unwrap();
        let code = mfa.sms.generate_code(&cid).await.unwrap();
        assert!(mfa.sms.verify_code(&cid, &code).await.unwrap());
    }

    #[tokio::test]
    async fn test_sms_verify_wrong_code() {
        let mfa = make_mfa();
        mfa.sms
            .register_phone_number("sms5", "+3333333333")
            .await
            .unwrap();
        let cid = mfa.sms.initiate_challenge("sms5").await.unwrap();
        let _code = mfa.sms.generate_code(&cid).await.unwrap();
        assert!(!mfa.sms.verify_code(&cid, "000000").await.unwrap());
    }
}
