//! Multi-Factor Authentication management module.

pub mod backup_codes;
pub mod email;
pub mod sms;
pub mod totp;

// SMSKit integration (next-generation SMS support)
#[cfg(feature = "smskit")]
pub mod sms_kit;

use crate::errors::Result;
use crate::methods::MfaChallenge;
use crate::storage::AuthStorage;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

pub use backup_codes::BackupCodesManager;
pub use email::EmailManager;
pub use sms::SmsManager;
pub use totp::TotpManager;

// Export SMSKit manager when feature is enabled
#[cfg(feature = "smskit")]
pub use sms_kit::{
    RateLimitConfig as SmsKitRateLimitConfig, SmsKitConfig, SmsKitManager, SmsKitProvider,
    SmsKitProviderConfig, WebhookConfig,
};

/// Centralized MFA manager that coordinates all MFA operations
pub struct MfaManager {
    /// TOTP manager
    pub totp: TotpManager,

    /// SMS manager (deprecated - use sms_kit when available)
    #[deprecated(
        since = "1.1.0",
        note = "Use sms_kit field instead when smskit feature is enabled"
    )]
    pub sms: SmsManager,

    /// SMSKit manager (next-generation SMS support)
    #[cfg(feature = "smskit")]
    pub sms_kit: SmsKitManager,

    /// Email manager
    pub email: EmailManager,

    /// Backup codes manager
    pub backup_codes: BackupCodesManager,

    /// Active MFA challenges
    challenges: Arc<RwLock<HashMap<String, MfaChallenge>>>,

    /// Storage backend
    #[allow(dead_code)] // Used in future MFA cross-method operations
    storage: Arc<dyn AuthStorage>,
}

impl MfaManager {
    /// Create a new MFA manager
    pub fn new(storage: Arc<dyn AuthStorage>) -> Self {
        Self {
            totp: TotpManager::new(storage.clone()),
            #[allow(deprecated)]
            sms: SmsManager::new(storage.clone()),
            #[cfg(feature = "smskit")]
            sms_kit: SmsKitManager::new(storage.clone()),
            email: EmailManager::new(storage.clone()),
            backup_codes: BackupCodesManager::new(storage.clone()),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            storage,
        }
    }

    /// Create a new MFA manager with SMSKit configuration
    #[cfg(feature = "smskit")]
    pub fn new_with_smskit_config(
        storage: Arc<dyn AuthStorage>,
        smskit_config: SmsKitConfig,
    ) -> Result<Self> {
        Ok(Self {
            totp: TotpManager::new(storage.clone()),
            #[allow(deprecated)]
            sms: SmsManager::new(storage.clone()),
            sms_kit: SmsKitManager::new_with_config(storage.clone(), smskit_config)?,
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
                    #[cfg(feature = "smskit")]
                    {
                        self.create_smskit_challenge(user_id, &challenge_id).await?
                    }
                    #[cfg(not(feature = "smskit"))]
                    {
                        #[allow(deprecated)]
                        self.create_sms_challenge(user_id, &challenge_id).await?
                    }
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
                    mfa_type: crate::methods::MfaType::Totp, // Placeholder for cross-method challenge
                    user_id: user_id.to_string(),
                    expires_at: cross_method_challenge.expires_at,
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
                #[cfg(feature = "smskit")]
                {
                    self.sms_kit
                        .verify_code(&cross_challenge.user_id, response)
                        .await
                }
                #[cfg(not(feature = "smskit"))]
                {
                    #[allow(deprecated)]
                    self.sms
                        .verify_code(&cross_challenge.user_id, response)
                        .await
                }
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

        let success = verification_result.is_ok();

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
                Some(format!(
                    "Verification failed: {:?}",
                    verification_result.unwrap_err()
                ))
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
        #[cfg(feature = "smskit")]
        {
            if self
                .sms_kit
                .has_phone_number(user_id)
                .await
                .unwrap_or(false)
            {
                available_methods.push(MfaMethod::Sms);
            }
        }
        #[cfg(not(feature = "smskit"))]
        {
            #[allow(deprecated)]
            if self.sms.has_phone_number(user_id).await.unwrap_or(false) {
                available_methods.push(MfaMethod::Sms);
            }
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
                    MfaMethod::Sms => {
                        #[cfg(feature = "smskit")]
                        {
                            self.create_smskit_challenge(user_id, "fallback").await?
                        }
                        #[cfg(not(feature = "smskit"))]
                        {
                            #[allow(deprecated)]
                            self.create_sms_challenge(user_id, "fallback").await?
                        }
                    }
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

    #[cfg(feature = "smskit")]
    async fn create_smskit_challenge(
        &self,
        user_id: &str,
        challenge_prefix: &str,
    ) -> Result<MethodChallenge> {
        let code = self.sms_kit.send_verification_code(user_id).await?;
        Ok(MethodChallenge::Sms {
            challenge_id: format!("{}-sms", challenge_prefix),
            instructions: "Enter the verification code sent to your phone".to_string(),
            phone_hint: self
                .get_phone_hint(user_id)
                .await
                .unwrap_or_else(|_| "***-***-****".to_string()),
        })
    }

    #[allow(deprecated)]
    async fn create_sms_challenge(
        &self,
        user_id: &str,
        challenge_prefix: &str,
    ) -> Result<MethodChallenge> {
        let _code = self.sms.send_sms_code(user_id).await?;
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
        // Mock implementation - in production, get from storage
        Ok(format!("***-***-{}", &user_id[..4]))
    }

    async fn get_email_hint(&self, user_id: &str) -> Result<String> {
        // Mock implementation - in production, get from storage
        Ok(format!("{}****@****.com", &user_id[..2]))
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
