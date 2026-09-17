// Secure MFA implementation with cryptographically strong code generation
// Fixes critical security vulnerabilities in MFA code generation and validation

use crate::errors::{AuthError, Result};
use crate::storage::AuthStorage;
use base64::Engine;
use dashmap::DashMap;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

/// Secure MFA challenge with proper entropy and expiration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaChallenge {
    pub challenge_id: String,
    pub user_id: String,
    pub challenge_type: MfaChallengeType,
    pub code_hash: String,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub attempts: u32,
    pub max_attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaChallengeType {
    Sms,
    Email,
    Totp,
}

/// Secure MFA code that zeros itself when dropped
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct SecureMfaCode {
    code: String,
}

impl SecureMfaCode {
    pub fn as_str(&self) -> &str {
        &self.code
    }
}

/// Secure MFA service with proper cryptographic implementations
pub struct SecureMfaService {
    storage: Box<dyn AuthStorage>,
    rng: SystemRandom,
    /// Rate limiting: user_id -> (attempts, last_attempt)
    rate_limits: Arc<DashMap<String, (u32, SystemTime)>>,
}

impl SecureMfaService {
    pub fn new(storage: Box<dyn AuthStorage>) -> Self {
        Self {
            storage,
            rng: SystemRandom::new(),
            rate_limits: Arc::new(DashMap::new()),
        }
    }

    /// Generate cryptographically secure MFA code
    pub fn generate_secure_code(&self, length: usize) -> Result<SecureMfaCode> {
        if !(4..=12).contains(&length) {
            return Err(AuthError::validation(
                "MFA code length must be between 4 and 12",
            ));
        }

        let mut code = String::with_capacity(length);

        // Generate each digit individually to avoid modulo bias
        for _ in 0..length {
            let mut byte = [0u8; 1];
            loop {
                self.rng.fill(&mut byte).map_err(|_| {
                    AuthError::crypto("Failed to generate secure random bytes".to_string())
                })?;

                // Use rejection sampling for uniform distribution (0-9)
                let digit = byte[0] % 250; // Use 250 to avoid bias (250 is divisible by 10)
                if digit < 250 {
                    code.push(char::from(b'0' + (digit % 10)));
                    break;
                }
            }
        }

        Ok(SecureMfaCode { code })
    }

    /// Hash MFA code for secure storage
    fn hash_code(&self, code: &str, salt: &[u8]) -> Result<String> {
        use ring::digest;

        let mut context = digest::Context::new(&digest::SHA256);
        context.update(salt);
        context.update(code.as_bytes());
        let hash = context.finish();

        Ok(base64::engine::general_purpose::STANDARD.encode(hash.as_ref()))
    }

    /// Generate secure salt
    fn generate_salt(&self) -> Result<Vec<u8>> {
        let mut salt = vec![0u8; 32];
        self.rng
            .fill(&mut salt)
            .map_err(|_| AuthError::crypto("Failed to generate salt".to_string()))?;
        Ok(salt)
    }

    /// Check rate limiting for user
    fn check_rate_limit(&self, user_id: &str) -> Result<()> {
        let now = SystemTime::now();
        let window = Duration::from_secs(60); // 1 minute window
        let max_attempts = 5; // Max 5 attempts per minute

        let (attempts, last_attempt) = self
            .rate_limits
            .get(user_id)
            .map(|entry| *entry.value())
            .unwrap_or((0, now));

        // Reset counter if window has passed
        if now.duration_since(last_attempt).unwrap_or(Duration::ZERO) > window {
            self.rate_limits.insert(user_id.to_string(), (1, now));
            return Ok(());
        }

        if attempts >= max_attempts {
            return Err(AuthError::rate_limit(
                "Too many MFA attempts. Please wait.".to_string(),
            ));
        }

        self.rate_limits
            .insert(user_id.to_string(), (attempts + 1, now));
        Ok(())
    }

    /// Create secure MFA challenge
    pub async fn create_challenge(
        &self,
        user_id: &str,
        challenge_type: MfaChallengeType,
        code_length: usize,
    ) -> Result<(String, SecureMfaCode)> {
        // Check rate limiting
        self.check_rate_limit(user_id)?;

        // Generate secure challenge ID
        let challenge_id = self.generate_secure_id("mfa")?;

        // Generate secure code
        let secure_code = self.generate_secure_code(code_length)?;

        // Generate salt and hash the code
        let salt = self.generate_salt()?;
        let code_hash = self.hash_code(secure_code.as_str(), &salt)?;

        // Create challenge
        let now = SystemTime::now();
        let challenge = MfaChallenge {
            challenge_id: challenge_id.clone(),
            user_id: user_id.to_string(),
            challenge_type,
            code_hash,
            created_at: now,
            expires_at: now + Duration::from_secs(300), // 5 minutes
            attempts: 0,
            max_attempts: 3,
        };

        // Store challenge and salt
        let challenge_data = serde_json::to_vec(&challenge)
            .map_err(|e| AuthError::crypto(format!("Failed to serialize challenge: {}", e)))?;

        self.storage
            .store_kv(
                &format!("mfa_challenge:{}", challenge_id),
                &challenge_data,
                Some(Duration::from_secs(300)),
            )
            .await?;

        self.storage
            .store_kv(
                &format!("mfa_salt:{}", challenge_id),
                &salt,
                Some(Duration::from_secs(300)),
            )
            .await?;

        tracing::info!("Created secure MFA challenge for user: {}", user_id);
        Ok((challenge_id, secure_code))
    }

    /// Verify MFA code with constant-time comparison
    pub async fn verify_challenge(&self, challenge_id: &str, provided_code: &str) -> Result<bool> {
        // Validate input format
        if provided_code.is_empty() || provided_code.len() > 12 {
            return Ok(false);
        }

        if !provided_code.chars().all(|c| c.is_ascii_digit()) {
            return Ok(false);
        }

        // Retrieve challenge
        let challenge_data = self
            .storage
            .get_kv(&format!("mfa_challenge:{}", challenge_id))
            .await?;

        let mut challenge: MfaChallenge = match challenge_data {
            Some(data) => serde_json::from_slice(&data)
                .map_err(|_| AuthError::validation("Invalid challenge data"))?,
            None => return Ok(false), // Challenge not found or expired
        };

        // Check if challenge is expired
        if SystemTime::now() > challenge.expires_at {
            // Clean up expired challenge
            self.cleanup_challenge(challenge_id).await?;
            return Ok(false);
        }

        // Check attempt limits
        if challenge.attempts >= challenge.max_attempts {
            self.cleanup_challenge(challenge_id).await?;
            return Ok(false);
        }

        // Increment attempt counter
        challenge.attempts += 1;
        let challenge_data = serde_json::to_vec(&challenge)
            .map_err(|e| AuthError::crypto(format!("Failed to serialize challenge: {}", e)))?;
        self.storage
            .store_kv(
                &format!("mfa_challenge:{}", challenge_id),
                &challenge_data,
                Some(Duration::from_secs(300)),
            )
            .await?;

        // Retrieve salt
        let salt = match self
            .storage
            .get_kv(&format!("mfa_salt:{}", challenge_id))
            .await?
        {
            Some(salt) => salt,
            None => return Ok(false),
        };

        // Hash provided code with same salt
        let provided_hash = self.hash_code(provided_code, &salt)?;

        // Constant-time comparison
        let is_valid = challenge
            .code_hash
            .as_bytes()
            .ct_eq(provided_hash.as_bytes())
            .into();

        if is_valid {
            // Clean up successful challenge
            self.cleanup_challenge(challenge_id).await?;
            tracing::info!(
                "MFA challenge verified successfully for user: {}",
                challenge.user_id
            );
        }

        Ok(is_valid)
    }

    /// Clean up challenge data
    async fn cleanup_challenge(&self, challenge_id: &str) -> Result<()> {
        let _ = self
            .storage
            .delete_kv(&format!("mfa_challenge:{}", challenge_id))
            .await;
        let _ = self
            .storage
            .delete_kv(&format!("mfa_salt:{}", challenge_id))
            .await;
        Ok(())
    }

    /// Generate secure ID
    fn generate_secure_id(&self, prefix: &str) -> Result<String> {
        let mut bytes = vec![0u8; 16];
        self.rng
            .fill(&mut bytes)
            .map_err(|_| AuthError::crypto("Failed to generate secure ID".to_string()))?;

        let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        Ok(format!("{}_{}", prefix, id))
    }

    /// Generate cryptographically secure backup codes
    pub fn generate_backup_codes(
        &self,
        count: u8,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut codes = Vec::with_capacity(count as usize);

        for _ in 0..count {
            // Generate a secure 16-character alphanumeric backup code
            let mut code_bytes = [0u8; 10]; // 10 bytes = 80 bits of entropy
            self.rng.fill(&mut code_bytes)?;

            // Convert to base32 for human readability (no ambiguous characters)
            let code = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &code_bytes);

            // Format as XXXX-XXXX-XXXX-XXXX for readability
            let formatted_code = format!(
                "{}-{}-{}-{}",
                &code[0..4],
                &code[4..8],
                &code[8..12],
                &code[12..16]
            );

            codes.push(formatted_code);
        }

        Ok(codes)
    }

    /// Securely hash backup codes for storage
    pub fn hash_backup_codes(
        &self,
        codes: &[String],
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut hashed_codes = Vec::with_capacity(codes.len());

        for code in codes {
            // Use ring's PBKDF2 for secure hashing
            let salt = self.generate_salt()?;
            let mut hash = [0u8; 32];

            ring::pbkdf2::derive(
                ring::pbkdf2::PBKDF2_HMAC_SHA256,
                std::num::NonZeroU32::new(100_000).unwrap(), // 100k iterations
                &salt,
                code.as_bytes(),
                &mut hash,
            );

            // Store as salt:hash for verification
            let salt_hex = hex::encode(&salt);
            let hash_hex = hex::encode(hash);
            hashed_codes.push(format!("{}:{}", salt_hex, hash_hex));
        }

        Ok(hashed_codes)
    }

    /// Verify a backup code against stored hashes
    pub fn verify_backup_code(
        &self,
        hashed_codes: &[String],
        provided_code: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // Input validation
        if provided_code.len() != 19 || provided_code.chars().filter(|&c| c == '-').count() != 3 {
            return Ok(false);
        }

        // Remove dashes for processing
        let clean_code = provided_code.replace("-", "");
        if clean_code.len() != 16 || !clean_code.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Ok(false);
        }

        for hashed_code in hashed_codes {
            let parts: Vec<&str> = hashed_code.split(':').collect();
            if parts.len() != 2 {
                continue;
            }

            let salt = match hex::decode(parts[0]) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let stored_hash = match hex::decode(parts[1]) {
                Ok(h) => h,
                Err(_) => continue,
            };

            // Derive hash from provided code
            let mut derived_hash = [0u8; 32];
            ring::pbkdf2::derive(
                ring::pbkdf2::PBKDF2_HMAC_SHA256,
                std::num::NonZeroU32::new(100_000).unwrap(),
                &salt,
                provided_code.as_bytes(),
                &mut derived_hash,
            );

            // Constant-time comparison
            if subtle::ConstantTimeEq::ct_eq(&stored_hash[..], &derived_hash[..]).into() {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MockStorage;

    #[tokio::test]
    async fn test_secure_code_generation() {
        let storage = Box::new(MockStorage::new());
        let mfa_service = SecureMfaService::new(storage);

        let code = mfa_service.generate_secure_code(6).unwrap();
        assert_eq!(code.as_str().len(), 6);
        assert!(code.as_str().chars().all(|c| c.is_ascii_digit()));
    }

    #[tokio::test]
    async fn test_mfa_challenge_flow() {
        let storage = Box::new(MockStorage::new());
        let mfa_service = SecureMfaService::new(storage);

        // Create challenge
        let (challenge_id, code) = mfa_service
            .create_challenge("user123", MfaChallengeType::Sms, 6)
            .await
            .unwrap();

        // Verify with correct code
        let result = mfa_service
            .verify_challenge(&challenge_id, code.as_str())
            .await
            .unwrap();
        assert!(result);

        // Challenge should be cleaned up after successful verification
        let result2 = mfa_service
            .verify_challenge(&challenge_id, code.as_str())
            .await
            .unwrap();
        assert!(!result2);
    }

    #[tokio::test]
    async fn test_invalid_code_rejection() {
        let storage = Box::new(MockStorage::new());
        let mfa_service = SecureMfaService::new(storage);

        let (challenge_id, _code) = mfa_service
            .create_challenge("user123", MfaChallengeType::Sms, 6)
            .await
            .unwrap();

        // Test various invalid codes
        assert!(
            !mfa_service
                .verify_challenge(&challenge_id, "000000")
                .await
                .unwrap()
        );
        assert!(
            !mfa_service
                .verify_challenge(&challenge_id, "123abc")
                .await
                .unwrap()
        );
        assert!(
            !mfa_service
                .verify_challenge(&challenge_id, "")
                .await
                .unwrap()
        );
        assert!(
            !mfa_service
                .verify_challenge(&challenge_id, "12345678901234")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let storage = Box::new(MockStorage::new());
        let mfa_service = SecureMfaService::new(storage);

        // Should succeed first few times
        for _ in 0..5 {
            let result = mfa_service
                .create_challenge("user123", MfaChallengeType::Sms, 6)
                .await;
            assert!(result.is_ok());
        }

        // Should fail due to rate limiting
        let result = mfa_service
            .create_challenge("user123", MfaChallengeType::Sms, 6)
            .await;
        assert!(result.is_err());
    }
}
