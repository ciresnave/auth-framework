//! Backup codes manager for MFA

use crate::errors::Result;
use crate::storage::AuthStorage;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tracing::{debug, info};

/// Backup codes manager for handling backup codes
pub struct BackupCodesManager {
    storage: Arc<dyn AuthStorage>,
}

impl BackupCodesManager {
    /// Create a new backup codes manager
    pub fn new(storage: Arc<dyn AuthStorage>) -> Self {
        Self { storage }
    }

    /// Generate backup codes for a user
    pub async fn generate_codes(&self, user_id: &str, count: usize) -> Result<Vec<String>> {
        debug!("Generating {} backup codes for user '{}'", count, user_id);

        let codes: Vec<String> = (0..count)
            .map(|_| format!("{:08}", rand::random::<u32>() % 100000000))
            .collect();

        // Store backup codes for the user
        let backup_key = format!("user:{}:backup_codes", user_id);
        let codes_json = serde_json::to_string(&codes).unwrap_or("[]".to_string());
        self.storage
            .store_kv(&backup_key, codes_json.as_bytes(), None)
            .await?;

        info!("Generated {} backup codes for user '{}'", count, user_id);
        Ok(codes)
    }

    /// Verify backup code and mark it as used
    pub async fn verify_code(&self, user_id: &str, code: &str) -> Result<bool> {
        debug!("Verifying backup code for user '{}'", user_id);

        // Validate code format
        if code.len() != 8 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Ok(false);
        }

        // Get user's backup codes
        let backup_key = format!("user:{}:backup_codes", user_id);
        if let Some(codes_data) = self.storage.get_kv(&backup_key).await? {
            let codes_str = std::str::from_utf8(&codes_data).unwrap_or("[]");
            let mut backup_codes: Vec<String> = serde_json::from_str(codes_str).unwrap_or_default();

            if let Some(index) = backup_codes
                .iter()
                .position(|c| bool::from(c.as_bytes().ct_eq(code.as_bytes())))
            {
                // Mark code as used by removing it
                backup_codes.remove(index);
                let updated_codes =
                    serde_json::to_string(&backup_codes).unwrap_or("[]".to_string());
                self.storage
                    .store_kv(&backup_key, updated_codes.as_bytes(), None)
                    .await?;

                info!("Backup code verified and consumed for user '{}'", user_id);
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    /// Get remaining backup codes count
    pub async fn get_remaining_count(&self, user_id: &str) -> Result<usize> {
        debug!("Getting remaining backup codes for user '{}'", user_id);

        let backup_key = format!("user:{}:backup_codes", user_id);
        if let Some(codes_data) = self.storage.get_kv(&backup_key).await? {
            let codes_str = std::str::from_utf8(&codes_data).unwrap_or("[]");
            let backup_codes: Vec<String> = serde_json::from_str(codes_str).unwrap_or_default();
            Ok(backup_codes.len())
        } else {
            Ok(0)
        }
    }

    /// Check if user has backup codes
    pub async fn has_backup_codes(&self, user_id: &str) -> Result<bool> {
        let count = self.get_remaining_count(user_id).await?;
        Ok(count > 0)
    }

    /// Regenerate backup codes (invalidating old ones)
    pub async fn regenerate_codes(&self, user_id: &str, count: usize) -> Result<Vec<String>> {
        info!("Regenerating backup codes for user '{}'", user_id);

        // This will overwrite existing codes
        self.generate_codes(user_id, count).await
    }

    /// Verify a backup code during the login MFA flow.
    /// Reads from `mfa_backup_codes:{user_id}` — the key written by the MFA setup flow.
    /// Codes are stored as SHA-256 hex strings; comparison is constant-time.
    pub async fn verify_login_code(&self, user_id: &str, code: &str) -> Result<bool> {
        use crate::security::secure_utils::constant_time_compare;
        use sha2::Digest as _;

        if code.trim().is_empty() {
            return Ok(false);
        }

        let backup_key = format!("mfa_backup_codes:{}", user_id);
        let codes: Vec<String> = match self.storage.get_kv(&backup_key).await? {
            Some(data) => serde_json::from_slice(&data).unwrap_or_default(),
            None => return Ok(false),
        };

        let provided_bytes = sha2::Sha256::digest(code.trim().as_bytes()).to_vec();

        let mut found_idx: Option<usize> = None;
        for (index, stored_hex) in codes.iter().enumerate() {
            let stored_bytes = hex::decode(stored_hex).unwrap_or_default();
            if stored_bytes.len() == provided_bytes.len()
                && constant_time_compare(&stored_bytes, &provided_bytes)
            {
                found_idx = Some(index);
            }
        }

        match found_idx {
            Some(index) => {
                let mut remaining = codes;
                remaining.remove(index);
                let updated = serde_json::to_vec(&remaining).unwrap_or_default();
                self.storage.store_kv(&backup_key, &updated, None).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}
