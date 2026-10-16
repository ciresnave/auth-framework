//! Backup codes manager for MFA

use crate::errors::Result;
use crate::storage::AuthStorage;
use std::sync::Arc;
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

            if let Some(index) = backup_codes.iter().position(|c| c == code) {
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
}
