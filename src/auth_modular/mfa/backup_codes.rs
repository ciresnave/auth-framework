//! Backup codes manager for MFA
//!
//! One store holds a user's backup codes: `mfa_backup_codes:{user_id}`, a JSON list of
//! SHA-256 hex digests. Plaintext codes exist only in the value returned to the caller when
//! they are generated. Rows an earlier release wrote in plaintext under
//! `user:{user_id}:backup_codes` are hashed into the store and deleted the first time the
//! user's codes are read.

use crate::errors::Result;
use crate::security::secure_utils::constant_time_compare;
use crate::storage::AuthStorage;
use rand::Rng as _;
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use tracing::{debug, info};

/// Characters a code is drawn from: unambiguous letters and digits (no 0/O, 1/I).
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Characters in a code (about 60 bits: out of reach of an offline search of a leaked digest).
pub const CODE_LENGTH: usize = 12;

/// The storage key of a user's hashed backup codes.
pub(crate) fn store_key(user_id: &str) -> String {
    format!("mfa_backup_codes:{user_id}")
}

/// The row an earlier release kept in plaintext.
fn legacy_key(user_id: &str) -> String {
    format!("user:{user_id}:backup_codes")
}

/// The form a code is compared in: trimmed and upper-case (codes are issued upper-case).
fn normalize(code: &str) -> String {
    code.trim().to_ascii_uppercase()
}

/// The stored form of a code.
pub(crate) fn hash_code(code: &str) -> String {
    hex::encode(Sha256::digest(normalize(code).as_bytes()))
}

/// Draw `count` codes from the system CSPRNG, without modulo bias. Returns the plaintext codes.
pub(crate) fn generate_plaintext(count: usize) -> Vec<String> {
    // 256 is a multiple of 32, so `byte % 32` is uniform.
    debug_assert_eq!(256 % ALPHABET.len(), 0);
    (0..count)
        .map(|_| {
            let mut bytes = [0u8; CODE_LENGTH];
            rand::rng().fill_bytes(&mut bytes);
            bytes
                .iter()
                .map(|b| ALPHABET[usize::from(*b) % ALPHABET.len()] as char)
                .collect()
        })
        .collect()
}

/// Backup codes manager for handling backup codes
pub struct BackupCodesManager {
    storage: Arc<dyn AuthStorage>,
}

impl BackupCodesManager {
    /// Create a new backup codes manager
    pub fn new(storage: Arc<dyn AuthStorage>) -> Self {
        Self { storage }
    }

    /// The user's stored digests, after adopting any plaintext row an earlier release left.
    async fn load(&self, user_id: &str) -> Result<Vec<String>> {
        let key = store_key(user_id);
        let mut digests: Vec<String> = match self.storage.get_kv(&key).await? {
            Some(data) => serde_json::from_slice(&data).unwrap_or_default(),
            None => Vec::new(),
        };
        let legacy = legacy_key(user_id);
        if let Some(data) = self.storage.get_kv(&legacy).await? {
            let old: Vec<String> = serde_json::from_slice(&data).unwrap_or_default();
            digests.extend(old.iter().map(|code| hash_code(code)));
            self.save(user_id, &digests).await?;
            self.storage.delete_kv(&legacy).await?;
            info!("Hashed legacy backup codes for user '{}'", user_id);
        }
        Ok(digests)
    }

    async fn save(&self, user_id: &str, digests: &[String]) -> Result<()> {
        let json = serde_json::to_vec(digests)
            .map_err(|e| crate::errors::AuthError::internal(e.to_string()))?;
        self.storage
            .store_kv(&store_key(user_id), &json, None)
            .await
    }

    /// Generate backup codes for a user. Only the digests are stored; the plaintext codes are
    /// returned once. Replaces the user's existing codes.
    pub async fn generate_codes(&self, user_id: &str, count: usize) -> Result<Vec<String>> {
        debug!("Generating {} backup codes for user '{}'", count, user_id);
        let codes = generate_plaintext(count);
        let digests: Vec<String> = codes.iter().map(|c| hash_code(c)).collect();
        self.save(user_id, &digests).await?;
        self.storage.delete_kv(&legacy_key(user_id)).await?;
        info!("Generated {} backup codes for user '{}'", count, user_id);
        Ok(codes)
    }

    /// Verify backup code and mark it as used
    pub async fn verify_code(&self, user_id: &str, code: &str) -> Result<bool> {
        debug!("Verifying backup code for user '{}'", user_id);
        if normalize(code).is_empty() {
            return Ok(false);
        }
        let mut digests = self.load(user_id).await?;
        let provided = hash_code(code);

        // Compare against every digest so the time does not say which one matched.
        let mut found: Option<usize> = None;
        for (index, stored) in digests.iter().enumerate() {
            if constant_time_compare(stored.as_bytes(), provided.as_bytes()) {
                found = Some(index);
            }
        }
        match found {
            Some(index) => {
                digests.remove(index);
                self.save(user_id, &digests).await?;
                info!("Backup code verified and consumed for user '{}'", user_id);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Get remaining backup codes count
    pub async fn get_remaining_count(&self, user_id: &str) -> Result<usize> {
        debug!("Getting remaining backup codes for user '{}'", user_id);
        Ok(self.load(user_id).await?.len())
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

    /// Verify a backup code during the login MFA flow. Same store and comparison as
    /// [`verify_code`](Self::verify_code).
    pub async fn verify_login_code(&self, user_id: &str, code: &str) -> Result<bool> {
        self.verify_code(user_id, code).await
    }
}
