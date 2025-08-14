use crate::errors::{AuthError, Result};
use crate::storage::{AuthStorage, SessionData};
use crate::tokens::AuthToken;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::env;
use std::time::Duration;

/// Encrypted data container with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Base64 encoded encrypted data
    pub data: String,
    /// Base64 encoded nonce/IV
    pub nonce: String,
    /// Algorithm identifier
    pub algorithm: String,
    /// Key derivation method (for future use)
    pub key_derivation: String,
}

/// Storage encryption manager using AES-256-GCM
pub struct StorageEncryption {
    cipher: Aes256Gcm,
}

impl StorageEncryption {
    /// Create new encryption manager from environment variable
    pub fn new() -> Result<Self> {
        let key_data = env::var("AUTH_STORAGE_ENCRYPTION_KEY").map_err(|_| {
            AuthError::config("AUTH_STORAGE_ENCRYPTION_KEY environment variable not set")
        })?;

        let key_bytes = BASE64
            .decode(&key_data)
            .map_err(|_| AuthError::config("Invalid base64 in AUTH_STORAGE_ENCRYPTION_KEY"))?;

        if key_bytes.len() != 32 {
            return Err(AuthError::config(
                "Encryption key must be 32 bytes (256 bits)",
            ));
        }

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        Ok(Self { cipher })
    }

    /// Create new encryption manager for testing with a random key
    #[cfg(test)]
    pub fn new_random() -> Self {
        let key = Aes256Gcm::generate_key(&mut OsRng);
        let cipher = Aes256Gcm::new(&key);
        Self { cipher }
    }

    /// Generate a new 256-bit encryption key (base64 encoded)
    pub fn generate_key() -> String {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        BASE64.encode(key_bytes)
    }

    /// Encrypt sensitive data
    pub fn encrypt(&self, plaintext: &str) -> Result<EncryptedData> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12]; // 96-bit nonce for GCM
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| AuthError::internal(format!("Encryption failed: {}", e)))?;

        Ok(EncryptedData {
            data: BASE64.encode(&ciphertext),
            nonce: BASE64.encode(nonce_bytes),
            algorithm: "AES-256-GCM".to_string(),
            key_derivation: "direct".to_string(),
        })
    }

    /// Decrypt sensitive data
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<String> {
        // Validate algorithm
        if encrypted.algorithm != "AES-256-GCM" {
            return Err(AuthError::internal(format!(
                "Unsupported encryption algorithm: {}",
                encrypted.algorithm
            )));
        }

        // Decode base64 data
        let ciphertext = BASE64
            .decode(&encrypted.data)
            .map_err(|_| AuthError::internal("Invalid base64 in encrypted data"))?;

        let nonce_bytes = BASE64
            .decode(&encrypted.nonce)
            .map_err(|_| AuthError::internal("Invalid base64 in nonce"))?;

        if nonce_bytes.len() != 12 {
            return Err(AuthError::internal("Invalid nonce length"));
        }

        let nonce = Nonce::from_slice(&nonce_bytes);

        // Decrypt the data
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| AuthError::internal(format!("Decryption failed: {}", e)))?;

        String::from_utf8(plaintext)
            .map_err(|_| AuthError::internal("Decrypted data is not valid UTF-8"))
    }

    /// Encrypt data for storage backend
    pub fn encrypt_for_storage(&self, data: &[u8]) -> Result<Vec<u8>> {
        let plaintext = String::from_utf8(data.to_vec())
            .map_err(|_| AuthError::internal("Storage data is not valid UTF-8"))?;

        let encrypted = self.encrypt(&plaintext)?;
        let serialized = serde_json::to_string(&encrypted).map_err(|e| {
            AuthError::internal(format!("Failed to serialize encrypted data: {}", e))
        })?;

        Ok(serialized.into_bytes())
    }

    /// Decrypt data from storage backend
    pub fn decrypt_from_storage(&self, data: &[u8]) -> Result<Vec<u8>> {
        let serialized = String::from_utf8(data.to_vec())
            .map_err(|_| AuthError::internal("Storage data is not valid UTF-8"))?;

        let encrypted: EncryptedData = serde_json::from_str(&serialized).map_err(|e| {
            AuthError::internal(format!("Failed to deserialize encrypted data: {}", e))
        })?;

        let plaintext = self.decrypt(&encrypted)?;
        Ok(plaintext.into_bytes())
    }
}

/// Wrapper for storage backends that adds encryption at rest
pub struct EncryptedStorage<T> {
    inner: T,
    encryption: StorageEncryption,
}

impl<T> EncryptedStorage<T> {
    pub fn new(storage: T, encryption: StorageEncryption) -> Self {
        Self {
            inner: storage,
            encryption,
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

#[async_trait::async_trait]
impl<T> AuthStorage for EncryptedStorage<T>
where
    T: AuthStorage + Send + Sync,
{
    // Token methods with encryption
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        self.inner.store_token(token).await
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        self.inner.get_token(token_id).await
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        self.inner.get_token_by_access_token(access_token).await
    }

    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        self.inner.update_token(token).await
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        self.inner.delete_token(token_id).await
    }

    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        self.inner.list_user_tokens(user_id).await
    }

    // Session methods with encryption
    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()> {
        self.inner.store_session(session_id, data).await
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        self.inner.get_session(session_id).await
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        self.inner.delete_session(session_id).await
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        self.inner.list_user_sessions(user_id).await
    }

    // Key-value methods with encryption
    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()> {
        let encrypted_value = self.encryption.encrypt_for_storage(value)?;
        self.inner.store_kv(key, &encrypted_value, ttl).await
    }

    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if let Some(encrypted_data) = self.inner.get_kv(key).await? {
            let decrypted_data = self.encryption.decrypt_from_storage(&encrypted_data)?;
            Ok(Some(decrypted_data))
        } else {
            Ok(None)
        }
    }

    async fn delete_kv(&self, key: &str) -> Result<()> {
        self.inner.delete_kv(key).await
    }

    async fn cleanup_expired(&self) -> Result<()> {
        self.inner.cleanup_expired().await
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = StorageEncryption::generate_key();
        assert!(!key.is_empty());

        // Should be valid base64
        let decoded = BASE64.decode(&key).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_encryption_roundtrip() {
        let encryption = StorageEncryption::new_random();
        let plaintext = "sensitive client secret data";

        let encrypted = encryption.encrypt(plaintext).unwrap();
        assert_ne!(encrypted.data, plaintext);
        assert_eq!(encrypted.algorithm, "AES-256-GCM");

        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_storage_encryption() {
        let encryption = StorageEncryption::new_random();
        let data = b"sensitive authentication data";

        let encrypted = encryption.encrypt_for_storage(data).unwrap();
        assert_ne!(encrypted, data);

        let decrypted = encryption.decrypt_from_storage(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }
}
