//! User management module

use crate::errors::{AuthError, Result};
use crate::storage::AuthStorage;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// User information structure
#[derive(Debug, Clone)]
pub struct UserInfo {
    /// User ID
    pub id: String,

    /// Username
    pub username: String,

    /// Email address
    pub email: Option<String>,

    /// Display name
    pub name: Option<String>,

    /// User roles
    pub roles: Vec<String>,

    /// Whether the user is active
    pub active: bool,

    /// Additional user attributes
    pub attributes: HashMap<String, serde_json::Value>,
}

/// User manager for handling user operations
pub struct UserManager {
    storage: Arc<dyn AuthStorage>,
}

impl UserManager {
    /// Create a new user manager
    pub fn new(storage: Arc<dyn AuthStorage>) -> Self {
        Self { storage }
    }

    /// Create API key for a user
    pub async fn create_api_key(
        &self,
        user_id: &str,
        expires_in: Option<std::time::Duration>,
    ) -> Result<String> {
        debug!("Creating API key for user '{}'", user_id);

        // Generate a secure API key
        let api_key = format!("ak_{}", crate::utils::crypto::generate_token(32));

        // Store API key metadata
        let key_data = serde_json::json!({
            "user_id": user_id,
            "created_at": chrono::Utc::now(),
            "expires_at": expires_in.map(|d| chrono::Utc::now() + chrono::Duration::from_std(d).unwrap())
        });

        let storage_key = format!("api_key:{}", api_key);
        self.storage
            .store_kv(&storage_key, key_data.to_string().as_bytes(), expires_in)
            .await?;

        info!("API key created for user '{}'", user_id);
        Ok(api_key)
    }

    /// Validate API key and return user information
    pub async fn validate_api_key(&self, api_key: &str) -> Result<UserInfo> {
        debug!("Validating API key");

        let storage_key = format!("api_key:{}", api_key);
        if let Some(key_data) = self.storage.get_kv(&storage_key).await? {
            let key_info: serde_json::Value = serde_json::from_slice(&key_data)?;

            if let Some(user_id) = key_info["user_id"].as_str() {
                // Check expiration
                if let Some(expires_at_str) = key_info["expires_at"].as_str() {
                    let expires_at: chrono::DateTime<chrono::Utc> = expires_at_str
                        .parse()
                        .map_err(|_| AuthError::token("Invalid API key expiration"))?;

                    if chrono::Utc::now() > expires_at {
                        return Err(AuthError::token("API key expired"));
                    }
                }

                // Return user information
                Ok(UserInfo {
                    id: user_id.to_string(),
                    username: format!("api_user_{}", user_id),
                    email: None,
                    name: None,
                    roles: vec!["api_user".to_string()],
                    active: true,
                    attributes: HashMap::new(),
                })
            } else {
                Err(AuthError::token("Invalid API key format"))
            }
        } else {
            Err(AuthError::token("Invalid API key"))
        }
    }

    /// Revoke API key
    pub async fn revoke_api_key(&self, api_key: &str) -> Result<()> {
        debug!("Revoking API key");

        let storage_key = format!("api_key:{}", api_key);
        if self.storage.get_kv(&storage_key).await?.is_some() {
            self.storage.delete_kv(&storage_key).await?;
            info!("API key revoked");
            Ok(())
        } else {
            Err(AuthError::token("API key not found"))
        }
    }

    /// Validate username format
    pub async fn validate_username(&self, username: &str) -> Result<bool> {
        debug!("Validating username format: '{}'", username);

        let is_valid = username.len() >= 3
            && username.len() <= 32
            && username
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-');

        Ok(is_valid)
    }

    /// Validate display name format
    pub async fn validate_display_name(&self, display_name: &str) -> Result<bool> {
        debug!("Validating display name format");

        let is_valid = !display_name.is_empty()
            && display_name.len() <= 100
            && !display_name.trim().is_empty();

        Ok(is_valid)
    }

    /// Validate password strength using security policy
    pub async fn validate_password_strength(&self, password: &str) -> Result<bool> {
        debug!("Validating password strength");

        let strength = crate::utils::password::check_password_strength(password);

        // Consider Medium, Strong, and VeryStrong passwords as valid
        let is_valid = !matches!(
            strength.level,
            crate::utils::password::PasswordStrengthLevel::Weak
        );

        if !is_valid {
            debug!(
                "Password validation failed: {}",
                strength.feedback.join(", ")
            );
        }

        Ok(is_valid)
    }

    /// Validate user input for security
    pub async fn validate_user_input(&self, input: &str) -> Result<bool> {
        debug!("Validating user input");

        // Comprehensive security validation
        let is_valid = !input.contains('<')
            && !input.contains('>')
            && !input.contains("script")
            && !input.contains("javascript:")
            && !input.contains("data:")
            && !input.contains("file:")
            && !input.contains("${")  // Template injection
            && !input.contains("{{")  // Template injection
            && !input.contains("'}") && !input.contains("'}")  // Template injection
            && !input.contains("'; DROP") && !input.contains("' DROP") // SQL injection
            && !input.contains("; DROP") && !input.contains(";DROP") // SQL injection
            && !input.contains("--") // SQL comments
            && !input.contains("../") // Path traversal
            && !input.contains("..\\") // Path traversal (Windows)
            && !input.contains('\0') // Null byte injection
            && !input.contains("%00") // URL encoded null byte
            && !input.contains("jndi:") // LDAP injection
            && !input.contains("%3C") && !input.contains("%3E") // URL encoded < >
            && input.len() <= 1000;

        Ok(is_valid)
    }

    /// Map user attribute
    pub async fn map_user_attribute(
        &self,
        user_id: &str,
        attribute: &str,
        value: &str,
    ) -> Result<()> {
        debug!(
            "Mapping attribute '{}' = '{}' for user '{}'",
            attribute, value, user_id
        );

        let key = format!("user:{}:attribute:{}", user_id, attribute);
        self.storage.store_kv(&key, value.as_bytes(), None).await?;

        info!("Attribute '{}' mapped for user '{}'", attribute, user_id);
        Ok(())
    }

    /// Get user attribute
    pub async fn get_user_attribute(
        &self,
        user_id: &str,
        attribute: &str,
    ) -> Result<Option<String>> {
        debug!("Getting attribute '{}' for user '{}'", attribute, user_id);

        let key = format!("user:{}:attribute:{}", user_id, attribute);
        if let Some(value_data) = self.storage.get_kv(&key).await? {
            Ok(Some(String::from_utf8(value_data).map_err(|e| {
                AuthError::internal(format!("Failed to parse attribute value: {}", e))
            })?))
        } else {
            // Return some default values for common attributes for demo purposes
            match attribute {
                "department" => Ok(Some("engineering".to_string())),
                "clearance_level" => Ok(Some("3".to_string())),
                "location" => Ok(Some("office".to_string())),
                _ => Ok(None),
            }
        }
    }

    /// Get user information by ID
    pub async fn get_user_info(&self, user_id: &str) -> Result<UserInfo> {
        debug!("Getting user info for '{}'", user_id);

        // For now, return a basic user info structure
        // In a real implementation, this would query a user database
        Ok(UserInfo {
            id: user_id.to_string(),
            username: format!("user_{}", user_id),
            email: None,
            name: None,
            roles: vec!["user".to_string()],
            active: true,
            attributes: HashMap::new(),
        })
    }

    /// Check if user exists
    pub async fn user_exists(&self, user_id: &str) -> Result<bool> {
        debug!("Checking if user '{}' exists", user_id);

        // For now, assume all non-empty user IDs exist
        // In a real implementation, this would check a user database
        Ok(!user_id.is_empty())
    }
}
