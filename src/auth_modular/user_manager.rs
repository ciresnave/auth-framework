//! User management module

use crate::errors::{AuthError, Result};
use crate::storage::AuthStorage;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Canonical user information type shared with [`crate::auth::UserInfo`].
pub type UserInfo = crate::auth::UserInfo;

/// Result of a successful credential verification via [`UserManager::verify_login_credentials`].
///
/// # Example
/// ```rust,ignore
/// if let Some(result) = mgr.verify_login_credentials("alice", "pass").await? {
///     println!("user_id={}, mfa={}", result.user_id, result.mfa_enabled);
/// }
/// ```
pub struct CredentialCheckResult {
    /// The verified user's ID.
    pub user_id: String,
    /// Whether the user has MFA enabled.
    pub mfa_enabled: bool,
}

/// User manager for handling user operations.
///
/// # Example
/// ```rust,ignore
/// use auth_framework::auth_modular::UserManager;
/// let um = UserManager::new(storage.clone());
/// let uid = um.register_user("alice", "alice@example.com", "Str0ng!Pass").await?;
/// ```
pub struct UserManager {
    storage: Arc<dyn AuthStorage>,
}

impl UserManager {
    /// Create a new user manager.
    ///
    /// # Example
    /// ```rust,ignore
    /// let um = UserManager::new(storage.clone());
    /// ```
    pub fn new(storage: Arc<dyn AuthStorage>) -> Self {
        Self { storage }
    }

    /// Create API key for a user.
    ///
    /// # Example
    /// ```rust,ignore
    /// let key = um.create_api_key("user-1", Some(Duration::from_secs(86400))).await?;
    /// ```
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
            "expires_at": expires_in.map(|d| chrono::Utc::now() + chrono::Duration::from_std(d).unwrap_or(chrono::Duration::days(365 * 10)))
        });

        let storage_key = format!("api_key:{}", api_key);
        self.storage
            .store_kv(&storage_key, key_data.to_string().as_bytes(), expires_in)
            .await?;

        info!("API key created for user '{}'", user_id);
        Ok(api_key)
    }

    /// Validate API key and return user information.
    ///
    /// # Example
    /// ```rust,ignore
    /// let info = um.validate_api_key("ak_abc123").await?;
    /// println!("user: {}", info.username);
    /// ```
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
                    roles: vec!["api_user".to_string()].into(),
                    active: true,
                    email_verified: false,
                    attributes: crate::types::UserAttributes::empty(),
                })
            } else {
                Err(AuthError::token("Invalid API key format"))
            }
        } else {
            Err(AuthError::token("Invalid API key"))
        }
    }

    /// Revoke API key.
    ///
    /// # Example
    /// ```rust,ignore
    /// um.revoke_api_key("ak_abc123").await?;
    /// ```
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

    /// Validate username format.
    ///
    /// # Example
    /// ```rust,ignore
    /// assert!(um.validate_username("alice").await?);
    /// assert!(!um.validate_username("").await?);
    /// ```
    pub async fn validate_username(&self, username: &str) -> Result<bool> {
        debug!("Validating username format: '{}'", username);

        let is_valid = username.len() >= 3
            && username.len() <= 32
            && username
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-');

        Ok(is_valid)
    }

    /// Validate display name format.
    ///
    /// # Example
    /// ```rust,ignore
    /// assert!(um.validate_display_name("Alice B.").await?);
    /// ```
    pub async fn validate_display_name(&self, display_name: &str) -> Result<bool> {
        debug!("Validating display name format");

        let is_valid = !display_name.is_empty()
            && display_name.len() <= 100
            && !display_name.trim().is_empty();

        Ok(is_valid)
    }

    /// Validate password strength using security policy.
    ///
    /// Requires Strong or VeryStrong to protect production deployments.
    ///
    /// # Example
    /// ```rust,ignore
    /// assert!(um.validate_password_strength("C0mpl3x!Pa$$word").await?);
    /// assert!(!um.validate_password_strength("weak").await?);
    /// ```
    pub async fn validate_password_strength(&self, password: &str) -> Result<bool> {
        debug!("Validating password strength");
        let strength = crate::utils::password::check_password_strength(password);
        let is_valid = crate::utils::password::meets_production_strength(strength.level);
        if !is_valid {
            warn!(
                "Password validation failed - Actual: {:?}, Feedback: {}",
                strength.level,
                strength.feedback.join(", ")
            );
        }
        Ok(is_valid)
    }

    /// Validate user input for security.
    ///
    /// Combines a character whitelist with pattern checks for common injection
    /// vectors. Rejects HTML tags, null bytes, path traversal sequences,
    /// template injection markers, and dangerous URI schemes.
    ///
    /// # Example
    /// ```rust,ignore
    /// assert!(um.validate_user_input("hello world").await?);
    /// assert!(!um.validate_user_input("<script>alert(1)</script>").await?);
    /// ```
    pub async fn validate_user_input(&self, input: &str) -> Result<bool> {
        debug!("Validating user input");

        if input.is_empty() || input.len() > 1000 {
            return Ok(false);
        }

        // Character whitelist: reject control characters and angle brackets.
        if !input.chars().all(|c| {
            if c.is_control() {
                matches!(c, ' ' | '\t' | '\n' | '\r')
            } else {
                !matches!(c, '<' | '>')
            }
        }) {
            return Ok(false);
        }

        let lower = input.to_ascii_lowercase();
        if lower.contains("%3c") || lower.contains("%3e") || lower.contains("%00") {
            return Ok(false);
        }
        if lower.contains("javascript:")
            || lower.contains("data:")
            || lower.contains("file:")
            || lower.contains("jndi:")
        {
            return Ok(false);
        }
        if input.contains("${") || input.contains("{{") {
            return Ok(false);
        }
        if input.contains("../") || input.contains("..\\") {
            return Ok(false);
        }
        if input.contains('\0') {
            return Ok(false);
        }
        if lower.contains("; drop")
            || lower.contains(";drop")
            || lower.contains("' drop")
            || lower.contains("'; drop")
            || lower.contains("--")
        {
            return Ok(false);
        }

        Ok(true)
    }

    /// Get user information by ID.
    ///
    /// # Example
    /// ```rust,ignore
    /// let info = um.get_user_info("user-1").await?;
    /// println!("username: {}", info.username);
    /// ```
    pub async fn get_user_info(&self, user_id: &str) -> Result<UserInfo> {
        debug!("Getting user info for '{}'", user_id);

        let key = format!("user:{}", user_id);
        if let Some(data) = self.storage.get_kv(&key).await? {
            let user_data: serde_json::Value = serde_json::from_slice(&data)
                .map_err(|e| AuthError::internal(format!("Failed to parse user data: {e}")))?;

            Ok(UserInfo {
                id: user_data["user_id"].as_str().unwrap_or(user_id).to_string(),
                username: user_data["username"].as_str().unwrap_or("").to_string(),
                email: user_data["email"].as_str().map(String::from),
                name: user_data["name"].as_str().map(String::from),
                roles: user_data["roles"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(|| vec!["user".to_string()])
                    .into(),
                active: user_data["active"].as_bool().unwrap_or(true),
                email_verified: user_data["email_verified"].as_bool().unwrap_or(false),
                attributes: crate::types::UserAttributes::empty(),
            })
        } else {
            Err(AuthError::validation(format!("User '{user_id}' not found")))
        }
    }

    /// List users from the canonical user index.
    ///
    /// # Example
    /// ```rust,ignore
    /// let users = um.list_users(Some(10), Some(0), true).await?;
    /// for u in &users { println!("{}", u.username); }
    /// ```
    pub async fn list_users(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
        active_only: bool,
    ) -> Result<Vec<UserInfo>> {
        let bytes = self.storage.get_kv("users:index").await?;
        let user_ids: Vec<String> = match bytes {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| AuthError::internal(format!("Failed to parse user index: {e}")))?,
            None => return Ok(Vec::new()),
        };

        let skip = offset.unwrap_or(0);
        let take = limit.unwrap_or(usize::MAX);
        let mut users = Vec::new();

        for user_id in user_ids.into_iter().skip(skip) {
            let user = self.get_user_info(&user_id).await?;
            if active_only && !user.active {
                continue;
            }
            users.push(user);
            if users.len() >= take {
                break;
            }
        }

        Ok(users)
    }

    /// Check if user exists.
    ///
    /// # Example
    /// ```rust,ignore
    /// if um.user_exists("user-1").await? {
    ///     println!("user found");
    /// }
    /// ```
    pub async fn user_exists(&self, user_id: &str) -> Result<bool> {
        debug!("Checking if user '{}' exists", user_id);

        if user_id.is_empty() {
            return Ok(false);
        }

        let key = format!("user:{}", user_id);
        Ok(self.storage.get_kv(&key).await?.is_some())
    }

    // ────────────────────────────────────────────────────────────────────────
    // Full user lifecycle management (migrated from auth.rs::AuthFramework)
    // ────────────────────────────────────────────────────────────────────────

    /// Register a new user, creating all required storage records.
    ///
    /// # Example
    /// ```rust,ignore
    /// let uid = um.register_user("alice", "alice@example.com", "Str0ng!Pass").await?;
    /// println!("registered user: {}", uid);
    /// ```
    pub async fn register_user(
        &self,
        username: &str,
        email: &str,
        password: &str,
    ) -> Result<String> {
        debug!("Registering new user: {}", username);

        let username_key = format!("user:username:{}", username);
        if self.storage.get_kv(&username_key).await?.is_some() {
            return Err(AuthError::validation("Username already exists".to_string()));
        }

        let email_key = format!("user:email:{}", email);
        if self.storage.get_kv(&email_key).await?.is_some() {
            return Err(AuthError::validation("Email already exists".to_string()));
        }

        let user_id = crate::utils::string::generate_id(Some("user"));

        let password_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)
            .map_err(|e| AuthError::crypto(format!("Failed to hash password: {}", e)))?;

        let user_data = serde_json::json!({
            "user_id": user_id,
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "roles": ["user"],
            "active": true,
            "email_verified": false,
            "created_at": chrono::Utc::now().to_rfc3339(),
        });

        let user_key = format!("user:{}", user_id);
        self.storage
            .store_kv(&user_key, user_data.to_string().as_bytes(), None)
            .await?;

        self.storage
            .store_kv(&username_key, user_id.as_bytes(), None)
            .await?;
        self.storage
            .store_kv(&email_key, user_id.as_bytes(), None)
            .await?;

        // Maintain global user index for admin listing.
        let index_key = "users:index";
        let mut ids: Vec<String> = match self.storage.get_kv(index_key).await? {
            Some(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            None => vec![],
        };
        ids.push(user_id.clone());
        if let Ok(idx_json) = serde_json::to_vec(&ids)
            && let Err(e) = self.storage.store_kv(index_key, &idx_json, None).await
        {
            warn!("Failed to update user index during registration: {}", e);
        }

        // Store Argon2 credentials record for authenticate_password_builtin.
        let creds_key = format!("user:credentials:{}", username);
        let creds_hash = match crate::utils::password::hash_password_argon2id(password) {
            Ok(h) => h,
            Err(e) => {
                warn!("Failed to hash credentials for user '{}': {}", username, e);
                return Ok(user_id);
            }
        };
        let creds_data = serde_json::json!({
            "user_id": user_id,
            "username": username,
            "email": email,
            "password_hash": creds_hash,
            "created_at": chrono::Utc::now().to_rfc3339(),
        });
        if let Err(e) = self
            .storage
            .store_kv(&creds_key, creds_data.to_string().as_bytes(), None)
            .await
        {
            warn!("Failed to store credentials for user '{}': {}", username, e);
        }

        info!("User '{}' registered successfully", username);
        Ok(user_id)
    }

    /// Delete a user and all associated storage records.
    ///
    /// # Example
    /// ```rust,ignore
    /// um.delete_user("alice").await?;
    /// ```
    pub async fn delete_user(&self, username: &str) -> Result<()> {
        debug!("Deleting user: {}", username);

        let username_key = format!("user:username:{}", username);
        let user_id_data = self
            .storage
            .get_kv(&username_key)
            .await?
            .ok_or_else(|| AuthError::validation("User not found".to_string()))?;

        let user_id = String::from_utf8(user_id_data)
            .map_err(|e| AuthError::crypto(format!("Invalid user ID format: {}", e)))?;

        // Remove email reverse-lookup.
        let user_key = format!("user:{}", user_id);
        if let Some(user_data_bytes) = self.storage.get_kv(&user_key).await?
            && let Ok(user_json_str) = String::from_utf8(user_data_bytes)
            && let Ok(user_data) = serde_json::from_str::<serde_json::Value>(&user_json_str)
            && let Some(email) = user_data.get("email").and_then(|v| v.as_str())
            && let Err(e) = self
                .storage
                .delete_kv(&format!("user:email:{}", email))
                .await
        {
            warn!(
                "Failed to delete email index for user '{}': {}",
                username, e
            );
        }

        // Remove from global index.
        let index_key = "users:index";
        if let Ok(Some(bytes)) = self.storage.get_kv(index_key).await {
            let mut ids: Vec<String> = serde_json::from_slice(&bytes).unwrap_or_default();
            ids.retain(|id| id != &user_id);
            if let Ok(idx_json) = serde_json::to_vec(&ids)
                && let Err(e) = self.storage.store_kv(index_key, &idx_json, None).await
            {
                warn!(
                    "Failed to update user index during deletion of '{}': {}",
                    username, e
                );
            }
        }

        if let Err(e) = self.storage.delete_kv(&user_key).await {
            warn!("Failed to delete user record for '{}': {}", username, e);
        }
        if let Err(e) = self.storage.delete_kv(&username_key).await {
            warn!("Failed to delete username index for '{}': {}", username, e);
        }
        if let Err(e) = self
            .storage
            .delete_kv(&format!("user:credentials:{}", username))
            .await
        {
            warn!("Failed to delete credentials for '{}': {}", username, e);
        }
        if let Err(e) = self
            .storage
            .delete_kv(&format!("user:{}:totp_secret", user_id))
            .await
        {
            warn!("Failed to delete TOTP secret for '{}': {}", username, e);
        }
        if let Err(e) = self
            .storage
            .delete_kv(&format!("user:{}:backup_codes", user_id))
            .await
        {
            warn!("Failed to delete backup codes for '{}': {}", username, e);
        }

        info!("User '{}' deleted successfully", username);
        Ok(())
    }

    /// Delete a user by canonical user ID.
    ///
    /// # Example
    /// ```rust,ignore
    /// um.delete_user_by_id("user-1").await?;
    /// ```
    pub async fn delete_user_by_id(&self, user_id: &str) -> Result<()> {
        let username = self.get_username_by_id(user_id).await?;
        self.delete_user(&username).await
    }

    /// Update the roles assigned to a user.
    ///
    /// # Example
    /// ```rust,ignore
    /// um.update_user_roles("user-1", &["admin".into(), "editor".into()]).await?;
    /// ```
    pub async fn update_user_roles(&self, user_id: &str, roles: &[String]) -> Result<()> {
        let user_key = format!("user:{}", user_id);
        let bytes = self
            .storage
            .get_kv(&user_key)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        let mut user_data: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| AuthError::crypto(format!("{e}")))?;
        user_data["roles"] = serde_json::json!(roles);
        user_data["updated_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
        self.storage
            .store_kv(&user_key, user_data.to_string().as_bytes(), None)
            .await?;
        info!("Roles updated for user '{}'", user_id);
        Ok(())
    }

    /// Enable or disable a user account.
    ///
    /// # Example
    /// ```rust,ignore
    /// um.set_user_active("user-1", false).await?; // disable
    /// ```
    pub async fn set_user_active(&self, user_id: &str, active: bool) -> Result<()> {
        let user_key = format!("user:{}", user_id);
        let bytes = self
            .storage
            .get_kv(&user_key)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        let mut user_data: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| AuthError::crypto(format!("{e}")))?;
        user_data["active"] = serde_json::json!(active);
        user_data["updated_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
        self.storage
            .store_kv(&user_key, user_data.to_string().as_bytes(), None)
            .await?;
        info!("User '{}' active status set to {}", user_id, active);
        Ok(())
    }

    /// Update the email address stored on a user.
    ///
    /// # Example
    /// ```rust,ignore
    /// um.update_user_email("user-1", "new@example.com").await?;
    /// ```
    pub async fn update_user_email(&self, user_id: &str, email: &str) -> Result<()> {
        let user_key = format!("user:{}", user_id);
        let bytes = self
            .storage
            .get_kv(&user_key)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        let mut user_data: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| AuthError::crypto(format!("{e}")))?;

        let new_email_key = format!("user:email:{}", email);
        if let Some(existing_user_id) = self.storage.get_kv(&new_email_key).await? {
            let existing_user_id = String::from_utf8(existing_user_id)
                .map_err(|e| AuthError::crypto(format!("Invalid user ID format: {e}")))?;
            if existing_user_id != user_id {
                return Err(AuthError::validation("Email already exists".to_string()));
            }
        }

        if let Some(old_email) = user_data.get("email").and_then(|value| value.as_str())
            && old_email != email
        {
            self.storage
                .delete_kv(&format!("user:email:{}", old_email))
                .await?;
        }

        user_data["email"] = serde_json::json!(email);
        user_data["updated_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());

        self.storage
            .store_kv(&user_key, user_data.to_string().as_bytes(), None)
            .await?;
        self.storage
            .store_kv(&new_email_key, user_id.as_bytes(), None)
            .await?;

        Ok(())
    }

    /// Verify a user's password against the stored bcrypt hash.
    ///
    /// # Example
    /// ```rust,ignore
    /// let ok = um.verify_user_password("user-1", "secret").await?;
    /// assert!(ok);
    /// ```
    pub async fn verify_user_password(&self, user_id: &str, password: &str) -> Result<bool> {
        let user_key = format!("user:{}", user_id);
        let bytes = self
            .storage
            .get_kv(&user_key)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        let user_data: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| AuthError::crypto(format!("{e}")))?;
        let hash = user_data["password_hash"]
            .as_str()
            .ok_or_else(|| AuthError::internal("User has no password hash".to_string()))?;
        bcrypt::verify(password, hash)
            .map_err(|e| AuthError::crypto(format!("Password verification failed: {}", e)))
    }

    /// Resolve a user_id to its username.
    ///
    /// # Example
    /// ```rust,ignore
    /// let name = um.get_username_by_id("user-1").await?;
    /// ```
    pub async fn get_username_by_id(&self, user_id: &str) -> Result<String> {
        let user_key = format!("user:{}", user_id);
        let bytes = self
            .storage
            .get_kv(&user_key)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        let user_data: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| AuthError::crypto(format!("{e}")))?;
        user_data["username"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| AuthError::internal("User has no username field".to_string()))
    }

    /// Check whether a username is already taken.
    ///
    /// # Example
    /// ```rust,ignore
    /// if um.username_exists("alice").await? {
    ///     println!("taken");
    /// }
    /// ```
    pub async fn username_exists(&self, username: &str) -> Result<bool> {
        Ok(self
            .storage
            .get_kv(&format!("user:username:{}", username))
            .await?
            .is_some())
    }

    /// Check whether an email address is already registered.
    ///
    /// # Example
    /// ```rust,ignore
    /// if um.email_exists("a@b.com").await? {
    ///     println!("already registered");
    /// }
    /// ```
    pub async fn email_exists(&self, email: &str) -> Result<bool> {
        Ok(self
            .storage
            .get_kv(&format!("user:email:{}", email))
            .await?
            .is_some())
    }

    /// Fetch raw user data by username.
    ///
    /// # Example
    /// ```rust,ignore
    /// let data = um.get_user_by_username("alice").await?;
    /// println!("email: {:?}", data.get("email"));
    /// ```
    pub async fn get_user_by_username(
        &self,
        username: &str,
    ) -> Result<HashMap<String, serde_json::Value>> {
        let username_key = format!("user:username:{}", username);
        let user_id_data = self
            .storage
            .get_kv(&username_key)
            .await?
            .ok_or_else(|| AuthError::validation("User not found".to_string()))?;
        let user_id = String::from_utf8(user_id_data)
            .map_err(|e| AuthError::crypto(format!("Invalid user ID format: {}", e)))?;
        let user_key = format!("user:{}", user_id);
        let user_data = self
            .storage
            .get_kv(&user_key)
            .await?
            .ok_or_else(|| AuthError::validation("User not found".to_string()))?;
        let user_obj: serde_json::Value = serde_json::from_slice(&user_data)
            .map_err(|e| AuthError::crypto(format!("Failed to parse user data: {}", e)))?;
        if let Some(obj) = user_obj.as_object() {
            Ok(obj
                .into_iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        } else {
            Err(AuthError::validation(
                "Invalid user data structure".to_string(),
            ))
        }
    }

    /// Get a sanitised user profile (no password hash) for display/API.
    ///
    /// # Example
    /// ```rust,ignore
    /// let profile = um.get_user_profile("user-1").await?;
    /// println!("email: {:?}", profile.email);
    /// ```
    pub async fn get_user_profile(
        &self,
        user_id: &str,
    ) -> Result<crate::providers::ProviderProfile> {
        let user_key = format!("user:{}", user_id);
        if let Ok(Some(bytes)) = self.storage.get_kv(&user_key).await
            && let Ok(user_data) = serde_json::from_slice::<serde_json::Value>(&bytes)
        {
            let username = user_data["username"].as_str().map(|s| s.to_string());
            let email = user_data["email"].as_str().map(|s| s.to_string());
            let name = user_data["name"].as_str().map(|s| s.to_string());
            let email_verified = user_data["email_verified"].as_bool();

            let mut additional_data = std::collections::HashMap::new();
            if let Some(obj) = user_data.as_object() {
                for (k, v) in obj {
                    match k.as_str() {
                        "user_id" | "username" | "email" | "name" | "email_verified"
                        | "password_hash" | "created_at" | "updated_at" => {}
                        _ => {
                            additional_data.insert(k.clone(), v.clone());
                        }
                    }
                }
            }

            return Ok(crate::providers::ProviderProfile {
                id: Some(user_id.to_string()),
                provider: Some("local".to_string()),
                username,
                name,
                email,
                email_verified,
                picture: None,
                locale: None,
                additional_data,
            });
        }
        Err(AuthError::UserNotFound)
    }

    /// Get a user's roles/scopes from storage, returning `["user"]` as fallback.
    ///
    /// # Example
    /// ```rust,ignore
    /// let roles = um.get_user_roles("user-1").await?;
    /// assert!(roles.contains(&"user".to_string()));
    /// ```
    pub async fn get_user_roles(&self, user_id: &str) -> Result<Vec<String>> {
        let user_key = format!("user:{}", user_id);
        if let Ok(Some(data)) = self.storage.get_kv(&user_key).await
            && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&data)
            && let Some(arr) = v.get("roles").and_then(|r| r.as_array())
        {
            let roles: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            if !roles.is_empty() {
                return Ok(roles);
            }
        }
        Ok(vec!["user".to_string()])
    }

    /// Verify username/password credentials in a timing-safe manner.
    ///
    /// Returns `Ok(None)` when the credentials are invalid — a dummy Argon2
    /// verification is always executed when the username is not found, so
    /// callers cannot distinguish missing users from wrong passwords via timing.
    /// Returns `Ok(Some(result))` on success.
    ///
    /// # Example
    /// ```rust,ignore
    /// match um.verify_login_credentials("alice", "password123").await? {
    ///     Some(cred) => println!("user_id={}, mfa={}", cred.user_id, cred.mfa_enabled),
    ///     None => println!("invalid credentials"),
    /// }
    /// ```
    pub async fn verify_login_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<CredentialCheckResult>> {
        use crate::utils::password::verify_password_argon2id;

        if username.is_empty() || password.is_empty() {
            return Ok(None);
        }

        let user_key = format!("user:credentials:{username}");
        let stored_bytes = match self.storage.get_kv(&user_key).await? {
            Some(bytes) => bytes,
            None => {
                // Constant-time: always do real work even for missing users.
                let _ = verify_password_argon2id(
                    password,
                    "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHRmb3J0aW1pbmc$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                );
                return Ok(None);
            }
        };

        let user_data_str = String::from_utf8(stored_bytes)
            .map_err(|e| AuthError::internal(format!("Failed to parse user data: {e}")))?;
        let user_data: serde_json::Value = serde_json::from_str(&user_data_str)
            .map_err(|e| AuthError::internal(format!("Failed to parse user JSON: {e}")))?;

        let password_hash = user_data["password_hash"].as_str().ok_or_else(|| {
            AuthError::internal("Missing password hash in user record".to_string())
        })?;

        if !verify_password_argon2id(password, password_hash).unwrap_or(false) {
            return Ok(None);
        }

        let user_id = user_data["user_id"]
            .as_str()
            .ok_or_else(|| AuthError::internal("Missing user_id in user record".to_string()))?
            .to_string();

        // Check whether the account has been deactivated.
        let canonical_key = format!("user:{}", user_id);
        if let Ok(Some(canonical_bytes)) = self.storage.get_kv(&canonical_key).await
            && let Ok(canonical_str) = String::from_utf8(canonical_bytes)
            && let Ok(canonical_data) = serde_json::from_str::<serde_json::Value>(&canonical_str)
            && !canonical_data["active"].as_bool().unwrap_or(true)
        {
            return Ok(None);
        }

        let mfa_enabled = matches!(
            self.storage
                .get_kv(&format!("mfa_enabled:{}", user_id))
                .await,
            Ok(Some(_))
        );

        Ok(Some(CredentialCheckResult {
            user_id,
            mfa_enabled,
        }))
    }

    /// Update a user's password by username.
    ///
    /// # Example
    /// ```rust,ignore
    /// um.update_user_password("alice", "N3wStr0ng!Pass").await?;
    /// ```
    pub async fn update_user_password(&self, username: &str, new_password: &str) -> Result<()> {
        debug!("Updating password for user: {}", username);

        crate::utils::validation::validate_password(new_password)
            .map_err(|e| AuthError::validation(format!("Password validation failed: {e}")))?;

        let username_key = format!("user:username:{}", username);
        let user_id_data = self
            .storage
            .get_kv(&username_key)
            .await?
            .ok_or_else(|| AuthError::validation("User not found".to_string()))?;
        let user_id = String::from_utf8(user_id_data)
            .map_err(|e| AuthError::crypto(format!("Invalid user ID format: {}", e)))?;

        let user_key = format!("user:{}", user_id);
        let user_bytes = self
            .storage
            .get_kv(&user_key)
            .await?
            .ok_or_else(|| AuthError::validation("User not found".to_string()))?;
        let mut user_data: serde_json::Value = serde_json::from_slice(&user_bytes)
            .map_err(|e| AuthError::crypto(format!("Failed to parse user data: {}", e)))?;

        let password_hash = bcrypt::hash(new_password, bcrypt::DEFAULT_COST)
            .map_err(|e| AuthError::crypto(format!("Failed to hash password: {}", e)))?;
        user_data["password_hash"] = serde_json::json!(password_hash);
        user_data["updated_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
        self.storage
            .store_kv(&user_key, user_data.to_string().as_bytes(), None)
            .await?;

        // Update Argon2 credentials record used by the login endpoint.
        let creds_key = format!("user:credentials:{}", username);
        let creds_hash = crate::utils::password::hash_password_argon2id(new_password)
            .map_err(|e| AuthError::crypto(format!("Failed to hash login credentials: {e}")))?;
        let creds_bytes =
            self.storage.get_kv(&creds_key).await?.ok_or_else(|| {
                AuthError::internal("Login credentials record not found".to_string())
            })?;
        let mut creds: serde_json::Value = serde_json::from_slice(&creds_bytes)
            .map_err(|e| AuthError::internal(format!("Failed to parse credentials record: {e}")))?;
        creds["password_hash"] = serde_json::json!(creds_hash);
        creds["updated_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
        self.storage
            .store_kv(&creds_key, creds.to_string().as_bytes(), None)
            .await?;

        info!("Password updated for user: {}", username);
        Ok(())
    }

    /// Update a user password by canonical user ID.
    ///
    /// # Example
    /// ```rust,ignore
    /// um.update_user_password_by_id("user-1", "N3wStr0ng!Pass").await?;
    /// ```
    pub async fn update_user_password_by_id(
        &self,
        user_id: &str,
        new_password: &str,
    ) -> Result<()> {
        let username = self.get_username_by_id(user_id).await?;
        self.update_user_password(&username, new_password).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    fn make_manager() -> UserManager {
        UserManager::new(Arc::new(MemoryStorage::new()))
    }

    // ── register_user ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_register_user_success() {
        let mgr = make_manager();
        let id = mgr
            .register_user("alice", "alice@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        assert!(id.starts_with("user"));
    }

    #[tokio::test]
    async fn test_register_user_duplicate_username() {
        let mgr = make_manager();
        mgr.register_user("bob", "bob@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        let err = mgr
            .register_user("bob", "bob2@example.com", "StrongP@ss1!")
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_register_user_duplicate_email() {
        let mgr = make_manager();
        mgr.register_user("carol", "dup@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        let err = mgr
            .register_user("carol2", "dup@example.com", "StrongP@ss1!")
            .await;
        assert!(err.is_err());
    }

    // ── get_user_info ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_user_info_success() {
        let mgr = make_manager();
        let id = mgr
            .register_user("dave", "dave@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        let info = mgr.get_user_info(&id).await.unwrap();
        assert_eq!(info.username, "dave");
        assert!(info.active);
    }

    #[tokio::test]
    async fn test_get_user_info_not_found() {
        let mgr = make_manager();
        assert!(mgr.get_user_info("nonexistent").await.is_err());
    }

    // ── user_exists ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_user_exists_true() {
        let mgr = make_manager();
        let id = mgr
            .register_user("eve", "eve@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        assert!(mgr.user_exists(&id).await.unwrap());
    }

    #[tokio::test]
    async fn test_user_exists_false() {
        let mgr = make_manager();
        assert!(!mgr.user_exists("nobody").await.unwrap());
    }

    #[tokio::test]
    async fn test_user_exists_empty_id() {
        let mgr = make_manager();
        assert!(!mgr.user_exists("").await.unwrap());
    }

    // ── delete_user ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_delete_user_success() {
        let mgr = make_manager();
        let id = mgr
            .register_user("frank", "frank@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        mgr.delete_user("frank").await.unwrap();
        assert!(!mgr.user_exists(&id).await.unwrap());
    }

    #[tokio::test]
    async fn test_delete_user_not_found() {
        let mgr = make_manager();
        assert!(mgr.delete_user("ghost").await.is_err());
    }

    #[tokio::test]
    async fn test_delete_user_by_id() {
        let mgr = make_manager();
        let id = mgr
            .register_user("gina", "gina@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        mgr.delete_user_by_id(&id).await.unwrap();
        assert!(!mgr.user_exists(&id).await.unwrap());
    }

    // ── list_users ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_users_empty() {
        let mgr = make_manager();
        let users = mgr.list_users(None, None, false).await.unwrap();
        assert!(users.is_empty());
    }

    #[tokio::test]
    async fn test_list_users_with_limit_and_offset() {
        let mgr = make_manager();
        mgr.register_user("u1", "u1@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        mgr.register_user("u2", "u2@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        mgr.register_user("u3", "u3@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        let page = mgr.list_users(Some(1), Some(1), false).await.unwrap();
        assert_eq!(page.len(), 1);
    }

    // ── verify_user_password ────────────────────────────────────────────

    #[tokio::test]
    async fn test_verify_password_correct() {
        let mgr = make_manager();
        let id = mgr
            .register_user("hank", "hank@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        assert!(mgr.verify_user_password(&id, "StrongP@ss1!").await.unwrap());
    }

    #[tokio::test]
    async fn test_verify_password_incorrect() {
        let mgr = make_manager();
        let id = mgr
            .register_user("ivan", "ivan@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        assert!(!mgr.verify_user_password(&id, "wrong").await.unwrap());
    }

    #[tokio::test]
    async fn test_verify_password_user_not_found() {
        let mgr = make_manager();
        assert!(mgr.verify_user_password("ghost", "x").await.is_err());
    }

    // ── update_user_password ────────────────────────────────────────────

    #[tokio::test]
    async fn test_update_password() {
        let mgr = make_manager();
        let id = mgr
            .register_user("jack", "jack@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        mgr.update_user_password("jack", "NewStr0ng!Pass")
            .await
            .unwrap();
        assert!(
            mgr.verify_user_password(&id, "NewStr0ng!Pass")
                .await
                .unwrap()
        );
        assert!(!mgr.verify_user_password(&id, "StrongP@ss1!").await.unwrap());
    }

    #[tokio::test]
    async fn test_update_password_user_not_found() {
        let mgr = make_manager();
        assert!(
            mgr.update_user_password("ghost", "NewStr0ng!Pass")
                .await
                .is_err()
        );
    }

    // ── update_user_roles ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_update_user_roles() {
        let mgr = make_manager();
        let id = mgr
            .register_user("kate", "kate@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        mgr.update_user_roles(&id, &["admin".into(), "user".into()])
            .await
            .unwrap();
        let info = mgr.get_user_info(&id).await.unwrap();
        assert!(info.roles.contains("admin"));
    }

    #[tokio::test]
    async fn test_update_user_roles_not_found() {
        let mgr = make_manager();
        assert!(
            mgr.update_user_roles("ghost", &["admin".into()])
                .await
                .is_err()
        );
    }

    // ── set_user_active ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_set_user_active_disable() {
        let mgr = make_manager();
        let id = mgr
            .register_user("leon", "leon@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        mgr.set_user_active(&id, false).await.unwrap();
        let info = mgr.get_user_info(&id).await.unwrap();
        assert!(!info.active);
    }

    #[tokio::test]
    async fn test_set_user_active_not_found() {
        let mgr = make_manager();
        assert!(mgr.set_user_active("ghost", false).await.is_err());
    }

    // ── update_user_email ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_update_user_email() {
        let mgr = make_manager();
        let id = mgr
            .register_user("mary", "mary@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        mgr.update_user_email(&id, "mary_new@example.com")
            .await
            .unwrap();
        let info = mgr.get_user_info(&id).await.unwrap();
        assert_eq!(info.email.as_deref(), Some("mary_new@example.com"));
    }

    #[tokio::test]
    async fn test_update_user_email_already_taken() {
        let mgr = make_manager();
        mgr.register_user("n1", "taken@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        let id2 = mgr
            .register_user("n2", "n2@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        assert!(
            mgr.update_user_email(&id2, "taken@example.com")
                .await
                .is_err()
        );
    }

    // ── API key operations ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_and_validate_api_key() {
        let mgr = make_manager();
        let id = mgr
            .register_user("oscar", "oscar@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        let key = mgr.create_api_key(&id, None).await.unwrap();
        assert!(key.starts_with("ak_"));
        let info = mgr.validate_api_key(&key).await.unwrap();
        assert_eq!(info.id, id);
    }

    #[tokio::test]
    async fn test_validate_api_key_invalid() {
        let mgr = make_manager();
        assert!(mgr.validate_api_key("bad_key").await.is_err());
    }

    #[tokio::test]
    async fn test_revoke_api_key() {
        let mgr = make_manager();
        let id = mgr
            .register_user("pat", "pat@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        let key = mgr.create_api_key(&id, None).await.unwrap();
        mgr.revoke_api_key(&key).await.unwrap();
        assert!(mgr.validate_api_key(&key).await.is_err());
    }

    #[tokio::test]
    async fn test_revoke_api_key_not_found() {
        let mgr = make_manager();
        assert!(mgr.revoke_api_key("nonexistent").await.is_err());
    }

    // ── validate_username ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_validate_username_valid() {
        let mgr = make_manager();
        assert!(mgr.validate_username("good_user-1").await.unwrap());
    }

    #[tokio::test]
    async fn test_validate_username_too_short() {
        let mgr = make_manager();
        assert!(!mgr.validate_username("ab").await.unwrap());
    }

    #[tokio::test]
    async fn test_validate_username_special_chars() {
        let mgr = make_manager();
        assert!(!mgr.validate_username("user@name").await.unwrap());
    }

    // ── validate_display_name ───────────────────────────────────────────

    #[tokio::test]
    async fn test_validate_display_name_valid() {
        let mgr = make_manager();
        assert!(mgr.validate_display_name("Alice Bob").await.unwrap());
    }

    #[tokio::test]
    async fn test_validate_display_name_empty() {
        let mgr = make_manager();
        assert!(!mgr.validate_display_name("").await.unwrap());
    }

    #[tokio::test]
    async fn test_validate_display_name_only_whitespace() {
        let mgr = make_manager();
        assert!(!mgr.validate_display_name("   ").await.unwrap());
    }

    // ── validate_password_strength ──────────────────────────────────────

    #[tokio::test]
    async fn test_validate_password_strong() {
        let mgr = make_manager();
        assert!(
            mgr.validate_password_strength("C0mpl3x!P@ssw0rd")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_validate_password_weak() {
        let mgr = make_manager();
        assert!(!mgr.validate_password_strength("123").await.unwrap());
    }

    // ── validate_user_input ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_validate_user_input_clean() {
        let mgr = make_manager();
        assert!(mgr.validate_user_input("Hello World 123").await.unwrap());
    }

    #[tokio::test]
    async fn test_validate_user_input_html_tags() {
        let mgr = make_manager();
        assert!(
            !mgr.validate_user_input("<script>alert(1)</script>")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_validate_user_input_sql_injection() {
        let mgr = make_manager();
        assert!(
            !mgr.validate_user_input("'; drop table users--")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_validate_user_input_template_injection() {
        let mgr = make_manager();
        assert!(!mgr.validate_user_input("${evil}").await.unwrap());
    }

    #[tokio::test]
    async fn test_validate_user_input_path_traversal() {
        let mgr = make_manager();
        assert!(!mgr.validate_user_input("../../etc/passwd").await.unwrap());
    }

    #[tokio::test]
    async fn test_validate_user_input_javascript_uri() {
        let mgr = make_manager();
        assert!(
            !mgr.validate_user_input("javascript:alert(1)")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_validate_user_input_empty() {
        let mgr = make_manager();
        assert!(!mgr.validate_user_input("").await.unwrap());
    }

    #[tokio::test]
    async fn test_validate_user_input_encoded_tags() {
        let mgr = make_manager();
        assert!(!mgr.validate_user_input("%3cscript%3e").await.unwrap());
    }

    // ── username_exists / email_exists ───────────────────────────────────

    #[tokio::test]
    async fn test_username_exists() {
        let mgr = make_manager();
        mgr.register_user("quinn", "quinn@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        assert!(mgr.username_exists("quinn").await.unwrap());
        assert!(!mgr.username_exists("noone").await.unwrap());
    }

    #[tokio::test]
    async fn test_email_exists() {
        let mgr = make_manager();
        mgr.register_user("ross", "ross@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        assert!(mgr.email_exists("ross@example.com").await.unwrap());
        assert!(!mgr.email_exists("nobody@example.com").await.unwrap());
    }

    // ── get_user_by_username ────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_user_by_username() {
        let mgr = make_manager();
        mgr.register_user("sam", "sam@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        let data = mgr.get_user_by_username("sam").await.unwrap();
        assert_eq!(data["username"].as_str(), Some("sam"));
    }

    #[tokio::test]
    async fn test_get_user_by_username_not_found() {
        let mgr = make_manager();
        assert!(mgr.get_user_by_username("ghost").await.is_err());
    }

    // ── get_user_profile ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_user_profile() {
        let mgr = make_manager();
        let id = mgr
            .register_user("tina", "tina@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        let profile = mgr.get_user_profile(&id).await.unwrap();
        assert_eq!(profile.username.as_deref(), Some("tina"));
        assert_eq!(profile.email.as_deref(), Some("tina@example.com"));
        // password_hash should NOT be in additional_data
        assert!(!profile.additional_data.contains_key("password_hash"));
    }

    #[tokio::test]
    async fn test_get_user_profile_not_found() {
        let mgr = make_manager();
        assert!(mgr.get_user_profile("ghost").await.is_err());
    }

    // ── get_user_roles ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_user_roles_default() {
        let mgr = make_manager();
        let id = mgr
            .register_user("uma", "uma@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        let roles = mgr.get_user_roles(&id).await.unwrap();
        assert!(roles.contains(&"user".to_string()));
    }

    #[tokio::test]
    async fn test_get_user_roles_not_found_returns_default() {
        let mgr = make_manager();
        let roles = mgr.get_user_roles("ghost").await.unwrap();
        assert_eq!(roles, vec!["user".to_string()]);
    }

    // ── verify_login_credentials ────────────────────────────────────────

    #[tokio::test]
    async fn test_verify_login_credentials_success() {
        let mgr = make_manager();
        mgr.register_user("vera", "vera@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        let result = mgr
            .verify_login_credentials("vera", "StrongP@ss1!")
            .await
            .unwrap();
        assert!(result.is_some());
        assert!(!result.unwrap().mfa_enabled);
    }

    #[tokio::test]
    async fn test_verify_login_credentials_wrong_password() {
        let mgr = make_manager();
        mgr.register_user("wanda", "wanda@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        let result = mgr
            .verify_login_credentials("wanda", "wrong")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_verify_login_credentials_unknown_user() {
        let mgr = make_manager();
        let result = mgr
            .verify_login_credentials("ghost", "StrongP@ss1!")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_verify_login_credentials_empty_inputs() {
        let mgr = make_manager();
        assert!(
            mgr.verify_login_credentials("", "pass")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            mgr.verify_login_credentials("user", "")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_verify_login_credentials_deactivated() {
        let mgr = make_manager();
        let id = mgr
            .register_user("xena", "xena@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        mgr.set_user_active(&id, false).await.unwrap();
        let result = mgr
            .verify_login_credentials("xena", "StrongP@ss1!")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    // ── get_username_by_id ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_username_by_id() {
        let mgr = make_manager();
        let id = mgr
            .register_user("yara", "yara@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        let username = mgr.get_username_by_id(&id).await.unwrap();
        assert_eq!(username, "yara");
    }

    #[tokio::test]
    async fn test_get_username_by_id_not_found() {
        let mgr = make_manager();
        assert!(mgr.get_username_by_id("ghost").await.is_err());
    }

    // ── list_users active_only filter ───────────────────────────────────

    #[tokio::test]
    async fn test_list_users_active_only() {
        let mgr = make_manager();
        let id1 = mgr
            .register_user("active1", "active1@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        let id2 = mgr
            .register_user("inactive1", "inactive1@example.com", "StrongP@ss1!")
            .await
            .unwrap();
        mgr.set_user_active(&id2, false).await.unwrap();

        let all = mgr.list_users(None, None, false).await.unwrap();
        let active = mgr.list_users(None, None, true).await.unwrap();
        assert!(all.len() > active.len());
        assert!(active.iter().all(|u| u.active));
        // The inactive user should still be in the "all" list
        assert!(all.iter().any(|u| u.id == id1));
        assert!(all.iter().any(|u| u.id == id2));
    }
}
