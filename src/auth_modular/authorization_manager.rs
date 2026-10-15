//! Authorization manager: wraps `PermissionChecker` and exposes all role/permission operations.

use crate::errors::{AuthError, Result};
use crate::permissions::{Permission, PermissionChecker, Role};
use crate::storage::AuthStorage;
use crate::tokens::AuthToken;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Authorization manager that owns the `PermissionChecker` and exposes
/// all role and permission operations for delegation from `AuthFramework`.
///
/// # Example
/// ```rust,ignore
/// use auth_framework::auth_modular::AuthorizationManager;
/// let am = AuthorizationManager::new(checker.clone(), storage.clone());
/// am.create_default_roles().await;
/// ```
pub struct AuthorizationManager {
    checker: Arc<RwLock<PermissionChecker>>,
    storage: Arc<dyn AuthStorage>,
}

impl AuthorizationManager {
    /// Create a new authorization manager.
    ///
    /// # Example
    /// ```rust,ignore
    /// let am = AuthorizationManager::new(checker.clone(), storage.clone());
    /// ```
    pub fn new(checker: Arc<RwLock<PermissionChecker>>, storage: Arc<dyn AuthStorage>) -> Self {
        Self { checker, storage }
    }

    /// Initialize the default roles in the permission checker (called during framework init).
    ///
    /// # Example
    /// ```rust,ignore
    /// am.create_default_roles().await;
    /// ```
    pub async fn create_default_roles(&self) {
        let mut c = self.checker.write().await;
        c.create_default_roles();
    }

    /// Load persisted roles and user→role assignments from KV storage into
    /// the in-memory permission checker. Called during framework initialization
    /// after `create_default_roles` so that previously persisted state survives
    /// process restarts.
    ///
    /// # Example
    /// ```rust,ignore
    /// am.load_persisted_roles().await?;
    /// ```
    pub async fn load_persisted_roles(&self) -> Result<()> {
        // Load roles
        let role_keys = self.storage.list_kv_keys("rbac:role:").await?;
        if !role_keys.is_empty() {
            let mut c = self.checker.write().await;
            for key in &role_keys {
                if let Some(bytes) = self.storage.get_kv(key).await?
                    && let Ok(role) = serde_json::from_slice::<Role>(&bytes)
                {
                    c.add_role(role);
                }
            }
        }

        // Load user→role assignments
        let assignment_keys = self.storage.list_kv_keys("rbac:user_roles:").await?;
        if !assignment_keys.is_empty() {
            let mut c = self.checker.write().await;
            for key in &assignment_keys {
                let user_id = key.strip_prefix("rbac:user_roles:").unwrap_or(key);
                if let Some(bytes) = self.storage.get_kv(key).await?
                    && let Ok(roles) = serde_json::from_slice::<Vec<String>>(&bytes)
                {
                    for role_name in roles {
                        if let Err(e) = c.assign_role_to_user(user_id, &role_name) {
                            tracing::warn!(
                                "Failed to assign role '{}' to user '{}': {}",
                                role_name,
                                user_id,
                                e
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Reset runtime authorization state back to the default role set.
    ///
    /// # Example
    /// ```rust,ignore
    /// am.reset_runtime_state().await;
    /// ```
    pub async fn reset_runtime_state(&self) {
        let mut c = self.checker.write().await;
        c.clear();
        c.create_default_roles();

        // Clean up persisted role data
        if let Ok(keys) = self.storage.list_kv_keys("rbac:role:").await {
            for key in keys {
                let _ = self.storage.delete_kv(&key).await;
            }
        }
        if let Ok(keys) = self.storage.list_kv_keys("rbac:user_roles:").await {
            for key in keys {
                let _ = self.storage.delete_kv(&key).await;
            }
        }
    }

    /// Grant a direct permission to a user.
    ///
    /// # Example
    /// ```rust,ignore
    /// am.grant_permission("user-1", "read", "documents").await?;
    /// ```
    pub async fn grant_permission(
        &self,
        user_id: &str,
        action: &str,
        resource: &str,
    ) -> Result<()> {
        debug!(
            "Granting permission '{}:{}' to user '{}'",
            action, resource, user_id
        );
        let mut c = self.checker.write().await;
        let permission = Permission::new(action, resource);
        c.add_user_permission(user_id, permission);
        info!(
            "Permission '{}:{}' granted to user '{}'",
            action, resource, user_id
        );
        Ok(())
    }

    /// Revoke a direct permission from a user.
    ///
    /// # Example
    /// ```rust,ignore
    /// am.revoke_permission("user-1", "read", "documents").await?;
    /// ```
    pub async fn revoke_permission(
        &self,
        user_id: &str,
        action: &str,
        resource: &str,
    ) -> Result<()> {
        debug!(
            "Revoking permission '{}:{}' from user '{}'",
            action, resource, user_id
        );
        if user_id.is_empty() || action.is_empty() || resource.is_empty() {
            return Err(AuthError::validation(
                "User ID, action, and resource cannot be empty",
            ));
        }
        let mut c = self.checker.write().await;
        let permission = Permission::new(action, resource);
        c.remove_user_permission(user_id, &permission);
        info!(
            "Permission '{}:{}' revoked from user '{}'",
            action, resource, user_id
        );
        Ok(())
    }

    /// Create (register) a new role.
    ///
    /// # Example
    /// ```rust,ignore
    /// use auth_framework::permissions::Role;
    /// am.create_role(Role::new("editor")).await?;
    /// ```
    pub async fn create_role(&self, role: Role) -> Result<()> {
        debug!("Creating role '{}'", role.name);
        if role.name.is_empty() {
            return Err(AuthError::validation("Role name cannot be empty"));
        }
        let mut c = self.checker.write().await;
        c.add_role(role.clone());
        drop(c);

        // Persist to storage
        let key = format!("rbac:role:{}", role.name);
        let role_json = serde_json::to_vec(&role)
            .map_err(|e| AuthError::internal(format!("Failed to serialize role: {e}")))?;
        self.storage.store_kv(&key, &role_json, None).await?;

        info!("Role '{}' created", role.name);
        Ok(())
    }

    /// Return all known roles.
    ///
    /// # Example
    /// ```rust,ignore
    /// let roles = am.list_roles().await;
    /// for r in &roles { println!("{}", r.name); }
    /// ```
    pub async fn list_roles(&self) -> Vec<Role> {
        let c = self.checker.read().await;
        c.list_roles()
    }

    /// Fetch a role definition by name.
    ///
    /// # Example
    /// ```rust,ignore
    /// let role = am.get_role("admin").await?;
    /// println!("permissions: {:?}", role.permissions());
    /// ```
    pub async fn get_role(&self, role_name: &str) -> Result<Role> {
        if role_name.is_empty() {
            return Err(AuthError::validation("Role name cannot be empty"));
        }

        let c = self.checker.read().await;
        c.get_role(role_name)
            .cloned()
            .ok_or_else(|| AuthError::validation(format!("Role '{role_name}' not found")))
    }

    /// Add a permission to an existing role.
    ///
    /// # Example
    /// ```rust,ignore
    /// use auth_framework::permissions::Permission;
    /// am.add_role_permission("editor", Permission::new("write", "posts")).await?;
    /// ```
    pub async fn add_role_permission(&self, role_name: &str, permission: Permission) -> Result<()> {
        if role_name.is_empty() {
            return Err(AuthError::validation("Role name cannot be empty"));
        }

        let mut c = self.checker.write().await;
        let role = c
            .get_role(role_name)
            .cloned()
            .ok_or_else(|| AuthError::validation(format!("Role '{role_name}' not found")))?;
        let mut updated_role = role;
        updated_role.add_permission(permission);
        c.add_role(updated_role.clone());
        drop(c);

        // Re-persist the updated role
        let key = format!("rbac:role:{}", role_name);
        let role_json = serde_json::to_vec(&updated_role)
            .map_err(|e| AuthError::internal(format!("Failed to serialize role: {e}")))?;
        self.storage.store_kv(&key, &role_json, None).await?;

        Ok(())
    }

    /// Assign a role to a user.
    ///
    /// # Example
    /// ```rust,ignore
    /// am.assign_role("user-1", "editor").await?;
    /// ```
    pub async fn assign_role(&self, user_id: &str, role_name: &str) -> Result<()> {
        debug!("Assigning role '{}' to user '{}'", role_name, user_id);
        if user_id.is_empty() {
            return Err(AuthError::validation("User ID cannot be empty"));
        }
        if role_name.is_empty() {
            return Err(AuthError::validation("Role name cannot be empty"));
        }
        let mut c = self.checker.write().await;
        c.assign_role_to_user(user_id, role_name)?;
        let roles = c.get_user_roles(user_id);
        drop(c);

        // Persist user→roles mapping to storage
        let key = format!("rbac:user_roles:{}", user_id);
        let roles_json = serde_json::to_vec(&roles)
            .map_err(|e| AuthError::internal(format!("Failed to serialize user roles: {e}")))?;
        self.storage.store_kv(&key, &roles_json, None).await?;

        info!("Role '{}' assigned to user '{}'", role_name, user_id);
        Ok(())
    }

    /// Remove a role from a user.
    ///
    /// # Example
    /// ```rust,ignore
    /// am.remove_role("user-1", "editor").await?;
    /// ```
    pub async fn remove_role(&self, user_id: &str, role_name: &str) -> Result<()> {
        debug!("Removing role '{}' from user '{}'", role_name, user_id);
        if user_id.is_empty() || role_name.is_empty() {
            return Err(AuthError::validation(
                "User ID and role name cannot be empty",
            ));
        }
        let mut c = self.checker.write().await;
        c.remove_user_role(user_id, role_name);
        let roles = c.get_user_roles(user_id);
        drop(c);

        // Update persisted user→roles mapping
        let key = format!("rbac:user_roles:{}", user_id);
        if roles.is_empty() {
            let _ = self.storage.delete_kv(&key).await;
        } else {
            let roles_json = serde_json::to_vec(&roles)
                .map_err(|e| AuthError::internal(format!("Failed to serialize user roles: {e}")))?;
            self.storage.store_kv(&key, &roles_json, None).await?;
        }

        info!("Role '{}' removed from user '{}'", role_name, user_id);
        Ok(())
    }

    /// Set role inheritance (`child_role` inherits all permissions from `parent_role`).
    ///
    /// # Example
    /// ```rust,ignore
    /// am.set_role_inheritance("moderator", "user").await?;
    /// ```
    pub async fn set_role_inheritance(&self, child_role: &str, parent_role: &str) -> Result<()> {
        debug!(
            "Setting inheritance: '{}' inherits from '{}'",
            child_role, parent_role
        );
        if child_role.is_empty() || parent_role.is_empty() {
            return Err(AuthError::validation("Role names cannot be empty"));
        }
        let mut c = self.checker.write().await;
        c.set_role_inheritance(child_role, parent_role)?;
        info!(
            "Role inheritance set: '{}' inherits from '{}'",
            child_role, parent_role
        );
        Ok(())
    }

    /// Check if a token has a specific direct permission.
    ///
    /// Does **not** validate the token itself — the caller must validate
    /// the token's signature and expiry before calling this method.
    ///
    /// # Example
    /// ```rust,ignore
    /// let allowed = am.check_token_permission(&token, "read", "users").await?;
    /// ```
    pub async fn check_token_permission(
        &self,
        token: &AuthToken,
        action: &str,
        resource: &str,
    ) -> Result<bool> {
        let permission = Permission::new(action, resource);
        let mut c = self.checker.write().await;
        c.check_token_permission(token, &permission)
    }

    /// Check if a user (by ID) has a specific permission (ABAC/RBAC evaluation).
    ///
    /// # Example
    /// ```rust,ignore
    /// if am.check_user_permission("user-1", "write", "posts").await {
    ///     println!("allowed");
    /// }
    /// ```
    pub async fn check_user_permission(&self, user_id: &str, action: &str, resource: &str) -> bool {
        let permission = Permission::new(action, resource);
        let mut c = self.checker.write().await;
        c.check_permission(user_id, &permission).unwrap_or(false)
    }

    /// Check whether a user currently holds a named role.
    ///
    /// # Example
    /// ```rust,ignore
    /// let is_admin = am.user_has_role("user-1", "admin").await?;
    /// ```
    pub async fn user_has_role(&self, user_id: &str, role_name: &str) -> Result<bool> {
        debug!("Checking if user '{}' has role '{}'", user_id, role_name);
        if user_id.is_empty() || role_name.is_empty() {
            return Err(AuthError::validation(
                "User ID and role name cannot be empty",
            ));
        }
        let c = self.checker.read().await;
        let has_role = c.user_has_role(user_id, role_name);
        debug!("User '{}' has role '{}': {}", user_id, role_name, has_role);
        Ok(has_role)
    }

    /// Get all effective permissions for a user (direct + role-inherited).
    ///
    /// # Example
    /// ```rust,ignore
    /// let perms = am.get_effective_permissions("user-1").await?;
    /// for p in &perms { println!("{}", p); }
    /// ```
    pub async fn get_effective_permissions(&self, user_id: &str) -> Result<Vec<String>> {
        debug!("Getting effective permissions for user '{}'", user_id);
        if user_id.is_empty() {
            return Err(AuthError::validation("User ID cannot be empty"));
        }
        let c = self.checker.read().await;
        let permissions = c.get_effective_permissions(user_id);
        debug!(
            "User '{}' has {} effective permissions",
            user_id,
            permissions.len()
        );
        Ok(permissions)
    }

    /// List the currently assigned runtime roles for a user.
    ///
    /// # Example
    /// ```rust,ignore
    /// let roles = am.list_user_roles("user-1").await?;
    /// ```
    pub async fn list_user_roles(&self, user_id: &str) -> Result<Vec<String>> {
        if user_id.is_empty() {
            return Err(AuthError::validation("User ID cannot be empty"));
        }

        let c = self.checker.read().await;
        Ok(c.get_user_roles(user_id))
    }

    /// Get raw permission metrics: `(role_count, user_count, total_direct_permission_count)`.
    ///
    /// # Example
    /// ```rust,ignore
    /// let (roles, users, perms) = am.get_metrics().await;
    /// ```
    pub async fn get_metrics(&self) -> (usize, usize, usize) {
        let c = self.checker.read().await;
        (
            c.role_count(),
            c.user_count(),
            c.total_direct_permission_count(),
        )
    }

    // ── ABAC / Storage-backed operations ────────────────────────────────────

    /// Create or overwrite an ABAC policy record in storage.
    ///
    /// # Example
    /// ```rust,ignore
    /// am.create_abac_policy("time-restricted", "Business hours only").await?;
    /// ```
    pub async fn create_abac_policy(&self, name: &str, description: &str) -> Result<()> {
        debug!("Creating ABAC policy '{}'", name);
        if name.is_empty() {
            return Err(AuthError::validation("Policy name cannot be empty"));
        }
        if description.is_empty() {
            return Err(AuthError::validation("Policy description cannot be empty"));
        }
        let policy_data = serde_json::json!({
            "name": name,
            "description": description,
            "created_at": chrono::Utc::now(),
            "rules": [],
            "active": true
        });
        let key = format!("abac:policy:{}", name);
        let policy_json = serde_json::to_vec(&policy_data)
            .map_err(|e| AuthError::validation(format!("Failed to serialize policy: {}", e)))?;
        self.storage.store_kv(&key, &policy_json, None).await?;
        info!("ABAC policy '{}' created", name);
        Ok(())
    }

    /// Store a user attribute used in ABAC policy evaluation.
    ///
    /// # Example
    /// ```rust,ignore
    /// am.map_user_attribute("user-1", "department", "engineering").await?;
    /// ```
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
        if user_id.is_empty() || attribute.is_empty() {
            return Err(AuthError::validation(
                "User ID and attribute name cannot be empty",
            ));
        }
        let attrs_key = format!("user:{}:attributes", user_id);
        let mut user_attrs = if let Some(bytes) = self.storage.get_kv(&attrs_key).await? {
            serde_json::from_slice::<std::collections::HashMap<String, String>>(&bytes)
                .unwrap_or_default()
        } else {
            std::collections::HashMap::new()
        };
        user_attrs.insert(attribute.to_string(), value.to_string());
        let attrs_json = serde_json::to_vec(&user_attrs)
            .map_err(|e| AuthError::validation(format!("Failed to serialize attributes: {}", e)))?;
        self.storage.store_kv(&attrs_key, &attrs_json, None).await?;
        info!("Attribute '{}' mapped for user '{}'", attribute, user_id);
        Ok(())
    }

    /// Retrieve a single user attribute.
    ///
    /// # Example
    /// ```rust,ignore
    /// let dept = am.get_user_attribute("user-1", "department").await?;
    /// ```
    pub async fn get_user_attribute(
        &self,
        user_id: &str,
        attribute: &str,
    ) -> Result<Option<String>> {
        debug!("Getting attribute '{}' for user '{}'", attribute, user_id);
        if user_id.is_empty() || attribute.is_empty() {
            return Err(AuthError::validation(
                "User ID and attribute name cannot be empty",
            ));
        }
        let attrs_key = format!("user:{}:attributes", user_id);
        if let Some(bytes) = self.storage.get_kv(&attrs_key).await? {
            let user_attrs: std::collections::HashMap<String, String> =
                serde_json::from_slice(&bytes).unwrap_or_default();
            Ok(user_attrs.get(attribute).cloned())
        } else {
            Ok(None)
        }
    }

    /// Evaluate a permission request with full ABAC context.
    ///
    /// # Example
    /// ```rust,ignore
    /// use std::collections::HashMap;
    /// let mut ctx = HashMap::new();
    /// ctx.insert("time_restriction".into(), "business_hours".into());
    /// let ok = am.check_dynamic_permission("user-1", "read", "reports", ctx).await?;
    /// ```
    pub async fn check_dynamic_permission(
        &self,
        user_id: &str,
        action: &str,
        resource: &str,
        context: std::collections::HashMap<String, String>,
    ) -> Result<bool> {
        debug!(
            "Checking dynamic permission for user '{}': {}:{} with context: {:?}",
            user_id, action, resource, context
        );
        if user_id.is_empty() || action.is_empty() || resource.is_empty() {
            return Err(AuthError::validation(
                "User ID, action, and resource cannot be empty",
            ));
        }
        // Load user attributes for ABAC evaluation.
        let user_attrs_key = format!("user:{}:attributes", user_id);
        let user_attrs = if let Some(bytes) = self.storage.get_kv(&user_attrs_key).await? {
            serde_json::from_slice::<std::collections::HashMap<String, String>>(&bytes)
                .unwrap_or_default()
        } else {
            std::collections::HashMap::new()
        };
        // Start with RBAC check.
        let mut permission_granted = self.check_user_permission(user_id, action, resource).await;
        // Apply context-based rules only when the base permission is granted.
        if permission_granted {
            // Time-based access control.
            if let Some(time_restriction) = context.get("time_restriction") {
                let current_hour = chrono::Utc::now()
                    .format("%H")
                    .to_string()
                    .parse::<u32>()
                    .unwrap_or(0);
                if time_restriction == "business_hours" && !(9..=17).contains(&current_hour) {
                    permission_granted = false;
                    debug!("Access denied: outside business hours");
                }
            }
            // Location-based access control.
            if let Some(required_location) = context.get("required_location")
                && let Some(user_location) = user_attrs.get("location")
                && user_location != required_location
            {
                permission_granted = false;
                debug!(
                    "Access denied: user location {} != required {}",
                    user_location, required_location
                );
            }
            // Clearance-level access control.
            if let Some(required_clearance) = context.get("required_clearance")
                && let Some(user_clearance) = user_attrs.get("clearance_level")
            {
                let required_level = required_clearance.parse::<u32>().unwrap_or(0);
                let user_level = user_clearance.parse::<u32>().unwrap_or(0);
                if user_level < required_level {
                    permission_granted = false;
                    debug!(
                        "Access denied: user clearance {} < required {}",
                        user_level, required_level
                    );
                }
            }
        }
        debug!(
            "Dynamic permission check result for user '{}': {}",
            user_id, permission_granted
        );
        Ok(permission_granted)
    }

    /// Register a resource in the permission system.
    ///
    /// # Example
    /// ```rust,ignore
    /// am.create_resource("documents").await?;
    /// ```
    pub async fn create_resource(&self, resource: &str) -> Result<()> {
        debug!("Creating resource '{}'", resource);
        if resource.is_empty() {
            return Err(AuthError::validation("Resource name cannot be empty"));
        }
        let resource_data = serde_json::json!({
            "name": resource,
            "created_at": chrono::Utc::now(),
            "active": true
        });
        let key = format!("resource:{}", resource);
        let resource_json = serde_json::to_vec(&resource_data)
            .map_err(|e| AuthError::validation(format!("Failed to serialize resource: {}", e)))?;
        self.storage.store_kv(&key, &resource_json, None).await?;
        info!("Resource '{}' created", resource);
        Ok(())
    }

    /// Delegate a permission from one user to another for a limited duration.
    ///
    /// # Example
    /// ```rust,ignore
    /// am.delegate_permission(
    ///     "admin-1", "user-2", "read", "reports",
    ///     std::time::Duration::from_secs(3600),
    /// ).await?;
    /// ```
    pub async fn delegate_permission(
        &self,
        delegator_id: &str,
        delegatee_id: &str,
        action: &str,
        resource: &str,
        duration: std::time::Duration,
    ) -> Result<()> {
        debug!(
            "Delegating permission '{}:{}' from '{}' to '{}' for {:?}",
            action, resource, delegator_id, delegatee_id, duration
        );
        if delegator_id.is_empty()
            || delegatee_id.is_empty()
            || action.is_empty()
            || resource.is_empty()
        {
            return Err(AuthError::validation(
                "All delegation parameters cannot be empty",
            ));
        }
        if !self
            .check_user_permission(delegator_id, action, resource)
            .await
        {
            return Err(AuthError::authorization(
                "Delegator does not have the permission to delegate",
            ));
        }
        let delegation_id = uuid::Uuid::new_v4().to_string();
        let expires_secs = std::time::SystemTime::now()
            .checked_add(duration)
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let delegation_data = serde_json::json!({
            "id": delegation_id,
            "delegator_id": delegator_id,
            "delegatee_id": delegatee_id,
            "action": action,
            "resource": resource,
            "created_at": chrono::Utc::now(),
            "expires_at": expires_secs
        });
        let key = format!("delegation:{}", delegation_id);
        let delegation_json = serde_json::to_vec(&delegation_data)
            .map_err(|e| AuthError::validation(format!("Failed to serialize delegation: {}", e)))?;
        self.storage
            .store_kv(&key, &delegation_json, Some(duration))
            .await?;
        // Maintain a per-delegatee index.
        let index_key = format!("delegations_index:{}", delegatee_id);
        let mut ids: Vec<String> = match self.storage.get_kv(&index_key).await? {
            Some(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            None => vec![],
        };
        ids.push(delegation_id.clone());
        let ids_json = serde_json::to_vec(&ids).map_err(|e| {
            AuthError::validation(format!("Failed to serialize delegation index: {}", e))
        })?;
        self.storage.store_kv(&index_key, &ids_json, None).await?;
        info!(
            "Permission '{}:{}' delegated from '{}' to '{}' for {:?}",
            action, resource, delegator_id, delegatee_id, duration
        );
        Ok(())
    }

    /// List currently active permission delegations for a user (as delegatee).
    ///
    /// # Example
    /// ```rust,ignore
    /// let delegations = am.get_active_delegations("user-2").await?;
    /// ```
    pub async fn get_active_delegations(&self, user_id: &str) -> Result<Vec<String>> {
        debug!("Getting active delegations for user '{}'", user_id);
        if user_id.is_empty() {
            return Err(AuthError::validation("User ID cannot be empty"));
        }
        let index_key = format!("delegations_index:{}", user_id);
        let delegation_ids: Vec<String> = match self.storage.get_kv(&index_key).await? {
            Some(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            None => return Ok(vec![]),
        };
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut result = Vec::new();
        let mut active_ids = Vec::new();
        for id in &delegation_ids {
            let key = format!("delegation:{}", id);
            if let Some(bytes) = self.storage.get_kv(&key).await?
                && let Ok(data) = serde_json::from_slice::<serde_json::Value>(&bytes)
            {
                let expires_at = data["expires_at"].as_u64().unwrap_or(0);
                if expires_at > now_secs {
                    let action = data["action"].as_str().unwrap_or("unknown");
                    let resource = data["resource"].as_str().unwrap_or("unknown");
                    let delegator = data["delegator_id"].as_str().unwrap_or("unknown");
                    result.push(format!(
                        "{}:{}:delegated_from:{}",
                        action, resource, delegator
                    ));
                    active_ids.push(id.clone());
                }
            }
        }
        // Prune stale entries from the index.
        if active_ids.len() != delegation_ids.len()
            && let Ok(pruned) = serde_json::to_vec(&active_ids)
        {
            let _ = self.storage.store_kv(&index_key, &pruned, None).await;
        }
        debug!(
            "Found {} active delegations for user '{}'",
            result.len(),
            user_id
        );
        Ok(result)
    }

    /// Assemble aggregated permission metrics.
    ///
    /// `active_sessions` and `permission_checks_last_hour` are provided by the
    /// caller so that the manager stays independent from the session and audit
    /// subsystems.
    ///
    /// # Example
    /// ```rust,ignore
    /// let metrics = am.get_permission_metrics(42, 1000).await?;
    /// println!("total_roles: {}", metrics["total_roles"]);
    /// ```
    pub async fn get_permission_metrics(
        &self,
        active_sessions: u64,
        permission_checks_last_hour: u64,
    ) -> Result<std::collections::HashMap<String, u64>> {
        let (total_roles, total_users, total_permissions) = self.get_metrics().await;
        let mut metrics = std::collections::HashMap::new();
        metrics.insert(
            "total_users_with_permissions".to_string(),
            total_users as u64,
        );
        metrics.insert("total_roles".to_string(), total_roles as u64);
        metrics.insert("total_permissions".to_string(), total_permissions as u64);
        metrics.insert("active_sessions".to_string(), active_sessions);
        metrics.insert(
            "permission_checks_last_hour".to_string(),
            permission_checks_last_hour,
        );
        debug!("Retrieved {} permission metrics", metrics.len());
        Ok(metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    fn make_manager() -> AuthorizationManager {
        let checker = Arc::new(RwLock::new(PermissionChecker::new()));
        let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
        AuthorizationManager::new(checker, storage)
    }

    // ── create_role ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_role_success() {
        let mgr = make_manager();
        let role = Role::new("editor");
        assert!(mgr.create_role(role).await.is_ok());
        let roles = mgr.list_roles().await;
        assert!(roles.iter().any(|r| r.name == "editor"));
    }

    #[tokio::test]
    async fn test_create_role_persists_to_storage() {
        let mgr = make_manager();
        mgr.create_role(Role::new("persisted_role")).await.unwrap();
        let data = mgr
            .storage
            .get_kv("rbac:role:persisted_role")
            .await
            .unwrap();
        assert!(data.is_some());
        let role: Role = serde_json::from_slice(&data.unwrap()).unwrap();
        assert_eq!(role.name, "persisted_role");
    }

    #[tokio::test]
    async fn test_create_role_empty_name_rejected() {
        let mgr = make_manager();
        let role = Role::new("");
        let err = mgr.create_role(role).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_create_role_duplicate_overwrites() {
        let mgr = make_manager();
        let mut role1 = Role::new("dup");
        role1.description = Some("first".into());
        mgr.create_role(role1).await.unwrap();

        let mut role2 = Role::new("dup");
        role2.description = Some("second".into());
        mgr.create_role(role2).await.unwrap();

        let fetched = mgr.get_role("dup").await.unwrap();
        assert_eq!(fetched.description.as_deref(), Some("second"));
    }

    // ── get_role ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_role_not_found() {
        let mgr = make_manager();
        assert!(mgr.get_role("nonexistent").await.is_err());
    }

    #[tokio::test]
    async fn test_get_role_empty_name_rejected() {
        let mgr = make_manager();
        assert!(mgr.get_role("").await.is_err());
    }

    // ── assign_role ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_assign_role_success() {
        let mgr = make_manager();
        mgr.create_role(Role::new("viewer")).await.unwrap();
        mgr.assign_role("user1", "viewer").await.unwrap();
        assert!(mgr.user_has_role("user1", "viewer").await.unwrap());
    }

    #[tokio::test]
    async fn test_assign_role_persists_to_storage() {
        let mgr = make_manager();
        mgr.create_role(Role::new("writer")).await.unwrap();
        mgr.assign_role("u2", "writer").await.unwrap();
        let data = mgr.storage.get_kv("rbac:user_roles:u2").await.unwrap();
        assert!(data.is_some());
        let roles: Vec<String> = serde_json::from_slice(&data.unwrap()).unwrap();
        assert!(roles.contains(&"writer".to_string()));
    }

    #[tokio::test]
    async fn test_assign_role_empty_user_rejected() {
        let mgr = make_manager();
        mgr.create_role(Role::new("r")).await.unwrap();
        assert!(mgr.assign_role("", "r").await.is_err());
    }

    #[tokio::test]
    async fn test_assign_role_empty_role_rejected() {
        let mgr = make_manager();
        assert!(mgr.assign_role("u", "").await.is_err());
    }

    // ── remove_role ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_remove_role_success() {
        let mgr = make_manager();
        mgr.create_role(Role::new("temp")).await.unwrap();
        mgr.assign_role("u3", "temp").await.unwrap();
        assert!(mgr.user_has_role("u3", "temp").await.unwrap());
        mgr.remove_role("u3", "temp").await.unwrap();
        assert!(!mgr.user_has_role("u3", "temp").await.unwrap());
    }

    #[tokio::test]
    async fn test_remove_role_cleans_storage() {
        let mgr = make_manager();
        mgr.create_role(Role::new("temp")).await.unwrap();
        mgr.assign_role("u4", "temp").await.unwrap();
        mgr.remove_role("u4", "temp").await.unwrap();
        let data = mgr.storage.get_kv("rbac:user_roles:u4").await.unwrap();
        // Should be deleted when empty
        assert!(data.is_none());
    }

    #[tokio::test]
    async fn test_remove_role_empty_params_rejected() {
        let mgr = make_manager();
        assert!(mgr.remove_role("", "role").await.is_err());
        assert!(mgr.remove_role("user", "").await.is_err());
    }

    // ── add_role_permission ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_add_role_permission_success() {
        let mgr = make_manager();
        mgr.create_role(Role::new("admin")).await.unwrap();
        let perm = Permission::new("write", "documents");
        mgr.add_role_permission("admin", perm).await.unwrap();
        let role = mgr.get_role("admin").await.unwrap();
        assert!(
            role.permissions
                .iter()
                .any(|p| p.action == "write" && p.resource == "documents")
        );
    }

    #[tokio::test]
    async fn test_add_role_permission_persists() {
        let mgr = make_manager();
        mgr.create_role(Role::new("admin2")).await.unwrap();
        mgr.add_role_permission("admin2", Permission::new("read", "reports"))
            .await
            .unwrap();
        let data = mgr
            .storage
            .get_kv("rbac:role:admin2")
            .await
            .unwrap()
            .unwrap();
        let role: Role = serde_json::from_slice(&data).unwrap();
        assert!(role.permissions.iter().any(|p| p.action == "read"));
    }

    #[tokio::test]
    async fn test_add_role_permission_nonexistent_role() {
        let mgr = make_manager();
        let result = mgr
            .add_role_permission("ghost", Permission::new("x", "y"))
            .await;
        assert!(result.is_err());
    }

    // ── set_role_inheritance ────────────────────────────────────────────

    #[tokio::test]
    async fn test_set_role_inheritance_success() {
        let mgr = make_manager();
        mgr.create_role(Role::new("parent")).await.unwrap();
        mgr.create_role(Role::new("child")).await.unwrap();
        assert!(mgr.set_role_inheritance("child", "parent").await.is_ok());
    }

    #[tokio::test]
    async fn test_set_role_inheritance_empty_names_rejected() {
        let mgr = make_manager();
        assert!(mgr.set_role_inheritance("", "parent").await.is_err());
        assert!(mgr.set_role_inheritance("child", "").await.is_err());
    }

    // ── grant_permission / check_user_permission ────────────────────────

    #[tokio::test]
    async fn test_grant_and_check_permission() {
        let mgr = make_manager();
        mgr.grant_permission("u5", "read", "files").await.unwrap();
        assert!(mgr.check_user_permission("u5", "read", "files").await);
    }

    #[tokio::test]
    async fn test_check_permission_not_granted() {
        let mgr = make_manager();
        assert!(!mgr.check_user_permission("u6", "delete", "files").await);
    }

    #[tokio::test]
    async fn test_revoke_permission() {
        let mgr = make_manager();
        mgr.grant_permission("u7", "write", "data").await.unwrap();
        assert!(mgr.check_user_permission("u7", "write", "data").await);
        mgr.revoke_permission("u7", "write", "data").await.unwrap();
        assert!(!mgr.check_user_permission("u7", "write", "data").await);
    }

    #[tokio::test]
    async fn test_revoke_permission_empty_params_rejected() {
        let mgr = make_manager();
        assert!(mgr.revoke_permission("", "a", "r").await.is_err());
        assert!(mgr.revoke_permission("u", "", "r").await.is_err());
        assert!(mgr.revoke_permission("u", "a", "").await.is_err());
    }

    // ── user_has_role ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_user_has_role_false_when_not_assigned() {
        let mgr = make_manager();
        mgr.create_role(Role::new("r")).await.unwrap();
        assert!(!mgr.user_has_role("u", "r").await.unwrap());
    }

    #[tokio::test]
    async fn test_user_has_role_empty_params_rejected() {
        let mgr = make_manager();
        assert!(mgr.user_has_role("", "r").await.is_err());
        assert!(mgr.user_has_role("u", "").await.is_err());
    }

    // ── list_user_roles ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_user_roles() {
        let mgr = make_manager();
        mgr.create_role(Role::new("a")).await.unwrap();
        mgr.create_role(Role::new("b")).await.unwrap();
        mgr.assign_role("u8", "a").await.unwrap();
        mgr.assign_role("u8", "b").await.unwrap();
        let roles = mgr.list_user_roles("u8").await.unwrap();
        assert!(roles.contains(&"a".to_string()));
        assert!(roles.contains(&"b".to_string()));
    }

    #[tokio::test]
    async fn test_list_user_roles_empty_user_rejected() {
        let mgr = make_manager();
        assert!(mgr.list_user_roles("").await.is_err());
    }

    // ── get_effective_permissions ────────────────────────────────────────

    #[tokio::test]
    async fn test_get_effective_permissions() {
        let mgr = make_manager();
        mgr.grant_permission("u9", "read", "docs").await.unwrap();
        let perms = mgr.get_effective_permissions("u9").await.unwrap();
        assert!(!perms.is_empty());
    }

    #[tokio::test]
    async fn test_get_effective_permissions_empty_user_rejected() {
        let mgr = make_manager();
        assert!(mgr.get_effective_permissions("").await.is_err());
    }

    // ── load_persisted_roles ────────────────────────────────────────────

    #[tokio::test]
    async fn test_load_persisted_roles_restores_roles() {
        let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());

        // Create manager, add roles and assignments, then drop it
        {
            let checker = Arc::new(RwLock::new(PermissionChecker::new()));
            let mgr = AuthorizationManager::new(checker, storage.clone());
            mgr.create_role(Role::new("restored_role")).await.unwrap();
            mgr.assign_role("restored_user", "restored_role")
                .await
                .unwrap();
        }

        // Create fresh manager with the SAME storage, load persisted data
        let checker2 = Arc::new(RwLock::new(PermissionChecker::new()));
        let mgr2 = AuthorizationManager::new(checker2, storage);
        mgr2.load_persisted_roles().await.unwrap();

        assert!(mgr2.get_role("restored_role").await.is_ok());
        assert!(
            mgr2.user_has_role("restored_user", "restored_role")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_load_persisted_roles_empty_storage_ok() {
        let mgr = make_manager();
        assert!(mgr.load_persisted_roles().await.is_ok());
    }

    // ── reset_runtime_state ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_reset_runtime_state_clears_roles() {
        let mgr = make_manager();
        mgr.create_role(Role::new("custom")).await.unwrap();
        mgr.assign_role("u10", "custom").await.unwrap();
        mgr.reset_runtime_state().await;
        assert!(!mgr.user_has_role("u10", "custom").await.unwrap_or(false));
        // Storage should also be cleaned
        assert!(
            mgr.storage
                .get_kv("rbac:role:custom")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            mgr.storage
                .get_kv("rbac:user_roles:u10")
                .await
                .unwrap()
                .is_none()
        );
    }

    // ── ABAC operations ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_abac_policy() {
        let mgr = make_manager();
        mgr.create_abac_policy("location_gate", "Restricts by location")
            .await
            .unwrap();
        let data = mgr
            .storage
            .get_kv("abac:policy:location_gate")
            .await
            .unwrap();
        assert!(data.is_some());
    }

    #[tokio::test]
    async fn test_create_abac_policy_empty_name_rejected() {
        let mgr = make_manager();
        assert!(mgr.create_abac_policy("", "desc").await.is_err());
    }

    #[tokio::test]
    async fn test_create_abac_policy_empty_description_rejected() {
        let mgr = make_manager();
        assert!(mgr.create_abac_policy("name", "").await.is_err());
    }

    #[tokio::test]
    async fn test_map_and_get_user_attribute() {
        let mgr = make_manager();
        mgr.map_user_attribute("u11", "department", "engineering")
            .await
            .unwrap();
        let val = mgr.get_user_attribute("u11", "department").await.unwrap();
        assert_eq!(val.as_deref(), Some("engineering"));
    }

    #[tokio::test]
    async fn test_get_user_attribute_nonexistent() {
        let mgr = make_manager();
        let val = mgr.get_user_attribute("nobody", "x").await.unwrap();
        assert!(val.is_none());
    }

    #[tokio::test]
    async fn test_map_user_attribute_empty_params_rejected() {
        let mgr = make_manager();
        assert!(mgr.map_user_attribute("", "a", "v").await.is_err());
        assert!(mgr.map_user_attribute("u", "", "v").await.is_err());
    }

    #[tokio::test]
    async fn test_get_user_attribute_empty_params_rejected() {
        let mgr = make_manager();
        assert!(mgr.get_user_attribute("", "x").await.is_err());
        assert!(mgr.get_user_attribute("u", "").await.is_err());
    }

    // ── check_dynamic_permission ────────────────────────────────────────

    #[tokio::test]
    async fn test_check_dynamic_permission_granted() {
        let mgr = make_manager();
        mgr.grant_permission("u12", "read", "reports")
            .await
            .unwrap();
        let ctx = std::collections::HashMap::new();
        assert!(
            mgr.check_dynamic_permission("u12", "read", "reports", ctx)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_check_dynamic_permission_denied_no_permission() {
        let mgr = make_manager();
        let ctx = std::collections::HashMap::new();
        assert!(
            !mgr.check_dynamic_permission("u13", "read", "reports", ctx)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_check_dynamic_permission_location_mismatch() {
        let mgr = make_manager();
        mgr.grant_permission("u14", "read", "files").await.unwrap();
        mgr.map_user_attribute("u14", "location", "US")
            .await
            .unwrap();
        let mut ctx = std::collections::HashMap::new();
        ctx.insert("required_location".to_string(), "EU".to_string());
        assert!(
            !mgr.check_dynamic_permission("u14", "read", "files", ctx)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_check_dynamic_permission_clearance_insufficient() {
        let mgr = make_manager();
        mgr.grant_permission("u15", "read", "secret").await.unwrap();
        mgr.map_user_attribute("u15", "clearance_level", "2")
            .await
            .unwrap();
        let mut ctx = std::collections::HashMap::new();
        ctx.insert("required_clearance".to_string(), "5".to_string());
        assert!(
            !mgr.check_dynamic_permission("u15", "read", "secret", ctx)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_check_dynamic_permission_empty_params_rejected() {
        let mgr = make_manager();
        let ctx = std::collections::HashMap::new();
        assert!(
            mgr.check_dynamic_permission("", "r", "x", ctx.clone())
                .await
                .is_err()
        );
        assert!(
            mgr.check_dynamic_permission("u", "", "x", ctx.clone())
                .await
                .is_err()
        );
        assert!(
            mgr.check_dynamic_permission("u", "r", "", ctx)
                .await
                .is_err()
        );
    }

    // ── create_resource ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_resource() {
        let mgr = make_manager();
        mgr.create_resource("documents").await.unwrap();
        let data = mgr.storage.get_kv("resource:documents").await.unwrap();
        assert!(data.is_some());
    }

    #[tokio::test]
    async fn test_create_resource_empty_name_rejected() {
        let mgr = make_manager();
        assert!(mgr.create_resource("").await.is_err());
    }

    // ── delegate_permission ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_delegate_permission_success() {
        let mgr = make_manager();
        mgr.grant_permission("delegator", "read", "files")
            .await
            .unwrap();
        mgr.delegate_permission(
            "delegator",
            "delegatee",
            "read",
            "files",
            std::time::Duration::from_secs(3600),
        )
        .await
        .unwrap();
        let delegations = mgr.get_active_delegations("delegatee").await.unwrap();
        assert!(!delegations.is_empty());
    }

    #[tokio::test]
    async fn test_delegate_permission_without_holding_it() {
        let mgr = make_manager();
        let result = mgr
            .delegate_permission(
                "delegator",
                "delegatee",
                "write",
                "files",
                std::time::Duration::from_secs(3600),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delegate_permission_empty_params_rejected() {
        let mgr = make_manager();
        let dur = std::time::Duration::from_secs(60);
        assert!(
            mgr.delegate_permission("", "d", "a", "r", dur)
                .await
                .is_err()
        );
        assert!(
            mgr.delegate_permission("d", "", "a", "r", dur)
                .await
                .is_err()
        );
        assert!(
            mgr.delegate_permission("d", "d2", "", "r", dur)
                .await
                .is_err()
        );
        assert!(
            mgr.delegate_permission("d", "d2", "a", "", dur)
                .await
                .is_err()
        );
    }

    // ── get_active_delegations ──────────────────────────────────────────

    #[tokio::test]
    async fn test_get_active_delegations_empty() {
        let mgr = make_manager();
        let delegations = mgr.get_active_delegations("nobody").await.unwrap();
        assert!(delegations.is_empty());
    }

    #[tokio::test]
    async fn test_get_active_delegations_empty_user_rejected() {
        let mgr = make_manager();
        assert!(mgr.get_active_delegations("").await.is_err());
    }

    // ── get_permission_metrics ──────────────────────────────────────────

    #[tokio::test]
    async fn test_get_permission_metrics() {
        let mgr = make_manager();
        mgr.create_default_roles().await;
        mgr.create_role(Role::new("custom")).await.unwrap();
        let metrics = mgr.get_permission_metrics(10, 100).await.unwrap();
        assert!(metrics.get("total_roles").copied().unwrap_or(0) > 0);
        assert_eq!(metrics["active_sessions"], 10);
        assert_eq!(metrics["permission_checks_last_hour"], 100);
    }

    // ── get_metrics ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_metrics() {
        let mgr = make_manager();
        mgr.create_role(Role::new("m")).await.unwrap();
        mgr.grant_permission("u16", "a", "r").await.unwrap();
        let (roles, users, perms) = mgr.get_metrics().await;
        assert!(roles >= 1);
        assert!(users >= 1);
        assert!(perms >= 1);
    }
}
