// SPDX-License-Identifier: MIT OR Apache-2.0
//! Enhanced Authorization Service using role-system v1.0
//!
//! This service provides a unified interface for all authorization operations,
//! replacing the fragmented authorization systems in AuthFramework.

use crate::errors::{AuthError, Result};
use role_system::{
    Permission, Resource, Role, Subject,
    async_support::{AsyncRoleSystem, AsyncRoleSystemBuilder},
    storage::{MemoryStorage, Storage},
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, info, warn};

/// Enhanced authorization service providing enterprise-grade RBAC
pub struct AuthorizationService<S = MemoryStorage>
where
    S: Storage + Send + Sync + Clone,
{
    /// The async role system from role-system v1.0
    pub role_system: AsyncRoleSystem<S>,

    /// Configuration for the service
    config: AuthorizationConfig,

    /// Cloned handle to the underlying storage, held behind a Mutex so that
    /// mutation operations not exposed by AsyncRoleSystem (e.g. delete_role)
    /// can be performed without requiring mutable access to the whole service.
    ///
    /// For MemoryStorage (the default) the clone shares the same `Arc<DashMap>`
    /// as the storage inside role_system, so mutations are immediately visible.
    storage_handle: Arc<TokioMutex<S>>,
}

/// Configuration for the authorization service
#[derive(Debug, Clone)]
pub struct AuthorizationConfig {
    /// Enable audit logging
    pub enable_audit: bool,

    /// Enable permission caching
    pub enable_caching: bool,

    /// Cache TTL in seconds
    pub cache_ttl_seconds: u64,

    /// Maximum role hierarchy depth
    pub max_hierarchy_depth: usize,
}

impl Default for AuthorizationConfig {
    fn default() -> Self {
        Self {
            enable_audit: true,
            enable_caching: true,
            cache_ttl_seconds: 300, // 5 minutes
            max_hierarchy_depth: 10,
        }
    }
}

impl AuthorizationService<MemoryStorage> {
    /// Create a new authorization service with default configuration
    pub async fn new() -> Result<Self> {
        Self::with_config(AuthorizationConfig::default()).await
    }

    /// Create a new authorization service with custom configuration
    pub async fn with_config(config: AuthorizationConfig) -> Result<Self> {
        let storage = MemoryStorage::new();
        // The clone shares the same Arc<DashMap> so mutations via storage_handle
        // are immediately reflected in the role_system's internal storage.
        let storage_handle = Arc::new(TokioMutex::new(storage.clone()));

        let role_system = AsyncRoleSystemBuilder::new().build_with_storage(storage);

        let service = Self {
            role_system,
            config,
            storage_handle,
        };

        // Initialize with standard AuthFramework roles
        service.initialize_authframework_roles().await?;

        info!("AuthorizationService initialized with enhanced RBAC");
        Ok(service)
    }
}

impl<S> AuthorizationService<S>
where
    S: Storage + Send + Sync + Clone + Default,
{
    /// Create authorization service with custom storage
    pub async fn with_storage(storage: S, config: AuthorizationConfig) -> Result<Self> {
        let storage_handle = Arc::new(TokioMutex::new(storage.clone()));
        // Build role system without RoleSystemConfig for now
        let role_system = AsyncRoleSystemBuilder::new().build_with_storage(storage);

        let service = Self {
            role_system,
            config,
            storage_handle,
        };

        service.initialize_authframework_roles().await?;

        info!("AuthorizationService initialized with custom storage");
        Ok(service)
    }

    /// Initialize standard AuthFramework roles
    async fn initialize_authframework_roles(&self) -> Result<()> {
        info!("Initializing AuthFramework standard roles");

        // Create guest role (minimal permissions)
        let guest_role = Role::new("guest")
            .with_description("Unauthenticated user with minimal access")
            .add_permission(Permission::new("read", "public"));

        // Create user role (authenticated user)
        let user_role = Role::new("user")
            .with_description("Authenticated user")
            .add_permission(Permission::new("read", "profile"))
            .add_permission(Permission::new("update", "profile:own"))
            .add_permission(Permission::new("read", "public"));

        // Create moderator role (content moderation)
        let moderator_role = Role::new("moderator")
            .with_description("Content moderator")
            .add_permission(Permission::new("read", "*"))
            .add_permission(Permission::new("update", "content"))
            .add_permission(Permission::new("delete", "content"));

        // Create admin role (system administration)
        let admin_role = Role::new("admin")
            .with_description("System administrator")
            .add_permission(Permission::super_admin());

        // Register roles
        self.role_system
            .register_role(guest_role)
            .await
            .map_err(|e| {
                AuthError::authorization(format!("Failed to register guest role: {}", e))
            })?;

        self.role_system
            .register_role(user_role)
            .await
            .map_err(|e| {
                AuthError::authorization(format!("Failed to register user role: {}", e))
            })?;

        self.role_system
            .register_role(moderator_role)
            .await
            .map_err(|e| {
                AuthError::authorization(format!("Failed to register moderator role: {}", e))
            })?;

        self.role_system
            .register_role(admin_role)
            .await
            .map_err(|e| {
                AuthError::authorization(format!("Failed to register admin role: {}", e))
            })?;

        // Set up role hierarchy: admin -> moderator -> user -> guest
        self.role_system
            .add_role_inheritance("admin", "moderator")
            .await
            .map_err(|e| {
                AuthError::authorization(format!(
                    "Failed to set admin->moderator inheritance: {}",
                    e
                ))
            })?;

        self.role_system
            .add_role_inheritance("moderator", "user")
            .await
            .map_err(|e| {
                AuthError::authorization(format!(
                    "Failed to set moderator->user inheritance: {}",
                    e
                ))
            })?;

        self.role_system
            .add_role_inheritance("user", "guest")
            .await
            .map_err(|e| {
                AuthError::authorization(format!("Failed to set user->guest inheritance: {}", e))
            })?;

        info!("AuthFramework standard roles initialized successfully");
        Ok(())
    }

    /// Check if a user has permission to perform an action on a resource
    pub async fn check_permission(
        &self,
        user_id: &str,
        action: &str,
        resource_type: &str,
        context: Option<&HashMap<String, String>>,
    ) -> Result<bool> {
        debug!(
            "Checking permission for user '{}': {}:{}",
            user_id, action, resource_type
        );

        let subject = Subject::user(user_id);
        // Create resource with resource_type as the type and no specific instance
        let resource = Resource::new("", resource_type); // Empty ID, resource_type as type

        let result = if let Some(context) = context {
            self.role_system
                .check_permission_with_context(&subject, action, &resource, context)
                .await
        } else {
            self.role_system
                .check_permission(&subject, action, &resource)
                .await
        };

        // Audit logging based on configuration
        if self.config.enable_audit {
            info!(
                target: "authorization_audit",
                user_id = user_id,
                action = action,
                resource_type = resource_type,
                permission_granted = result.is_ok() && *result.as_ref().unwrap_or(&false),
                timestamp = chrono::Utc::now().to_rfc3339(),
                "Permission check performed"
            );
        }

        match result {
            Ok(granted) => {
                debug!("Permission check result: {}", granted);
                Ok(granted)
            }
            Err(e) => {
                warn!("Permission check failed: {}", e);
                Err(AuthError::authorization(format!(
                    "Permission check failed: {}",
                    e
                )))
            }
        }
    }

    /// Check API endpoint permission
    pub async fn check_api_permission(
        &self,
        user_id: &str,
        method: &str,
        endpoint: &str,
        context: &HashMap<String, String>,
    ) -> Result<bool> {
        // Convert HTTP method to action
        let action = match method.to_uppercase().as_str() {
            "GET" => "read",
            "POST" => "create",
            "PUT" | "PATCH" => "update",
            "DELETE" => "delete",
            _ => "access",
        };

        self.check_permission(user_id, action, endpoint, Some(context))
            .await
    }

    /// Assign a role to a user
    pub async fn assign_role(&self, user_id: &str, role_name: &str) -> Result<()> {
        debug!("Assigning role '{}' to user '{}'", role_name, user_id);

        let subject = Subject::user(user_id);

        self.role_system
            .assign_role(&subject, role_name)
            .await
            .map_err(|e| AuthError::authorization(format!("Failed to assign role: {}", e)))?;

        info!("Role '{}' assigned to user '{}'", role_name, user_id);
        Ok(())
    }

    /// Remove a role from a user
    pub async fn remove_role(&self, user_id: &str, role_name: &str) -> Result<()> {
        debug!("Removing role '{}' from user '{}'", role_name, user_id);

        let subject = Subject::user(user_id);

        self.role_system
            .remove_role(&subject, role_name)
            .await
            .map_err(|e| AuthError::authorization(format!("Failed to remove role: {}", e)))?;

        info!("Role '{}' removed from user '{}'", role_name, user_id);
        Ok(())
    }

    /// Temporarily elevate a user's role
    pub async fn elevate_role(
        &self,
        user_id: &str,
        role_name: &str,
        duration_seconds: Option<u64>,
    ) -> Result<()> {
        debug!(
            "Elevating user '{}' to role '{}' for {:?} seconds",
            user_id, role_name, duration_seconds
        );

        let subject = Subject::user(user_id);
        let duration = duration_seconds.map(std::time::Duration::from_secs);

        self.role_system
            .elevate_role(&subject, role_name, duration)
            .await
            .map_err(|e| AuthError::authorization(format!("Failed to elevate role: {}", e)))?;

        info!(
            "User '{}' elevated to role '{}' for {:?} seconds",
            user_id, role_name, duration_seconds
        );
        Ok(())
    }

    /// Get all roles assigned to a user
    pub async fn get_user_roles(&self, user_id: &str) -> Result<Vec<String>> {
        let subject = Subject::user(user_id);

        let roles = self
            .role_system
            .get_subject_roles(&subject)
            .await
            .map_err(|e| AuthError::authorization(format!("Failed to get user roles: {}", e)))?;

        Ok(roles.into_iter().collect())
    }

    /// Create a new role
    pub async fn create_role(
        &self,
        name: &str,
        description: &str,
        permissions: Vec<Permission>,
        parent_roles: Option<Vec<String>>,
    ) -> Result<()> {
        debug!(
            "Creating role '{}' with {} permissions",
            name,
            permissions.len()
        );

        let mut role = Role::new(name).with_description(description);

        for permission in permissions {
            role = role.add_permission(permission);
        }

        self.role_system
            .register_role(role)
            .await
            .map_err(|e| AuthError::authorization(format!("Failed to create role: {}", e)))?;

        // Set up inheritance if specified
        if let Some(parents) = parent_roles {
            for parent in parents {
                self.role_system
                    .add_role_inheritance(name, &parent)
                    .await
                    .map_err(|e| {
                        AuthError::authorization(format!("Failed to set role inheritance: {}", e))
                    })?;
            }
        }

        info!("Role '{}' created successfully", name);
        Ok(())
    }

    /// Get role hierarchy (using new role-system v1.1.1 features)
    pub async fn get_role_hierarchy(&self, role_id: &str) -> Result<Vec<String>> {
        // For now, use the working single role approach with parent_role_id
        if let Ok(Some(role)) = self.role_system.get_role(role_id).await {
            let mut result = vec![role.id().to_string()];
            if let Some(parent_id) = role.parent_role_id() {
                result.push(parent_id.to_string());
            }
            Ok(result)
        } else {
            Ok(vec![])
        }
    }

    /// Test role hierarchy metadata access
    pub async fn get_role_metadata(&self, role_id: &str) -> Result<String> {
        if let Ok(Some(role)) = self.role_system.get_role(role_id).await {
            let depth = role.hierarchy_depth();
            let is_root = role.is_root_role();
            let is_leaf = role.is_leaf_role();
            let children = role.child_role_ids();

            Ok(format!(
                "Role '{}': depth={}, root={}, leaf={}, children={:?}",
                role.name(),
                depth,
                is_root,
                is_leaf,
                children
            ))
        } else {
            Err(AuthError::authorization("Role not found".to_string()))
        }
    }

    /// Delete a role
    pub async fn delete_role(&self, name: &str) -> Result<()> {
        // Verify the role actually exists before attempting deletion.
        let exists = self
            .role_system
            .get_role(name)
            .await
            .map_err(|e| AuthError::authorization(format!("Failed to look up role: {}", e)))?;

        if exists.is_none() {
            return Err(AuthError::authorization(format!(
                "Role '{}' not found",
                name
            )));
        }

        // Acquire the storage handle and call delete_role.
        // For MemoryStorage the underlying Arc<DashMap> is shared between this
        // handle and the role_system, so the deletion is immediately visible.
        let mut storage = self.storage_handle.lock().await;
        match storage.delete_role(name) {
            Ok(true) => {
                info!("Role deleted: {}", name);
                Ok(())
            }
            Ok(false) => {
                // Row already gone – treat as success (idempotent delete).
                warn!("delete_role: role '{}' was not found in storage", name);
                Ok(())
            }
            Err(e) => Err(AuthError::authorization(format!(
                "Failed to delete role '{}': {}",
                name, e
            ))),
        }
    }

    /// Get role by name
    pub async fn get_role(&self, name: &str) -> Result<Option<Role>> {
        self.role_system
            .get_role(name)
            .await
            .map_err(|e| AuthError::authorization(format!("Failed to get role: {}", e)))
    }

    /// Update an existing role's description and/or parent relationship.
    ///
    /// Permissions are not changed by this method; use create_role to start fresh
    /// or extend the API with a dedicated permission-update path if needed.
    pub async fn update_role(
        &self,
        name: &str,
        new_description: Option<&str>,
        new_parent_id: Option<Option<&str>>,
    ) -> Result<()> {
        let role = self
            .role_system
            .get_role(name)
            .await
            .map_err(|e| AuthError::authorization(format!("Failed to look up role: {}", e)))?
            .ok_or_else(|| AuthError::authorization(format!("Role '{}' not found", name)))?;

        // Rebuild the role with the updated fields, preserving id and permissions
        let mut updated = Role::with_id(role.id(), role.name());

        let description = new_description
            .map(|s| s.to_string())
            .or_else(|| role.description().map(|s| s.to_string()));
        if let Some(desc) = description {
            updated = updated.with_description(desc);
        }

        // Carry over existing permissions
        for perm in role.permissions().permissions() {
            updated = updated.add_permission(perm.clone());
        }

        // Apply the update to underlying storage
        let mut storage = self.storage_handle.lock().await;
        storage
            .update_role(updated)
            .map_err(|e| AuthError::authorization(format!("Failed to update role: {}", e)))?;
        drop(storage);

        // Handle parent-role change if requested
        if let Some(new_parent) = new_parent_id {
            // Remove old inheritance if any parent was set
            if let Some(old_parent) = role.parent_role_id() {
                let _ = self
                    .role_system
                    .remove_role_inheritance(name, old_parent)
                    .await;
            }
            if let Some(parent) = new_parent {
                self.role_system
                    .add_role_inheritance(name, parent)
                    .await
                    .map_err(|e| {
                        AuthError::authorization(format!(
                            "Failed to update role inheritance: {}",
                            e
                        ))
                    })?;
            }
        }

        info!("Role '{}' updated", name);
        Ok(())
    }

    /// List all registered role names.
    pub async fn list_roles(&self) -> Result<Vec<Role>> {
        let storage = self.storage_handle.lock().await;
        let names = storage
            .list_roles()
            .map_err(|e| AuthError::authorization(format!("Failed to list roles: {}", e)))?;
        drop(storage);

        // Fetch the full Role object for each name
        let mut roles = Vec::with_capacity(names.len());
        for name in names {
            if let Ok(Some(role)) = self.role_system.get_role(&name).await {
                roles.push(role);
            }
        }
        Ok(roles)
    }

    /// Batch check multiple permissions
    pub async fn batch_check_permissions(
        &self,
        user_id: &str,
        checks: &[(String, String)], // (action, resource) pairs
    ) -> Result<Vec<(String, String, bool)>> {
        let subject = Subject::user(user_id);

        let resource_checks: Vec<(String, Resource)> = checks
            .iter()
            .map(|(action, resource)| (action.clone(), Resource::new(resource, "api")))
            .collect();

        let results = self
            .role_system
            .batch_check_permissions(&subject, &resource_checks)
            .await
            .map_err(|e| {
                AuthError::authorization(format!("Batch permission check failed: {}", e))
            })?;

        Ok(results
            .into_iter()
            .map(|(action, resource, granted)| {
                (
                    action,
                    resource.name().unwrap_or("unknown").to_string(),
                    granted,
                )
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_authorization_service_creation() {
        let service = AuthorizationService::new().await.unwrap();

        // Test that standard roles were created
        let roles = ["guest", "user", "moderator", "admin"];
        for role_name in &roles {
            let role = service.get_role(role_name).await.unwrap();
            assert!(role.is_some(), "Role '{}' should exist", role_name);
        }
    }

    #[tokio::test]
    async fn test_role_assignment_and_permission_check() {
        let service = AuthorizationService::new().await.unwrap();

        // Assign user role
        service.assign_role("test_user", "user").await.unwrap();

        // Check permissions
        let can_read_profile = service
            .check_permission("test_user", "read", "profile", None)
            .await
            .unwrap();
        assert!(can_read_profile, "User should have read access to profile");

        let can_admin = service
            .check_permission("test_user", "admin", "system", None)
            .await
            .unwrap();
        assert!(!can_admin);
    }

    #[tokio::test]
    async fn test_role_hierarchy() {
        let service = AuthorizationService::new().await.unwrap();

        // Assign admin role
        service.assign_role("admin_user", "admin").await.unwrap();

        // Admin should have user permissions through inheritance
        let can_read_profile = service
            .check_permission("admin_user", "read", "profile", None)
            .await
            .unwrap();
        assert!(can_read_profile);

        // Admin should have admin permissions
        let can_admin = service
            .check_permission("admin_user", "admin", "system", None)
            .await
            .unwrap();
        assert!(can_admin);
    }
}
