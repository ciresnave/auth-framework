//! Role-Based Access Control (RBAC) and Authorization framework.
//!
//! This module provides a comprehensive authorization system with support for
//! roles, permissions, hierarchical access control, and dynamic policy evaluation.

use crate::errors::{AuthError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

/// A permission represents a specific action that can be performed on a resource
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission {
    /// The resource being accessed (e.g., "users", "documents", "api")
    pub resource: String,
    /// The action being performed (e.g., "read", "write", "delete", "admin")
    pub action: String,
    /// Optional conditions for the permission
    pub conditions: Option<AccessCondition>,
    /// Optional resource-specific attributes (as key-value pairs)
    pub attributes: Vec<(String, String)>,
}

impl Permission {
    /// Create a new permission
    pub fn new(resource: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            action: action.into(),
            conditions: None,
            attributes: Vec::new(),
        }
    }

    /// Add a condition to this permission
    pub fn with_condition(mut self, condition: AccessCondition) -> Self {
        self.conditions = Some(condition);
        self
    }

    /// Add an attribute to this permission
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.push((key.into(), value.into()));
        self
    }

    /// Check if this permission matches a requested permission
    pub fn matches(&self, requested: &Permission, context: &AccessContext) -> bool {
        // Resource and action must match
        if self.resource != requested.resource || self.action != requested.action {
            return false;
        }

        // Check conditions if present
        if let Some(condition) = &self.conditions {
            return condition.evaluate(context);
        }

        true
    }
}

/// Access conditions for dynamic permission evaluation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessCondition {
    /// Time-based access (only allow during certain hours)
    TimeRange {
        start_hour: u8,
        end_hour: u8,
        timezone: String,
    },
    /// Location-based access
    IpWhitelist(Vec<String>),
    /// User attribute condition
    UserAttribute {
        attribute: String,
        value: String,
        operator: ComparisonOperator,
    },
    /// Resource attribute condition
    ResourceAttribute {
        attribute: String,
        value: String,
        operator: ComparisonOperator,
    },
    /// Combine multiple conditions
    And(Vec<AccessCondition>),
    Or(Vec<AccessCondition>),
    Not(Box<AccessCondition>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComparisonOperator {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    Contains,
    StartsWith,
    EndsWith,
}

impl AccessCondition {
    /// Evaluate the condition against the given context
    pub fn evaluate(&self, context: &AccessContext) -> bool {
        match self {
            AccessCondition::TimeRange {
                start_hour,
                end_hour,
                timezone: _,
            } => {
                // Simplified time check (in production, handle timezones properly)
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let hour = ((now / 3600) % 24) as u8;
                hour >= *start_hour && hour <= *end_hour
            }
            AccessCondition::IpWhitelist(ips) => context
                .ip_address
                .as_ref()
                .map(|ip| ips.contains(ip))
                .unwrap_or(false),
            AccessCondition::UserAttribute {
                attribute,
                value,
                operator,
            } => context
                .user_attributes
                .get(attribute)
                .map(|attr_value| compare_values(attr_value, value, operator))
                .unwrap_or(false),
            AccessCondition::ResourceAttribute {
                attribute,
                value,
                operator,
            } => context
                .resource_attributes
                .get(attribute)
                .map(|attr_value| compare_values(attr_value, value, operator))
                .unwrap_or(false),
            AccessCondition::And(conditions) => conditions.iter().all(|c| c.evaluate(context)),
            AccessCondition::Or(conditions) => conditions.iter().any(|c| c.evaluate(context)),
            AccessCondition::Not(condition) => !condition.evaluate(context),
        }
    }
}

fn compare_values(left: &str, right: &str, operator: &ComparisonOperator) -> bool {
    match operator {
        ComparisonOperator::Equals => left == right,
        ComparisonOperator::NotEquals => left != right,
        ComparisonOperator::GreaterThan => left > right,
        ComparisonOperator::LessThan => left < right,
        ComparisonOperator::Contains => left.contains(right),
        ComparisonOperator::StartsWith => left.starts_with(right),
        ComparisonOperator::EndsWith => left.ends_with(right),
    }
}

/// A role groups permissions and can be assigned to users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Unique role identifier
    pub id: String,
    /// Human-readable role name
    pub name: String,
    /// Role description
    pub description: String,
    /// Permissions granted by this role
    pub permissions: HashSet<Permission>,
    /// Parent roles (for hierarchical RBAC)
    pub parent_roles: HashSet<String>,
    /// Role metadata
    pub metadata: HashMap<String, String>,
    /// When the role was created
    pub created_at: SystemTime,
    /// When the role was last modified
    pub updated_at: SystemTime,
}

impl Role {
    /// Create a new role
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        let now = SystemTime::now();
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            permissions: HashSet::new(),
            parent_roles: HashSet::new(),
            metadata: HashMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Add a permission to this role
    pub fn add_permission(&mut self, permission: Permission) {
        self.permissions.insert(permission);
        self.updated_at = SystemTime::now();
    }

    /// Remove a permission from this role
    pub fn remove_permission(&mut self, permission: &Permission) {
        self.permissions.remove(permission);
        self.updated_at = SystemTime::now();
    }

    /// Add a parent role
    pub fn add_parent_role(&mut self, role_id: impl Into<String>) {
        self.parent_roles.insert(role_id.into());
        self.updated_at = SystemTime::now();
    }

    /// Check if this role has a specific permission
    pub fn has_permission(&self, permission: &Permission, context: &AccessContext) -> bool {
        self.permissions
            .iter()
            .any(|p| p.matches(permission, context))
    }
}

/// Context information for access control decisions
#[derive(Debug, Clone)]
pub struct AccessContext {
    /// User ID making the request
    pub user_id: String,
    /// User attributes (department, level, etc.)
    pub user_attributes: HashMap<String, String>,
    /// Resource being accessed
    pub resource_id: Option<String>,
    /// Resource attributes
    pub resource_attributes: HashMap<String, String>,
    /// Request IP address
    pub ip_address: Option<String>,
    /// Request timestamp
    pub timestamp: SystemTime,
    /// Additional context data
    pub metadata: HashMap<String, String>,
}

impl AccessContext {
    /// Create a new access context
    pub fn new(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            user_attributes: HashMap::new(),
            resource_id: None,
            resource_attributes: HashMap::new(),
            ip_address: None,
            timestamp: SystemTime::now(),
            metadata: HashMap::new(),
        }
    }

    /// Add user attribute
    pub fn with_user_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.user_attributes.insert(key.into(), value.into());
        self
    }

    /// Set resource information
    pub fn with_resource(mut self, resource_id: impl Into<String>) -> Self {
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Add resource attribute
    pub fn with_resource_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.resource_attributes.insert(key.into(), value.into());
        self
    }

    /// Set IP address
    pub fn with_ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }
}

/// User role assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRole {
    /// User ID
    pub user_id: String,
    /// Role ID
    pub role_id: String,
    /// When the role was assigned
    pub assigned_at: SystemTime,
    /// Optional expiration time
    pub expires_at: Option<SystemTime>,
    /// Who assigned the role
    pub assigned_by: String,
}

/// Policy evaluation result
#[derive(Debug, Clone)]
pub struct AuthorizationResult {
    /// Whether access is granted
    pub granted: bool,
    /// Reason for the decision
    pub reason: String,
    /// Applicable permissions
    pub permissions: Vec<Permission>,
    /// Policy evaluation time
    pub evaluation_time: std::time::Duration,
}

/// Authorization storage trait
#[async_trait]
pub trait AuthorizationStorage: Send + Sync {
    /// Store a role
    async fn store_role(&self, role: &Role) -> Result<()>;

    /// Get a role by ID
    async fn get_role(&self, role_id: &str) -> Result<Option<Role>>;

    /// Update a role
    async fn update_role(&self, role: &Role) -> Result<()>;

    /// Delete a role
    async fn delete_role(&self, role_id: &str) -> Result<()>;

    /// List all roles
    async fn list_roles(&self) -> Result<Vec<Role>>;

    /// Assign a role to a user
    async fn assign_role(&self, user_role: &UserRole) -> Result<()>;

    /// Remove a role from a user
    async fn remove_role(&self, user_id: &str, role_id: &str) -> Result<()>;

    /// Get user's roles
    async fn get_user_roles(&self, user_id: &str) -> Result<Vec<UserRole>>;

    /// Get users with a specific role
    async fn get_role_users(&self, role_id: &str) -> Result<Vec<UserRole>>;
}

/// Authorization engine for evaluating permissions
pub struct AuthorizationEngine<S: AuthorizationStorage> {
    storage: S,
    role_cache: std::sync::RwLock<HashMap<String, Role>>,
}

impl<S: AuthorizationStorage> AuthorizationEngine<S> {
    /// Create a new authorization engine
    pub fn new(storage: S) -> Self {
        Self {
            storage,
            role_cache: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Check if a user has permission to perform an action
    pub async fn check_permission(
        &self,
        user_id: &str,
        permission: &Permission,
        context: &AccessContext,
    ) -> Result<AuthorizationResult> {
        let start_time = std::time::Instant::now();

        // Get user's roles
        let user_roles = self.storage.get_user_roles(user_id).await?;

        let mut applicable_permissions = Vec::new();
        let mut granted = false;
        let mut reason = "No matching permissions found".to_string();

        for user_role in user_roles {
            // Check if role assignment is still valid
            if let Some(expires_at) = user_role.expires_at
                && SystemTime::now() > expires_at
            {
                continue;
            }

            // Get role permissions (including inherited)
            let role_permissions = self.get_role_permissions(&user_role.role_id).await?;

            for role_permission in role_permissions {
                if role_permission.matches(permission, context) {
                    applicable_permissions.push(role_permission);
                    granted = true;
                    reason = format!("Permission granted via role: {}", user_role.role_id);
                    break;
                }
            }

            if granted {
                break;
            }
        }

        let evaluation_time = start_time.elapsed();

        Ok(AuthorizationResult {
            granted,
            reason,
            permissions: applicable_permissions,
            evaluation_time,
        })
    }

    /// Get all permissions for a role (including inherited permissions)
    async fn get_role_permissions(&self, role_id: &str) -> Result<Vec<Permission>> {
        let mut all_permissions = Vec::new();
        let mut visited_roles = HashSet::new();

        self.collect_role_permissions(role_id, &mut all_permissions, &mut visited_roles)
            .await?;

        Ok(all_permissions)
    }

    /// Recursively collect permissions from role hierarchy
    fn collect_role_permissions<'a>(
        &'a self,
        role_id: &'a str,
        permissions: &'a mut Vec<Permission>,
        visited: &'a mut HashSet<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            // Prevent infinite loops
            if visited.contains(role_id) {
                return Ok(());
            }
            visited.insert(role_id.to_string());

            // Get role from cache or storage
            let role = match self.get_cached_role(role_id).await? {
                Some(role) => role,
                None => return Ok(()),
            };

            // Add role's direct permissions
            permissions.extend(role.permissions.iter().cloned());

            // Recursively collect from parent roles
            for parent_role_id in &role.parent_roles {
                self.collect_role_permissions(parent_role_id, permissions, visited)
                    .await?;
            }

            Ok(())
        })
    }

    /// Get role from cache or storage
    async fn get_cached_role(&self, role_id: &str) -> Result<Option<Role>> {
        // Check cache first
        {
            let cache = self
                .role_cache
                .read()
                .map_err(|_| AuthError::internal("Failed to acquire role cache lock"))?;
            if let Some(role) = cache.get(role_id) {
                return Ok(Some(role.clone()));
            }
        }

        // Load from storage
        if let Some(role) = self.storage.get_role(role_id).await? {
            // Update cache
            {
                let mut cache = self
                    .role_cache
                    .write()
                    .map_err(|_| AuthError::internal("Failed to acquire role cache lock"))?;
                cache.insert(role_id.to_string(), role.clone());
            }
            Ok(Some(role))
        } else {
            Ok(None)
        }
    }

    /// Invalidate role cache
    pub fn invalidate_role_cache(&self, role_id: &str) -> Result<()> {
        let mut cache = self
            .role_cache
            .write()
            .map_err(|_| AuthError::internal("Failed to acquire role cache lock"))?;
        cache.remove(role_id);
        Ok(())
    }

    /// Create a new role
    pub async fn create_role(&self, role: Role) -> Result<()> {
        self.storage.store_role(&role).await?;
        self.invalidate_role_cache(&role.id)?;
        Ok(())
    }

    /// Assign a role to a user
    pub async fn assign_role(&self, user_id: &str, role_id: &str, assigned_by: &str) -> Result<()> {
        // Verify role exists
        if self.storage.get_role(role_id).await?.is_none() {
            return Err(AuthError::validation(format!(
                "Role '{}' does not exist",
                role_id
            )));
        }

        let user_role = UserRole {
            user_id: user_id.to_string(),
            role_id: role_id.to_string(),
            assigned_at: SystemTime::now(),
            expires_at: None,
            assigned_by: assigned_by.to_string(),
        };

        self.storage.assign_role(&user_role).await
    }

    /// Check if user has any of the specified roles
    pub async fn has_any_role(&self, user_id: &str, role_ids: &[String]) -> Result<bool> {
        let user_roles = self.storage.get_user_roles(user_id).await?;
        Ok(user_roles.iter().any(|ur| role_ids.contains(&ur.role_id)))
    }
}

/// Predefined permissions for common operations
pub struct CommonPermissions;

impl CommonPermissions {
    /// User management permissions
    pub fn user_read() -> Permission {
        Permission::new("users", "read")
    }

    pub fn user_write() -> Permission {
        Permission::new("users", "write")
    }

    pub fn user_delete() -> Permission {
        Permission::new("users", "delete")
    }

    pub fn user_admin() -> Permission {
        Permission::new("users", "admin")
    }

    /// Document management permissions
    pub fn document_read() -> Permission {
        Permission::new("documents", "read")
    }

    pub fn document_write() -> Permission {
        Permission::new("documents", "write")
    }

    pub fn document_delete() -> Permission {
        Permission::new("documents", "delete")
    }

    /// API access permissions
    pub fn api_read() -> Permission {
        Permission::new("api", "read")
    }

    pub fn api_write() -> Permission {
        Permission::new("api", "write")
    }

    /// System administration permissions
    pub fn system_admin() -> Permission {
        Permission::new("system", "admin")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_matching() {
        let context = AccessContext::new("user123");

        let permission = Permission::new("users", "read");
        let requested = Permission::new("users", "read");

        assert!(permission.matches(&requested, &context));

        let different_action = Permission::new("users", "write");
        assert!(!permission.matches(&different_action, &context));
    }

    #[test]
    fn test_access_condition_evaluation() {
        let mut context = AccessContext::new("user123");
        context
            .user_attributes
            .insert("department".to_string(), "engineering".to_string());

        let condition = AccessCondition::UserAttribute {
            attribute: "department".to_string(),
            value: "engineering".to_string(),
            operator: ComparisonOperator::Equals,
        };

        assert!(condition.evaluate(&context));

        let wrong_condition = AccessCondition::UserAttribute {
            attribute: "department".to_string(),
            value: "sales".to_string(),
            operator: ComparisonOperator::Equals,
        };

        assert!(!wrong_condition.evaluate(&context));
    }

    #[test]
    fn test_role_hierarchy() {
        let mut admin_role = Role::new("admin", "Administrator");
        admin_role.add_permission(CommonPermissions::system_admin());

        let mut manager_role = Role::new("manager", "Manager");
        manager_role.add_permission(CommonPermissions::user_write());
        manager_role.add_parent_role("admin");

        let context = AccessContext::new("user123");

        // Manager should have user_write permission
        assert!(manager_role.has_permission(&CommonPermissions::user_write(), &context));

        // But not system_admin (would need to check parent role)
        assert!(!manager_role.has_permission(&CommonPermissions::system_admin(), &context));
    }
}


