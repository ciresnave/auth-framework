//! Permission and role-based access control system.

use crate::errors::{PermissionError, Result};
use crate::tokens::AuthToken;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Represents a permission with action and resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission {
    /// The action being performed (e.g., "read", "write", "delete")
    pub action: String,
    
    /// The resource being accessed (e.g., "documents", "users", "settings")
    pub resource: String,
    
    /// Optional resource instance (e.g., specific document ID)
    pub instance: Option<String>,
}

/// Represents a role with associated permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Role name
    pub name: String,
    
    /// Role description
    pub description: Option<String>,
    
    /// Permissions granted to this role
    pub permissions: HashSet<Permission>,
    
    /// Parent roles this role inherits from
    pub parent_roles: HashSet<String>,
    
    /// Whether this role is active
    pub active: bool,
}

/// User permissions and roles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPermissions {
    /// User ID
    pub user_id: String,
    
    /// Direct permissions granted to the user
    pub direct_permissions: HashSet<Permission>,
    
    /// Roles assigned to the user
    pub roles: HashSet<String>,
    
    /// Cached computed permissions (includes role permissions)
    pub computed_permissions: Option<HashSet<Permission>>,
    
    /// When the permissions were last updated
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Permission checker for validating access rights.
#[derive(Debug, Clone)]
pub struct PermissionChecker {
    /// All defined roles
    roles: HashMap<String, Role>,
    
    /// User permissions cache
    user_permissions: HashMap<String, UserPermissions>,
    
    /// Permission hierarchy (for resource hierarchies)
    #[allow(dead_code)]
    resource_hierarchy: HashMap<String, Vec<String>>,
}

impl Permission {
    /// Create a new permission.
    pub fn new(action: impl Into<String>, resource: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            resource: resource.into(),
            instance: None,
        }
    }

    /// Create a new permission with just an action (resource defaults to "*").
    pub fn from_action(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            resource: "*".to_string(),
            instance: None,
        }
    }

    /// Create a new permission with a specific instance.
    pub fn with_instance(
        action: impl Into<String>,
        resource: impl Into<String>,
        instance: impl Into<String>,
    ) -> Self {
        Self {
            action: action.into(),
            resource: resource.into(),
            instance: Some(instance.into()),
        }
    }

    /// Parse a permission from a string format "action:resource" or "action:resource:instance".
    pub fn parse(permission_str: &str) -> Result<Self> {
        let parts: Vec<&str> = permission_str.split(':').collect();
        
        match parts.len() {
            2 => Ok(Self::new(parts[0], parts[1])),
            3 => Ok(Self::with_instance(parts[0], parts[1], parts[2])),
            _ => Err(PermissionError::invalid_format(
                format!("Invalid permission format: {permission_str}")
            ).into()),
        }
    }

}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.instance {
            Some(instance) => write!(f, "{}:{}:{}", self.action, self.resource, instance),
            None => write!(f, "{}:{}", self.action, self.resource),
        }
    }
}

impl Permission {
    /// Check if this permission matches another permission (considering wildcards).
    pub fn matches(&self, other: &Permission) -> bool {
        // Check action
        if self.action != "*" && other.action != "*" && self.action != other.action {
            return false;
        }

        // Check resource
        if self.resource != "*" && other.resource != "*" && self.resource != other.resource {
            return false;
        }

        // Check instance
        match (&self.instance, &other.instance) {
            (Some(self_instance), Some(other_instance)) => {
                self_instance == "*" || other_instance == "*" || self_instance == other_instance
            }
            (None, None) => true,
            (Some(_), None) => false, // Specific instance doesn't match general permission
            (None, Some(_)) => true,  // General permission matches specific instance
        }
    }

    /// Check if this permission implies another permission.
    pub fn implies(&self, other: &Permission) -> bool {
        // A permission implies another if it's more general or equal
        let action_implies = self.action == "*" || self.action == other.action;
        let resource_implies = self.resource == "*" || self.resource == other.resource;
        let instance_implies = match (&self.instance, &other.instance) {
            (None, _) => true,          // General permission implies specific
            (Some(self_instance), Some(other_instance)) => {
                self_instance == "*" || self_instance == other_instance
            }
            (Some(_), None) => false,   // Specific doesn't imply general
        };

        action_implies && resource_implies && instance_implies
    }
}

impl Role {
    /// Create a new role.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            permissions: HashSet::new(),
            parent_roles: HashSet::new(),
            active: true,
        }
    }

    /// Set the role description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Add a permission to the role.
    pub fn add_permission(&mut self, permission: Permission) {
        self.permissions.insert(permission);
    }

    /// Add multiple permissions to the role.
    pub fn with_permissions(mut self, permissions: Vec<Permission>) -> Self {
        for permission in permissions {
            self.permissions.insert(permission);
        }
        self
    }

    /// Remove a permission from the role.
    pub fn remove_permission(&mut self, permission: &Permission) {
        self.permissions.remove(permission);
    }

    /// Add a parent role.
    pub fn add_parent_role(&mut self, parent_role: impl Into<String>) {
        self.parent_roles.insert(parent_role.into());
    }

    /// Check if the role has a specific permission.
    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.permissions.iter().any(|p| p.implies(permission))
    }

    /// Get all permissions including inherited ones.
    pub fn get_all_permissions(&self, role_resolver: &dyn Fn(&str) -> Option<Role>) -> HashSet<Permission> {
        let mut all_permissions = self.permissions.clone();
        
        // Add permissions from parent roles
        for parent_role_name in &self.parent_roles {
            if let Some(parent_role) = role_resolver(parent_role_name) {
                all_permissions.extend(parent_role.get_all_permissions(role_resolver));
            }
        }
        
        all_permissions
    }

    /// Activate or deactivate the role.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }
}

impl UserPermissions {
    /// Create new user permissions.
    pub fn new(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            direct_permissions: HashSet::new(),
            roles: HashSet::new(),
            computed_permissions: None,
            last_updated: chrono::Utc::now(),
        }
    }

    /// Add a direct permission to the user.
    pub fn add_permission(&mut self, permission: Permission) {
        self.direct_permissions.insert(permission);
        self.computed_permissions = None; // Invalidate cache
        self.last_updated = chrono::Utc::now();
    }

    /// Remove a direct permission from the user.
    pub fn remove_permission(&mut self, permission: &Permission) {
        self.direct_permissions.remove(permission);
        self.computed_permissions = None; // Invalidate cache
        self.last_updated = chrono::Utc::now();
    }

    /// Add a role to the user.
    pub fn add_role(&mut self, role: impl Into<String>) {
        self.roles.insert(role.into());
        self.computed_permissions = None; // Invalidate cache
        self.last_updated = chrono::Utc::now();
    }

    /// Remove a role from the user.
    pub fn remove_role(&mut self, role: &str) {
        self.roles.remove(role);
        self.computed_permissions = None; // Invalidate cache
        self.last_updated = chrono::Utc::now();
    }

    /// Compute all permissions for the user (including role permissions).
    pub fn compute_permissions(&mut self, role_resolver: &dyn Fn(&str) -> Option<Role>) -> &HashSet<Permission> {
        if self.computed_permissions.is_none() {
            let mut all_permissions = self.direct_permissions.clone();
            
            // Add permissions from roles
            for role_name in &self.roles {
                if let Some(role) = role_resolver(role_name) {
                    if role.active {
                        all_permissions.extend(role.get_all_permissions(role_resolver));
                    }
                }
            }
            
            self.computed_permissions = Some(all_permissions);
        }
        
        self.computed_permissions.as_ref().unwrap()
    }

    /// Check if the user has a specific permission.
    pub fn has_permission(&mut self, permission: &Permission, role_resolver: &dyn Fn(&str) -> Option<Role>) -> bool {
        let all_permissions = self.compute_permissions(role_resolver);
        all_permissions.iter().any(|p| p.implies(permission))
    }
}

impl PermissionChecker {
    /// Create a new permission checker.
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
            user_permissions: HashMap::new(),
            resource_hierarchy: HashMap::new(),
        }
    }

    /// Add a role definition.
    pub fn add_role(&mut self, role: Role) {
        self.roles.insert(role.name.clone(), role);
    }

    /// Remove a role definition.
    pub fn remove_role(&mut self, role_name: &str) {
        self.roles.remove(role_name);
    }

    /// Get a role by name.
    pub fn get_role(&self, role_name: &str) -> Option<&Role> {
        self.roles.get(role_name)
    }

    /// Set user permissions.
    pub fn set_user_permissions(&mut self, user_permissions: UserPermissions) {
        self.user_permissions.insert(user_permissions.user_id.clone(), user_permissions);
    }

    /// Get user permissions.
    pub fn get_user_permissions(&self, user_id: &str) -> Option<&UserPermissions> {
        self.user_permissions.get(user_id)
    }

    /// Get mutable user permissions.
    pub fn get_user_permissions_mut(&mut self, user_id: &str) -> Option<&mut UserPermissions> {
        self.user_permissions.get_mut(user_id)
    }

    /// Add a permission to a user.
    pub fn add_user_permission(&mut self, user_id: &str, permission: Permission) {
        let user_perms = self.user_permissions
            .entry(user_id.to_string())
            .or_insert_with(|| UserPermissions::new(user_id));
        
        user_perms.add_permission(permission);
    }

    /// Add a role to a user.
    pub fn add_user_role(&mut self, user_id: &str, role: impl Into<String>) {
        let user_perms = self.user_permissions
            .entry(user_id.to_string())
            .or_insert_with(|| UserPermissions::new(user_id));
        
        user_perms.add_role(role);
    }

    /// Check if a user has a specific permission.
    pub fn check_permission(&mut self, user_id: &str, permission: &Permission) -> Result<bool> {
        let user_perms = self.user_permissions
            .get_mut(user_id)
            .ok_or_else(|| PermissionError::access_denied(
                permission.to_string(),
                "unknown user".to_string(),
            ))?;

        let role_resolver = |role_name: &str| self.roles.get(role_name).cloned();
        
        Ok(user_perms.has_permission(permission, &role_resolver))
    }

    /// Check if a user has permission for a specific action on a resource.
    pub fn check_access(&mut self, user_id: &str, action: &str, resource: &str) -> Result<bool> {
        let permission = Permission::new(action, resource);
        self.check_permission(user_id, &permission)
    }

    /// Check if a user has permission for a specific action on a resource instance.
    pub fn check_instance_access(
        &mut self,
        user_id: &str,
        action: &str,
        resource: &str,
        instance: &str,
    ) -> Result<bool> {
        let permission = Permission::with_instance(action, resource, instance);
        self.check_permission(user_id, &permission)
    }

    /// Check permission from an auth token.
    pub fn check_token_permission(&mut self, token: &AuthToken, permission: &Permission) -> Result<bool> {
        if !token.is_valid() {
            return Ok(false);
        }

        // Check if the token has the required scope
        let required_scope = permission.to_string();
        if !token.has_scope(&required_scope) {
            // Also check for wildcard scopes
            let wildcard_action = format!("*:{}", permission.resource);
            let wildcard_resource = format!("{}:*", permission.action);
            let wildcard_all = "*:*".to_string();
            
            if !token.has_scope(&wildcard_action) 
                && !token.has_scope(&wildcard_resource) 
                && !token.has_scope(&wildcard_all) {
                return Ok(false);
            }
        }

        // Check user permissions
        self.check_permission(&token.user_id, permission)
    }

    /// Create some default roles for common use cases.
    pub fn create_default_roles(&mut self) {
        // Admin role with all permissions
        let mut admin_role = Role::new("admin")
            .with_description("Administrator with full access");
        admin_role.add_permission(Permission::new("*", "*"));
        self.add_role(admin_role);

        // User role with basic permissions
        let mut user_role = Role::new("user")
            .with_description("Regular user with basic access");
        user_role.add_permission(Permission::new("read", "profile"));
        user_role.add_permission(Permission::new("write", "profile"));
        user_role.add_permission(Permission::new("read", "public"));
        self.add_role(user_role);

        // Guest role with read-only access
        let mut guest_role = Role::new("guest")
            .with_description("Guest user with read-only access");
        guest_role.add_permission(Permission::new("read", "public"));
        self.add_role(guest_role);
    }

    /// Load permissions from a configuration or database.
    pub fn load_permissions(&mut self, _config: &str) -> Result<()> {
        // This would typically load from a configuration file or database
        // For now, we'll create some default permissions
        self.create_default_roles();
        Ok(())
    }
}

impl Default for PermissionChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_parsing() {
        let perm = Permission::parse("read:documents").unwrap();
        assert_eq!(perm.action, "read");
        assert_eq!(perm.resource, "documents");
        assert_eq!(perm.instance, None);

        let perm = Permission::parse("write:documents:123").unwrap();
        assert_eq!(perm.action, "write");
        assert_eq!(perm.resource, "documents");
        assert_eq!(perm.instance, Some("123".to_string()));
    }

    #[test]
    fn test_permission_matching() {
        let perm1 = Permission::new("read", "documents");
        let perm2 = Permission::new("read", "documents");
        let perm3 = Permission::new("write", "documents");
        let wildcard = Permission::new("*", "documents");

        assert!(perm1.matches(&perm2));
        assert!(!perm1.matches(&perm3));
        assert!(wildcard.matches(&perm1));
        assert!(wildcard.matches(&perm3));
    }

    #[test]
    fn test_permission_implies() {
        let general = Permission::new("read", "documents");
        let specific = Permission::with_instance("read", "documents", "123");
        let wildcard = Permission::new("*", "*");

        assert!(general.implies(&specific));
        assert!(!specific.implies(&general));
        assert!(wildcard.implies(&general));
        assert!(wildcard.implies(&specific));
    }

    #[test]
    fn test_role_permissions() {
        let mut role = Role::new("editor");
        role.add_permission(Permission::new("read", "documents"));
        role.add_permission(Permission::new("write", "documents"));

        let read_perm = Permission::new("read", "documents");
        let delete_perm = Permission::new("delete", "documents");

        assert!(role.has_permission(&read_perm));
        assert!(!role.has_permission(&delete_perm));
    }

    #[test]
    fn test_user_permissions() {
        let mut user_perms = UserPermissions::new("user123");
        user_perms.add_permission(Permission::new("read", "profile"));
        user_perms.add_role("user");

        let role_resolver = |_: &str| Some(Role::new("user"));
        
        let read_perm = Permission::new("read", "profile");
        assert!(user_perms.has_permission(&read_perm, &role_resolver));
    }

    #[test]
    fn test_permission_checker() {
        let mut checker = PermissionChecker::new();
        checker.create_default_roles();

        checker.add_user_role("user123", "admin");
        
        let result = checker.check_access("user123", "read", "documents").unwrap();
        assert!(result);

        let result = checker.check_access("user123", "delete", "system").unwrap();
        assert!(result); // Admin has all permissions
    }
}
