//! Permission and role-based access control (RBAC / ABAC).
//!
//! Core types for the authorization subsystem:
//!
//! - [`Permission`] — An `(action, resource)` pair representing a capability.
//! - [`Role`] — A named set of permissions with optional inheritance.
//! - [`UserPermissions`] — Resolved permissions for a single user.
//! - [`PermissionChecker`] — Evaluates access decisions, including ABAC
//!   policies and delegation chains.
//!
//! For the async, storage-backed authorization API see
//! [`AuthorizationOperations`](crate::auth::AuthorizationOperations).

/// Attribute-Based Access Control (ABAC) policy.
///
/// Associates a set of attribute rules with the permissions they grant.
/// Evaluated by [`PermissionChecker::check_advanced_permission`].
#[derive(Debug, Clone)]
pub struct AbacPolicy {
    pub attributes: HashMap<String, serde_json::Value>,
    pub rules: Vec<AbacRule>,
}

#[derive(Debug, Clone)]
pub struct AbacRule {
    pub attribute: String,
    pub expected_value: serde_json::Value,
    pub permission: Permission,
}

impl Default for AbacPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl AbacPolicy {
    /// Create a new empty ABAC policy.
    pub fn new() -> Self {
        Self {
            attributes: HashMap::new(),
            rules: Vec::new(),
        }
    }

    /// Add an attribute to the policy.
    pub fn with_attribute(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }

    /// Add multiple attributes to the policy.
    pub fn with_attributes<I, K>(mut self, attributes: I) -> Self
    where
        I: IntoIterator<Item = (K, serde_json::Value)>,
        K: Into<String>,
    {
        for (key, value) in attributes {
            self.attributes.insert(key.into(), value);
        }
        self
    }

    /// Add a rule to the policy.
    pub fn with_rule(
        mut self,
        attribute: impl Into<String>,
        expected_value: serde_json::Value,
        permission: Permission,
    ) -> Self {
        self.rules.push(AbacRule {
            attribute: attribute.into(),
            expected_value,
            permission,
        });
        self
    }

    /// Add multiple rules to the policy.
    pub fn with_rules<I>(mut self, rules: I) -> Self
    where
        I: IntoIterator<Item = AbacRule>,
    {
        self.rules.extend(rules);
        self
    }
}

/// Permission delegation record.
///
/// Represents a delegator granting a subset of their permissions to a delegatee,
/// optionally for a limited time window.
#[derive(Debug, Clone)]
pub struct Delegation {
    pub delegator: String,
    pub delegatee: String,
    pub permissions: HashSet<Permission>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Delegation {
    /// Create a new delegation with required fields.
    pub fn new(delegator: impl Into<String>, delegatee: impl Into<String>) -> Self {
        Self {
            delegator: delegator.into(),
            delegatee: delegatee.into(),
            permissions: HashSet::new(),
            expires_at: None,
        }
    }

    /// Add permissions to the delegation.
    pub fn with_permissions<I>(mut self, permissions: I) -> Self
    where
        I: IntoIterator<Item = Permission>,
    {
        self.permissions.extend(permissions);
        self
    }

    /// Add a single permission to the delegation.
    pub fn with_permission(mut self, permission: Permission) -> Self {
        self.permissions.insert(permission);
        self
    }

    /// Set the expiration time for the delegation.
    pub fn with_expiry(mut self, expires_at: chrono::DateTime<chrono::Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set the delegation to never expire.
    pub fn permanent(mut self) -> Self {
        self.expires_at = None;
        self
    }
}

impl PermissionChecker {
    /// Check permission for a user with ABAC and delegation support.
    ///
    /// This is the low-level API with positional parameters.  For a more
    /// readable alternative, use [`check_advanced`](Self::check_advanced)
    /// with an [`AdvancedPermissionCheck`] builder.
    ///
    /// # Arguments
    ///
    /// * `user_id` — the user to check
    /// * `permission` — the required permission
    /// * `user_attributes` — runtime attributes for ABAC evaluation
    /// * `abac_policy` — optional ABAC policy
    /// * `delegations` — optional active delegations
    /// * `role_resolver` — closure that resolves role names to definitions
    pub fn check_advanced_permission(
        &self,
        user_id: &str,
        permission: &Permission,
        user_attributes: &HashMap<String, serde_json::Value>,
        abac_policy: Option<&AbacPolicy>,
        delegations: Option<&[Delegation]>,
        role_resolver: &dyn Fn(&str) -> Option<Role>,
    ) -> bool {
        // Check direct and role permissions
        let has_basic = self.user_permissions.get(user_id).is_some_and(|up| {
            let mut up = up.clone();
            up.has_permission(permission, role_resolver)
        });
        if has_basic {
            return true;
        }
        // Check ABAC policy
        if let Some(policy) = abac_policy
            && self.check_abac(user_attributes, permission, policy)
        {
            return true;
        }
        // Check delegation
        if let Some(delegations) = delegations
            && self.check_delegation(user_id, permission, delegations)
        {
            return true;
        }
        false
    }
    /// Check permission with ABAC policy
    pub fn check_abac(
        &self,
        user_attributes: &HashMap<String, serde_json::Value>,
        permission: &Permission,
        abac_policy: &AbacPolicy,
    ) -> bool {
        for rule in &abac_policy.rules {
            if let Some(attr_value) = user_attributes.get(&rule.attribute)
                && attr_value == &rule.expected_value
                && rule.permission.implies(permission)
            {
                return true;
            }
        }
        false
    }

    /// Check permission with delegation
    pub fn check_delegation(
        &self,
        user_id: &str,
        permission: &Permission,
        delegations: &[Delegation],
    ) -> bool {
        for delegation in delegations {
            if delegation.delegatee == user_id
                && delegation.permissions.iter().any(|p| p.implies(permission))
            {
                if let Some(expiry) = delegation.expires_at
                    && expiry < chrono::Utc::now()
                {
                    continue;
                }
                return true;
            }
        }
        false
    }
}

/// Builder for constructing an advanced permission check with ABAC policies,
/// delegations, and role resolution.
///
/// Wraps the six parameters of
/// [`PermissionChecker::check_advanced_permission`] into a self-documenting
/// builder so callers don't need to remember parameter order.
///
/// # Example
///
/// ```rust,ignore
/// use auth_framework::permissions::*;
///
/// let granted = checker.check_advanced(
///     AdvancedPermissionCheck::new("user_123", &permission, &role_resolver)
///         .user_attributes(&attrs)
///         .abac_policy(&policy)
///         .delegations(&delegations),
/// );
/// ```
pub struct AdvancedPermissionCheck<'a> {
    user_id: &'a str,
    permission: &'a Permission,
    user_attributes: Option<&'a HashMap<String, serde_json::Value>>,
    abac_policy: Option<&'a AbacPolicy>,
    delegations: Option<&'a [Delegation]>,
    role_resolver: &'a dyn Fn(&str) -> Option<Role>,
}

impl<'a> AdvancedPermissionCheck<'a> {
    /// Start building an advanced permission check with the required fields.
    pub fn new(
        user_id: &'a str,
        permission: &'a Permission,
        role_resolver: &'a dyn Fn(&str) -> Option<Role>,
    ) -> Self {
        Self {
            user_id,
            permission,
            user_attributes: None,
            abac_policy: None,
            delegations: None,
            role_resolver,
        }
    }

    /// Provide user attributes for ABAC evaluation.
    pub fn user_attributes(mut self, attrs: &'a HashMap<String, serde_json::Value>) -> Self {
        self.user_attributes = Some(attrs);
        self
    }

    /// Provide an ABAC policy to evaluate against.
    pub fn abac_policy(mut self, policy: &'a AbacPolicy) -> Self {
        self.abac_policy = Some(policy);
        self
    }

    /// Provide active delegations to consider.
    pub fn delegations(mut self, delegations: &'a [Delegation]) -> Self {
        self.delegations = Some(delegations);
        self
    }
}

impl PermissionChecker {
    /// Check permission using an [`AdvancedPermissionCheck`] builder.
    ///
    /// This is the recommended entry point when combining RBAC, ABAC, and
    /// delegation checks — it avoids the six positional parameters of the
    /// legacy [`check_advanced_permission`](Self::check_advanced_permission).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let allowed = checker.check_advanced(
    ///     AdvancedPermissionCheck::new("user_1", &perm, &resolver)
    ///         .user_attributes(&attrs)
    ///         .abac_policy(&policy),
    /// );
    /// ```
    pub fn check_advanced(&self, check: AdvancedPermissionCheck<'_>) -> bool {
        static EMPTY: std::sync::LazyLock<HashMap<String, serde_json::Value>> =
            std::sync::LazyLock::new(HashMap::new);
        self.check_advanced_permission(
            check.user_id,
            check.permission,
            check.user_attributes.unwrap_or(&EMPTY),
            check.abac_policy,
            check.delegations,
            check.role_resolver,
        )
    }
}
/// Permission and role-based access control system.
use crate::errors::{PermissionError, Result};
use crate::tokens::AuthToken;
use chrono;
use serde::{Deserialize, Serialize};
use serde_json;
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
    /// Optional unique identifier (populated when persisted via `AuthorizationEngine`)
    pub id: Option<String>,

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

    /// Arbitrary metadata key-value pairs
    pub metadata: HashMap<String, String>,

    /// When the role was created (populated when loaded from persistent storage)
    pub created_at: Option<std::time::SystemTime>,

    /// When the role was last modified
    pub updated_at: Option<std::time::SystemTime>,
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
            _ => Err(PermissionError::invalid_format(format!(
                "Invalid permission format: {permission_str}"
            ))
            .into()),
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
            (None, _) => true, // General permission implies specific
            (Some(self_instance), Some(other_instance)) => {
                self_instance == "*" || self_instance == other_instance
            }
            (Some(_), None) => false, // Specific doesn't imply general
        };

        action_implies && resource_implies && instance_implies
    }
}

impl Role {
    /// Create a new role.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: None,
            name: name.into(),
            description: None,
            permissions: HashSet::new(),
            parent_roles: HashSet::new(),
            active: true,
            metadata: HashMap::new(),
            created_at: None,
            updated_at: None,
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

    /// Add parent roles to the role.
    pub fn with_parent_roles<I, S>(mut self, parent_roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for parent_role in parent_roles {
            self.parent_roles.insert(parent_role.into());
        }
        self
    }

    /// Add metadata to the role.
    pub fn with_metadata<I, K, V>(mut self, metadata: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (key, value) in metadata {
            self.metadata.insert(key.into(), value.into());
        }
        self
    }

    /// Set the active status of the role.
    pub fn with_active(mut self, active: bool) -> Self {
        self.active = active;
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
    pub fn get_all_permissions(
        &self,
        role_resolver: &dyn Fn(&str) -> Option<Role>,
    ) -> HashSet<Permission> {
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

impl PermissionChecker {
    /// Remove all runtime roles, assignments, and cached permission state.
    pub fn clear(&mut self) {
        self.roles.clear();
        self.user_permissions.clear();
        self.resource_hierarchy.clear();
    }

    /// Return the currently assigned role names for a user.
    pub fn get_user_roles(&self, user_id: &str) -> Vec<String> {
        self.user_permissions
            .get(user_id)
            .map(|permissions| permissions.roles.iter().cloned().collect())
            .unwrap_or_default()
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
    pub fn compute_permissions(
        &mut self,
        role_resolver: &dyn Fn(&str) -> Option<Role>,
    ) -> &HashSet<Permission> {
        if self.computed_permissions.is_none() {
            let mut all_permissions = self.direct_permissions.clone();

            // Add permissions from roles
            for role_name in &self.roles {
                if let Some(role) = role_resolver(role_name)
                    && role.active
                {
                    all_permissions.extend(role.get_all_permissions(role_resolver));
                }
            }

            self.computed_permissions = Some(all_permissions);
        }

        // SAFETY: guaranteed Some — either it was Some on entry or we just assigned it above.
        self.computed_permissions
            .as_ref()
            .expect("computed_permissions is always Some after this block")
    }

    /// Check if the user has a specific permission.
    pub fn has_permission(
        &mut self,
        permission: &Permission,
        role_resolver: &dyn Fn(&str) -> Option<Role>,
    ) -> bool {
        let all_permissions = self.compute_permissions(role_resolver);
        all_permissions.iter().any(|p| p.implies(permission))
    }
}

/// Returns `true` if `broader` is a higher-privilege action that implies `required`.
///
/// Action hierarchy:
/// - `"manage"` / `"admin"` imply all common CRUD + management actions
/// - `"write"` / `"update"` imply `"read"`
fn broader_action_implies(broader: &str, required: &str) -> bool {
    // Wildcard is handled in Permission::implies; exact match is handled before calling this.
    if broader == required {
        return true;
    }
    match broader {
        "manage" | "admin" => matches!(
            required,
            "read" | "write" | "delete" | "create" | "list" | "update" | "get"
        ),
        "write" | "update" => matches!(required, "read" | "get" | "list"),
        _ => false,
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

    /// Return all defined roles.
    pub fn list_roles(&self) -> Vec<Role> {
        self.roles.values().cloned().collect()
    }

    /// Set user permissions.
    pub fn set_user_permissions(&mut self, user_permissions: UserPermissions) {
        self.user_permissions
            .insert(user_permissions.user_id.clone(), user_permissions);
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
        let user_perms = self
            .user_permissions
            .entry(user_id.to_string())
            .or_insert_with(|| UserPermissions::new(user_id));

        user_perms.add_permission(permission);
    }

    /// Add a role to a user.
    pub fn add_user_role(&mut self, user_id: &str, role: impl Into<String>) {
        let user_perms = self
            .user_permissions
            .entry(user_id.to_string())
            .or_insert_with(|| UserPermissions::new(user_id));

        user_perms.add_role(role);
    }

    /// Remove a role from a user.
    pub fn remove_user_role(&mut self, user_id: &str, role_name: &str) {
        if let Some(user_perms) = self.user_permissions.get_mut(user_id) {
            user_perms.remove_role(role_name);
        }
    }

    /// Count the number of defined roles.
    pub fn role_count(&self) -> usize {
        self.roles.len()
    }

    /// Count the number of users that have explicit permissions recorded.
    pub fn user_count(&self) -> usize {
        self.user_permissions.len()
    }

    /// Count the total number of direct permissions across all users.
    pub fn total_direct_permission_count(&self) -> usize {
        self.user_permissions
            .values()
            .map(|up| up.direct_permissions.len())
            .sum()
    }

    /// Check if a user has a specific permission.
    pub fn check_permission(&mut self, user_id: &str, permission: &Permission) -> Result<bool> {
        let user_perms = self.user_permissions.get_mut(user_id).ok_or_else(|| {
            PermissionError::access_denied(permission.to_string(), "unknown user".to_string())
        })?;

        let role_resolver = |role_name: &str| self.roles.get(role_name).cloned();

        Ok(user_perms.has_permission(permission, &role_resolver))
    }

    /// Check if a user has permission for a specific action on a resource.
    pub fn check_access(&mut self, user_id: &str, action: &str, resource: &str) -> Result<bool> {
        let permission = Permission::new(action, resource);

        // First check direct permission
        if self.check_permission(user_id, &permission)? {
            return Ok(true);
        }

        // Check hierarchical permissions if direct permission not found
        self.check_hierarchical_permission(user_id, action, resource)
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
    pub fn check_token_permission(
        &mut self,
        token: &AuthToken,
        permission: &Permission,
    ) -> Result<bool> {
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
                && !token.has_scope(&wildcard_all)
            {
                return Ok(false);
            }
        }

        // Check user permissions
        self.check_permission(&token.user_id, permission)
    }

    /// Add resource hierarchy relationship
    pub fn add_resource_hierarchy(&mut self, parent: String, children: Vec<String>) {
        self.resource_hierarchy.insert(parent, children);
    }

    /// Get child resources for a parent resource
    pub fn get_child_resources(&self, parent: &str) -> Option<&Vec<String>> {
        self.resource_hierarchy.get(parent)
    }

    /// Check hierarchical permission - if user has permission on parent, they have it on children
    pub fn check_hierarchical_permission(
        &mut self,
        user_id: &str,
        action: &str,
        resource: &str,
    ) -> Result<bool> {
        // Clone the hierarchy to avoid borrow checker issues
        let hierarchy = self.resource_hierarchy.clone();

        // Check all ancestor resources recursively
        if self.has_ancestor_permission(&hierarchy, user_id, action, resource)? {
            return Ok(true);
        }

        // Check for wildcard permissions that might apply
        if self.check_wildcard_permissions(&hierarchy, user_id, action, resource)? {
            return Ok(true);
        }

        Ok(false)
    }

    /// Check wildcard permissions that might apply to this resource
    fn check_wildcard_permissions(
        &mut self,
        hierarchy: &HashMap<String, Vec<String>>,
        user_id: &str,
        action: &str,
        resource: &str,
    ) -> Result<bool> {
        // Check if any parent resource has a wildcard permission that applies
        for (parent_resource, children) in hierarchy {
            if children.contains(&resource.to_string()) {
                // Check for wildcard permission on parent (e.g., "projects.*" covering "documents")
                let wildcard_permission = Permission::new(action, format!("{}.*", parent_resource));
                if self
                    .check_permission(user_id, &wildcard_permission)
                    .unwrap_or(false)
                {
                    return Ok(true);
                }
            }
        }

        // Also check direct wildcard on resource itself
        if let Some(_children) = hierarchy.get(resource) {
            let wildcard_permission = Permission::new(action, format!("{}.*", resource));
            if self
                .check_permission(user_id, &wildcard_permission)
                .unwrap_or(false)
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Recursively check if user has permission on any ancestor resource
    fn has_ancestor_permission(
        &mut self,
        hierarchy: &HashMap<String, Vec<String>>,
        user_id: &str,
        action: &str,
        resource: &str,
    ) -> Result<bool> {
        // Find direct parent resources
        for (parent_resource, children) in hierarchy {
            if children.contains(&resource.to_string()) {
                // Check if user has the exact permission on the parent resource, OR any
                // higher-privilege action that implies the required action (e.g. "manage"
                // implies "read" and "write").
                if self.check_permission_with_action_hierarchy(user_id, action, parent_resource)? {
                    return Ok(true);
                }

                // Recursively check if user has permission on ancestor of this parent
                if self.has_ancestor_permission(hierarchy, user_id, action, parent_resource)? {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Check if a user has permission for `action` on `resource`, considering action hierarchy.
    ///
    /// In addition to an exact match, higher-privilege actions imply less-privileged ones:
    /// - `"manage"` / `"admin"` imply `"read"`, `"write"`, `"delete"`, `"create"`, `"list"`, `"update"`
    /// - `"write"` / `"update"` imply `"read"`
    fn check_permission_with_action_hierarchy(
        &mut self,
        user_id: &str,
        required_action: &str,
        resource: &str,
    ) -> Result<bool> {
        // First try exact match via the standard path
        let exact = Permission::new(required_action, resource);
        if self.check_permission(user_id, &exact).unwrap_or(false) {
            return Ok(true);
        }

        // Walk user's permissions and check action hierarchy
        let role_resolver = |role_name: &str| self.roles.get(role_name).cloned();
        let user_perms = match self.user_permissions.get_mut(user_id) {
            Some(p) => p,
            None => return Ok(false),
        };
        let all_perms = user_perms.compute_permissions(&role_resolver);

        Ok(all_perms.iter().any(|p| {
            let resource_match = p.resource == "*" || p.resource == resource;
            let action_match =
                p.action == "*" || broader_action_implies(&p.action, required_action);
            resource_match && action_match
        }))
    }

    /// Create some default roles for common use cases.
    pub fn create_default_roles(&mut self) {
        // Admin role with all permissions
        let mut admin_role = Role::new("admin").with_description("Administrator with full access");
        admin_role.add_permission(Permission::new("*", "*"));
        self.add_role(admin_role);

        // User role with basic permissions
        let mut user_role = Role::new("user").with_description("Regular user with basic access");
        user_role.add_permission(Permission::new("read", "profile"));
        user_role.add_permission(Permission::new("write", "profile"));
        user_role.add_permission(Permission::new("read", "public"));
        self.add_role(user_role);

        // Guest role with read-only access
        let mut guest_role =
            Role::new("guest").with_description("Guest user with read-only access");
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

    /// Assign a role to a user.
    pub fn assign_role_to_user(&mut self, user_id: &str, role_name: &str) -> Result<()> {
        // Validate that role exists
        if !self.roles.contains_key(role_name) {
            return Err(PermissionError::access_denied(
                role_name.to_string(),
                "Role does not exist".to_string(),
            )
            .into());
        }

        // Add role to user
        self.add_user_role(user_id, role_name);
        Ok(())
    }

    /// Set role inheritance relationship.
    pub fn set_role_inheritance(&mut self, child_role: &str, parent_role: &str) -> Result<()> {
        // Validate that both roles exist
        if !self.roles.contains_key(child_role) {
            return Err(PermissionError::access_denied(
                child_role.to_string(),
                "Child role does not exist".to_string(),
            )
            .into());
        }
        if !self.roles.contains_key(parent_role) {
            return Err(PermissionError::access_denied(
                parent_role.to_string(),
                "Parent role does not exist".to_string(),
            )
            .into());
        }

        // Update role inheritance
        if let Some(child) = self.roles.get_mut(child_role) {
            child.add_parent_role(parent_role);
        }

        Ok(())
    }

    /// Remove a permission from a user.
    pub fn remove_user_permission(&mut self, user_id: &str, permission: &Permission) {
        if let Some(user_perms) = self.user_permissions.get_mut(user_id) {
            user_perms.remove_permission(permission);
        }
    }

    /// Check if a user has a specific role.
    pub fn user_has_role(&self, user_id: &str, role_name: &str) -> bool {
        if let Some(user_perms) = self.user_permissions.get(user_id) {
            user_perms.roles.contains(role_name)
        } else {
            false
        }
    }

    /// Get effective permissions for a user (including role-based permissions).
    pub fn get_effective_permissions(&self, user_id: &str) -> Vec<String> {
        if let Some(user_perms) = self.user_permissions.get(user_id) {
            let role_resolver = |role_name: &str| self.roles.get(role_name).cloned();

            // Create a mutable clone to compute permissions
            let mut user_perms_clone = user_perms.clone();
            let all_permissions = user_perms_clone.compute_permissions(&role_resolver);

            all_permissions.iter().map(|p| p.to_string()).collect()
        } else {
            Vec::new()
        }
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

        let result = checker
            .check_access("user123", "read", "documents")
            .unwrap();
        assert!(result);

        let result = checker.check_access("user123", "delete", "system").unwrap();
        assert!(result); // Admin has all permissions
    }
}

#[cfg(test)]
pub mod abac_delegation_tests;
