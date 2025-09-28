//! Migration converters for transforming legacy data structures
//!
//! This module provides converters to transform legacy authorization
//! data into role-system v1.0 compatible formats.

use super::{LegacyPermission, LegacyRole, LegacyUserAssignment, MigrationError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Converted role data compatible with role-system v1.0
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvertedRole {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub parent_role_id: Option<String>,
    pub metadata: HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Converted permission data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvertedPermission {
    pub id: String,
    pub action: String,
    pub resource: String,
    pub conditions: HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Converted user assignment data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvertedUserAssignment {
    pub user_id: String,
    pub role_id: String,
    pub assigned_at: chrono::DateTime<chrono::Utc>,
    pub assigned_by: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: HashMap<String, String>,
}

/// Role converter for transforming legacy roles
pub struct RoleConverter {
    id_prefix: String,
    preserve_hierarchy: bool,
    merge_duplicate_permissions: bool,
}

impl Default for RoleConverter {
    fn default() -> Self {
        Self {
            id_prefix: "migrated_".to_string(),
            preserve_hierarchy: true,
            merge_duplicate_permissions: true,
        }
    }
}

impl RoleConverter {
    /// Create new role converter with custom settings
    pub fn new(
        id_prefix: String,
        preserve_hierarchy: bool,
        merge_duplicate_permissions: bool,
    ) -> Self {
        Self {
            id_prefix,
            preserve_hierarchy,
            merge_duplicate_permissions,
        }
    }

    /// Convert legacy role to role-system v1.0 format
    pub fn convert_role(&self, legacy_role: &LegacyRole) -> Result<ConvertedRole, MigrationError> {
        let now = chrono::Utc::now();

        let mut permissions = legacy_role.permissions.clone();

        // Remove duplicates if enabled
        if self.merge_duplicate_permissions {
            permissions.sort();
            permissions.dedup();
        }

        // Handle parent role (role-system v1.0 supports single parent)
        let parent_role_id = if self.preserve_hierarchy && !legacy_role.parent_roles.is_empty() {
            // Take the first parent role if multiple exist
            Some(format!(
                "{}{}",
                self.id_prefix, &legacy_role.parent_roles[0]
            ))
        } else {
            None
        };

        // Convert metadata
        let mut metadata = legacy_role.metadata.clone();

        // Add migration metadata
        metadata.insert("migration_source".to_string(), "legacy_system".to_string());
        metadata.insert("original_id".to_string(), legacy_role.id.clone());

        if legacy_role.parent_roles.len() > 1 {
            metadata.insert(
                "original_parent_roles".to_string(),
                legacy_role.parent_roles.join(","),
            );
        }

        Ok(ConvertedRole {
            id: format!("{}{}", self.id_prefix, legacy_role.id),
            name: legacy_role.name.clone(),
            description: legacy_role.description.clone(),
            permissions,
            parent_role_id,
            metadata,
            created_at: now,
            updated_at: now,
        })
    }

    /// Convert multiple legacy roles with dependency resolution
    pub fn convert_roles(
        &self,
        legacy_roles: &[LegacyRole],
    ) -> Result<Vec<ConvertedRole>, MigrationError> {
        let mut converted_roles = Vec::new();
        let mut role_map: HashMap<String, &LegacyRole> = HashMap::new();

        // Build role map for dependency lookup
        for role in legacy_roles {
            role_map.insert(role.id.clone(), role);
        }

        // Convert roles in dependency order (parents first)
        let ordered_roles = self.order_roles_by_dependencies(legacy_roles)?;

        for role in ordered_roles {
            let converted = self.convert_role(role)?;
            converted_roles.push(converted);
        }

        Ok(converted_roles)
    }

    /// Order roles by dependencies (parents before children)
    fn order_roles_by_dependencies<'a>(
        &self,
        roles: &'a [LegacyRole],
    ) -> Result<Vec<&'a LegacyRole>, MigrationError> {
        let mut ordered = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut visiting = std::collections::HashSet::new();
        let role_map: HashMap<String, &LegacyRole> =
            roles.iter().map(|role| (role.id.clone(), role)).collect();

        for role in roles {
            if !visited.contains(&role.id) {
                self.visit_role_dependencies(
                    role,
                    &role_map,
                    &mut ordered,
                    &mut visited,
                    &mut visiting,
                )?;
            }
        }

        Ok(ordered)
    }

    /// Visit role dependencies recursively
    #[allow(clippy::only_used_in_recursion)]
    fn visit_role_dependencies<'a>(
        &self,
        role: &'a LegacyRole,
        role_map: &HashMap<String, &'a LegacyRole>,
        ordered: &mut Vec<&'a LegacyRole>,
        visited: &mut std::collections::HashSet<String>,
        visiting: &mut std::collections::HashSet<String>,
    ) -> Result<(), MigrationError> {
        if visiting.contains(&role.id) {
            return Err(MigrationError::AnalysisError(format!(
                "Circular dependency detected involving role '{}'",
                role.id
            )));
        }

        if visited.contains(&role.id) {
            return Ok(());
        }

        visiting.insert(role.id.clone());

        // Visit all parent roles first
        for parent_id in &role.parent_roles {
            if let Some(parent_role) = role_map.get(parent_id) {
                self.visit_role_dependencies(parent_role, role_map, ordered, visited, visiting)?;
            }
        }

        visiting.remove(&role.id);
        visited.insert(role.id.clone());
        ordered.push(role);

        Ok(())
    }
}

/// Permission converter for transforming legacy permissions
pub struct PermissionConverter {
    id_prefix: String,
    normalize_actions: bool,
    normalize_resources: bool,
}

impl Default for PermissionConverter {
    fn default() -> Self {
        Self {
            id_prefix: "migrated_".to_string(),
            normalize_actions: true,
            normalize_resources: true,
        }
    }
}

impl PermissionConverter {
    /// Create new permission converter
    pub fn new(id_prefix: String, normalize_actions: bool, normalize_resources: bool) -> Self {
        Self {
            id_prefix,
            normalize_actions,
            normalize_resources,
        }
    }

    /// Convert legacy permission to role-system v1.0 format
    pub fn convert_permission(
        &self,
        legacy_permission: &LegacyPermission,
    ) -> Result<ConvertedPermission, MigrationError> {
        let now = chrono::Utc::now();

        let action = if self.normalize_actions {
            self.normalize_action(&legacy_permission.action)
        } else {
            legacy_permission.action.clone()
        };

        let resource = if self.normalize_resources {
            self.normalize_resource(&legacy_permission.resource)
        } else {
            legacy_permission.resource.clone()
        };

        let mut conditions = legacy_permission.conditions.clone();

        // Add migration metadata to conditions
        conditions.insert("migration_source".to_string(), "legacy_system".to_string());
        conditions.insert("original_id".to_string(), legacy_permission.id.clone());

        Ok(ConvertedPermission {
            id: format!("{}{}", self.id_prefix, legacy_permission.id),
            action,
            resource,
            conditions,
            created_at: now,
        })
    }

    /// Convert multiple permissions
    pub fn convert_permissions(
        &self,
        legacy_permissions: &[LegacyPermission],
    ) -> Result<Vec<ConvertedPermission>, MigrationError> {
        legacy_permissions
            .iter()
            .map(|perm| self.convert_permission(perm))
            .collect()
    }

    /// Normalize action names to standard format
    fn normalize_action(&self, action: &str) -> String {
        match action.to_lowercase().as_str() {
            "read" | "view" | "get" | "list" => "read".to_string(),
            "write" | "create" | "post" | "add" => "create".to_string(),
            "update" | "put" | "patch" | "modify" | "edit" => "update".to_string(),
            "delete" | "remove" | "destroy" => "delete".to_string(),
            "execute" | "run" | "invoke" => "execute".to_string(),
            "admin" | "manage" | "administrate" => "manage".to_string(),
            _ => action.to_string(),
        }
    }

    /// Normalize resource names to standard format
    fn normalize_resource(&self, resource: &str) -> String {
        // Convert to lowercase and replace common separators
        resource
            .to_lowercase()
            .replace("-", "_")
            .replace(" ", "_")
            .replace("/", "_")
    }
}

/// User assignment converter
pub struct UserAssignmentConverter {
    default_assigned_by: Option<String>,
    preserve_expiration: bool,
}

impl Default for UserAssignmentConverter {
    fn default() -> Self {
        Self {
            default_assigned_by: Some("migration_system".to_string()),
            preserve_expiration: true,
        }
    }
}

impl UserAssignmentConverter {
    /// Create new user assignment converter
    pub fn new(default_assigned_by: Option<String>, preserve_expiration: bool) -> Self {
        Self {
            default_assigned_by,
            preserve_expiration,
        }
    }

    /// Convert legacy user assignment
    pub fn convert_user_assignment(
        &self,
        legacy_assignment: &LegacyUserAssignment,
        role_mappings: &HashMap<String, String>,
    ) -> Result<Option<ConvertedUserAssignment>, MigrationError> {
        let now = chrono::Utc::now();

        // Get the mapped role ID
        let role_id = if let Some(legacy_role_id) = &legacy_assignment.role_id {
            if let Some(new_role_id) = role_mappings.get(legacy_role_id) {
                new_role_id.clone()
            } else {
                return Err(MigrationError::AnalysisError(format!(
                    "No role mapping found for legacy role '{}'",
                    legacy_role_id
                )));
            }
        } else {
            // Handle permission-only assignments by creating a temporary role
            return Ok(None); // Skip for now, could be handled with dynamic role creation
        };

        let expires_at = if self.preserve_expiration {
            legacy_assignment.expiration
        } else {
            None
        };

        let mut metadata = HashMap::new();

        // Convert attributes to metadata
        for (key, value) in &legacy_assignment.attributes {
            metadata.insert(key.clone(), value.clone());
        }

        // Add migration metadata
        metadata.insert("migration_source".to_string(), "legacy_system".to_string());
        metadata.insert(
            "original_permissions".to_string(),
            legacy_assignment.permissions.join(","),
        );

        Ok(Some(ConvertedUserAssignment {
            user_id: legacy_assignment.user_id.clone(),
            role_id,
            assigned_at: now,
            assigned_by: self.default_assigned_by.clone(),
            expires_at,
            metadata,
        }))
    }

    /// Convert multiple user assignments
    pub fn convert_user_assignments(
        &self,
        legacy_assignments: &[LegacyUserAssignment],
        role_mappings: &HashMap<String, String>,
    ) -> Result<Vec<ConvertedUserAssignment>, MigrationError> {
        let mut converted = Vec::new();

        for assignment in legacy_assignments {
            if let Some(converted_assignment) =
                self.convert_user_assignment(assignment, role_mappings)?
            {
                converted.push(converted_assignment);
            }
        }

        Ok(converted)
    }
}

/// Comprehensive converter that handles all data types
#[derive(Default)]
pub struct LegacySystemConverter {
    role_converter: RoleConverter,
    permission_converter: PermissionConverter,
    user_assignment_converter: UserAssignmentConverter,
}

impl LegacySystemConverter {
    /// Create new system converter with custom components
    pub fn new(
        role_converter: RoleConverter,
        permission_converter: PermissionConverter,
        user_assignment_converter: UserAssignmentConverter,
    ) -> Self {
        Self {
            role_converter,
            permission_converter,
            user_assignment_converter,
        }
    }

    /// Convert entire legacy system
    pub fn convert_system(
        &self,
        legacy_roles: &[LegacyRole],
        legacy_permissions: &[LegacyPermission],
        legacy_assignments: &[LegacyUserAssignment],
    ) -> Result<ConvertedSystem, MigrationError> {
        // Convert roles first (needed for user assignment mapping)
        let converted_roles = self.role_converter.convert_roles(legacy_roles)?;

        // Build role mapping
        let role_mappings: HashMap<String, String> = legacy_roles
            .iter()
            .zip(&converted_roles)
            .map(|(legacy, converted)| (legacy.id.clone(), converted.id.clone()))
            .collect();

        // Convert permissions
        let converted_permissions = self
            .permission_converter
            .convert_permissions(legacy_permissions)?;

        // Convert user assignments
        let converted_assignments = self
            .user_assignment_converter
            .convert_user_assignments(legacy_assignments, &role_mappings)?;

        Ok(ConvertedSystem {
            roles: converted_roles,
            permissions: converted_permissions,
            user_assignments: converted_assignments,
            role_mappings,
            conversion_metadata: self.generate_conversion_metadata(
                legacy_roles,
                legacy_permissions,
                legacy_assignments,
            ),
        })
    }

    /// Generate metadata about the conversion process
    fn generate_conversion_metadata(
        &self,
        legacy_roles: &[LegacyRole],
        legacy_permissions: &[LegacyPermission],
        legacy_assignments: &[LegacyUserAssignment],
    ) -> ConversionMetadata {
        ConversionMetadata {
            converted_at: chrono::Utc::now(),
            legacy_role_count: legacy_roles.len(),
            legacy_permission_count: legacy_permissions.len(),
            legacy_assignment_count: legacy_assignments.len(),
            conversion_summary: format!(
                "Converted {} roles, {} permissions, and {} user assignments",
                legacy_roles.len(),
                legacy_permissions.len(),
                legacy_assignments.len()
            ),
        }
    }
}

/// Complete converted system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvertedSystem {
    pub roles: Vec<ConvertedRole>,
    pub permissions: Vec<ConvertedPermission>,
    pub user_assignments: Vec<ConvertedUserAssignment>,
    pub role_mappings: HashMap<String, String>,
    pub conversion_metadata: ConversionMetadata,
}

/// Metadata about the conversion process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionMetadata {
    pub converted_at: chrono::DateTime<chrono::Utc>,
    pub legacy_role_count: usize,
    pub legacy_permission_count: usize,
    pub legacy_assignment_count: usize,
    pub conversion_summary: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_role() -> LegacyRole {
        LegacyRole {
            id: "admin".to_string(),
            name: "Administrator".to_string(),
            description: Some("Admin role".to_string()),
            permissions: vec!["read".to_string(), "write".to_string(), "read".to_string()], // Duplicate
            parent_roles: vec!["super_admin".to_string()],
            metadata: {
                let mut map = HashMap::new();
                map.insert("priority".to_string(), "high".to_string());
                map
            },
        }
    }

    #[test]
    fn test_role_converter() {
        let converter = RoleConverter::default();
        let legacy_role = create_test_role();

        let converted = converter.convert_role(&legacy_role).unwrap();

        assert_eq!(converted.id, "migrated_admin");
        assert_eq!(converted.name, "Administrator");
        assert_eq!(converted.permissions.len(), 2); // Duplicates removed
        assert_eq!(
            converted.parent_role_id,
            Some("migrated_super_admin".to_string())
        );
        assert!(converted.metadata.contains_key("migration_source"));
    }

    #[test]
    fn test_permission_converter() {
        let converter = PermissionConverter::default();
        let legacy_permission = LegacyPermission {
            id: "read_data".to_string(),
            action: "VIEW".to_string(),
            resource: "User-Data".to_string(),
            conditions: HashMap::new(),
            metadata: HashMap::new(),
        };

        let converted = converter.convert_permission(&legacy_permission).unwrap();

        assert_eq!(converted.id, "migrated_read_data");
        assert_eq!(converted.action, "read"); // Normalized
        assert_eq!(converted.resource, "user_data"); // Normalized
        assert!(converted.conditions.contains_key("migration_source"));
    }

    #[test]
    fn test_user_assignment_converter() {
        let converter = UserAssignmentConverter::default();
        let legacy_assignment = LegacyUserAssignment {
            user_id: "user123".to_string(),
            role_id: Some("admin".to_string()),
            permissions: vec!["read".to_string()],
            attributes: {
                let mut map = HashMap::new();
                map.insert("department".to_string(), "IT".to_string());
                map
            },
            expiration: None,
        };

        let mut role_mappings = HashMap::new();
        role_mappings.insert("admin".to_string(), "migrated_admin".to_string());

        let converted = converter
            .convert_user_assignment(&legacy_assignment, &role_mappings)
            .unwrap()
            .unwrap();

        assert_eq!(converted.user_id, "user123");
        assert_eq!(converted.role_id, "migrated_admin");
        assert!(converted.metadata.contains_key("department"));
        assert!(converted.metadata.contains_key("migration_source"));
    }

    #[test]
    fn test_system_converter() {
        let converter = LegacySystemConverter::default();

        let legacy_roles = vec![create_test_role()];
        let legacy_permissions = vec![];
        let legacy_assignments = vec![];

        let converted_system = converter
            .convert_system(&legacy_roles, &legacy_permissions, &legacy_assignments)
            .unwrap();

        assert_eq!(converted_system.roles.len(), 1);
        assert_eq!(converted_system.permissions.len(), 0);
        assert_eq!(converted_system.user_assignments.len(), 0);
        assert_eq!(converted_system.role_mappings.len(), 1);
    }
}
