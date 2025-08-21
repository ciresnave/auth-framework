//! Legacy system analyzers for migration planning
//!
//! This module provides analyzers to detect and analyze various
//! types of legacy authorization systems.

use super::{
    LegacyPermission, LegacyRole, LegacySystemAnalysis, LegacySystemType, LegacyUserAssignment,
    MigrationConfig, MigrationError, MigrationStrategy,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tokio::fs;

/// Analyze legacy authorization system from configuration
pub async fn analyze_legacy_system<P: AsRef<Path>>(
    config_path: P,
    _config: &MigrationConfig,
) -> Result<LegacySystemAnalysis, MigrationError> {
    let config_content = fs::read_to_string(config_path).await?;

    // Try to parse as JSON first
    if let Ok(json_value) = serde_json::from_str::<Value>(&config_content) {
        return analyze_json_config(&json_value).await;
    }

    // Try to parse as TOML
    if let Ok(toml_value) = toml::from_str::<Value>(&config_content) {
        return analyze_toml_config(&toml_value).await;
    }

    // Try to parse as YAML
    if let Ok(yaml_value) = serde_yaml::from_str::<Value>(&config_content) {
        return analyze_yaml_config(&yaml_value).await;
    }

    Err(MigrationError::AnalysisError(
        "Unable to parse configuration file format".to_string(),
    ))
}

/// Analyze JSON-based authorization configuration
async fn analyze_json_config(config: &Value) -> Result<LegacySystemAnalysis, MigrationError> {
    let mut analysis = LegacySystemAnalysis {
        system_type: LegacySystemType::Custom("JSON-based".to_string()),
        role_count: 0,
        permission_count: 0,
        user_assignment_count: 0,
        roles: Vec::new(),
        permissions: Vec::new(),
        user_assignments: Vec::new(),
        hierarchy_depth: 0,
        duplicates_found: false,
        orphaned_permissions: Vec::new(),
        circular_dependencies: Vec::new(),
        custom_attributes: HashSet::new(),
        complexity_score: 1,
        recommended_strategy: MigrationStrategy::DirectMapping,
    };

    // Detect system type based on structure
    analysis.system_type = detect_json_system_type(config);

    // Extract roles
    if let Some(roles_section) = config.get("roles") {
        analysis.roles = extract_json_roles(roles_section)?;
        analysis.role_count = analysis.roles.len();
    }

    // Extract permissions
    if let Some(permissions_section) = config.get("permissions") {
        analysis.permissions = extract_json_permissions(permissions_section)?;
        analysis.permission_count = analysis.permissions.len();
    }

    // Extract user assignments
    if let Some(users_section) = config.get("users") {
        analysis.user_assignments = extract_json_user_assignments(users_section)?;
        analysis.user_assignment_count = analysis.user_assignments.len();
    }

    // Analyze complexity and generate recommendations
    analyze_complexity_and_recommend_strategy(&mut analysis);

    Ok(analysis)
}

/// Detect system type from JSON structure
fn detect_json_system_type(config: &Value) -> LegacySystemType {
    let has_roles = config.get("roles").is_some();
    let has_permissions = config.get("permissions").is_some();
    let has_attributes = config.get("attributes").is_some();
    let has_policies = config.get("policies").is_some();

    match (has_roles, has_permissions, has_attributes, has_policies) {
        (true, true, false, false) => LegacySystemType::BasicRbac,
        (false, true, false, false) => LegacySystemType::PermissionBased,
        (true, true, true, _) => LegacySystemType::Abac,
        _ => LegacySystemType::Custom("JSON-based".to_string()),
    }
}

/// Extract roles from JSON configuration
fn extract_json_roles(roles_section: &Value) -> Result<Vec<LegacyRole>, MigrationError> {
    let mut roles = Vec::new();

    match roles_section {
        Value::Object(roles_map) => {
            for (role_id, role_data) in roles_map {
                let role = parse_json_role(role_id, role_data)?;
                roles.push(role);
            }
        }
        Value::Array(roles_array) => {
            for role_data in roles_array {
                if let Some(role_id) = role_data.get("id").and_then(|v| v.as_str()) {
                    let role = parse_json_role(role_id, role_data)?;
                    roles.push(role);
                }
            }
        }
        _ => {
            return Err(MigrationError::AnalysisError(
                "Invalid roles format".to_string(),
            ));
        }
    }

    Ok(roles)
}

/// Parse individual role from JSON
fn parse_json_role(role_id: &str, role_data: &Value) -> Result<LegacyRole, MigrationError> {
    let name = role_data
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(role_id)
        .to_string();

    let description = role_data
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let permissions = role_data
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let parent_roles = role_data
        .get("parents")
        .or_else(|| role_data.get("inherits"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let mut metadata = HashMap::new();
    if let Some(meta) = role_data.get("metadata").and_then(|v| v.as_object()) {
        for (key, value) in meta {
            if let Some(value_str) = value.as_str() {
                metadata.insert(key.clone(), value_str.to_string());
            }
        }
    }

    Ok(LegacyRole {
        id: role_id.to_string(),
        name,
        description,
        permissions,
        parent_roles,
        metadata,
    })
}

/// Extract permissions from JSON configuration
fn extract_json_permissions(
    permissions_section: &Value,
) -> Result<Vec<LegacyPermission>, MigrationError> {
    let mut permissions = Vec::new();

    match permissions_section {
        Value::Object(perms_map) => {
            for (perm_id, perm_data) in perms_map {
                let permission = parse_json_permission(perm_id, perm_data)?;
                permissions.push(permission);
            }
        }
        Value::Array(perms_array) => {
            for perm_data in perms_array {
                if let Some(perm_id) = perm_data.get("id").and_then(|v| v.as_str()) {
                    let permission = parse_json_permission(perm_id, perm_data)?;
                    permissions.push(permission);
                }
            }
        }
        _ => {
            return Err(MigrationError::AnalysisError(
                "Invalid permissions format".to_string(),
            ));
        }
    }

    Ok(permissions)
}

/// Parse individual permission from JSON
fn parse_json_permission(
    perm_id: &str,
    perm_data: &Value,
) -> Result<LegacyPermission, MigrationError> {
    let action = perm_data
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let resource = perm_data
        .get("resource")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut conditions = HashMap::new();
    if let Some(cond) = perm_data.get("conditions").and_then(|v| v.as_object()) {
        for (key, value) in cond {
            if let Some(value_str) = value.as_str() {
                conditions.insert(key.clone(), value_str.to_string());
            }
        }
    }

    let mut metadata = HashMap::new();
    if let Some(meta) = perm_data.get("metadata").and_then(|v| v.as_object()) {
        for (key, value) in meta {
            if let Some(value_str) = value.as_str() {
                metadata.insert(key.clone(), value_str.to_string());
            }
        }
    }

    Ok(LegacyPermission {
        id: perm_id.to_string(),
        action,
        resource,
        conditions,
        metadata,
    })
}

/// Extract user assignments from JSON configuration
fn extract_json_user_assignments(
    users_section: &Value,
) -> Result<Vec<LegacyUserAssignment>, MigrationError> {
    let mut assignments = Vec::new();

    match users_section {
        Value::Object(users_map) => {
            for (user_id, user_data) in users_map {
                let assignment = parse_json_user_assignment(user_id, user_data)?;
                assignments.push(assignment);
            }
        }
        Value::Array(users_array) => {
            for user_data in users_array {
                if let Some(user_id) = user_data.get("id").and_then(|v| v.as_str()) {
                    let assignment = parse_json_user_assignment(user_id, user_data)?;
                    assignments.push(assignment);
                }
            }
        }
        _ => {
            return Err(MigrationError::AnalysisError(
                "Invalid users format".to_string(),
            ));
        }
    }

    Ok(assignments)
}

/// Parse individual user assignment from JSON
fn parse_json_user_assignment(
    user_id: &str,
    user_data: &Value,
) -> Result<LegacyUserAssignment, MigrationError> {
    let role_id = user_data
        .get("role")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let permissions = user_data
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let mut attributes = HashMap::new();
    if let Some(attrs) = user_data.get("attributes").and_then(|v| v.as_object()) {
        for (key, value) in attrs {
            if let Some(value_str) = value.as_str() {
                attributes.insert(key.clone(), value_str.to_string());
            }
        }
    }

    let expiration = user_data
        .get("expires_at")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    Ok(LegacyUserAssignment {
        user_id: user_id.to_string(),
        role_id,
        permissions,
        attributes,
        expiration,
    })
}

/// Analyze TOML-based authorization configuration
async fn analyze_toml_config(config: &Value) -> Result<LegacySystemAnalysis, MigrationError> {
    // Convert TOML Value to similar analysis as JSON
    // TOML and JSON structures are similar enough to reuse logic
    analyze_json_config(config).await
}

/// Analyze YAML-based authorization configuration
async fn analyze_yaml_config(config: &Value) -> Result<LegacySystemAnalysis, MigrationError> {
    // Convert YAML Value to similar analysis as JSON
    // YAML and JSON structures are similar enough to reuse logic
    analyze_json_config(config).await
}

/// Analyze complexity and recommend migration strategy
fn analyze_complexity_and_recommend_strategy(analysis: &mut LegacySystemAnalysis) {
    let mut complexity_score = 1u8;

    // Factor in number of roles
    complexity_score += match analysis.role_count {
        0..=10 => 1,
        11..=50 => 2,
        51..=200 => 3,
        _ => 4,
    };

    // Factor in number of permissions
    complexity_score += match analysis.permission_count {
        0..=20 => 1,
        21..=100 => 2,
        101..=500 => 3,
        _ => 4,
    };

    // Factor in hierarchy depth
    let max_depth = calculate_hierarchy_depth(&analysis.roles);
    analysis.hierarchy_depth = max_depth;
    complexity_score += match max_depth {
        0..=2 => 1,
        3..=5 => 2,
        6..=10 => 3,
        _ => 4,
    };

    // Check for duplicates
    analysis.duplicates_found = check_for_duplicates(&analysis.roles, &analysis.permissions);
    if analysis.duplicates_found {
        complexity_score += 1;
    }

    // Find orphaned permissions
    analysis.orphaned_permissions =
        find_orphaned_permissions(&analysis.roles, &analysis.permissions);
    if !analysis.orphaned_permissions.is_empty() {
        complexity_score += 1;
    }

    // Check for circular dependencies
    analysis.circular_dependencies = find_circular_dependencies(&analysis.roles);
    if !analysis.circular_dependencies.is_empty() {
        complexity_score += 2;
    }

    // Collect custom attributes
    for assignment in &analysis.user_assignments {
        for key in assignment.attributes.keys() {
            analysis.custom_attributes.insert(key.clone());
        }
    }

    if !analysis.custom_attributes.is_empty() {
        complexity_score += 1;
    }

    // Cap complexity score at 10
    analysis.complexity_score = complexity_score.min(10);

    // Recommend strategy based on complexity
    analysis.recommended_strategy = match analysis.complexity_score {
        1..=3 => MigrationStrategy::DirectMapping,
        4..=6 => MigrationStrategy::GradualMigration,
        7..=8 => MigrationStrategy::Rebuild,
        _ => MigrationStrategy::Custom("High complexity requires custom approach".to_string()),
    };
}

/// Calculate maximum hierarchy depth
fn calculate_hierarchy_depth(roles: &[LegacyRole]) -> usize {
    let mut max_depth = 0;
    let mut role_map: HashMap<String, &LegacyRole> = HashMap::new();

    for role in roles {
        role_map.insert(role.id.clone(), role);
    }

    for role in roles {
        let depth = calculate_role_depth(&role.id, &role_map, &mut HashSet::new());
        max_depth = max_depth.max(depth);
    }

    max_depth
}

/// Calculate depth for a specific role
fn calculate_role_depth(
    role_id: &str,
    role_map: &HashMap<String, &LegacyRole>,
    visited: &mut HashSet<String>,
) -> usize {
    if visited.contains(role_id) {
        return 0; // Circular dependency
    }

    visited.insert(role_id.to_string());

    if let Some(role) = role_map.get(role_id) {
        if role.parent_roles.is_empty() {
            visited.remove(role_id);
            return 0;
        }

        let mut max_parent_depth = 0;
        for parent_id in &role.parent_roles {
            let parent_depth = calculate_role_depth(parent_id, role_map, visited);
            max_parent_depth = max_parent_depth.max(parent_depth);
        }

        visited.remove(role_id);
        return max_parent_depth + 1;
    }

    visited.remove(role_id);
    0
}

/// Check for duplicate roles and permissions
fn check_for_duplicates(roles: &[LegacyRole], permissions: &[LegacyPermission]) -> bool {
    let mut role_names = HashSet::new();
    let mut permission_names = HashSet::new();

    for role in roles {
        if !role_names.insert(&role.name) {
            return true; // Duplicate role name found
        }
    }

    for permission in permissions {
        let perm_key = format!("{}:{}", permission.action, permission.resource);
        if !permission_names.insert(perm_key) {
            return true; // Duplicate permission found
        }
    }

    false
}

/// Find permissions not assigned to any role
fn find_orphaned_permissions(
    roles: &[LegacyRole],
    permissions: &[LegacyPermission],
) -> Vec<String> {
    let mut assigned_permissions = HashSet::new();

    for role in roles {
        for permission in &role.permissions {
            assigned_permissions.insert(permission.clone());
        }
    }

    permissions
        .iter()
        .filter(|perm| !assigned_permissions.contains(&perm.id))
        .map(|perm| perm.id.clone())
        .collect()
}

/// Find circular dependencies in role hierarchy
fn find_circular_dependencies(roles: &[LegacyRole]) -> Vec<Vec<String>> {
    let mut circular_deps = Vec::new();
    let role_map: HashMap<String, &LegacyRole> =
        roles.iter().map(|role| (role.id.clone(), role)).collect();

    for role in roles {
        if let Some(cycle) = detect_cycle(&role.id, &role_map, &mut Vec::new(), &mut HashSet::new())
            && !circular_deps.contains(&cycle)
        {
            circular_deps.push(cycle);
        }
    }

    circular_deps
}

/// Detect cycle in role hierarchy
fn detect_cycle(
    role_id: &str,
    role_map: &HashMap<String, &LegacyRole>,
    path: &mut Vec<String>,
    visited: &mut HashSet<String>,
) -> Option<Vec<String>> {
    if path.contains(&role_id.to_string()) {
        // Found cycle
        if let Some(cycle_start) = path.iter().position(|id| id == role_id) {
            return Some(path[cycle_start..].to_vec());
        }
    }

    if visited.contains(role_id) {
        return None;
    }

    visited.insert(role_id.to_string());
    path.push(role_id.to_string());

    if let Some(role) = role_map.get(role_id) {
        for parent_id in &role.parent_roles {
            if let Some(cycle) = detect_cycle(parent_id, role_map, path, visited) {
                return Some(cycle);
            }
        }
    }

    path.pop();
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_analyze_json_config() {
        let config = json!({
            "roles": {
                "admin": {
                    "name": "Administrator",
                    "permissions": ["read", "write", "delete"]
                },
                "user": {
                    "name": "User",
                    "permissions": ["read"]
                }
            },
            "permissions": {
                "read": {
                    "action": "read",
                    "resource": "data"
                }
            }
        });

        let analysis = analyze_json_config(&config).await.unwrap();
        assert_eq!(analysis.role_count, 2);
        assert_eq!(analysis.permission_count, 1);
        assert_eq!(analysis.system_type, LegacySystemType::BasicRbac);
    }

    #[test]
    fn test_detect_json_system_type() {
        let basic_rbac = json!({
            "roles": {},
            "permissions": {}
        });
        assert_eq!(
            detect_json_system_type(&basic_rbac),
            LegacySystemType::BasicRbac
        );

        let permission_based = json!({
            "permissions": {}
        });
        assert_eq!(
            detect_json_system_type(&permission_based),
            LegacySystemType::PermissionBased
        );
    }

    #[test]
    fn test_calculate_hierarchy_depth() {
        let roles = vec![
            LegacyRole {
                id: "admin".to_string(),
                name: "Admin".to_string(),
                description: None,
                permissions: vec![],
                parent_roles: vec!["super_admin".to_string()],
                metadata: HashMap::new(),
            },
            LegacyRole {
                id: "super_admin".to_string(),
                name: "Super Admin".to_string(),
                description: None,
                permissions: vec![],
                parent_roles: vec![],
                metadata: HashMap::new(),
            },
        ];

        let depth = calculate_hierarchy_depth(&roles);
        assert_eq!(depth, 1);
    }
}


