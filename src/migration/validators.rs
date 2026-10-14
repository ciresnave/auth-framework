//! Migration plan validators
//!
//! This module provides validation functionality for migration plans
//! to ensure they are safe and complete before execution.

use super::{MigrationConfig, MigrationError, MigrationOperation, MigrationPlan, ValidationType};
use std::collections::{HashMap, HashSet};

/// Validate migration plan for safety and completeness
pub async fn validate_migration_plan(
    plan: &MigrationPlan,
    _config: &MigrationConfig,
) -> Result<Vec<String>, MigrationError> {
    let mut warnings = Vec::new();

    // Validate phase dependencies
    validate_phase_dependencies(plan, &mut warnings)?;

    // Validate role mappings
    validate_role_mappings(plan, &mut warnings)?;

    // Validate permission mappings
    validate_permission_mappings(plan, &mut warnings)?;

    // Validate user migrations
    validate_user_migrations(plan, &mut warnings)?;

    // Validate backup operations
    validate_backup_operations(plan, &mut warnings)?;

    // Validate rollback plan
    validate_rollback_plan(plan, &mut warnings)?;

    // Validate validation steps
    validate_validation_steps(plan, &mut warnings)?;

    // Check for common migration pitfalls
    check_migration_pitfalls(plan, &mut warnings)?;

    Ok(warnings)
}

/// Validate phase dependencies are correct and achievable
fn validate_phase_dependencies(
    plan: &MigrationPlan,
    warnings: &mut Vec<String>,
) -> Result<(), MigrationError> {
    let mut phase_ids: HashSet<String> = HashSet::new();
    let mut phase_order_map: HashMap<String, u32> = HashMap::new();

    // Collect phase IDs and orders
    for phase in &plan.phases {
        if phase_ids.contains(&phase.id) {
            return Err(MigrationError::ValidationError(format!(
                "Duplicate phase ID found: {}",
                phase.id
            )));
        }
        phase_ids.insert(phase.id.clone());
        phase_order_map.insert(phase.id.clone(), phase.order);
    }

    // Check for circular dependencies first
    if has_circular_dependencies(&plan.phases) {
        return Err(MigrationError::ValidationError(
            "Circular dependencies detected in migration phases".to_string(),
        ));
    }

    // Validate dependencies
    for phase in &plan.phases {
        for dependency in &phase.dependencies {
            if !phase_ids.contains(dependency) {
                return Err(MigrationError::ValidationError(format!(
                    "Phase '{}' depends on non-existent phase '{}'",
                    phase.id, dependency
                )));
            }

            // Check dependency ordering
            if let Some(&dep_order) = phase_order_map.get(dependency)
                && dep_order >= phase.order
            {
                return Err(MigrationError::ValidationError(format!(
                    "Phase '{}' (order {}) depends on phase '{}' (order {}), but dependency should have lower order",
                    phase.id, phase.order, dependency, dep_order
                )));
            }
        }
    }

    // Previous circular dependency check was here - moved up

    // Warn about phases with no dependencies (except the first)
    let phases_with_deps: HashSet<_> = plan.phases.iter().flat_map(|p| &p.dependencies).collect();

    for phase in &plan.phases {
        if phase.dependencies.is_empty() && phase.order > 1 {
            warnings.push(format!(
                "Phase '{}' has no dependencies but is not the first phase",
                phase.id
            ));
        }
        if !phases_with_deps.contains(&phase.id) && phase.order < plan.phases.len() as u32 {
            warnings.push(format!(
                "Phase '{}' is not a dependency of any other phase",
                phase.id
            ));
        }
    }

    Ok(())
}

/// Check for circular dependencies in phases
fn has_circular_dependencies(phases: &[super::MigrationPhase]) -> bool {
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();

    for phase in phases {
        graph.insert(phase.id.clone(), phase.dependencies.clone());
    }

    for phase_id in graph.keys() {
        if has_cycle_from_node(phase_id, &graph, &mut HashSet::new(), &mut HashSet::new()) {
            return true;
        }
    }

    false
}

/// Check for cycles starting from a specific node
fn has_cycle_from_node(
    node: &str,
    graph: &HashMap<String, Vec<String>>,
    visiting: &mut HashSet<String>,
    visited: &mut HashSet<String>,
) -> bool {
    if visiting.contains(node) {
        return true; // Cycle detected
    }

    if visited.contains(node) {
        return false; // Already processed
    }

    visiting.insert(node.to_string());

    if let Some(dependencies) = graph.get(node) {
        for dep in dependencies {
            if has_cycle_from_node(dep, graph, visiting, visited) {
                return true;
            }
        }
    }

    visiting.remove(node);
    visited.insert(node.to_string());
    false
}

/// Validate role mappings are complete and consistent
fn validate_role_mappings(
    plan: &MigrationPlan,
    warnings: &mut Vec<String>,
) -> Result<(), MigrationError> {
    let legacy_roles: HashSet<_> = plan.source_analysis.roles.iter().map(|r| &r.id).collect();

    let mapped_roles: HashSet<_> = plan.role_mappings.keys().collect();

    // Check for unmapped legacy roles
    for legacy_role in &legacy_roles {
        if !mapped_roles.contains(legacy_role) {
            warnings.push(format!(
                "Legacy role '{}' is not mapped to a new role",
                legacy_role
            ));
        }
    }

    // Check for duplicate new role IDs
    let mut new_role_ids: HashMap<&String, Vec<&String>> = HashMap::new();
    for (legacy_id, new_id) in &plan.role_mappings {
        new_role_ids.entry(new_id).or_default().push(legacy_id);
    }

    for (new_id, legacy_ids) in new_role_ids {
        if legacy_ids.len() > 1 {
            warnings.push(format!(
                "New role '{}' is mapped from multiple legacy roles: {:?}",
                new_id, legacy_ids
            ));
        }
    }

    // Validate role creation operations
    let role_creation_ops: HashSet<_> = plan
        .phases
        .iter()
        .flat_map(|p| &p.operations)
        .filter_map(|op| match op {
            MigrationOperation::CreateRole { role_id, .. } => Some(role_id),
            _ => None,
        })
        .collect();

    for new_role_id in plan.role_mappings.values() {
        if !role_creation_ops.contains(new_role_id) {
            warnings.push(format!(
                "Role '{}' is mapped but not created in any phase",
                new_role_id
            ));
        }
    }

    Ok(())
}

/// Validate permission mappings
fn validate_permission_mappings(
    plan: &MigrationPlan,
    warnings: &mut Vec<String>,
) -> Result<(), MigrationError> {
    let legacy_permissions: HashSet<_> = plan
        .source_analysis
        .permissions
        .iter()
        .map(|p| &p.id)
        .collect();

    let mapped_permissions: HashSet<_> = plan.permission_mappings.keys().collect();

    // Check for unmapped legacy permissions
    for legacy_permission in &legacy_permissions {
        if !mapped_permissions.contains(legacy_permission) {
            warnings.push(format!(
                "Legacy permission '{}' is not mapped",
                legacy_permission
            ));
        }
    }

    // Validate permission creation operations
    let permission_creation_ops: HashSet<_> = plan
        .phases
        .iter()
        .flat_map(|p| &p.operations)
        .filter_map(|op| match op {
            MigrationOperation::CreatePermission { permission_id, .. } => Some(permission_id),
            _ => None,
        })
        .collect();

    for new_permission_id in plan.permission_mappings.values() {
        if !permission_creation_ops.contains(new_permission_id) {
            warnings.push(format!(
                "Permission '{}' is mapped but not created in any phase",
                new_permission_id
            ));
        }
    }

    Ok(())
}

/// Validate user migrations
fn validate_user_migrations(
    plan: &MigrationPlan,
    warnings: &mut Vec<String>,
) -> Result<(), MigrationError> {
    let legacy_users: HashSet<_> = plan
        .source_analysis
        .user_assignments
        .iter()
        .map(|u| &u.user_id)
        .collect();

    let migrated_users: HashSet<_> = plan.user_migrations.iter().map(|m| &m.user_id).collect();

    // Check for unmigrated users
    for legacy_user in &legacy_users {
        if !migrated_users.contains(legacy_user) {
            warnings.push(format!(
                "User '{}' has legacy assignments but no migration plan",
                legacy_user
            ));
        }
    }

    // Validate user role assignment operations
    let user_assignment_ops: HashSet<_> = plan
        .phases
        .iter()
        .flat_map(|p| &p.operations)
        .filter_map(|op| match op {
            MigrationOperation::AssignUserRole { user_id, .. } => Some(user_id),
            _ => None,
        })
        .collect();

    for user_migration in &plan.user_migrations {
        if user_migration.user_id != "TEMPLATE"
            && !user_assignment_ops.contains(&user_migration.user_id)
        {
            warnings.push(format!(
                "User '{}' has migration plan but no assignment operations",
                user_migration.user_id
            ));
        }
    }

    // Check for role mappings consistency
    for user_migration in &plan.user_migrations {
        for legacy_role in &user_migration.legacy_roles {
            if !plan.role_mappings.contains_key(legacy_role)
                && legacy_role != "REQUIRES_MANUAL_MAPPING"
            {
                warnings.push(format!(
                    "User migration for '{}' references unmapped legacy role '{}'",
                    user_migration.user_id, legacy_role
                ));
            }
        }
    }

    Ok(())
}

/// Validate backup operations
fn validate_backup_operations(
    plan: &MigrationPlan,
    warnings: &mut Vec<String>,
) -> Result<(), MigrationError> {
    let backup_ops: Vec<_> = plan
        .phases
        .iter()
        .flat_map(|p| &p.operations)
        .filter_map(|op| match op {
            MigrationOperation::Backup {
                backup_location,
                backup_type,
            } => Some((backup_location, backup_type)),
            _ => None,
        })
        .collect();

    if backup_ops.is_empty() {
        return Err(MigrationError::ValidationError(
            "No backup operations found in migration plan".to_string(),
        ));
    }

    // Check if first phase includes backup
    if let Some(first_phase) = plan.phases.first() {
        let has_backup = first_phase
            .operations
            .iter()
            .any(|op| matches!(op, MigrationOperation::Backup { .. }));

        if !has_backup {
            warnings.push("First phase does not include a backup operation".to_string());
        }
    }

    // Validate backup locations are different
    let mut backup_locations = HashSet::new();
    for (location, _) in backup_ops {
        if !backup_locations.insert(location) {
            warnings.push(format!("Duplicate backup location: {:?}", location));
        }
    }

    Ok(())
}

/// Validate rollback plan
fn validate_rollback_plan(
    plan: &MigrationPlan,
    warnings: &mut Vec<String>,
) -> Result<(), MigrationError> {
    if plan.rollback_plan.phases.is_empty() {
        return Err(MigrationError::ValidationError(
            "Rollback plan has no phases".to_string(),
        ));
    }

    if plan.rollback_plan.backup_locations.is_empty() {
        warnings.push("Rollback plan has no backup locations specified".to_string());
    }

    // Check if rollback phases are ordered
    let mut last_order = 0;
    for phase in &plan.rollback_plan.phases {
        if phase.order <= last_order && last_order > 0 {
            warnings.push(format!("Rollback phase '{}' has incorrect order", phase.id));
        }
        last_order = phase.order;
    }

    // Validate RTO is reasonable
    if plan.rollback_plan.recovery_time_objective > chrono::Duration::hours(24) {
        warnings.push("Recovery Time Objective exceeds 24 hours".to_string());
    }

    Ok(())
}

/// Validate validation steps
fn validate_validation_steps(
    plan: &MigrationPlan,
    warnings: &mut Vec<String>,
) -> Result<(), MigrationError> {
    // Check for required validation types
    let required_validations = vec![
        ValidationType::HierarchyIntegrity,
        ValidationType::PermissionConsistency,
        ValidationType::UserAssignmentValidity,
    ];

    let post_validation_types: HashSet<_> = plan
        .post_validation_steps
        .iter()
        .map(|step| &step.validation_type)
        .collect();

    for required_validation in required_validations {
        if !post_validation_types.contains(&required_validation) {
            warnings.push(format!(
                "Missing required post-migration validation: {:?}",
                required_validation
            ));
        }
    }

    // Check for duplicate validation IDs
    let mut validation_ids = HashSet::new();
    for step in &plan.pre_validation_steps {
        if !validation_ids.insert(&step.id) {
            return Err(MigrationError::ValidationError(format!(
                "Duplicate pre-validation step ID: {}",
                step.id
            )));
        }
    }

    validation_ids.clear();
    for step in &plan.post_validation_steps {
        if !validation_ids.insert(&step.id) {
            return Err(MigrationError::ValidationError(format!(
                "Duplicate post-validation step ID: {}",
                step.id
            )));
        }
    }

    Ok(())
}

/// Check for common migration pitfalls
fn check_migration_pitfalls(
    plan: &MigrationPlan,
    warnings: &mut Vec<String>,
) -> Result<(), MigrationError> {
    // Check for privilege escalation risks
    check_privilege_escalation_risks(plan, warnings);

    // Check for orphaned permissions
    check_orphaned_permissions_handling(plan, warnings);

    // Check for circular dependencies in source
    check_circular_dependency_handling(plan, warnings);

    // Check duration estimates
    check_duration_estimates(plan, warnings);

    // Check for missing error handling
    check_error_handling(plan, warnings);

    Ok(())
}

/// Check for potential privilege escalation during migration
fn check_privilege_escalation_risks(plan: &MigrationPlan, warnings: &mut Vec<String>) {
    // Look for users getting more permissions than they had before
    for user_migration in &plan.user_migrations {
        if user_migration.legacy_permissions.len() < user_migration.new_roles.len() * 5 {
            // Rough heuristic: if new roles significantly outnumber legacy permissions, investigate
            warnings.push(format!(
                "User '{}' may have privilege escalation - verify role assignments",
                user_migration.user_id
            ));
        }
    }

    // Check if privilege escalation validation is included
    let has_privilege_check = plan.post_validation_steps.iter().any(|step| {
        matches!(
            step.validation_type,
            ValidationType::PrivilegeEscalationCheck
        )
    });

    if !has_privilege_check {
        warnings
            .push("No privilege escalation check found in post-migration validation".to_string());
    }
}

/// Check how orphaned permissions are handled
fn check_orphaned_permissions_handling(plan: &MigrationPlan, warnings: &mut Vec<String>) {
    if !plan.source_analysis.orphaned_permissions.is_empty() {
        let orphaned_handled = plan.phases.iter().any(|phase| {
            phase.operations.iter().any(|op| match op {
                MigrationOperation::CreatePermission { permission_id, .. } => plan
                    .source_analysis
                    .orphaned_permissions
                    .contains(permission_id),
                _ => false,
            })
        });

        if !orphaned_handled {
            warnings.push(format!("Found {} orphaned permissions in source system, but no handling strategy in migration plan",
                                plan.source_analysis.orphaned_permissions.len()));
        }
    }
}

/// Check how circular dependencies are handled
fn check_circular_dependency_handling(plan: &MigrationPlan, warnings: &mut Vec<String>) {
    if !plan.source_analysis.circular_dependencies.is_empty() {
        warnings.push(format!(
            "Source system has {} circular dependencies - ensure migration plan addresses these",
            plan.source_analysis.circular_dependencies.len()
        ));
    }
}

/// Check if duration estimates are reasonable
fn check_duration_estimates(plan: &MigrationPlan, warnings: &mut Vec<String>) {
    let total_operations = plan
        .phases
        .iter()
        .map(|phase| phase.operations.len())
        .sum::<usize>();

    let avg_time_per_operation =
        plan.estimated_duration.num_minutes() as f64 / total_operations as f64;

    if avg_time_per_operation < 1.0 {
        warnings.push(
            "Duration estimates may be too optimistic - less than 1 minute per operation"
                .to_string(),
        );
    } else if avg_time_per_operation > 30.0 {
        warnings.push(
            "Duration estimates may be too conservative - more than 30 minutes per operation"
                .to_string(),
        );
    }

    // Check for unrealistic downtime
    if let Some(downtime) = plan.downtime_required
        && downtime > chrono::Duration::hours(8)
    {
        warnings.push("Required downtime exceeds 8 hours - consider gradual migration".to_string());
    }
}

/// Check for error handling provisions
fn check_error_handling(plan: &MigrationPlan, warnings: &mut Vec<String>) {
    let has_validation_ops = plan.phases.iter().any(|phase| {
        phase
            .operations
            .iter()
            .any(|op| matches!(op, MigrationOperation::ValidateIntegrity { .. }))
    });

    if !has_validation_ops {
        warnings.push("No validation operations found in migration phases".to_string());
    }

    // Check if each phase has rollback operations
    for phase in &plan.phases {
        if phase.rollback_operations.is_empty() {
            warnings.push(format!(
                "Phase '{}' has no rollback operations defined",
                phase.id
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{
        BackupType, LegacySystemAnalysis, LegacySystemType, MigrationOperation, MigrationPhase,
        MigrationStrategy,
    };

    fn create_test_plan() -> MigrationPlan {
        MigrationPlan {
            id: "test_plan".to_string(),
            source_analysis: LegacySystemAnalysis {
                system_type: LegacySystemType::BasicRbac,
                role_count: 1,
                permission_count: 1,
                user_assignment_count: 1,
                roles: vec![],
                permissions: vec![],
                user_assignments: vec![],
                hierarchy_depth: 0,
                duplicates_found: false,
                orphaned_permissions: vec![],
                circular_dependencies: vec![],
                custom_attributes: std::collections::HashSet::new(),
                complexity_score: 3,
                recommended_strategy: MigrationStrategy::DirectMapping,
            },
            strategy: MigrationStrategy::DirectMapping,
            phases: vec![
                MigrationPhase {
                    id: "phase1".to_string(),
                    name: "Phase 1".to_string(),
                    description: "First phase".to_string(),
                    order: 1,
                    operations: vec![MigrationOperation::Backup {
                        backup_location: std::path::PathBuf::from("./backup"),
                        backup_type: BackupType::Full,
                    }],
                    dependencies: vec![],
                    estimated_duration: chrono::Duration::minutes(30),
                    rollback_operations: vec![],
                },
                MigrationPhase {
                    id: "phase2".to_string(),
                    name: "Phase 2".to_string(),
                    description: "Second phase".to_string(),
                    order: 2,
                    operations: vec![],
                    dependencies: vec!["phase1".to_string()],
                    estimated_duration: chrono::Duration::minutes(30),
                    rollback_operations: vec![],
                },
            ],
            role_mappings: HashMap::new(),
            permission_mappings: HashMap::new(),
            user_migrations: vec![],
            pre_validation_steps: vec![],
            post_validation_steps: vec![],
            rollback_plan: super::super::RollbackPlan {
                phases: vec![
                    super::super::RollbackPhase {
                        id: "rollback_phase1".to_string(),
                        name: "Rollback Phase 1".to_string(),
                        order: 1,
                        operations: vec![],
                    },
                    super::super::RollbackPhase {
                        id: "rollback_phase2".to_string(),
                        name: "Rollback Phase 2".to_string(),
                        order: 2,
                        operations: vec![],
                    },
                ],
                backup_locations: vec![std::path::PathBuf::from("./backup")],
                recovery_time_objective: chrono::Duration::hours(2),
                manual_steps: vec![],
            },
            estimated_duration: chrono::Duration::hours(1),
            risk_level: super::super::RiskLevel::Low,
            downtime_required: None,
        }
    }

    #[tokio::test]
    async fn test_validate_phase_dependencies() {
        let plan = create_test_plan();
        let config = MigrationConfig::default();

        let warnings = validate_migration_plan(&plan, &config).await.unwrap();

        // Should have some warnings but no errors
        assert!(!warnings.is_empty());
    }

    #[tokio::test]
    async fn test_circular_dependency_detection() {
        let mut plan = create_test_plan();

        // Create circular dependency without violating order constraints
        // Add a third phase with order 0 (before phase1)
        plan.phases.push(super::super::MigrationPhase {
            id: "phase0".to_string(),
            name: "Phase 0".to_string(),
            description: "Zero phase".to_string(),
            order: 0,
            operations: vec![],
            dependencies: vec!["phase2".to_string()], // phase0 depends on phase2 (creates cycle: phase0 -> phase2 -> phase1 -> phase0)
            estimated_duration: chrono::Duration::minutes(30),
            rollback_operations: vec![],
        });

        // Now make phase1 depend on phase0 to create a cycle
        plan.phases[0].dependencies = vec!["phase0".to_string()];

        let config = MigrationConfig::default();
        let result = validate_migration_plan(&plan, &config).await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Circular dependencies")
        );
    }

    #[test]
    fn test_has_circular_dependencies() {
        let phases = vec![
            super::super::MigrationPhase {
                id: "a".to_string(),
                name: "A".to_string(),
                description: "".to_string(),
                order: 1,
                operations: vec![],
                dependencies: vec!["b".to_string()],
                estimated_duration: chrono::Duration::minutes(1),
                rollback_operations: vec![],
            },
            super::super::MigrationPhase {
                id: "b".to_string(),
                name: "B".to_string(),
                description: "".to_string(),
                order: 2,
                operations: vec![],
                dependencies: vec!["a".to_string()],
                estimated_duration: chrono::Duration::minutes(1),
                rollback_operations: vec![],
            },
        ];

        assert!(has_circular_dependencies(&phases));
    }
}
