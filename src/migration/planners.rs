//! Migration plan generators
//!
//! This module provides migration plan generation based on legacy
//! system analysis and selected migration strategy.

use super::{
    BackupType, LegacySystemAnalysis, MigrationConfig, MigrationError, MigrationOperation,
    MigrationPhase, MigrationPlan, MigrationStrategy, RiskLevel, RollbackPhase, RollbackPlan,
    UserMigration, ValidationStep, ValidationType,
};
use std::collections::HashMap;
use uuid::Uuid;

/// Generate comprehensive migration plan
pub async fn generate_migration_plan(
    analysis: &LegacySystemAnalysis,
    strategy: Option<MigrationStrategy>,
    _config: &MigrationConfig,
) -> Result<MigrationPlan, MigrationError> {
    let selected_strategy = strategy.unwrap_or_else(|| analysis.recommended_strategy.clone());

    let plan_id = Uuid::new_v4().to_string();

    let mut plan = MigrationPlan {
        id: plan_id,
        source_analysis: analysis.clone(),
        strategy: selected_strategy.clone(),
        phases: Vec::new(),
        role_mappings: HashMap::new(),
        permission_mappings: HashMap::new(),
        user_migrations: Vec::new(),
        pre_validation_steps: Vec::new(),
        post_validation_steps: Vec::new(),
        rollback_plan: RollbackPlan {
            phases: Vec::new(),
            backup_locations: Vec::new(),
            recovery_time_objective: chrono::Duration::hours(4),
            manual_steps: Vec::new(),
        },
        estimated_duration: chrono::Duration::hours(1),
        risk_level: assess_risk_level(analysis),
        downtime_required: None,
    };

    match selected_strategy {
        MigrationStrategy::DirectMapping => {
            generate_direct_mapping_plan(&mut plan, analysis).await?;
        }
        MigrationStrategy::GradualMigration => {
            generate_gradual_migration_plan(&mut plan, analysis).await?;
        }
        MigrationStrategy::Rebuild => {
            generate_rebuild_plan(&mut plan, analysis).await?;
        }
        MigrationStrategy::Custom(ref description) => {
            generate_custom_plan(&mut plan, analysis, description).await?;
        }
    }

    // Generate validation steps
    generate_validation_steps(&mut plan, analysis);

    // Generate rollback plan
    generate_rollback_plan(&mut plan, analysis);

    // Estimate duration and assess risk
    estimate_migration_duration(&mut plan);

    Ok(plan)
}

/// Generate direct mapping migration plan
async fn generate_direct_mapping_plan(
    plan: &mut MigrationPlan,
    analysis: &LegacySystemAnalysis,
) -> Result<(), MigrationError> {
    // Phase 1: Backup and preparation
    let backup_phase = MigrationPhase {
        id: "backup".to_string(),
        name: "Backup and Preparation".to_string(),
        description: "Create backups and prepare for migration".to_string(),
        order: 1,
        operations: vec![
            MigrationOperation::Backup {
                backup_location: std::path::PathBuf::from("./backups/pre_migration"),
                backup_type: BackupType::Full,
            },
            MigrationOperation::ValidateIntegrity {
                validation_type: "pre_migration_check".to_string(),
                parameters: HashMap::new(),
            },
        ],
        dependencies: Vec::new(),
        estimated_duration: chrono::Duration::minutes(30),
        rollback_operations: Vec::new(),
    };

    // Phase 2: Create roles
    let mut role_operations = Vec::new();
    for role in &analysis.roles {
        // Direct mapping: use existing role structure
        let role_id = format!("migrated_{}", role.id);
        plan.role_mappings.insert(role.id.clone(), role_id.clone());

        role_operations.push(MigrationOperation::CreateRole {
            role_id: role_id.clone(),
            name: role.name.clone(),
            description: role.description.clone(),
            permissions: role.permissions.clone(),
            parent_role: role.parent_roles.first().map(|p| format!("migrated_{}", p)),
        });
    }

    let roles_phase = MigrationPhase {
        id: "create_roles".to_string(),
        name: "Create Roles".to_string(),
        description: "Create all roles in the new system".to_string(),
        order: 2,
        operations: role_operations,
        dependencies: vec!["backup".to_string()],
        estimated_duration: chrono::Duration::minutes(analysis.role_count as i64 * 2),
        rollback_operations: Vec::new(),
    };

    // Phase 3: Create permissions
    let mut permission_operations = Vec::new();
    for permission in &analysis.permissions {
        let permission_id = format!("migrated_{}", permission.id);
        plan.permission_mappings
            .insert(permission.id.clone(), permission_id.clone());

        permission_operations.push(MigrationOperation::CreatePermission {
            permission_id: permission_id.clone(),
            action: permission.action.clone(),
            resource: permission.resource.clone(),
            conditions: permission.conditions.clone(),
        });
    }

    let permissions_phase = MigrationPhase {
        id: "create_permissions".to_string(),
        name: "Create Permissions".to_string(),
        description: "Create all permissions in the new system".to_string(),
        order: 3,
        operations: permission_operations,
        dependencies: vec!["create_roles".to_string()],
        estimated_duration: chrono::Duration::minutes(analysis.permission_count as i64),
        rollback_operations: Vec::new(),
    };

    // Phase 4: Migrate user assignments
    let mut user_operations = Vec::new();
    for assignment in &analysis.user_assignments {
        if let Some(role_id) = &assignment.role_id
            && let Some(new_role_id) = plan.role_mappings.get(role_id)
        {
            user_operations.push(MigrationOperation::AssignUserRole {
                user_id: assignment.user_id.clone(),
                role_id: new_role_id.clone(),
                expiration: assignment.expiration,
            });

            plan.user_migrations.push(UserMigration {
                user_id: assignment.user_id.clone(),
                legacy_roles: vec![role_id.clone()],
                legacy_permissions: assignment.permissions.clone(),
                new_roles: vec![new_role_id.clone()],
                migration_notes: Some("Direct mapping migration".to_string()),
            });
        }
    }

    let users_phase = MigrationPhase {
        id: "migrate_users".to_string(),
        name: "Migrate User Assignments".to_string(),
        description: "Migrate all user role assignments".to_string(),
        order: 4,
        operations: user_operations,
        dependencies: vec!["create_permissions".to_string()],
        estimated_duration: chrono::Duration::minutes(analysis.user_assignment_count as i64),
        rollback_operations: Vec::new(),
    };

    // Phase 5: Final validation
    let validation_phase = MigrationPhase {
        id: "final_validation".to_string(),
        name: "Final Validation".to_string(),
        description: "Validate migration completeness and integrity".to_string(),
        order: 5,
        operations: vec![MigrationOperation::ValidateIntegrity {
            validation_type: "post_migration_check".to_string(),
            parameters: HashMap::new(),
        }],
        dependencies: vec!["migrate_users".to_string()],
        estimated_duration: chrono::Duration::minutes(15),
        rollback_operations: Vec::new(),
    };

    plan.phases = vec![
        backup_phase,
        roles_phase,
        permissions_phase,
        users_phase,
        validation_phase,
    ];
    plan.downtime_required = Some(chrono::Duration::minutes(10));

    Ok(())
}

/// Generate gradual migration plan
async fn generate_gradual_migration_plan(
    plan: &mut MigrationPlan,
    analysis: &LegacySystemAnalysis,
) -> Result<(), MigrationError> {
    // Phase 1: Setup parallel systems
    let setup_phase = MigrationPhase {
        id: "setup_parallel".to_string(),
        name: "Setup Parallel Systems".to_string(),
        description: "Setup new role system alongside existing system".to_string(),
        order: 1,
        operations: vec![MigrationOperation::Backup {
            backup_location: std::path::PathBuf::from("./backups/pre_gradual_migration"),
            backup_type: BackupType::Full,
        }],
        dependencies: Vec::new(),
        estimated_duration: chrono::Duration::hours(1),
        rollback_operations: Vec::new(),
    };

    // Phase 2: Migrate critical roles first
    let critical_roles = identify_critical_roles(analysis);
    let mut critical_role_operations = Vec::new();

    for role_id in &critical_roles {
        if let Some(role) = analysis.roles.iter().find(|r| r.id == *role_id) {
            let new_role_id = format!("migrated_{}", role.id);
            plan.role_mappings
                .insert(role.id.clone(), new_role_id.clone());

            critical_role_operations.push(MigrationOperation::CreateRole {
                role_id: new_role_id,
                name: role.name.clone(),
                description: role.description.clone(),
                permissions: role.permissions.clone(),
                parent_role: None, // Handle hierarchy in later phase
            });
        }
    }

    let critical_phase = MigrationPhase {
        id: "migrate_critical_roles".to_string(),
        name: "Migrate Critical Roles".to_string(),
        description: "Migrate business-critical roles first".to_string(),
        order: 2,
        operations: critical_role_operations,
        dependencies: vec!["setup_parallel".to_string()],
        estimated_duration: chrono::Duration::minutes(critical_roles.len() as i64 * 5),
        rollback_operations: Vec::new(),
    };

    // Phase 3: Migrate remaining roles in batches
    let remaining_roles: Vec<_> = analysis
        .roles
        .iter()
        .filter(|role| !critical_roles.contains(&role.id))
        .collect();

    let batch_size = 10;
    let mut batch_phases = Vec::new();

    for (batch_idx, batch) in remaining_roles.chunks(batch_size).enumerate() {
        let mut batch_operations = Vec::new();

        for role in batch {
            let new_role_id = format!("migrated_{}", role.id);
            plan.role_mappings
                .insert(role.id.clone(), new_role_id.clone());

            batch_operations.push(MigrationOperation::CreateRole {
                role_id: new_role_id,
                name: role.name.clone(),
                description: role.description.clone(),
                permissions: role.permissions.clone(),
                parent_role: role.parent_roles.first().map(|p| format!("migrated_{}", p)),
            });
        }

        let phase = MigrationPhase {
            id: format!("migrate_batch_{}", batch_idx + 1),
            name: format!("Migrate Role Batch {}", batch_idx + 1),
            description: format!(
                "Migrate roles in batch {} of {}",
                batch_idx + 1,
                remaining_roles.len().div_ceil(batch_size)
            ),
            order: 3 + batch_idx as u32,
            operations: batch_operations,
            dependencies: if batch_idx == 0 {
                vec!["migrate_critical_roles".to_string()]
            } else {
                vec![format!("migrate_batch_{}", batch_idx)]
            },
            estimated_duration: chrono::Duration::minutes(batch.len() as i64 * 3),
            rollback_operations: Vec::new(),
        };

        batch_phases.push(phase);
    }

    // Phase N: Migrate users gradually
    let user_batches: Vec<_> = analysis.user_assignments.chunks(50).collect();
    let mut user_phases = Vec::new();

    for (batch_idx, batch) in user_batches.iter().enumerate() {
        let mut user_operations = Vec::new();

        for assignment in *batch {
            if let Some(role_id) = &assignment.role_id
                && let Some(new_role_id) = plan.role_mappings.get(role_id)
            {
                user_operations.push(MigrationOperation::AssignUserRole {
                    user_id: assignment.user_id.clone(),
                    role_id: new_role_id.clone(),
                    expiration: assignment.expiration,
                });
            }
        }

        let phase = MigrationPhase {
            id: format!("migrate_users_batch_{}", batch_idx + 1),
            name: format!("Migrate User Batch {}", batch_idx + 1),
            description: format!("Migrate user assignments in batch {}", batch_idx + 1),
            order: 100 + batch_idx as u32,
            operations: user_operations,
            dependencies: vec![format!("migrate_batch_{}", batch_phases.len())],
            estimated_duration: chrono::Duration::minutes(batch.len() as i64 * 2),
            rollback_operations: Vec::new(),
        };

        user_phases.push(phase);
    }

    // Combine all phases
    plan.phases = vec![setup_phase, critical_phase];
    plan.phases.extend(batch_phases);
    plan.phases.extend(user_phases);

    // No downtime required for gradual migration
    plan.downtime_required = None;

    Ok(())
}

/// Generate rebuild migration plan
async fn generate_rebuild_plan(
    plan: &mut MigrationPlan,
    analysis: &LegacySystemAnalysis,
) -> Result<(), MigrationError> {
    // Phase 1: Analysis and design
    let analysis_phase = MigrationPhase {
        id: "analyze_and_design".to_string(),
        name: "Analyze and Design New Structure".to_string(),
        description: "Analyze existing system and design optimized role structure".to_string(),
        order: 1,
        operations: vec![MigrationOperation::Backup {
            backup_location: std::path::PathBuf::from("./backups/pre_rebuild"),
            backup_type: BackupType::Full,
        }],
        dependencies: Vec::new(),
        estimated_duration: chrono::Duration::hours(2),
        rollback_operations: Vec::new(),
    };

    // Phase 2: Create consolidated roles
    let consolidated_roles = consolidate_roles(analysis);
    let mut role_operations = Vec::new();

    for (new_role_id, role_data) in &consolidated_roles {
        plan.role_mappings.extend(role_data.legacy_mappings.clone());

        role_operations.push(MigrationOperation::CreateRole {
            role_id: new_role_id.clone(),
            name: role_data.name.clone(),
            description: role_data.description.clone(),
            permissions: role_data.permissions.clone(),
            parent_role: role_data.parent_role.clone(),
        });
    }

    let roles_phase = MigrationPhase {
        id: "create_consolidated_roles".to_string(),
        name: "Create Consolidated Roles".to_string(),
        description: "Create optimized, consolidated role structure".to_string(),
        order: 2,
        operations: role_operations,
        dependencies: vec!["analyze_and_design".to_string()],
        estimated_duration: chrono::Duration::minutes(consolidated_roles.len() as i64 * 3),
        rollback_operations: Vec::new(),
    };

    // Phase 3: Migrate users to new structure
    let mut user_operations = Vec::new();
    for assignment in &analysis.user_assignments {
        if let Some(role_id) = &assignment.role_id
            && let Some(new_role_id) = plan.role_mappings.get(role_id)
        {
            user_operations.push(MigrationOperation::AssignUserRole {
                user_id: assignment.user_id.clone(),
                role_id: new_role_id.clone(),
                expiration: assignment.expiration,
            });

            plan.user_migrations.push(UserMigration {
                user_id: assignment.user_id.clone(),
                legacy_roles: vec![role_id.clone()],
                legacy_permissions: assignment.permissions.clone(),
                new_roles: vec![new_role_id.clone()],
                migration_notes: Some("Rebuilt with consolidated roles".to_string()),
            });
        }
    }

    let users_phase = MigrationPhase {
        id: "migrate_to_new_structure".to_string(),
        name: "Migrate to New Structure".to_string(),
        description: "Migrate users to the new consolidated role structure".to_string(),
        order: 3,
        operations: user_operations,
        dependencies: vec!["create_consolidated_roles".to_string()],
        estimated_duration: chrono::Duration::minutes(analysis.user_assignment_count as i64),
        rollback_operations: Vec::new(),
    };

    plan.phases = vec![analysis_phase, roles_phase, users_phase];
    plan.downtime_required = Some(chrono::Duration::hours(1));

    Ok(())
}

/// Generate custom migration plan
async fn generate_custom_plan(
    plan: &mut MigrationPlan,
    _analysis: &LegacySystemAnalysis,
    _description: &str,
) -> Result<(), MigrationError> {
    // For custom plans, create a template that can be manually customized
    let template_phase = MigrationPhase {
        id: "custom_migration".to_string(),
        name: "Custom Migration Template".to_string(),
        description: "Template for custom migration - requires manual customization".to_string(),
        order: 1,
        operations: vec![MigrationOperation::Backup {
            backup_location: std::path::PathBuf::from("./backups/pre_custom_migration"),
            backup_type: BackupType::Full,
        }],
        dependencies: Vec::new(),
        estimated_duration: chrono::Duration::hours(4),
        rollback_operations: Vec::new(),
    };

    plan.phases = vec![template_phase];
    plan.downtime_required = Some(chrono::Duration::hours(2));

    // Add note that this requires manual customization
    plan.user_migrations.push(UserMigration {
        user_id: "TEMPLATE".to_string(),
        legacy_roles: vec!["REQUIRES_MANUAL_MAPPING".to_string()],
        legacy_permissions: vec!["REQUIRES_MANUAL_MAPPING".to_string()],
        new_roles: vec!["REQUIRES_MANUAL_MAPPING".to_string()],
        migration_notes: Some(
            "Custom migration plan requires manual customization based on specific requirements"
                .to_string(),
        ),
    });

    Ok(())
}

/// Identify critical roles that should be migrated first
fn identify_critical_roles(analysis: &LegacySystemAnalysis) -> Vec<String> {
    let mut critical_roles = Vec::new();

    // Roles with many permissions are likely critical
    for role in &analysis.roles {
        if role.permissions.len() > 5 {
            critical_roles.push(role.id.clone());
        }
    }

    // Roles that are parents to other roles are critical
    let parent_roles: std::collections::HashSet<_> = analysis
        .roles
        .iter()
        .flat_map(|role| &role.parent_roles)
        .collect();

    for parent_role in parent_roles {
        if !critical_roles.contains(parent_role) {
            critical_roles.push(parent_role.clone());
        }
    }

    // If no critical roles identified, pick the first few
    if critical_roles.is_empty() {
        critical_roles.extend(analysis.roles.iter().take(3).map(|role| role.id.clone()));
    }

    critical_roles
}

/// Consolidated role data for rebuild strategy
#[derive(Debug, Clone)]
struct ConsolidatedRole {
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
    parent_role: Option<String>,
    legacy_mappings: HashMap<String, String>,
}

/// Consolidate roles for rebuild strategy
fn consolidate_roles(analysis: &LegacySystemAnalysis) -> HashMap<String, ConsolidatedRole> {
    let mut consolidated = HashMap::new();

    // Group roles by similar permission sets
    let mut permission_groups: HashMap<Vec<String>, Vec<&super::LegacyRole>> = HashMap::new();

    for role in &analysis.roles {
        let mut permissions = role.permissions.clone();
        permissions.sort();

        permission_groups.entry(permissions).or_default().push(role);
    }

    // Create consolidated roles
    for (permissions, roles) in permission_groups {
        if roles.len() == 1 {
            // Single role, keep as-is
            let role = roles[0];
            let new_id = format!("consolidated_{}", role.id);
            let mut mappings = HashMap::new();
            mappings.insert(role.id.clone(), new_id.clone());

            consolidated.insert(
                new_id.clone(),
                ConsolidatedRole {
                    name: role.name.clone(),
                    description: role.description.clone(),
                    permissions: role.permissions.clone(),
                    parent_role: role.parent_roles.first().cloned(),
                    legacy_mappings: mappings,
                },
            );
        } else {
            // Multiple roles with same permissions, consolidate them
            let consolidated_name = format!("Consolidated_{}", roles[0].name);
            let new_id = format!("consolidated_group_{}", roles[0].id);
            let mut mappings = HashMap::new();

            for role in &roles {
                mappings.insert(role.id.clone(), new_id.clone());
            }

            consolidated.insert(
                new_id.clone(),
                ConsolidatedRole {
                    name: consolidated_name,
                    description: Some(format!(
                        "Consolidated from: {}",
                        roles
                            .iter()
                            .map(|r| r.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                    permissions,
                    parent_role: None, // Simplified hierarchy
                    legacy_mappings: mappings,
                },
            );
        }
    }

    consolidated
}

/// Generate validation steps for migration plan
fn generate_validation_steps(plan: &mut MigrationPlan, analysis: &LegacySystemAnalysis) {
    // Pre-migration validation
    plan.pre_validation_steps = vec![
        ValidationStep {
            id: "backup_validation".to_string(),
            name: "Backup Validation".to_string(),
            description: "Verify backup integrity and completeness".to_string(),
            validation_type: ValidationType::Custom("backup_check".to_string()),
            parameters: HashMap::new(),
            required: true,
        },
        ValidationStep {
            id: "system_health_check".to_string(),
            name: "System Health Check".to_string(),
            description: "Verify system is ready for migration".to_string(),
            validation_type: ValidationType::Custom("health_check".to_string()),
            parameters: HashMap::new(),
            required: true,
        },
    ];

    // Post-migration validation
    plan.post_validation_steps = vec![
        ValidationStep {
            id: "role_hierarchy_validation".to_string(),
            name: "Role Hierarchy Validation".to_string(),
            description: "Verify role hierarchy integrity".to_string(),
            validation_type: ValidationType::HierarchyIntegrity,
            parameters: HashMap::new(),
            required: true,
        },
        ValidationStep {
            id: "permission_consistency_validation".to_string(),
            name: "Permission Consistency Validation".to_string(),
            description: "Verify permission assignments are consistent".to_string(),
            validation_type: ValidationType::PermissionConsistency,
            parameters: HashMap::new(),
            required: true,
        },
        ValidationStep {
            id: "user_assignment_validation".to_string(),
            name: "User Assignment Validation".to_string(),
            description: "Verify all user assignments migrated correctly".to_string(),
            validation_type: ValidationType::UserAssignmentValidity,
            parameters: HashMap::new(),
            required: true,
        },
        ValidationStep {
            id: "privilege_escalation_check".to_string(),
            name: "Privilege Escalation Check".to_string(),
            description: "Verify no unintended privilege escalation occurred".to_string(),
            validation_type: ValidationType::PrivilegeEscalationCheck,
            parameters: HashMap::new(),
            required: true,
        },
    ];

    // Add complexity-specific validations
    if !analysis.circular_dependencies.is_empty() {
        plan.post_validation_steps.push(ValidationStep {
            id: "circular_dependency_check".to_string(),
            name: "Circular Dependency Check".to_string(),
            description: "Verify circular dependencies were resolved".to_string(),
            validation_type: ValidationType::Custom("circular_check".to_string()),
            parameters: HashMap::new(),
            required: true,
        });
    }
}

/// Generate rollback plan for migration
fn generate_rollback_plan(plan: &mut MigrationPlan, _analysis: &LegacySystemAnalysis) {
    plan.rollback_plan = RollbackPlan {
        phases: vec![
            RollbackPhase {
                id: "stop_migration".to_string(),
                name: "Stop Migration Process".to_string(),
                operations: vec![MigrationOperation::ValidateIntegrity {
                    validation_type: "stop_migration".to_string(),
                    parameters: HashMap::new(),
                }],
                order: 1,
            },
            RollbackPhase {
                id: "restore_backup".to_string(),
                name: "Restore from Backup".to_string(),
                operations: vec![MigrationOperation::Backup {
                    backup_location: std::path::PathBuf::from("./restore"),
                    backup_type: BackupType::Full,
                }],
                order: 2,
            },
        ],
        backup_locations: vec![
            std::path::PathBuf::from("./backups/pre_migration"),
            std::path::PathBuf::from("./backups/incremental"),
        ],
        recovery_time_objective: chrono::Duration::hours(2),
        manual_steps: vec![
            "Verify system state after rollback".to_string(),
            "Check user access and permissions".to_string(),
            "Validate application functionality".to_string(),
        ],
    };
}

/// Assess risk level for migration
fn assess_risk_level(analysis: &LegacySystemAnalysis) -> RiskLevel {
    match analysis.complexity_score {
        1..=3 => RiskLevel::Low,
        4..=6 => RiskLevel::Medium,
        7..=8 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

/// Estimate migration duration
fn estimate_migration_duration(plan: &mut MigrationPlan) {
    let total_duration = plan
        .phases
        .iter()
        .map(|phase| phase.estimated_duration)
        .fold(chrono::Duration::zero(), |acc, duration| acc + duration);

    // Add 20% buffer for unexpected issues
    plan.estimated_duration = total_duration + (total_duration / 5);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{LegacyRole, LegacySystemType, LegacyUserAssignment};

    fn create_test_analysis() -> LegacySystemAnalysis {
        LegacySystemAnalysis {
            system_type: LegacySystemType::BasicRbac,
            role_count: 5,
            permission_count: 10,
            user_assignment_count: 3,
            roles: vec![
                LegacyRole {
                    id: "admin".to_string(),
                    name: "Administrator".to_string(),
                    description: Some("Admin role".to_string()),
                    permissions: vec![
                        "read".to_string(),
                        "write".to_string(),
                        "delete".to_string(),
                        "admin".to_string(),
                        "manage_users".to_string(),
                        "manage_system".to_string(),
                    ],
                    parent_roles: vec![],
                    metadata: HashMap::new(),
                },
                LegacyRole {
                    id: "moderator".to_string(),
                    name: "Moderator".to_string(),
                    description: Some("Moderator role".to_string()),
                    permissions: vec![
                        "read".to_string(),
                        "write".to_string(),
                        "moderate".to_string(),
                    ],
                    parent_roles: vec![],
                    metadata: HashMap::new(),
                },
                LegacyRole {
                    id: "user".to_string(),
                    name: "User".to_string(),
                    description: Some("User role".to_string()),
                    permissions: vec!["read".to_string()],
                    parent_roles: vec![],
                    metadata: HashMap::new(),
                },
                LegacyRole {
                    id: "guest".to_string(),
                    name: "Guest".to_string(),
                    description: Some("Guest role".to_string()),
                    permissions: vec!["read_public".to_string()],
                    parent_roles: vec![],
                    metadata: HashMap::new(),
                },
                LegacyRole {
                    id: "support".to_string(),
                    name: "Support".to_string(),
                    description: Some("Support role".to_string()),
                    permissions: vec!["read".to_string(), "support_tickets".to_string()],
                    parent_roles: vec![],
                    metadata: HashMap::new(),
                },
            ],
            permissions: vec![],
            user_assignments: vec![
                LegacyUserAssignment {
                    user_id: "user1".to_string(),
                    role_id: Some("admin".to_string()),
                    permissions: vec!["admin:read".to_string(), "admin:write".to_string()],
                    attributes: HashMap::new(),
                    expiration: None,
                },
                LegacyUserAssignment {
                    user_id: "user2".to_string(),
                    role_id: Some("user".to_string()),
                    permissions: vec!["user:read".to_string()],
                    attributes: HashMap::new(),
                    expiration: None,
                },
                LegacyUserAssignment {
                    user_id: "user3".to_string(),
                    role_id: Some("moderator".to_string()),
                    permissions: vec!["mod:moderate".to_string()],
                    attributes: HashMap::new(),
                    expiration: None,
                },
            ],
            hierarchy_depth: 0,
            duplicates_found: false,
            orphaned_permissions: vec![],
            circular_dependencies: vec![],
            custom_attributes: std::collections::HashSet::new(),
            complexity_score: 8,
            recommended_strategy: MigrationStrategy::GradualMigration,
        }
    }

    #[tokio::test]
    async fn test_generate_direct_mapping_plan() {
        let analysis = create_test_analysis();
        let config = MigrationConfig::default();

        let plan =
            generate_migration_plan(&analysis, Some(MigrationStrategy::DirectMapping), &config)
                .await
                .unwrap();

        assert_eq!(plan.strategy, MigrationStrategy::DirectMapping);
        assert_eq!(plan.phases.len(), 5); // backup, roles, permissions, users, validation
        assert_eq!(plan.role_mappings.len(), 5); // Now we have 5 roles
    }

    #[tokio::test]
    async fn test_generate_gradual_migration_plan() {
        let analysis = create_test_analysis();
        let config = MigrationConfig::default();

        let plan = generate_migration_plan(
            &analysis,
            Some(MigrationStrategy::GradualMigration),
            &config,
        )
        .await
        .unwrap();

        assert_eq!(plan.strategy, MigrationStrategy::GradualMigration);
        assert!(plan.phases.len() >= 3); // At least setup, critical roles, and user batches
    }

    #[test]
    fn test_assess_risk_level() {
        let mut analysis = create_test_analysis();

        analysis.complexity_score = 2;
        assert_eq!(assess_risk_level(&analysis), RiskLevel::Low);

        analysis.complexity_score = 5;
        assert_eq!(assess_risk_level(&analysis), RiskLevel::Medium);

        analysis.complexity_score = 8;
        assert_eq!(assess_risk_level(&analysis), RiskLevel::High);

        analysis.complexity_score = 10;
        assert_eq!(assess_risk_level(&analysis), RiskLevel::Critical);
    }

    #[test]
    fn test_identify_critical_roles() {
        let analysis = create_test_analysis();
        let critical_roles = identify_critical_roles(&analysis);

        // Should identify admin role as critical (has more permissions)
        assert!(critical_roles.contains(&"admin".to_string()));
    }
}


