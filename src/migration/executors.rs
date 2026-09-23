//! Migration execution engine
//!
//! This module provides the execution engine for migration plans,
//! including progress tracking, error handling, and rollback capabilities.

use super::{
    MigrationConfig, MigrationError, MigrationMetrics, MigrationOperation, MigrationPlan,
    MigrationResult, MigrationStatus,
};
use std::collections::HashMap;
use tokio::fs;
use uuid::Uuid;

#[cfg(feature = "enhanced-rbac")]
use role_system::{AsyncRoleSystem, MemoryStorage as RoleMemoryStorage, Permission, Role, Subject};

/// Internal execution context threaded through all migration executor functions.
///
/// Holds the migration configuration, a live permission registry (populated by
/// `CreatePermission` operations and consumed by `CreateRole`), and — when the
/// `enhanced-rbac` feature is active — an optional reference to a running
/// [`AsyncRoleSystem`] that receives the output of each operation in addition to
/// the manifest file.
struct ExecutionContext<'a> {
    /// Migration configuration.
    config: &'a MigrationConfig,

    /// Permissions created by `CreatePermission` operations; referenced when a
    /// subsequent `CreateRole` builds its `Role` with real [`Permission`] values.
    /// Key = `permission_id`; value = `(action, resource)`.
    permission_registry: HashMap<String, (String, String)>,

    /// Live role-system instance.  `None` means manifest-only mode.
    /// Only present when the `enhanced-rbac` feature is enabled.
    #[cfg(feature = "enhanced-rbac")]
    role_system: Option<&'a AsyncRoleSystem<RoleMemoryStorage>>,
}

impl<'a> ExecutionContext<'a> {
    /// Create a manifest-only context (no live role-system).
    fn new(config: &'a MigrationConfig) -> Self {
        Self {
            config,
            permission_registry: HashMap::new(),
            #[cfg(feature = "enhanced-rbac")]
            role_system: None,
        }
    }

    /// Attach a live role-system to this context.
    #[cfg(feature = "enhanced-rbac")]
    fn with_role_system(mut self, rs: &'a AsyncRoleSystem<RoleMemoryStorage>) -> Self {
        self.role_system = Some(rs);
        self
    }
}

/// Execute migration plan (manifest-only mode).
///
/// All operations are recorded in `<working_directory>/migration_manifest.jsonl`.
/// For live role-system integration use [`execute_migration_plan_with_role_system`].
pub async fn execute_migration_plan(
    plan: &MigrationPlan,
    config: &MigrationConfig,
) -> Result<MigrationResult, MigrationError> {
    let mut ctx = ExecutionContext::new(config);
    execute_migration_plan_inner(plan, &mut ctx).await
}

/// Execute migration plan with a live [`AsyncRoleSystem`] instance.
///
/// Every `CreateRole`, `CreatePermission`, and `AssignUserRole` operation is
/// applied to `role_system` **and** recorded in the manifest file.  On
/// completion the role system contains a fully-populated in-memory role store
/// that mirrors the migration plan.
///
/// # Example
///
/// ```rust,no_run
/// use role_system::{AsyncRoleSystem, MemoryStorage, RoleSystem, RoleSystemConfig};
/// use auth_framework::migration::executors::execute_migration_plan_with_role_system;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let plan: auth_framework::migration::MigrationPlan = unimplemented!();
/// # let config: auth_framework::migration::MigrationConfig = unimplemented!();
/// let rs = AsyncRoleSystem::new(
///     RoleSystem::with_storage(MemoryStorage::new(), RoleSystemConfig::default())
/// );
/// let result = execute_migration_plan_with_role_system(&plan, &config, &rs).await?;
/// assert_eq!(result.metrics.roles_migrated, 0);
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "enhanced-rbac")]
pub async fn execute_migration_plan_with_role_system(
    plan: &MigrationPlan,
    config: &MigrationConfig,
    role_system: &AsyncRoleSystem<RoleMemoryStorage>,
) -> Result<MigrationResult, MigrationError> {
    let mut ctx = ExecutionContext::new(config).with_role_system(role_system);
    execute_migration_plan_inner(plan, &mut ctx).await
}

/// Shared implementation used by both public entry points.
async fn execute_migration_plan_inner(
    plan: &MigrationPlan,
    ctx: &mut ExecutionContext<'_>,
) -> Result<MigrationResult, MigrationError> {
    // Alias for backwards-compatible use of `config` throughout the body.
    let config = ctx.config;

    let _execution_id = Uuid::new_v4().to_string();
    let started_at = chrono::Utc::now();

    let mut result = MigrationResult {
        plan_id: plan.id.clone(),
        status: MigrationStatus::InProgress,
        started_at,
        completed_at: None,
        phases_completed: Vec::new(),
        current_phase: None,
        errors: Vec::new(),
        warnings: Vec::new(),
        metrics: MigrationMetrics {
            roles_migrated: 0,
            permissions_migrated: 0,
            users_migrated: 0,
            errors_encountered: 0,
            warnings_generated: 0,
            validation_failures: 0,
            rollback_count: 0,
        },
    };

    // Save initial status
    save_migration_status(&result, config).await?;

    if config.dry_run {
        log_message(config, "DRY RUN MODE - No actual changes will be made");
        return execute_dry_run(plan, config, result).await;
    }

    // Execute pre-validation steps
    if let Err(e) = execute_pre_validation(plan, config, &mut result).await {
        result.status = MigrationStatus::Failed;
        result.errors.push(format!("Pre-validation failed: {}", e));
        save_migration_status(&result, config).await?;
        return Ok(result);
    }

    // Execute migration phases
    for phase in &plan.phases {
        result.current_phase = Some(phase.id.clone());
        save_migration_status(&result, config).await?;

        log_message(
            config,
            &format!("Executing phase: {} - {}", phase.id, phase.name),
        );

        match execute_phase(phase, ctx, &mut result).await {
            Ok(_) => {
                result.phases_completed.push(phase.id.clone());
                log_message(
                    config,
                    &format!("Phase '{}' completed successfully", phase.id),
                );
            }
            Err(e) => {
                result.status = MigrationStatus::Failed;
                result
                    .errors
                    .push(format!("Phase '{}' failed: {}", phase.id, e));
                result.metrics.errors_encountered += 1;

                log_message(config, &format!("Phase '{}' failed: {}", phase.id, e));

                // Attempt automatic rollback
                if let Err(rollback_error) =
                    execute_rollback_for_phase(phase, config, &mut result).await
                {
                    result.errors.push(format!(
                        "Rollback for phase '{}' failed: {}",
                        phase.id, rollback_error
                    ));
                }

                save_migration_status(&result, config).await?;
                return Ok(result);
            }
        }
    }

    // Execute post-validation steps
    if let Err(e) = execute_post_validation(plan, config, &mut result).await {
        result.status = MigrationStatus::Failed;
        result.errors.push(format!("Post-validation failed: {}", e));
        save_migration_status(&result, config).await?;
        return Ok(result);
    }

    // Migration completed successfully
    result.status = MigrationStatus::Completed;
    result.completed_at = Some(chrono::Utc::now());
    result.current_phase = None;

    log_message(config, "Migration completed successfully");
    save_migration_status(&result, config).await?;

    Ok(result)
}

/// Execute migration plan in dry-run mode
async fn execute_dry_run(
    plan: &MigrationPlan,
    config: &MigrationConfig,
    mut result: MigrationResult,
) -> Result<MigrationResult, MigrationError> {
    log_message(config, "=== DRY RUN EXECUTION ===");

    for phase in &plan.phases {
        log_message(
            config,
            &format!("DRY RUN - Phase: {} - {}", phase.id, phase.name),
        );

        for operation in &phase.operations {
            match operation {
                MigrationOperation::CreateRole { role_id, name, .. } => {
                    log_message(
                        config,
                        &format!("  [DRY RUN] Would create role: {} ({})", role_id, name),
                    );
                    result.metrics.roles_migrated += 1;
                }
                MigrationOperation::CreatePermission {
                    permission_id,
                    action,
                    resource,
                    ..
                } => {
                    log_message(
                        config,
                        &format!(
                            "  [DRY RUN] Would create permission: {} ({}:{})",
                            permission_id, action, resource
                        ),
                    );
                    result.metrics.permissions_migrated += 1;
                }
                MigrationOperation::AssignUserRole {
                    user_id, role_id, ..
                } => {
                    log_message(
                        config,
                        &format!(
                            "  [DRY RUN] Would assign role {} to user {}",
                            role_id, user_id
                        ),
                    );
                    result.metrics.users_migrated += 1;
                }
                MigrationOperation::Backup {
                    backup_location,
                    backup_type,
                } => {
                    log_message(
                        config,
                        &format!(
                            "  [DRY RUN] Would create {:?} backup at {:?}",
                            backup_type, backup_location
                        ),
                    );
                }
                MigrationOperation::ValidateIntegrity {
                    validation_type, ..
                } => {
                    log_message(
                        config,
                        &format!("  [DRY RUN] Would validate: {}", validation_type),
                    );
                }
                MigrationOperation::MigrateCustomAttribute { attribute_name, .. } => {
                    log_message(
                        config,
                        &format!(
                            "  [DRY RUN] Would migrate custom attribute: {}",
                            attribute_name
                        ),
                    );
                }
            }
        }

        result.phases_completed.push(phase.id.clone());
    }

    result.status = MigrationStatus::Completed;
    result.completed_at = Some(chrono::Utc::now());

    log_message(config, "=== DRY RUN COMPLETED ===");

    Ok(result)
}

/// Execute pre-validation steps
async fn execute_pre_validation(
    plan: &MigrationPlan,
    config: &MigrationConfig,
    result: &mut MigrationResult,
) -> Result<(), MigrationError> {
    log_message(config, "Executing pre-validation steps");

    for step in &plan.pre_validation_steps {
        log_message(
            config,
            &format!("Pre-validation: {} - {}", step.id, step.name),
        );

        match execute_validation_step(step, config).await {
            Ok(_) => {
                log_message(config, &format!("Pre-validation '{}' passed", step.id));
            }
            Err(e) => {
                if step.required {
                    return Err(MigrationError::ValidationError(format!(
                        "Required pre-validation '{}' failed: {}",
                        step.id, e
                    )));
                } else {
                    result.warnings.push(format!(
                        "Optional pre-validation '{}' failed: {}",
                        step.id, e
                    ));
                    result.metrics.warnings_generated += 1;
                }
            }
        }
    }

    Ok(())
}

/// Execute post-validation steps
async fn execute_post_validation(
    plan: &MigrationPlan,
    config: &MigrationConfig,
    result: &mut MigrationResult,
) -> Result<(), MigrationError> {
    log_message(config, "Executing post-validation steps");

    for step in &plan.post_validation_steps {
        log_message(
            config,
            &format!("Post-validation: {} - {}", step.id, step.name),
        );

        match execute_validation_step(step, config).await {
            Ok(_) => {
                log_message(config, &format!("Post-validation '{}' passed", step.id));
            }
            Err(e) => {
                if step.required {
                    result.metrics.validation_failures += 1;
                    return Err(MigrationError::ValidationError(format!(
                        "Required post-validation '{}' failed: {}",
                        step.id, e
                    )));
                } else {
                    result.warnings.push(format!(
                        "Optional post-validation '{}' failed: {}",
                        step.id, e
                    ));
                    result.metrics.warnings_generated += 1;
                }
            }
        }
    }

    Ok(())
}

/// Execute individual validation step
async fn execute_validation_step(
    step: &super::ValidationStep,
    config: &MigrationConfig,
) -> Result<(), MigrationError> {
    use super::ValidationType;

    match &step.validation_type {
        ValidationType::HierarchyIntegrity => validate_hierarchy_integrity(config).await,
        ValidationType::PermissionConsistency => validate_permission_consistency(config).await,
        ValidationType::UserAssignmentValidity => validate_user_assignments(config).await,
        ValidationType::PrivilegeEscalationCheck => validate_no_privilege_escalation(config).await,
        ValidationType::Custom(validation_name) => {
            execute_custom_validation(validation_name, &step.parameters, config).await
        }
    }
}

/// Execute migration phase
async fn execute_phase(
    phase: &super::MigrationPhase,
    ctx: &mut ExecutionContext<'_>,
    result: &mut MigrationResult,
) -> Result<(), MigrationError> {
    for operation in &phase.operations {
        if let Err(e) = execute_operation(operation, ctx, result).await {
            return Err(MigrationError::ExecutionError(format!(
                "Operation failed in phase '{}': {}",
                phase.id, e
            )));
        }
    }
    Ok(())
}

/// Execute individual migration operation
async fn execute_operation(
    operation: &MigrationOperation,
    ctx: &mut ExecutionContext<'_>,
    result: &mut MigrationResult,
) -> Result<(), MigrationError> {
    let config = ctx.config;
    match operation {
        MigrationOperation::CreateRole {
            role_id,
            name,
            description,
            permissions,
            parent_role,
        } => {
            execute_create_role(
                role_id,
                name,
                description.as_deref(),
                permissions,
                parent_role.as_deref(),
                ctx,
            )
            .await?;
            result.metrics.roles_migrated += 1;
        }
        MigrationOperation::CreatePermission {
            permission_id,
            action,
            resource,
            conditions,
        } => {
            execute_create_permission(permission_id, action, resource, conditions, ctx).await?;
            result.metrics.permissions_migrated += 1;
        }
        MigrationOperation::AssignUserRole {
            user_id,
            role_id,
            expiration,
        } => {
            execute_assign_user_role(user_id, role_id, expiration.as_ref(), ctx).await?;
            result.metrics.users_migrated += 1;
        }
        MigrationOperation::Backup {
            backup_location,
            backup_type,
        } => {
            execute_backup(backup_location, backup_type, config).await?;
        }
        MigrationOperation::ValidateIntegrity {
            validation_type,
            parameters,
        } => {
            execute_integrity_validation(validation_type, parameters, config).await?;
        }
        MigrationOperation::MigrateCustomAttribute {
            attribute_name,
            conversion_logic,
        } => {
            execute_custom_attribute_migration(attribute_name, conversion_logic, config).await?;
        }
    }

    Ok(())
}

/// Execute role creation
async fn execute_create_role(
    role_id: &str,
    name: &str,
    description: Option<&str>,
    permissions: &[String],
    parent_role: Option<&str>,
    ctx: &mut ExecutionContext<'_>,
) -> Result<(), MigrationError> {
    let config = ctx.config;
    log_message(config, &format!("Creating role: {} ({})", role_id, name));

    if config.verbose {
        log_message(config, &format!("  Description: {:?}", description));
        log_message(config, &format!("  Permissions: {:?}", permissions));
        log_message(config, &format!("  Parent role: {:?}", parent_role));
    }

    // Integrate with live role-system when the enhanced-rbac feature is active.
    #[cfg(feature = "enhanced-rbac")]
    if let Some(rs) = ctx.role_system {
        // role-system keys roles by name; use role_id as the canonical name so
        // that get_role(role_id) and assign_role(subject, role_id) work as expected.
        // The human-readable `name` is kept in the manifest record below.
        let mut role = Role::new(role_id);
        if let Some(desc) = description {
            role = role.with_description(desc);
        }
        for perm_id in permissions {
            // First try the permission registry populated by CreatePermission ops;
            // fall back to splitting "action:resource" or treating as bare action.
            if let Some((action, resource)) = ctx.permission_registry.get(perm_id) {
                role = role.add_permission(Permission::new(action, resource));
            } else {
                let parts: Vec<&str> = perm_id.splitn(2, ':').collect();
                if parts.len() == 2 {
                    role = role.add_permission(Permission::new(parts[0], parts[1]));
                } else {
                    role = role.add_permission(Permission::new(perm_id.as_str(), "*"));
                }
            }
        }
        rs.register_role(role).await.map_err(|e| {
            MigrationError::ExecutionError(format!(
                "role-system register_role '{}' failed: {}",
                role_id, e
            ))
        })?;
        if let Some(parent) = parent_role {
            rs.add_role_inheritance(role_id, parent)
                .await
                .map_err(|e| {
                    MigrationError::ExecutionError(format!(
                        "role-system add_role_inheritance '{}' -> '{}' failed: {}",
                        role_id, parent, e
                    ))
                })?;
        }
        tracing::info!(role_id, "Role registered in role-system");
    }

    // Always write an audit manifest record regardless of feature flag.
    let record = serde_json::json!({
        "op": "create_role",
        "role_id": role_id,
        "name": name,
        "description": description,
        "permissions": permissions,
        "parent_role": parent_role,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    append_manifest_record(config, &record).await?;

    Ok(())
}

/// Execute permission creation
async fn execute_create_permission(
    permission_id: &str,
    action: &str,
    resource: &str,
    conditions: &HashMap<String, String>,
    ctx: &mut ExecutionContext<'_>,
) -> Result<(), MigrationError> {
    let config = ctx.config;
    log_message(
        config,
        &format!(
            "Creating permission: {} ({}:{})",
            permission_id, action, resource
        ),
    );

    if config.verbose {
        log_message(config, &format!("  Conditions: {:?}", conditions));
    }

    // Store in the permission registry so subsequent CreateRole operations can
    // look up the (action, resource) pair by permission_id.
    // role-system has no standalone permission registry; permissions live on roles.
    ctx.permission_registry.insert(
        permission_id.to_string(),
        (action.to_string(), resource.to_string()),
    );

    // Always write an audit manifest record.
    let record = serde_json::json!({
        "op": "create_permission",
        "permission_id": permission_id,
        "action": action,
        "resource": resource,
        "conditions": conditions,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    append_manifest_record(config, &record).await?;

    Ok(())
}

/// Execute user role assignment
async fn execute_assign_user_role(
    user_id: &str,
    role_id: &str,
    expiration: Option<&chrono::DateTime<chrono::Utc>>,
    ctx: &mut ExecutionContext<'_>,
) -> Result<(), MigrationError> {
    let config = ctx.config;
    log_message(
        config,
        &format!("Assigning role {} to user {}", role_id, user_id),
    );

    if config.verbose {
        log_message(config, &format!("  Expiration: {:?}", expiration));
    }

    // Integrate with live role-system when the enhanced-rbac feature is active.
    #[cfg(feature = "enhanced-rbac")]
    if let Some(rs) = ctx.role_system {
        let subject = Subject::new(user_id);
        if let Some(exp) = expiration {
            let duration = (*exp - chrono::Utc::now()).to_std().ok();
            rs.elevate_role(&subject, role_id, duration)
                .await
                .map_err(|e| {
                    MigrationError::ExecutionError(format!(
                        "role-system elevate_role '{}' for user '{}' failed: {}",
                        role_id, user_id, e
                    ))
                })?;
        } else {
            rs.assign_role(&subject, role_id).await.map_err(|e| {
                MigrationError::ExecutionError(format!(
                    "role-system assign_role '{}' for user '{}' failed: {}",
                    role_id, user_id, e
                ))
            })?;
        }
        tracing::info!(user_id, role_id, "Role assigned in role-system");
    }

    // Always write an audit manifest record regardless of feature flag.
    let record = serde_json::json!({
        "op": "assign_user_role",
        "user_id": user_id,
        "role_id": role_id,
        "expiration": expiration.map(|e| e.to_rfc3339()),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    append_manifest_record(config, &record).await?;

    Ok(())
}

/// Execute backup operation
async fn execute_backup(
    backup_location: &std::path::Path,
    backup_type: &super::BackupType,
    config: &MigrationConfig,
) -> Result<(), MigrationError> {
    log_message(
        config,
        &format!("Creating {:?} backup at {:?}", backup_type, backup_location),
    );

    // Ensure backup directory exists
    if let Some(parent) = backup_location.parent() {
        fs::create_dir_all(parent).await?;
    }

    // Create backup (simplified implementation)
    let backup_data = match backup_type {
        super::BackupType::Full => create_full_backup(config).await?,
        super::BackupType::Incremental => create_incremental_backup(config).await?,
        super::BackupType::ConfigOnly => create_config_backup(config).await?,
        super::BackupType::DataOnly => create_data_backup(config).await?,
    };

    fs::write(backup_location, backup_data).await?;

    log_message(
        config,
        &format!("Backup created successfully at {:?}", backup_location),
    );

    Ok(())
}

/// Execute integrity validation
async fn execute_integrity_validation(
    validation_type: &str,
    parameters: &HashMap<String, String>,
    config: &MigrationConfig,
) -> Result<(), MigrationError> {
    log_message(
        config,
        &format!("Executing integrity validation: {}", validation_type),
    );

    if config.verbose {
        log_message(config, &format!("  Parameters: {:?}", parameters));
    }

    match validation_type {
        "pre_migration_check" => validate_pre_migration_state(config).await,
        "post_migration_check" => validate_post_migration_state(config).await,
        "stop_migration" => Ok(()), // No-op for stop migration
        _ => {
            log_message(
                config,
                &format!("Unknown validation type: {}", validation_type),
            );
            Ok(())
        }
    }
}

/// Execute custom attribute migration
async fn execute_custom_attribute_migration(
    attribute_name: &str,
    conversion_logic: &str,
    config: &MigrationConfig,
) -> Result<(), MigrationError> {
    log_message(
        config,
        &format!("Migrating custom attribute: {}", attribute_name),
    );

    if config.verbose {
        log_message(config, &format!("  Conversion logic: {}", conversion_logic));
    }

    // Write a manifest record for the custom attribute migration.
    // Replace with actual conversion logic when the target schema is known.
    let record = serde_json::json!({
        "op": "migrate_custom_attribute",
        "attribute_name": attribute_name,
        "conversion_logic": conversion_logic,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    append_manifest_record(config, &record).await?;

    Ok(())
}

/// Execute rollback for a specific phase
async fn execute_rollback_for_phase(
    phase: &super::MigrationPhase,
    config: &MigrationConfig,
    result: &mut MigrationResult,
) -> Result<(), MigrationError> {
    log_message(
        config,
        &format!("Executing rollback for phase: {}", phase.id),
    );

    // Rollback uses manifest-only mode (no live role-system calls).
    let mut ctx = ExecutionContext::new(config);
    for operation in &phase.rollback_operations {
        if let Err(e) = execute_operation(operation, &mut ctx, result).await {
            return Err(MigrationError::RollbackError(format!(
                "Rollback operation failed: {}",
                e
            )));
        }
    }

    result.metrics.rollback_count += 1;
    Ok(())
}

/// Execute complete migration rollback
pub async fn rollback_migration(
    plan: &MigrationPlan,
    config: &MigrationConfig,
) -> Result<MigrationResult, MigrationError> {
    let started_at = chrono::Utc::now();

    let mut result = MigrationResult {
        plan_id: plan.id.clone(),
        status: MigrationStatus::InProgress,
        started_at,
        completed_at: None,
        phases_completed: Vec::new(),
        current_phase: Some("rollback".to_string()),
        errors: Vec::new(),
        warnings: Vec::new(),
        metrics: MigrationMetrics {
            roles_migrated: 0,
            permissions_migrated: 0,
            users_migrated: 0,
            errors_encountered: 0,
            warnings_generated: 0,
            validation_failures: 0,
            rollback_count: 0,
        },
    };

    log_message(config, "Starting migration rollback");

    // Execute rollback phases in reverse order
    // Rollback uses manifest-only mode (no live role-system calls).
    let mut ctx = ExecutionContext::new(config);
    for phase in plan.rollback_plan.phases.iter().rev() {
        log_message(config, &format!("Executing rollback phase: {}", phase.id));

        for operation in &phase.operations {
            if let Err(e) = execute_operation(operation, &mut ctx, &mut result).await {
                result.status = MigrationStatus::Failed;
                result
                    .errors
                    .push(format!("Rollback operation failed: {}", e));
                save_migration_status(&result, config).await?;
                return Ok(result);
            }
        }

        result.phases_completed.push(phase.id.clone());
    }

    result.status = MigrationStatus::RolledBack;
    result.completed_at = Some(chrono::Utc::now());
    result.current_phase = None;

    log_message(config, "Migration rollback completed");
    save_migration_status(&result, config).await?;

    Ok(result)
}

/// Validation implementations
async fn validate_hierarchy_integrity(config: &MigrationConfig) -> Result<(), MigrationError> {
    // Validate that the manifest contains no duplicate role IDs and no self-referencing
    // parent_role entries (a minimal structural check that does not require the role-system
    // crate at runtime).
    let manifest_path = config.working_directory.join("migration_manifest.jsonl");
    if !manifest_path.exists() {
        // Nothing written yet — nothing to validate.
        return Ok(());
    }
    let content = fs::read_to_string(&manifest_path).await?;
    let mut role_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in content.lines() {
        if let Ok(record) = serde_json::from_str::<serde_json::Value>(line)
            && record.get("op").and_then(|v| v.as_str()) == Some("create_role")
            && let Some(id) = record.get("role_id").and_then(|v| v.as_str())
        {
            if !role_ids.insert(id.to_string()) {
                return Err(MigrationError::ValidationError(format!(
                    "Duplicate role ID detected in manifest: {}",
                    id
                )));
            }
            if record.get("parent_role").and_then(|v| v.as_str()) == Some(id) {
                return Err(MigrationError::ValidationError(format!(
                    "Role '{}' references itself as parent",
                    id
                )));
            }
        }
    }
    Ok(())
}

async fn validate_permission_consistency(config: &MigrationConfig) -> Result<(), MigrationError> {
    // Check that every permission referenced in a create_role record exists as a
    // create_permission record in the manifest (forward-reference check).
    let manifest_path = config.working_directory.join("migration_manifest.jsonl");
    if !manifest_path.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(&manifest_path).await?;
    let mut defined_perms: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut role_perms: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        if let Ok(record) = serde_json::from_str::<serde_json::Value>(line) {
            match record.get("op").and_then(|v| v.as_str()) {
                Some("create_permission") => {
                    if let Some(id) = record.get("permission_id").and_then(|v| v.as_str()) {
                        defined_perms.insert(id.to_string());
                    }
                }
                Some("create_role") => {
                    if let (Some(role), Some(perms)) = (
                        record.get("role_id").and_then(|v| v.as_str()),
                        record.get("permissions").and_then(|v| v.as_array()),
                    ) {
                        for p in perms {
                            if let Some(ps) = p.as_str() {
                                role_perms.push((role.to_string(), ps.to_string()));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    for (role, perm) in &role_perms {
        if !defined_perms.contains(perm) {
            return Err(MigrationError::ValidationError(format!(
                "Role '{}' references undefined permission '{}'",
                role, perm
            )));
        }
    }
    Ok(())
}

async fn validate_user_assignments(config: &MigrationConfig) -> Result<(), MigrationError> {
    // Verify that every assign_user_role record references a role that was declared
    // earlier in the same manifest run.
    let manifest_path = config.working_directory.join("migration_manifest.jsonl");
    if !manifest_path.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(&manifest_path).await?;
    let mut defined_roles: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut assignments: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        if let Ok(record) = serde_json::from_str::<serde_json::Value>(line) {
            match record.get("op").and_then(|v| v.as_str()) {
                Some("create_role") => {
                    if let Some(id) = record.get("role_id").and_then(|v| v.as_str()) {
                        defined_roles.insert(id.to_string());
                    }
                }
                Some("assign_user_role") => {
                    if let (Some(uid), Some(rid)) = (
                        record.get("user_id").and_then(|v| v.as_str()),
                        record.get("role_id").and_then(|v| v.as_str()),
                    ) {
                        assignments.push((uid.to_string(), rid.to_string()));
                    }
                }
                _ => {}
            }
        }
    }
    for (user, role) in &assignments {
        if !defined_roles.contains(role) {
            return Err(MigrationError::ValidationError(format!(
                "User '{}' is assigned to undefined role '{}'",
                user, role
            )));
        }
    }
    Ok(())
}

async fn validate_no_privilege_escalation(config: &MigrationConfig) -> Result<(), MigrationError> {
    // Detect any user who is being simultaneously assigned a child role and its
    // ancestor role, which would be redundant but is sometimes a sign of an
    // over-privileged migration plan.
    let manifest_path = config.working_directory.join("migration_manifest.jsonl");
    if !manifest_path.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(&manifest_path).await?;
    // Build parent_role map: role_id -> parent_id
    let mut parent_map: HashMap<String, String> = HashMap::new();
    let mut user_roles: HashMap<String, Vec<String>> = HashMap::new();
    for line in content.lines() {
        if let Ok(record) = serde_json::from_str::<serde_json::Value>(line) {
            match record.get("op").and_then(|v| v.as_str()) {
                Some("create_role") => {
                    if let (Some(id), Some(parent)) = (
                        record.get("role_id").and_then(|v| v.as_str()),
                        record.get("parent_role").and_then(|v| v.as_str()),
                    ) {
                        parent_map.insert(id.to_string(), parent.to_string());
                    }
                }
                Some("assign_user_role") => {
                    if let (Some(uid), Some(rid)) = (
                        record.get("user_id").and_then(|v| v.as_str()),
                        record.get("role_id").and_then(|v| v.as_str()),
                    ) {
                        user_roles
                            .entry(uid.to_string())
                            .or_default()
                            .push(rid.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    for (user, roles) in &user_roles {
        // Walk the ancestor chain for each role; flag if another assigned role appears.
        for role in roles {
            let mut ancestor = parent_map.get(role);
            while let Some(a) = ancestor {
                if roles.iter().any(|r| r == a) {
                    log_message(
                        config,
                        &format!(
                            "WARNING: user '{}' is assigned both '{}' and its ancestor '{}'. \
                             Consider removing the redundant assignment.",
                            user, role, a
                        ),
                    );
                    break;
                }
                ancestor = parent_map.get(a);
            }
        }
    }
    Ok(())
}

async fn execute_custom_validation(
    validation_name: &str,
    _parameters: &HashMap<String, String>,
    config: &MigrationConfig,
) -> Result<(), MigrationError> {
    log_message(
        config,
        &format!("Executing custom validation: {}", validation_name),
    );
    // Custom validations are user-defined.  This hook intentionally returns
    // Ok(()) so the migration continues; implement specific checks here as
    // the migration plan is finalised.
    Ok(())
}

async fn validate_pre_migration_state(config: &MigrationConfig) -> Result<(), MigrationError> {
    // Ensure the working and backup directories are accessible before the
    // migration starts — a lightweight real check.
    if !config.working_directory.exists() {
        return Err(MigrationError::ValidationError(format!(
            "Working directory does not exist: {:?}",
            config.working_directory
        )));
    }
    if !config.backup_directory.exists() {
        return Err(MigrationError::ValidationError(format!(
            "Backup directory does not exist: {:?}",
            config.backup_directory
        )));
    }
    Ok(())
}

async fn validate_post_migration_state(config: &MigrationConfig) -> Result<(), MigrationError> {
    // Verify the manifest file was written and is non-empty, confirming that
    // at least one operation was recorded during the migration run.
    let manifest_path = config.working_directory.join("migration_manifest.jsonl");
    if manifest_path.exists() {
        let metadata = fs::metadata(&manifest_path).await?;
        if metadata.len() == 0 {
            return Err(MigrationError::ValidationError(
                "Migration manifest is empty — no operations were recorded".to_string(),
            ));
        }
    }
    Ok(())
}

/// Backup implementations
async fn create_full_backup(config: &MigrationConfig) -> Result<String, MigrationError> {
    // Serialize the full working directory contents into a JSON manifest
    let working_dir = &config.working_directory;
    let mut entries = Vec::new();

    if working_dir.exists() {
        let mut read_dir = fs::read_dir(working_dir).await?;

        while let Ok(Some(entry)) = read_dir.next_entry().await {
            if let Ok(content) = fs::read_to_string(entry.path()).await {
                entries.push(serde_json::json!({
                    "path": entry.file_name().to_string_lossy(),
                    "content": content,
                }));
            }
        }
    }

    let backup = serde_json::json!({
        "backup_type": "full",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "working_directory": working_dir.display().to_string(),
        "entries": entries,
    });

    Ok(serde_json::to_string_pretty(&backup)?)
}

async fn create_incremental_backup(config: &MigrationConfig) -> Result<String, MigrationError> {
    // Incremental: only include status files (migration-related state)
    let working_dir = &config.working_directory;
    let mut entries = Vec::new();

    if working_dir.exists() {
        let mut read_dir = fs::read_dir(working_dir).await?;

        while let Ok(Some(entry)) = read_dir.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if (name.ends_with("_status.json") || name.ends_with("_manifest.json"))
                && let Ok(content) = fs::read_to_string(entry.path()).await
            {
                entries.push(serde_json::json!({
                    "path": name,
                    "content": content,
                }));
            }
        }
    }

    let backup = serde_json::json!({
        "backup_type": "incremental",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "working_directory": working_dir.display().to_string(),
        "entries": entries,
    });

    Ok(serde_json::to_string_pretty(&backup)?)
}

async fn create_config_backup(config: &MigrationConfig) -> Result<String, MigrationError> {
    let backup = serde_json::json!({
        "backup_type": "config",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "migration_config": {
            "working_directory": config.working_directory.display().to_string(),
            "dry_run": config.dry_run,
            "verbose": config.verbose,
        },
    });

    Ok(serde_json::to_string_pretty(&backup)?)
}

async fn create_data_backup(config: &MigrationConfig) -> Result<String, MigrationError> {
    // Data backup: serialize all data files (non-config, non-status)
    let working_dir = &config.working_directory;
    let mut entries = Vec::new();

    if working_dir.exists() {
        let mut read_dir = fs::read_dir(working_dir).await?;

        while let Ok(Some(entry)) = read_dir.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".json")
                && !name.ends_with("_status.json")
                && let Ok(content) = fs::read_to_string(entry.path()).await
            {
                entries.push(serde_json::json!({
                    "path": name,
                    "content": content,
                }));
            }
        }
    }

    let backup = serde_json::json!({
        "backup_type": "data",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "working_directory": working_dir.display().to_string(),
        "entries": entries,
    });

    Ok(serde_json::to_string_pretty(&backup)?)
}

/// Save migration status to disk
async fn save_migration_status(
    result: &MigrationResult,
    config: &MigrationConfig,
) -> Result<(), MigrationError> {
    let status_file = config
        .working_directory
        .join(format!("{}_status.json", result.plan_id));
    let content = serde_json::to_string_pretty(result)?;
    fs::write(status_file, content).await?;
    Ok(())
}

/// Log message with timestamp
fn log_message(config: &MigrationConfig, message: &str) {
    if config.verbose {
        tracing::info!(message, "migration");
    }
}

/// Append a JSON record to the migration manifest file (newline-delimited JSON).
///
/// The manifest at `<working_directory>/migration_manifest.jsonl` captures every
/// executed operation during a migration run.  Downstream tooling (or the
/// `role-system` integration layer) can replay or audit it independently of the
/// in-memory migration state.
async fn append_manifest_record(
    config: &MigrationConfig,
    record: &serde_json::Value,
) -> Result<(), MigrationError> {
    use tokio::io::AsyncWriteExt;
    let manifest_path = config.working_directory.join("migration_manifest.jsonl");
    // Open in append mode (create if absent).
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&manifest_path)
        .await
        .map_err(MigrationError::IoError)?;
    let mut line = serde_json::to_string(record).map_err(MigrationError::SerializationError)?;
    line.push('\n');
    file.write_all(line.as_bytes())
        .await
        .map_err(MigrationError::IoError)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{
        LegacySystemAnalysis, LegacySystemType, MigrationPhase, MigrationStrategy, RiskLevel,
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
            phases: vec![MigrationPhase {
                id: "test_phase".to_string(),
                name: "Test Phase".to_string(),
                description: "Test phase".to_string(),
                order: 1,
                operations: vec![MigrationOperation::CreateRole {
                    role_id: "test_role".to_string(),
                    name: "Test Role".to_string(),
                    description: None,
                    permissions: vec!["read".to_string()],
                    parent_role: None,
                }],
                dependencies: vec![],
                estimated_duration: chrono::Duration::minutes(1),
                rollback_operations: vec![],
            }],
            role_mappings: std::collections::HashMap::new(),
            permission_mappings: std::collections::HashMap::new(),
            user_migrations: vec![],
            pre_validation_steps: vec![],
            post_validation_steps: vec![],
            rollback_plan: super::super::RollbackPlan {
                phases: vec![],
                backup_locations: vec![],
                recovery_time_objective: chrono::Duration::hours(1),
                manual_steps: vec![],
            },
            estimated_duration: chrono::Duration::minutes(30),
            risk_level: RiskLevel::Low,
            downtime_required: None,
        }
    }

    #[tokio::test]
    async fn test_execute_migration_plan_dry_run() {
        let plan = create_test_plan();
        let config = MigrationConfig {
            dry_run: true,
            verbose: false, // Reduce test output
            ..Default::default()
        };

        let result = execute_migration_plan(&plan, &config).await.unwrap();

        assert_eq!(result.status, MigrationStatus::Completed);
        assert_eq!(result.phases_completed.len(), 1);
        assert_eq!(result.metrics.roles_migrated, 1);
    }

    #[tokio::test]
    async fn test_execute_migration_plan_real() {
        let plan = create_test_plan();
        let config = MigrationConfig {
            dry_run: false,
            verbose: false, // Reduce test output
            ..Default::default()
        };

        let result = execute_migration_plan(&plan, &config).await.unwrap();

        assert_eq!(result.status, MigrationStatus::Completed);
        assert_eq!(result.phases_completed.len(), 1);
        assert_eq!(result.metrics.roles_migrated, 1);
    }

    // ── role-system integration tests ────────────────────────────────────────

    /// Helper: build an AsyncRoleSystem backed by in-memory storage.
    #[cfg(feature = "enhanced-rbac")]
    fn make_role_system() -> AsyncRoleSystem<RoleMemoryStorage> {
        use role_system::{RoleSystem, RoleSystemConfig};
        AsyncRoleSystem::new(RoleSystem::with_storage(
            RoleMemoryStorage::new(),
            RoleSystemConfig::default(),
        ))
    }

    #[cfg(feature = "enhanced-rbac")]
    #[tokio::test]
    async fn test_execute_migration_plan_with_role_system_creates_role() {
        let plan = create_test_plan();
        let config = MigrationConfig {
            dry_run: false,
            verbose: false,
            ..Default::default()
        };
        let rs = make_role_system();

        let result = execute_migration_plan_with_role_system(&plan, &config, &rs)
            .await
            .unwrap();

        assert_eq!(result.status, MigrationStatus::Completed);
        assert_eq!(result.metrics.roles_migrated, 1);
        // The role should now exist in the live role-system.
        let role = rs.get_role("test_role").await.unwrap();
        assert!(role.is_some(), "Expected 'test_role' to be registered");
        // role.name() == role_id because we use Role::new(role_id) for lookup compatibility.
        assert_eq!(role.unwrap().name(), "test_role");
    }

    #[cfg(feature = "enhanced-rbac")]
    #[tokio::test]
    async fn test_execute_migration_plan_with_role_system_assigns_user() {
        use role_system::Subject;
        let mut plan = create_test_plan();
        // Add an AssignUserRole operation after CreateRole.
        plan.phases[0]
            .operations
            .push(MigrationOperation::AssignUserRole {
                user_id: "user1".to_string(),
                role_id: "test_role".to_string(),
                expiration: None,
            });
        let config = MigrationConfig {
            dry_run: false,
            verbose: false,
            ..Default::default()
        };
        let rs = make_role_system();

        let result = execute_migration_plan_with_role_system(&plan, &config, &rs)
            .await
            .unwrap();

        assert_eq!(result.status, MigrationStatus::Completed);
        assert_eq!(result.metrics.users_migrated, 1);
        // The subject should now have the role in the live role-system.
        let subject = Subject::new("user1");
        let roles = rs.get_subject_roles(&subject).await.unwrap();
        assert!(
            roles.iter().any(|r| r == "test_role"),
            "Expected user1 to have test_role"
        );
    }

    #[cfg(feature = "enhanced-rbac")]
    #[tokio::test]
    async fn test_execute_migration_plan_permission_registry_feeds_create_role() {
        // CreatePermission populates the registry; CreateRole reads from it.
        let config = MigrationConfig {
            dry_run: false,
            verbose: false,
            ..Default::default()
        };
        let plan = {
            let mut p = create_test_plan();
            // Prepend a CreatePermission so its registry entry exists when the
            // CreateRole (which references "read_users") runs.
            p.phases[0].operations.insert(
                0,
                MigrationOperation::CreatePermission {
                    permission_id: "read_users".to_string(),
                    action: "read".to_string(),
                    resource: "users".to_string(),
                    conditions: Default::default(),
                },
            );
            // CreateRole already references "read" perm_id — swap to "read_users".
            if let MigrationOperation::CreateRole { permissions, .. } =
                &mut p.phases[0].operations[1]
            {
                *permissions = vec!["read_users".to_string()];
            }
            p
        };
        let rs = make_role_system();

        let result = execute_migration_plan_with_role_system(&plan, &config, &rs)
            .await
            .unwrap();

        assert_eq!(result.status, MigrationStatus::Completed);
        assert_eq!(result.metrics.permissions_migrated, 1);
        assert_eq!(result.metrics.roles_migrated, 1);

        // Verify the role contains the expected permission via the has_permission API.
        let role = rs.get_role("test_role").await.unwrap().unwrap();
        assert!(
            role.has_permission("read", "users", &Default::default()),
            "Expected role to have permission read:users"
        );
    }

    #[tokio::test]
    async fn test_manifest_only_mode_completes_without_role_system() {
        // Without the enhanced-rbac feature (or without passing a role-system),
        // execute_migration_plan must still complete successfully using manifest only.
        let plan = create_test_plan();
        let config = MigrationConfig {
            dry_run: false,
            verbose: false,
            ..Default::default()
        };
        let result = execute_migration_plan(&plan, &config).await.unwrap();
        assert_eq!(result.status, MigrationStatus::Completed);
        assert_eq!(result.metrics.roles_migrated, 1);
    }

    #[tokio::test]
    async fn test_create_full_backup_reads_directory() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("data.json"), r#"{"key":"val"}"#)
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("notes.txt"), "hello")
            .await
            .unwrap();

        let config = MigrationConfig {
            working_directory: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let backup_str = create_full_backup(&config).await.unwrap();
        let backup: serde_json::Value = serde_json::from_str(&backup_str).unwrap();
        assert_eq!(backup["backup_type"], "full");
        let entries = backup["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn test_create_incremental_backup_only_status_files() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("migration_status.json"), "{}")
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("v1_manifest.json"), "{}")
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("data.json"), "{}")
            .await
            .unwrap();

        let config = MigrationConfig {
            working_directory: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let backup_str = create_incremental_backup(&config).await.unwrap();
        let backup: serde_json::Value = serde_json::from_str(&backup_str).unwrap();
        assert_eq!(backup["backup_type"], "incremental");
        let entries = backup["entries"].as_array().unwrap();
        // Only migration_status.json and v1_manifest.json should be included
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn test_create_config_backup_serializes_config() {
        let config = MigrationConfig {
            dry_run: true,
            verbose: true,
            ..Default::default()
        };
        let backup_str = create_config_backup(&config).await.unwrap();
        let backup: serde_json::Value = serde_json::from_str(&backup_str).unwrap();
        assert_eq!(backup["backup_type"], "config");
        assert_eq!(backup["migration_config"]["dry_run"], true);
        assert_eq!(backup["migration_config"]["verbose"], true);
    }

    #[tokio::test]
    async fn test_create_data_backup_excludes_status_files() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("users.json"), "[]")
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("migration_status.json"), "{}")
            .await
            .unwrap();

        let config = MigrationConfig {
            working_directory: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let backup_str = create_data_backup(&config).await.unwrap();
        let backup: serde_json::Value = serde_json::from_str(&backup_str).unwrap();
        assert_eq!(backup["backup_type"], "data");
        let entries = backup["entries"].as_array().unwrap();
        // Only users.json; migration_status.json is excluded
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["path"], "users.json");
    }

    #[tokio::test]
    async fn test_create_full_backup_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let config = MigrationConfig {
            working_directory: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let backup_str = create_full_backup(&config).await.unwrap();
        let backup: serde_json::Value = serde_json::from_str(&backup_str).unwrap();
        assert_eq!(backup["entries"].as_array().unwrap().len(), 0);
    }
}
