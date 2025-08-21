//! Migration utilities for transitioning to role-system v1.0
//!
//! This module provides comprehensive migration tools to help users
//! transition from legacy authorization systems to the unified
//! role-system v1.0 approach with minimal disruption.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs;

pub mod analyzers;
pub mod converters;
pub mod executors;
pub mod planners;
pub mod validators;

/// Migration-related errors
#[derive(Error, Debug)]
pub enum MigrationError {
    #[error("Legacy system analysis failed: {0}")]
    AnalysisError(String),

    #[error("Migration plan generation failed: {0}")]
    PlanningError(String),

    #[error("Migration execution failed: {0}")]
    ExecutionError(String),

    #[error("Migration validation failed: {0}")]
    ValidationError(String),

    #[error("Rollback operation failed: {0}")]
    RollbackError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// Type of legacy authorization system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LegacySystemType {
    /// Simple permission lists
    PermissionBased,
    /// Basic role-based access control
    BasicRbac,
    /// Attribute-based access control
    Abac,
    /// Custom authorization implementation
    Custom(String),
    /// Multiple mixed systems
    Hybrid(Vec<LegacySystemType>),
}

/// Legacy role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyRole {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub parent_roles: Vec<String>,
    pub metadata: HashMap<String, String>,
}

/// Legacy user assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyUserAssignment {
    pub user_id: String,
    pub role_id: Option<String>,
    pub permissions: Vec<String>,
    pub attributes: HashMap<String, String>,
    pub expiration: Option<chrono::DateTime<chrono::Utc>>,
}

/// Legacy permission definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyPermission {
    pub id: String,
    pub action: String,
    pub resource: String,
    pub conditions: HashMap<String, String>,
    pub metadata: HashMap<String, String>,
}

/// Analysis result of legacy authorization system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacySystemAnalysis {
    /// Type of legacy system detected
    pub system_type: LegacySystemType,

    /// Total number of roles found
    pub role_count: usize,

    /// Total number of permissions found
    pub permission_count: usize,

    /// Total number of user assignments
    pub user_assignment_count: usize,

    /// Discovered roles
    pub roles: Vec<LegacyRole>,

    /// Discovered permissions
    pub permissions: Vec<LegacyPermission>,

    /// User assignments
    pub user_assignments: Vec<LegacyUserAssignment>,

    /// Role hierarchy complexity (depth levels)
    pub hierarchy_depth: usize,

    /// Duplicate roles/permissions detected
    pub duplicates_found: bool,

    /// Orphaned permissions (not assigned to any role)
    pub orphaned_permissions: Vec<String>,

    /// Circular dependencies in role hierarchy
    pub circular_dependencies: Vec<Vec<String>>,

    /// Custom attributes that need special handling
    pub custom_attributes: HashSet<String>,

    /// Estimated migration complexity (1-10 scale)
    pub complexity_score: u8,

    /// Recommended migration strategy
    pub recommended_strategy: MigrationStrategy,
}

/// Migration strategy options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MigrationStrategy {
    /// Direct mapping with minimal changes
    DirectMapping,
    /// Gradual migration with coexistence period
    GradualMigration,
    /// Complete rebuild with role consolidation
    Rebuild,
    /// Custom strategy for complex scenarios
    Custom(String),
}

/// Migration plan for transitioning to role-system v1.0
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// Unique plan identifier
    pub id: String,

    /// Source system analysis
    pub source_analysis: LegacySystemAnalysis,

    /// Selected migration strategy
    pub strategy: MigrationStrategy,

    /// Planned migration phases
    pub phases: Vec<MigrationPhase>,

    /// Role mapping from legacy to new system
    pub role_mappings: HashMap<String, String>,

    /// Permission mapping from legacy to new system
    pub permission_mappings: HashMap<String, String>,

    /// User assignment migrations
    pub user_migrations: Vec<UserMigration>,

    /// Pre-migration validation steps
    pub pre_validation_steps: Vec<ValidationStep>,

    /// Post-migration validation steps
    pub post_validation_steps: Vec<ValidationStep>,

    /// Rollback plan
    pub rollback_plan: RollbackPlan,

    /// Estimated migration time
    pub estimated_duration: chrono::Duration,

    /// Risk assessment
    pub risk_level: RiskLevel,

    /// Required downtime (if any)
    pub downtime_required: Option<chrono::Duration>,
}

/// Individual migration phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPhase {
    pub id: String,
    pub name: String,
    pub description: String,
    pub order: u32,
    pub operations: Vec<MigrationOperation>,
    pub dependencies: Vec<String>,
    pub estimated_duration: chrono::Duration,
    pub rollback_operations: Vec<MigrationOperation>,
}

/// Migration operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MigrationOperation {
    CreateRole {
        role_id: String,
        name: String,
        description: Option<String>,
        permissions: Vec<String>,
        parent_role: Option<String>,
    },
    AssignUserRole {
        user_id: String,
        role_id: String,
        expiration: Option<chrono::DateTime<chrono::Utc>>,
    },
    CreatePermission {
        permission_id: String,
        action: String,
        resource: String,
        conditions: HashMap<String, String>,
    },
    MigrateCustomAttribute {
        attribute_name: String,
        conversion_logic: String,
    },
    ValidateIntegrity {
        validation_type: String,
        parameters: HashMap<String, String>,
    },
    Backup {
        backup_location: PathBuf,
        backup_type: BackupType,
    },
}

/// User migration details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMigration {
    pub user_id: String,
    pub legacy_roles: Vec<String>,
    pub legacy_permissions: Vec<String>,
    pub new_roles: Vec<String>,
    pub migration_notes: Option<String>,
}

/// Validation step definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationStep {
    pub id: String,
    pub name: String,
    pub description: String,
    pub validation_type: ValidationType,
    pub parameters: HashMap<String, String>,
    pub required: bool,
}

/// Types of validation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ValidationType {
    /// Check role hierarchy integrity
    HierarchyIntegrity,
    /// Validate permission consistency
    PermissionConsistency,
    /// Check user assignment validity
    UserAssignmentValidity,
    /// Verify no privilege escalation
    PrivilegeEscalationCheck,
    /// Custom validation script
    Custom(String),
}

/// Rollback plan for migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackPlan {
    pub phases: Vec<RollbackPhase>,
    pub backup_locations: Vec<PathBuf>,
    pub recovery_time_objective: chrono::Duration,
    pub manual_steps: Vec<String>,
}

/// Rollback phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackPhase {
    pub id: String,
    pub name: String,
    pub operations: Vec<MigrationOperation>,
    pub order: u32,
}

/// Risk assessment levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Backup types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupType {
    /// Full system backup
    Full,
    /// Incremental backup
    Incremental,
    /// Configuration only
    ConfigOnly,
    /// Data only
    DataOnly,
}

/// Migration execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationResult {
    pub plan_id: String,
    pub status: MigrationStatus,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub phases_completed: Vec<String>,
    pub current_phase: Option<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub metrics: MigrationMetrics,
}

/// Migration execution status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MigrationStatus {
    Planned,
    InProgress,
    Completed,
    Failed,
    RolledBack,
    Paused,
}

/// Migration execution metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationMetrics {
    pub roles_migrated: usize,
    pub permissions_migrated: usize,
    pub users_migrated: usize,
    pub errors_encountered: usize,
    pub warnings_generated: usize,
    pub validation_failures: usize,
    pub rollback_count: usize,
}

/// Main migration manager
pub struct MigrationManager {
    /// Configuration for migration operations
    config: MigrationConfig,
}

/// Migration manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationConfig {
    /// Working directory for migration files
    pub working_directory: PathBuf,

    /// Backup directory
    pub backup_directory: PathBuf,

    /// Maximum concurrent operations
    pub max_concurrent_operations: usize,

    /// Operation timeout
    pub operation_timeout: chrono::Duration,

    /// Enable dry-run mode
    pub dry_run: bool,

    /// Verbose logging
    pub verbose: bool,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            working_directory: PathBuf::from("./migration"),
            backup_directory: PathBuf::from("./migration/backups"),
            max_concurrent_operations: 4,
            operation_timeout: chrono::Duration::minutes(30),
            dry_run: false,
            verbose: false,
        }
    }
}

impl MigrationManager {
    /// Create new migration manager
    pub fn new(config: MigrationConfig) -> Result<Self, MigrationError> {
        // Ensure directories exist
        std::fs::create_dir_all(&config.working_directory)?;
        std::fs::create_dir_all(&config.backup_directory)?;

        Ok(Self { config })
    }

    /// Analyze legacy authorization system
    pub async fn analyze_legacy_system<P: AsRef<std::path::Path>>(
        &self,
        config_path: P,
    ) -> Result<LegacySystemAnalysis, MigrationError> {
        analyzers::analyze_legacy_system(config_path, &self.config).await
    }

    /// Generate migration plan
    pub async fn generate_migration_plan(
        &self,
        analysis: &LegacySystemAnalysis,
        strategy: Option<MigrationStrategy>,
    ) -> Result<MigrationPlan, MigrationError> {
        planners::generate_migration_plan(analysis, strategy, &self.config).await
    }

    /// Validate migration plan
    pub async fn validate_migration_plan(
        &self,
        plan: &MigrationPlan,
    ) -> Result<Vec<String>, MigrationError> {
        validators::validate_migration_plan(plan, &self.config).await
    }

    /// Execute migration plan
    pub async fn execute_migration(
        &self,
        plan: &MigrationPlan,
    ) -> Result<MigrationResult, MigrationError> {
        executors::execute_migration_plan(plan, &self.config).await
    }

    /// Get migration status
    pub async fn get_migration_status(
        &self,
        plan_id: &str,
    ) -> Result<Option<MigrationResult>, MigrationError> {
        let status_file = self
            .config
            .working_directory
            .join(format!("{}_status.json", plan_id));

        if !status_file.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(status_file).await?;
        let result: MigrationResult = serde_json::from_str(&content)?;
        Ok(Some(result))
    }

    /// Rollback migration
    pub async fn rollback_migration(
        &self,
        plan: &MigrationPlan,
    ) -> Result<MigrationResult, MigrationError> {
        executors::rollback_migration(plan, &self.config).await
    }

    /// List available migration plans
    pub async fn list_migration_plans(&self) -> Result<Vec<String>, MigrationError> {
        let mut plans = Vec::new();
        let mut entries = fs::read_dir(&self.config.working_directory).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json")
                && let Some(file_name) = path.file_stem()
                && let Some(name) = file_name.to_str()
                && name.ends_with("_plan")
            {
                plans.push(name.trim_end_matches("_plan").to_string());
            }
        }

        Ok(plans)
    }

    /// Save migration plan to disk
    pub async fn save_migration_plan(
        &self,
        plan: &MigrationPlan,
    ) -> Result<PathBuf, MigrationError> {
        let plan_file = self
            .config
            .working_directory
            .join(format!("{}_plan.json", plan.id));
        let content = serde_json::to_string_pretty(plan)?;
        fs::write(&plan_file, content).await?;
        Ok(plan_file)
    }

    /// Load migration plan from disk
    pub async fn load_migration_plan(
        &self,
        plan_id: &str,
    ) -> Result<MigrationPlan, MigrationError> {
        let plan_file = self
            .config
            .working_directory
            .join(format!("{}_plan.json", plan_id));
        let content = fs::read_to_string(plan_file).await?;
        let plan: MigrationPlan = serde_json::from_str(&content)?;
        Ok(plan)
    }

    /// Generate migration report
    pub async fn generate_migration_report(
        &self,
        result: &MigrationResult,
    ) -> Result<String, MigrationError> {
        let mut report = String::new();

        report.push_str("# Migration Report\n\n");
        report.push_str(&format!("**Plan ID**: {}\n", result.plan_id));
        report.push_str(&format!("**Status**: {:?}\n", result.status));
        report.push_str(&format!("**Started**: {}\n", result.started_at));

        if let Some(completed) = result.completed_at {
            report.push_str(&format!("**Completed**: {}\n", completed));
            let duration = completed - result.started_at;
            report.push_str(&format!(
                "**Duration**: {} minutes\n",
                duration.num_minutes()
            ));
        }

        report.push_str("\n## Metrics\n\n");
        report.push_str(&format!(
            "- Roles migrated: {}\n",
            result.metrics.roles_migrated
        ));
        report.push_str(&format!(
            "- Permissions migrated: {}\n",
            result.metrics.permissions_migrated
        ));
        report.push_str(&format!(
            "- Users migrated: {}\n",
            result.metrics.users_migrated
        ));
        report.push_str(&format!(
            "- Errors: {}\n",
            result.metrics.errors_encountered
        ));
        report.push_str(&format!(
            "- Warnings: {}\n",
            result.metrics.warnings_generated
        ));

        if !result.errors.is_empty() {
            report.push_str("\n## Errors\n\n");
            for error in &result.errors {
                report.push_str(&format!("- {}\n", error));
            }
        }

        if !result.warnings.is_empty() {
            report.push_str("\n## Warnings\n\n");
            for warning in &result.warnings {
                report.push_str(&format!("- {}\n", warning));
            }
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_migration_manager_creation() {
        let config = MigrationConfig::default();
        let manager = MigrationManager::new(config);
        assert!(manager.is_ok());
    }

    #[test]
    fn test_legacy_system_type_serialization() {
        let system_type = LegacySystemType::BasicRbac;
        let serialized = serde_json::to_string(&system_type).unwrap();
        let deserialized: LegacySystemType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(system_type, deserialized);
    }

    #[test]
    fn test_migration_strategy_serialization() {
        let strategy = MigrationStrategy::GradualMigration;
        let serialized = serde_json::to_string(&strategy).unwrap();
        let deserialized: MigrationStrategy = serde_json::from_str(&serialized).unwrap();
        assert_eq!(strategy, deserialized);
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }
}


