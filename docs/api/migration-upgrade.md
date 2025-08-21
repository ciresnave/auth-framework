# Migration and Upgrade Documentation

## Introduction

This guide provides comprehensive instructions for migrating to AuthFramework from other authentication systems and upgrading between AuthFramework versions. It includes migration strategies, compatibility matrices, automated tools, and step-by-step procedures to ensure smooth transitions.

## Table of Contents

1. [Migration Overview](#migration-overview)
2. [Version Compatibility](#version-compatibility)
3. [Migration from Other Systems](#migration-from-other-systems)
4. [Version Upgrade Procedures](#version-upgrade-procedures)
5. [Data Migration Tools](#data-migration-tools)
6. [Breaking Changes Guide](#breaking-changes-guide)
7. [Rollback Procedures](#rollback-procedures)
8. [Testing Migration](#testing-migration)
9. [Production Migration](#production-migration)
10. [Post-Migration Validation](#post-migration-validation)

## Migration Overview

### Migration Types

AuthFramework supports several migration scenarios:

- **Fresh Installation**: New deployment with no existing auth system
- **System Migration**: Moving from another authentication system
- **Version Upgrade**: Upgrading between AuthFramework versions
- **Configuration Migration**: Updating configuration formats
- **Data Migration**: Migrating user data and sessions

### Migration Planning Checklist

```yaml
Pre-Migration:
  - [ ] Backup existing authentication data
  - [ ] Document current authentication flows
  - [ ] Identify custom integrations
  - [ ] Plan migration timeline
  - [ ] Prepare rollback strategy
  - [ ] Set up staging environment
  - [ ] Test migration procedures

During Migration:
  - [ ] Monitor system health
  - [ ] Validate data integrity
  - [ ] Test authentication flows
  - [ ] Monitor error rates
  - [ ] Check performance metrics

Post-Migration:
  - [ ] Validate all features work
  - [ ] Clean up old authentication data
  - [ ] Update documentation
  - [ ] Train operations team
  - [ ] Monitor production metrics
```

## Version Compatibility

### Compatibility Matrix

| From Version | To Version | Compatibility | Migration Required | Notes |
|--------------|------------|---------------|-------------------|-------|
| 0.1.x | 0.2.x | ❌ Breaking | Yes | Major API changes |
| 0.2.x | 0.3.x | ⚠️ Partial | Configuration | Database schema changes |
| 0.3.x | 0.4.x | ✅ Compatible | Minimal | Backward compatible |
| 0.4.x | 0.5.x | ✅ Compatible | Configuration | New features available |

### Version Support Policy

```yaml
Support Levels:
  Active: "Latest major version"
  Maintenance: "Previous major version"
  End-of-Life: "2+ versions behind"

Security Updates:
  Active: "All security fixes"
  Maintenance: "Critical security fixes only"
  End-of-Life: "No security fixes"

Migration Support:
  Supported: "2 major versions back"
  Limited: "3 major versions back"
  Unsupported: "4+ major versions back"
```

## Migration from Other Systems

### From Auth0

```rust
use auth_framework::{Auth0Migrator, MigrationConfig};

pub struct Auth0Migration {
    auth0_client: Auth0Client,
    auth_framework: AuthFramework,
    migrator: Auth0Migrator,
}

impl Auth0Migration {
    pub async fn migrate_users(&self) -> Result<MigrationReport, MigrationError> {
        let config = MigrationConfig {
            batch_size: 100,
            parallel_batches: 5,
            retry_attempts: 3,
            validation_enabled: true,
        };

        // 1. Export users from Auth0
        let users = self.export_auth0_users().await?;

        // 2. Transform user data
        let transformed_users = self.transform_auth0_users(users).await?;

        // 3. Import to AuthFramework
        let import_result = self.import_users(transformed_users, &config).await?;

        // 4. Migrate user metadata
        self.migrate_user_metadata().await?;

        // 5. Migrate roles and permissions
        self.migrate_roles_and_permissions().await?;

        Ok(import_result)
    }

    async fn transform_auth0_users(&self, auth0_users: Vec<Auth0User>) -> Result<Vec<AuthFrameworkUser>, MigrationError> {
        let mut transformed = Vec::with_capacity(auth0_users.len());

        for auth0_user in auth0_users {
            let user = AuthFrameworkUser {
                id: generate_user_id(),
                external_id: Some(auth0_user.user_id),
                username: auth0_user.email.clone(),
                email: auth0_user.email,
                email_verified: auth0_user.email_verified,
                profile: UserProfile {
                    first_name: auth0_user.given_name,
                    last_name: auth0_user.family_name,
                    display_name: auth0_user.name,
                    picture: auth0_user.picture,
                },
                metadata: transform_metadata(auth0_user.user_metadata),
                created_at: auth0_user.created_at,
                updated_at: auth0_user.updated_at,
                last_login: auth0_user.last_login,
                login_count: auth0_user.logins_count.unwrap_or(0),
            };

            transformed.push(user);
        }

        Ok(transformed)
    }
}
```

### From Firebase Auth

```rust
use auth_framework::{FirebaseMigrator, FirebaseExportData};

pub struct FirebaseMigration {
    firebase_admin: FirebaseAdmin,
    auth_framework: AuthFramework,
}

impl FirebaseMigration {
    pub async fn migrate_from_firebase(&self) -> Result<MigrationReport, MigrationError> {
        // 1. Export Firebase users
        let firebase_export = self.export_firebase_users().await?;

        // 2. Migrate user accounts
        let user_migration = self.migrate_user_accounts(&firebase_export).await?;

        // 3. Migrate custom claims as permissions
        self.migrate_custom_claims(&firebase_export).await?;

        // 4. Migrate phone number authentication
        self.migrate_phone_auth(&firebase_export).await?;

        // 5. Migrate social provider links
        self.migrate_provider_links(&firebase_export).await?;

        Ok(user_migration)
    }

    async fn migrate_user_accounts(&self, export: &FirebaseExportData) -> Result<MigrationReport, MigrationError> {
        let mut migrated_count = 0;
        let mut failed_count = 0;
        let mut errors = Vec::new();

        for firebase_user in &export.users {
            match self.migrate_single_firebase_user(firebase_user).await {
                Ok(_) => migrated_count += 1,
                Err(e) => {
                    failed_count += 1;
                    errors.push(MigrationError::UserMigrationFailed {
                        user_id: firebase_user.uid.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }

        Ok(MigrationReport {
            total_users: export.users.len(),
            migrated_count,
            failed_count,
            errors,
        })
    }
}
```

### From Custom JWT System

```rust
use auth_framework::{JwtMigrator, CustomJwtConfig};

pub struct CustomJwtMigration {
    old_jwt_config: CustomJwtConfig,
    auth_framework: AuthFramework,
}

impl CustomJwtMigration {
    pub async fn migrate_jwt_system(&self) -> Result<(), MigrationError> {
        // 1. Migrate JWT signing keys
        self.migrate_signing_keys().await?;

        // 2. Create user migration mapping
        let user_mapping = self.create_user_mapping().await?;

        // 3. Migrate active sessions
        self.migrate_active_sessions(&user_mapping).await?;

        // 4. Set up JWT compatibility layer
        self.setup_compatibility_layer().await?;

        Ok(())
    }

    async fn migrate_signing_keys(&self) -> Result<(), MigrationError> {
        // Import existing JWT signing keys for token validation
        let old_public_key = self.old_jwt_config.get_public_key();

        // Add old key to AuthFramework for backward compatibility
        self.auth_framework
            .add_legacy_signing_key(LegacySigningKey {
                key_id: "legacy-jwt-key".to_string(),
                public_key: old_public_key,
                algorithm: self.old_jwt_config.algorithm.clone(),
                valid_until: Utc::now() + Duration::from_days(30), // Grace period
            })
            .await?;

        Ok(())
    }

    async fn migrate_active_sessions(&self, user_mapping: &UserMapping) -> Result<(), MigrationError> {
        // Get all active JWT tokens from your session store
        let active_tokens = self.get_active_jwt_tokens().await?;

        for token in active_tokens {
            // Validate old token
            let old_claims = self.validate_old_jwt(&token)?;

            // Map to new user ID
            let new_user_id = user_mapping.get_new_user_id(&old_claims.user_id)
                .ok_or(MigrationError::UserMappingNotFound)?;

            // Create new AuthFramework session
            let new_session = self.auth_framework
                .create_session(CreateSessionRequest {
                    user_id: new_user_id,
                    permissions: map_permissions(&old_claims.permissions),
                    expires_in: calculate_remaining_time(&old_claims.exp),
                    metadata: SessionMetadata {
                        migrated_from: Some("custom-jwt".to_string()),
                        original_token_id: Some(old_claims.jti),
                    },
                })
                .await?;

            // Store mapping for gradual migration
            self.store_token_mapping(&token, &new_session.token).await?;
        }

        Ok(())
    }
}
```

## Version Upgrade Procedures

### Upgrade from 0.3.x to 0.4.x

```rust
use auth_framework::{UpgradeManager, DatabaseMigrator};

pub struct V03ToV04Upgrade {
    upgrade_manager: UpgradeManager,
    database_migrator: DatabaseMigrator,
}

impl V03ToV04Upgrade {
    pub async fn perform_upgrade(&self) -> Result<UpgradeReport, UpgradeError> {
        // 1. Pre-upgrade validation
        self.validate_pre_upgrade_state().await?;

        // 2. Backup current state
        let backup_id = self.create_backup().await?;

        // 3. Run database migrations
        self.run_database_migrations().await?;

        // 4. Update configuration format
        self.migrate_configuration().await?;

        // 5. Migrate API endpoints
        self.update_api_endpoints().await?;

        // 6. Validate upgrade
        let validation_result = self.validate_upgrade().await?;

        if validation_result.success {
            Ok(UpgradeReport {
                from_version: "0.3.x".to_string(),
                to_version: "0.4.0".to_string(),
                backup_id,
                migration_time: validation_result.duration,
                warnings: validation_result.warnings,
            })
        } else {
            // Rollback on failure
            self.rollback_upgrade(&backup_id).await?;
            Err(UpgradeError::ValidationFailed(validation_result.errors))
        }
    }

    async fn run_database_migrations(&self) -> Result<(), UpgradeError> {
        // Migration 1: Add new columns for enhanced security
        self.database_migrator
            .run_migration("2024_08_01_add_security_columns.sql")
            .await?;

        // Migration 2: Update permission schema
        self.database_migrator
            .run_migration("2024_08_02_update_permissions.sql")
            .await?;

        // Migration 3: Add audit log improvements
        self.database_migrator
            .run_migration("2024_08_03_enhance_audit_log.sql")
            .await?;

        Ok(())
    }

    async fn migrate_configuration(&self) -> Result<(), UpgradeError> {
        // Load old configuration
        let old_config = self.load_v03_config().await?;

        // Convert to new format
        let new_config = AuthFrameworkConfig {
            version: "0.4.0".to_string(),
            server: ServerConfig {
                host: old_config.server.host,
                port: old_config.server.port,
                tls: old_config.server.tls,
                // New security settings
                security: SecurityConfig {
                    jwt_algorithm: JwtAlgorithm::RS256, // Upgraded from HS256
                    token_ttl: old_config.auth.token_ttl,
                    refresh_token_ttl: old_config.auth.refresh_token_ttl,
                    // New security features in 0.4.x
                    require_mfa: false, // Default to backward compatibility
                    password_policy: PasswordPolicy::default(),
                    rate_limiting: RateLimitingConfig::default(),
                },
            },
            database: old_config.database, // Compatible
            redis: old_config.redis,       // Compatible
            // New sections in 0.4.x
            monitoring: MonitoringConfig::default(),
            audit: AuditConfig::default(),
        };

        // Validate new configuration
        new_config.validate()?;

        // Save new configuration
        self.save_config(&new_config).await?;

        Ok(())
    }
}
```

### Major Version Upgrade (0.x to 1.0)

```rust
use auth_framework::{MajorVersionUpgrade, BreakingChangeHandler};

pub struct MajorVersionUpgrader {
    breaking_change_handler: BreakingChangeHandler,
    compatibility_layer: CompatibilityLayer,
}

impl MajorVersionUpgrader {
    pub async fn upgrade_to_v1(&self) -> Result<MajorUpgradeReport, UpgradeError> {
        // 1. Analyze breaking changes
        let breaking_changes = self.analyze_breaking_changes().await?;

        // 2. Create migration plan
        let migration_plan = self.create_migration_plan(&breaking_changes).await?;

        // 3. Set up compatibility layer for gradual migration
        self.setup_compatibility_layer().await?;

        // 4. Execute migration in phases
        for phase in migration_plan.phases {
            self.execute_migration_phase(phase).await?;
        }

        // 5. Validate complete migration
        self.validate_v1_migration().await?;

        Ok(MajorUpgradeReport {
            breaking_changes_handled: breaking_changes.len(),
            migration_phases: migration_plan.phases.len(),
            compatibility_layer_active: true,
        })
    }

    async fn handle_api_breaking_changes(&self) -> Result<(), UpgradeError> {
        // Handle removed/changed API endpoints
        let deprecated_endpoints = vec![
            "/auth/legacy-login",
            "/users/permissions",  // Moved to /users/{id}/permissions
        ];

        for endpoint in deprecated_endpoints {
            self.compatibility_layer
                .add_endpoint_redirect(endpoint, self.get_new_endpoint(endpoint))
                .await?;
        }

        // Handle changed request/response formats
        self.compatibility_layer
            .add_format_transformer("login_response", |old_format| {
                // Transform old login response to new format
                serde_json::json!({
                    "access_token": old_format["token"],
                    "refresh_token": old_format["refresh_token"],
                    "token_type": "Bearer",
                    "expires_in": old_format["expires_in"],
                    "user": old_format["user_info"]
                })
            })
            .await?;

        Ok(())
    }
}
```

## Data Migration Tools

### Automated Migration CLI

```rust
use auth_framework::{MigrationCli, MigrationCommand};

pub struct AuthFrameworkMigrationCli {
    config: MigrationConfig,
}

impl AuthFrameworkMigrationCli {
    pub async fn run_migration(&self, command: MigrationCommand) -> Result<(), MigrationError> {
        match command {
            MigrationCommand::Plan { from_version, to_version } => {
                let plan = self.create_migration_plan(&from_version, &to_version).await?;
                self.display_migration_plan(&plan);
            }

            MigrationCommand::Execute { plan_file, dry_run } => {
                let plan = self.load_migration_plan(&plan_file)?;

                if dry_run {
                    self.simulate_migration(&plan).await?;
                } else {
                    self.execute_migration(&plan).await?;
                }
            }

            MigrationCommand::Validate { backup_id } => {
                self.validate_migration_result(&backup_id).await?;
            }

            MigrationCommand::Rollback { backup_id } => {
                self.rollback_migration(&backup_id).await?;
            }
        }

        Ok(())
    }

    async fn create_migration_plan(&self, from: &str, to: &str) -> Result<MigrationPlan, MigrationError> {
        let mut plan = MigrationPlan::new(from, to);

        // Analyze current system
        let current_state = self.analyze_current_system().await?;

        // Add required migrations
        if self.requires_database_migration(from, to) {
            plan.add_step(MigrationStep::DatabaseMigration {
                scripts: self.get_required_db_migrations(from, to),
                backup_required: true,
            });
        }

        if self.requires_config_migration(from, to) {
            plan.add_step(MigrationStep::ConfigMigration {
                transformations: self.get_config_transformations(from, to),
                backup_required: true,
            });
        }

        if self.has_breaking_changes(from, to) {
            plan.add_step(MigrationStep::BreakingChanges {
                changes: self.get_breaking_changes(from, to),
                compatibility_layer: true,
            });
        }

        Ok(plan)
    }
}
```

### Data Export/Import Tools

```rust
use auth_framework::{DataExporter, DataImporter};

pub struct AuthFrameworkDataTools {
    exporter: DataExporter,
    importer: DataImporter,
}

impl AuthFrameworkDataTools {
    pub async fn export_system_data(&self, export_config: ExportConfig) -> Result<ExportResult, ExportError> {
        let mut export_data = SystemExportData::new();

        // Export users
        if export_config.include_users {
            export_data.users = self.exporter.export_users(&export_config.user_filter).await?;
        }

        // Export roles and permissions
        if export_config.include_permissions {
            export_data.roles = self.exporter.export_roles().await?;
            export_data.permissions = self.exporter.export_permissions().await?;
        }

        // Export configuration
        if export_config.include_config {
            export_data.config = self.exporter.export_configuration().await?;
        }

        // Export audit logs
        if export_config.include_audit_logs {
            export_data.audit_logs = self.exporter
                .export_audit_logs(&export_config.audit_date_range)
                .await?;
        }

        // Create export package
        let export_file = self.create_export_package(export_data, &export_config).await?;

        Ok(ExportResult {
            export_file,
            exported_users: export_data.users.len(),
            exported_roles: export_data.roles.len(),
            exported_permissions: export_data.permissions.len(),
            export_size: self.get_file_size(&export_file).await?,
        })
    }

    pub async fn import_system_data(&self, import_file: &str, import_config: ImportConfig) -> Result<ImportResult, ImportError> {
        // Load and validate export package
        let export_data = self.load_export_package(import_file).await?;
        self.validate_export_data(&export_data).await?;

        let mut import_result = ImportResult::new();

        // Import in correct order (dependencies first)

        // 1. Import permissions
        if import_config.include_permissions && !export_data.permissions.is_empty() {
            import_result.permissions = self.importer
                .import_permissions(&export_data.permissions, &import_config)
                .await?;
        }

        // 2. Import roles
        if import_config.include_roles && !export_data.roles.is_empty() {
            import_result.roles = self.importer
                .import_roles(&export_data.roles, &import_config)
                .await?;
        }

        // 3. Import users
        if import_config.include_users && !export_data.users.is_empty() {
            import_result.users = self.importer
                .import_users(&export_data.users, &import_config)
                .await?;
        }

        // 4. Import configuration
        if import_config.include_config && export_data.config.is_some() {
            import_result.config_imported = self.importer
                .import_configuration(&export_data.config.unwrap(), &import_config)
                .await?;
        }

        Ok(import_result)
    }
}
```

## Breaking Changes Guide

### Version 0.4.x Breaking Changes

```yaml
API Changes:
  Removed Endpoints:
    - "/auth/legacy-login": "Use /auth/login"
    - "/users/bulk": "Use /admin/users/bulk"

  Changed Request Formats:
    - "/auth/login":
        old: "{ username, password }"
        new: "{ username, password, client_info? }"

    - "/users/{id}/permissions":
        old: "Array of permission strings"
        new: "Object with permissions and metadata"

  Changed Response Formats:
    - "/auth/login":
        old: "{ token, user_info }"
        new: "{ access_token, refresh_token, token_type, expires_in, user }"

Configuration Changes:
  Renamed Fields:
    - "auth.jwt_secret" → "security.jwt_signing_key"
    - "auth.token_expiry" → "security.token_ttl"

  New Required Fields:
    - "security.password_policy"
    - "monitoring.metrics_endpoint"

  Removed Fields:
    - "auth.legacy_mode" # No longer supported

Database Schema Changes:
  New Tables:
    - "audit_logs"
    - "rate_limits"
    - "password_history"

  Modified Tables:
    - "users": Added columns "mfa_enabled", "password_updated_at"
    - "tokens": Added columns "token_type", "scope"

  Removed Tables:
    - "legacy_sessions" # Migrated to "sessions"
```

### Migration Code for Breaking Changes

```rust
use auth_framework::{BreakingChangesMigrator, CompatibilityMode};

pub struct BreakingChangeHandler {
    compatibility_mode: CompatibilityMode,
}

impl BreakingChangeHandler {
    pub async fn handle_login_endpoint_changes(&self) -> Result<(), MigrationError> {
        // Handle old login request format
        self.compatibility_mode
            .add_request_transformer("/auth/login", |old_request| {
                let old_data: serde_json::Value = serde_json::from_slice(&old_request)?;

                let new_request = serde_json::json!({
                    "username": old_data["username"],
                    "password": old_data["password"],
                    "client_info": {
                        "migrated_from": "legacy_format"
                    }
                });

                Ok(serde_json::to_vec(&new_request)?)
            })
            .await?;

        // Handle old login response format
        self.compatibility_mode
            .add_response_transformer("/auth/login", |new_response| {
                let new_data: serde_json::Value = serde_json::from_slice(&new_response)?;

                // Transform new format back to old for legacy clients
                let old_response = serde_json::json!({
                    "token": new_data["access_token"],
                    "user_info": new_data["user"]
                });

                Ok(serde_json::to_vec(&old_response)?)
            })
            .await?;

        Ok(())
    }

    pub async fn migrate_configuration_format(&self, old_config_path: &str) -> Result<(), MigrationError> {
        // Load old configuration
        let old_config: OldConfigFormat = serde_yaml::from_str(
            &std::fs::read_to_string(old_config_path)?
        )?;

        // Transform to new format
        let new_config = NewConfigFormat {
            version: "0.4.0".to_string(),
            security: SecurityConfig {
                jwt_signing_key: old_config.auth.jwt_secret,
                token_ttl: old_config.auth.token_expiry,
                password_policy: PasswordPolicy::default(), // New required field
            },
            monitoring: MonitoringConfig {
                metrics_endpoint: "/metrics".to_string(), // New required field
                enabled: true,
            },
            // Copy compatible fields
            database: old_config.database,
            redis: old_config.redis,
        };

        // Save new configuration
        let new_config_yaml = serde_yaml::to_string(&new_config)?;
        std::fs::write(
            old_config_path.replace(".yaml", ".v04.yaml"),
            new_config_yaml
        )?;

        Ok(())
    }
}
```

## Rollback Procedures

### Automated Rollback System

```rust
use auth_framework::{RollbackManager, BackupMetadata};

pub struct AuthFrameworkRollback {
    rollback_manager: RollbackManager,
    backup_store: BackupStore,
}

impl AuthFrameworkRollback {
    pub async fn perform_rollback(&self, backup_id: &str) -> Result<RollbackReport, RollbackError> {
        // 1. Validate backup exists and is complete
        let backup_metadata = self.backup_store.get_metadata(backup_id).await?;
        self.validate_backup(&backup_metadata).await?;

        // 2. Create pre-rollback snapshot
        let pre_rollback_backup = self.create_emergency_backup().await?;

        // 3. Stop services gracefully
        self.stop_auth_services().await?;

        // 4. Restore database
        self.restore_database(&backup_metadata).await?;

        // 5. Restore configuration
        self.restore_configuration(&backup_metadata).await?;

        // 6. Restore file system data
        self.restore_filesystem_data(&backup_metadata).await?;

        // 7. Start services
        self.start_auth_services().await?;

        // 8. Validate rollback
        let validation_result = self.validate_rollback().await?;

        if validation_result.success {
            Ok(RollbackReport {
                backup_id: backup_id.to_string(),
                rollback_time: validation_result.duration,
                services_restored: validation_result.services_validated,
                pre_rollback_backup: pre_rollback_backup.id,
            })
        } else {
            Err(RollbackError::ValidationFailed(validation_result.errors))
        }
    }

    async fn validate_rollback(&self) -> Result<ValidationResult, RollbackError> {
        let mut validation = ValidationResult::new();

        // Test database connectivity
        validation.add_check("database", self.test_database_connection().await);

        // Test authentication flow
        validation.add_check("authentication", self.test_authentication_flow().await);

        // Test API endpoints
        validation.add_check("api_endpoints", self.test_api_endpoints().await);

        // Check configuration
        validation.add_check("configuration", self.validate_configuration().await);

        // Test user management
        validation.add_check("user_management", self.test_user_management().await);

        Ok(validation)
    }
}
```

### Manual Rollback Guide

```bash
#!/bin/bash
# AuthFramework Manual Rollback Script

set -e

BACKUP_ID=$1
BACKUP_DIR="/var/backups/authframework"
SERVICE_NAME="auth-framework"

if [ -z "$BACKUP_ID" ]; then
    echo "Usage: $0 <backup_id>"
    exit 1
fi

echo "Starting rollback to backup: $BACKUP_ID"

# 1. Stop services
echo "Stopping AuthFramework services..."
systemctl stop $SERVICE_NAME
systemctl stop auth-framework-worker

# 2. Create emergency backup
echo "Creating emergency backup..."
EMERGENCY_BACKUP="emergency_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR/$EMERGENCY_BACKUP"

# Backup current database
pg_dump auth_framework > "$BACKUP_DIR/$EMERGENCY_BACKUP/database.sql"

# Backup current configuration
cp -r /etc/auth-framework "$BACKUP_DIR/$EMERGENCY_BACKUP/config"

# Backup current data directory
cp -r /var/lib/auth-framework "$BACKUP_DIR/$EMERGENCY_BACKUP/data"

echo "Emergency backup created: $EMERGENCY_BACKUP"

# 3. Restore from backup
echo "Restoring from backup: $BACKUP_ID"

# Restore database
echo "Restoring database..."
dropdb auth_framework
createdb auth_framework
psql auth_framework < "$BACKUP_DIR/$BACKUP_ID/database.sql"

# Restore configuration
echo "Restoring configuration..."
rm -rf /etc/auth-framework
cp -r "$BACKUP_DIR/$BACKUP_ID/config" /etc/auth-framework

# Restore data directory
echo "Restoring data directory..."
rm -rf /var/lib/auth-framework
cp -r "$BACKUP_DIR/$BACKUP_ID/data" /var/lib/auth-framework

# Fix permissions
chown -R auth-framework:auth-framework /var/lib/auth-framework
chmod 600 /etc/auth-framework/config.yaml

# 4. Start services
echo "Starting AuthFramework services..."
systemctl start $SERVICE_NAME
systemctl start auth-framework-worker

# 5. Validate rollback
echo "Validating rollback..."
sleep 10

# Test service health
if curl -f http://localhost:8080/health > /dev/null 2>&1; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
    exit 1
fi

# Test authentication
if curl -f -X POST http://localhost:8080/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}' > /dev/null 2>&1; then
    echo "✅ Authentication test passed"
else
    echo "❌ Authentication test failed"
    exit 1
fi

echo "🎉 Rollback completed successfully!"
echo "Emergency backup available at: $EMERGENCY_BACKUP"
```

---

*AuthFramework v0.4.0 - Migration and Upgrade Documentation*
