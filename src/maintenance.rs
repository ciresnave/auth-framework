//! Maintenance utilities: snapshots, data export, and health checks.
//!
//! Provides tools for operational maintenance including:
//!
//! - **Snapshot & restore** — Serialise the entire storage state to a
//!   versioned, checksummed snapshot file and restore from it.
//! - **Data export** — Export users, sessions, tokens, and audit logs as
//!   structured JSON for compliance or migration purposes.
//! - **Health checks** — Verify storage connectivity, token validity, and
//!   system integrity.
//!
//! Most operations are available through the
//! [`MaintenanceOperations`](crate::auth::MaintenanceOperations) facade.

use crate::auth::AuthFramework;
use crate::auth_operations::UserListQuery;
use crate::config::{StorageConfig, app_config::AppConfig};
use crate::errors::{AuthError, Result};
use crate::permissions::Role;
use crate::storage::SessionData;
use crate::tokens::AuthToken;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const SNAPSHOT_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub format_version: u32,
    pub created_at: DateTime<Utc>,
    pub storage_backend: String,
    pub user_count: usize,
    pub role_count: usize,
    pub token_count: usize,
    pub session_count: usize,
    pub kv_entry_count: usize,
    pub checksum_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotUserSummary {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotKvEntry {
    pub key: String,
    pub value_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceSnapshot {
    pub manifest: SnapshotManifest,
    pub users: Vec<SnapshotUserSummary>,
    pub roles: Vec<Role>,
    pub tokens: Vec<AuthToken>,
    pub sessions: Vec<SessionData>,
    pub kv_entries: Vec<SnapshotKvEntry>,
}

#[derive(Debug, Clone)]
pub struct BackupReport {
    pub manifest: SnapshotManifest,
    pub output_path: PathBuf,
    pub dry_run: bool,
}

#[derive(Debug, Clone)]
pub struct ResetReport {
    pub users_deleted: usize,
    pub roles_seen: usize,
    pub tokens_deleted: usize,
    pub sessions_deleted: usize,
    pub kv_entries_deleted: usize,
    pub dry_run: bool,
}

#[derive(Debug, Clone)]
pub struct RestoreReport {
    pub manifest: SnapshotManifest,
    pub input_path: PathBuf,
    pub reset_report: ResetReport,
    pub dry_run: bool,
}

#[derive(Debug, Clone)]
pub struct MigrationFileReport {
    pub backend: String,
    pub path: PathBuf,
}

#[derive(Serialize)]
struct SnapshotChecksumPayload<'a> {
    users: &'a [SnapshotUserSummary],
    roles: &'a [Role],
    tokens: &'a [AuthToken],
    sessions: &'a [SessionData],
    kv_entries: &'a [SnapshotKvEntry],
}

fn normalize_json_value(value: Value) -> Value {
    match value {
        Value::Array(values) => {
            let mut normalized = values
                .into_iter()
                .map(normalize_json_value)
                .collect::<Vec<_>>();
            normalized.sort_by_key(|left| left.to_string());
            Value::Array(normalized)
        }
        Value::Object(object) => {
            let mut entries = object.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));

            let normalized = entries
                .into_iter()
                .map(|(key, value)| (key, normalize_json_value(value)))
                .collect::<Map<String, Value>>();
            Value::Object(normalized)
        }
        other => other,
    }
}

fn storage_backend_name(config: &StorageConfig) -> &'static str {
    match config {
        StorageConfig::Memory => "memory",
        #[cfg(feature = "postgres-storage")]
        StorageConfig::Postgres { .. } => "postgres",
        #[cfg(feature = "redis-storage")]
        StorageConfig::Redis { .. } => "redis",
        #[cfg(feature = "mysql-storage")]
        StorageConfig::MySQL { .. } => "mysql",
        #[cfg(feature = "sqlite-storage")]
        StorageConfig::Sqlite { .. } => "sqlite",
        StorageConfig::Custom(_) => "custom",
    }
}

fn backend_name_from_database_url(database_url: &str) -> &'static str {
    let database_url = database_url.trim().to_ascii_lowercase();

    if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://") {
        "postgres"
    } else if database_url.starts_with("mysql://") {
        "mysql"
    } else if database_url.starts_with("sqlite:") || database_url.ends_with(".db") {
        "sqlite"
    } else if database_url.starts_with("redis://") || database_url.starts_with("rediss://") {
        "redis"
    } else if database_url.is_empty() {
        "memory"
    } else {
        "custom"
    }
}

fn checksum_snapshot(
    users: &[SnapshotUserSummary],
    roles: &[Role],
    tokens: &[AuthToken],
    sessions: &[SessionData],
    kv_entries: &[SnapshotKvEntry],
) -> Result<String> {
    let payload = SnapshotChecksumPayload {
        users,
        roles,
        tokens,
        sessions,
        kv_entries,
    };
    let encoded = serde_json::to_value(&payload)
        .map(normalize_json_value)
        .and_then(|value| serde_json::to_vec(&value))
        .map_err(|e| AuthError::internal(format!("Failed to serialize snapshot payload: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(encoded);
    Ok(hex::encode(hasher.finalize()))
}

fn sanitize_migration_name(name: &str) -> Result<String> {
    let sanitized = name
        .trim()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();

    let collapsed = sanitized
        .split('_')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("_");

    if collapsed.is_empty() {
        return Err(AuthError::validation(
            "Migration name must contain at least one alphanumeric character",
        ));
    }

    Ok(collapsed)
}

async fn collect_snapshot(framework: &AuthFramework) -> Result<MaintenanceSnapshot> {
    let storage = framework.storage();

    let mut users = framework
        .users()
        .list_with_query(UserListQuery::new())
        .await?;
    users.sort_by(|left, right| left.id.cmp(&right.id));

    let mut snapshot_users = Vec::with_capacity(users.len());
    for user in &users {
        let mut roles: HashSet<String> = user.roles.iter().cloned().collect();
        roles.extend(framework.authorization().roles_for_user(&user.id).await?);
        let mut roles = roles.into_iter().collect::<Vec<_>>();
        roles.sort();

        snapshot_users.push(SnapshotUserSummary {
            id: user.id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            roles,
            active: user.active,
        });
    }

    let mut roles = framework.authorization().list_roles().await;
    roles.sort_by(|left, right| left.name.cmp(&right.name));

    let mut tokens = Vec::new();
    let mut seen_tokens = HashSet::new();
    let mut sessions = Vec::new();
    let mut seen_sessions = HashSet::new();

    for user in &users {
        for token in framework.tokens().list_for_user(&user.id).await? {
            if seen_tokens.insert(token.token_id.clone()) {
                tokens.push(token);
            }
        }

        for session in framework.sessions().list_for_user(&user.id).await? {
            if seen_sessions.insert(session.session_id.clone()) {
                sessions.push(session);
            }
        }
    }

    tokens.sort_by(|left, right| left.token_id.cmp(&right.token_id));
    sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));

    let mut kv_keys = storage.list_kv_keys("").await?;
    kv_keys.sort();
    kv_keys.dedup();

    let mut kv_entries = Vec::with_capacity(kv_keys.len());
    for key in kv_keys {
        if let Some(value) = storage.get_kv(&key).await? {
            kv_entries.push(SnapshotKvEntry {
                key,
                value_base64: BASE64_STANDARD.encode(value),
            });
        }
    }

    let manifest = SnapshotManifest {
        format_version: SNAPSHOT_FORMAT_VERSION,
        created_at: Utc::now(),
        storage_backend: storage_backend_name(&framework.config().storage).to_string(),
        user_count: snapshot_users.len(),
        role_count: roles.len(),
        token_count: tokens.len(),
        session_count: sessions.len(),
        kv_entry_count: kv_entries.len(),
        checksum_sha256: checksum_snapshot(
            &snapshot_users,
            &roles,
            &tokens,
            &sessions,
            &kv_entries,
        )?,
    };

    Ok(MaintenanceSnapshot {
        manifest,
        users: snapshot_users,
        roles,
        tokens,
        sessions,
        kv_entries,
    })
}

fn validate_snapshot(snapshot: &MaintenanceSnapshot) -> Result<()> {
    if snapshot.manifest.format_version != SNAPSHOT_FORMAT_VERSION {
        return Err(AuthError::configuration(format!(
            "Unsupported snapshot format version {}",
            snapshot.manifest.format_version
        )));
    }

    let expected_checksum = checksum_snapshot(
        &snapshot.users,
        &snapshot.roles,
        &snapshot.tokens,
        &snapshot.sessions,
        &snapshot.kv_entries,
    )?;

    if expected_checksum != snapshot.manifest.checksum_sha256 {
        return Err(AuthError::validation(
            "Snapshot checksum validation failed; restore aborted",
        ));
    }

    Ok(())
}

pub async fn backup_to_file(
    framework: &AuthFramework,
    output_path: impl AsRef<Path>,
    dry_run: bool,
) -> Result<BackupReport> {
    let output_path = output_path.as_ref().to_path_buf();
    let snapshot = collect_snapshot(framework).await?;

    if !dry_run {
        if let Some(parent) = output_path.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent).await?;
        }

        let data = serde_json::to_vec_pretty(&snapshot).map_err(|e| {
            AuthError::internal(format!("Failed to serialize maintenance snapshot: {e}"))
        })?;
        tokio::fs::write(&output_path, data).await?;
    }

    Ok(BackupReport {
        manifest: snapshot.manifest,
        output_path,
        dry_run,
    })
}

pub async fn reset_runtime_data(framework: &AuthFramework, dry_run: bool) -> Result<ResetReport> {
    let storage = framework.storage();
    let users = framework
        .users()
        .list_with_query(UserListQuery::new())
        .await?;
    let roles = framework.authorization().list_roles().await;

    let mut token_ids = HashSet::new();
    let mut session_ids = HashSet::new();
    for user in &users {
        for token in framework.tokens().list_for_user(&user.id).await? {
            token_ids.insert(token.token_id);
        }

        for session in framework.sessions().list_for_user(&user.id).await? {
            session_ids.insert(session.session_id);
        }
    }

    let mut kv_keys = storage.list_kv_keys("").await?;
    kv_keys.sort();
    kv_keys.dedup();

    if !dry_run {
        for token_id in &token_ids {
            storage.delete_token(token_id).await?;
        }

        for session_id in &session_ids {
            storage.delete_session(session_id).await?;
        }

        for user in &users {
            framework.users().delete_by_id(&user.id).await?;
        }

        for key in &kv_keys {
            storage.delete_kv(key).await?;
        }

        framework.reset_authorization_runtime().await;
    }

    Ok(ResetReport {
        users_deleted: users.len(),
        roles_seen: roles.len(),
        tokens_deleted: token_ids.len(),
        sessions_deleted: session_ids.len(),
        kv_entries_deleted: kv_keys.len(),
        dry_run,
    })
}

pub async fn restore_from_file(
    framework: &AuthFramework,
    input_path: impl AsRef<Path>,
    dry_run: bool,
) -> Result<RestoreReport> {
    let input_path = input_path.as_ref().to_path_buf();
    let data = tokio::fs::read(&input_path).await?;
    let snapshot: MaintenanceSnapshot = serde_json::from_slice(&data)
        .map_err(|e| AuthError::validation(format!("Failed to parse maintenance snapshot: {e}")))?;
    validate_snapshot(&snapshot)?;

    let reset_report = reset_runtime_data(framework, dry_run).await?;

    if !dry_run {
        let storage = framework.storage();

        for entry in &snapshot.kv_entries {
            let value = BASE64_STANDARD.decode(&entry.value_base64).map_err(|e| {
                AuthError::validation(format!(
                    "Snapshot KV entry '{}' is not valid base64: {e}",
                    entry.key
                ))
            })?;
            storage.store_kv(&entry.key, &value, None).await?;
        }

        for token in &snapshot.tokens {
            storage.store_token(token).await?;
        }

        for session in &snapshot.sessions {
            storage.store_session(&session.session_id, session).await?;
        }

        framework.reset_authorization_runtime().await;
        for role in &snapshot.roles {
            framework.authorization().create_role(role.clone()).await?;
        }
        for user in &snapshot.users {
            for role_name in &user.roles {
                framework
                    .authorization()
                    .assign_role(&user.id, role_name)
                    .await?;
            }
        }
    }

    Ok(RestoreReport {
        manifest: snapshot.manifest,
        input_path,
        reset_report,
        dry_run,
    })
}

fn build_migration_template(backend: &str, migration_name: &str, original_name: &str) -> String {
    format!(
        "-- AuthFramework migration template\n-- Backend: {backend}\n-- Name: {original_name}\n-- Generated at: {}\n\n-- Replace this placeholder with idempotent DDL for {migration_name}.\n-- Prefer CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS where supported.\n\nBEGIN;\n\n-- Add migration SQL here\n\nCOMMIT;\n",
        Utc::now().to_rfc3339(),
    )
}

pub async fn create_migration_file(config: &AppConfig, name: &str) -> Result<MigrationFileReport> {
    let backend = backend_name_from_database_url(&config.database.url).to_string();
    create_migration_template_for_backend(&backend, name).await
}

pub async fn create_migration_file_for_storage(
    storage: &StorageConfig,
    name: &str,
) -> Result<MigrationFileReport> {
    let backend = storage_backend_name(storage).to_string();
    create_migration_template_for_backend(&backend, name).await
}

async fn create_migration_template_for_backend(
    backend: &str,
    name: &str,
) -> Result<MigrationFileReport> {
    let sanitized_name = sanitize_migration_name(name)?;
    let directory = PathBuf::from("migrations").join(backend);
    tokio::fs::create_dir_all(&directory).await?;

    let file_name = format!(
        "{}_{}.sql",
        Utc::now().format("%Y%m%d%H%M%S"),
        sanitized_name
    );
    let path = directory.join(file_name);
    let template = build_migration_template(backend, &sanitized_name, name);
    tokio::fs::write(&path, template).await?;

    Ok(MigrationFileReport {
        backend: backend.to_string(),
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use crate::methods::{AuthMethodEnum, JwtMethod};
    use std::time::Duration;
    use tempfile::tempdir;

    async fn create_framework() -> AuthFramework {
        let config = AuthConfig::new()
            .secret("0123456789abcdef0123456789abcdef")
            .token_lifetime(Duration::from_secs(3600));
        let mut framework = AuthFramework::new(config);
        framework.register_method("jwt", AuthMethodEnum::Jwt(JwtMethod::new()));
        framework.initialize().await.unwrap();
        framework
    }

    #[tokio::test]
    async fn backup_restore_roundtrip_preserves_runtime_state() {
        let framework = create_framework().await;
        let user_id = framework
            .users()
            .register("alice", "alice@example.com", "Password123!")
            .await
            .unwrap();
        framework
            .authorization()
            .create_role(Role::new("auditor"))
            .await
            .unwrap();
        framework
            .authorization()
            .assign_role(&user_id, "auditor")
            .await
            .unwrap();
        framework
            .tokens()
            .create(&user_id, &["read"], "jwt", None)
            .await
            .unwrap();
        framework
            .sessions()
            .create(
                &user_id,
                Duration::from_secs(900),
                Some("127.0.0.1".into()),
                None,
            )
            .await
            .unwrap();
        framework
            .storage()
            .store_kv("custom:test", b"value", None)
            .await
            .unwrap();

        let dir = tempdir().unwrap();
        let path = dir.path().join("snapshot.json");

        backup_to_file(&framework, &path, false).await.unwrap();
        reset_runtime_data(&framework, false).await.unwrap();
        assert!(
            framework
                .users()
                .list_with_query(UserListQuery::new())
                .await
                .unwrap()
                .is_empty()
        );

        restore_from_file(&framework, &path, false).await.unwrap();

        let restored_user = framework.users().get(&user_id).await.unwrap();
        assert_eq!(restored_user.username, "alice");
        assert!(
            framework
                .authorization()
                .has_role(&user_id, "auditor")
                .await
                .unwrap()
        );
        assert_eq!(
            framework
                .tokens()
                .list_for_user(&user_id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            framework
                .sessions()
                .list_for_user(&user_id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            framework
                .storage()
                .get_kv("custom:test")
                .await
                .unwrap()
                .unwrap(),
            b"value"
        );
    }

    #[tokio::test]
    async fn reset_dry_run_leaves_state_unchanged() {
        let framework = create_framework().await;
        let user_id = framework
            .users()
            .register("bob", "bob@example.com", "Password123!")
            .await
            .unwrap();
        framework
            .storage()
            .store_kv("custom:dry-run", b"present", None)
            .await
            .unwrap();

        let report = reset_runtime_data(&framework, true).await.unwrap();
        assert!(report.dry_run);
        assert_eq!(
            framework.users().get(&user_id).await.unwrap().username,
            "bob"
        );
        assert!(
            framework
                .storage()
                .get_kv("custom:dry-run")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn create_migration_file_uses_backend_directory_and_sanitized_name() {
        let dir = tempdir().unwrap();
        let old_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let outcome = async {
            let mut config = AppConfig::default();
            config.database.url = "sqlite::memory:".to_string();
            let report = create_migration_file(&config, "Add Audit Table!")
                .await
                .unwrap();
            assert_eq!(report.backend, "sqlite");
            assert!(
                report
                    .path
                    .starts_with(Path::new("migrations").join("sqlite"))
            );
            assert!(
                report
                    .path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .contains("add_audit_table")
            );
        }
        .await;

        std::env::set_current_dir(old_dir).unwrap();
        outcome
    }

    #[tokio::test]
    async fn backup_dry_run_does_not_write_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("shouldnt_exist.json");
        let framework = create_framework().await;
        let report = backup_to_file(&framework, &path, true).await.unwrap();
        assert!(report.dry_run);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn backup_empty_framework() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.json");
        let framework = create_framework().await;
        let report = backup_to_file(&framework, &path, false).await.unwrap();
        assert_eq!(report.manifest.user_count, 0);
        assert_eq!(report.manifest.token_count, 0);
        assert_eq!(report.manifest.session_count, 0);
        assert!(path.exists());
    }

    #[tokio::test]
    async fn reset_clears_all_data() {
        let framework = create_framework().await;
        framework
            .users()
            .register("clear_me", "clear@example.com", "Password123!")
            .await
            .unwrap();
        framework
            .storage()
            .store_kv("custom:keep", b"nope", None)
            .await
            .unwrap();

        let report = reset_runtime_data(&framework, false).await.unwrap();
        assert!(!report.dry_run);
        assert!(report.users_deleted >= 1);
        assert!(
            framework
                .users()
                .list_with_query(UserListQuery::new())
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            framework
                .storage()
                .get_kv("custom:keep")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn restore_nonexistent_file_fails() {
        let framework = create_framework().await;
        let result = restore_from_file(&framework, "/definitely/not/real.json", false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn backup_manifest_has_checksum() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("checksummed.json");
        let framework = create_framework().await;
        framework
            .users()
            .register("chk_user", "chk@example.com", "Password123!")
            .await
            .unwrap();
        let report = backup_to_file(&framework, &path, false).await.unwrap();
        assert!(!report.manifest.checksum_sha256.is_empty());
        assert_eq!(report.manifest.format_version, SNAPSHOT_FORMAT_VERSION);
    }
}
