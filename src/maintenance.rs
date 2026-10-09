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
use crate::storage::encryption::StorageEncryption;
use crate::tokens::AuthToken;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

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
    /// Absolute expiry of the entry at backup time. `None` = the entry did
    /// not expire. Omitted from the file when `None`, so snapshots (and
    /// their checksums) written before this field existed stay valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// What restore should do with a KV entry, given its recorded expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreTtl {
    /// Store without an expiry.
    Forever,
    /// Store with this much lifetime left.
    Remaining(std::time::Duration),
    /// Expired between backup and restore: do not bring it back.
    Expired,
}

fn restore_ttl(expires_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> RestoreTtl {
    match expires_at {
        None => RestoreTtl::Forever,
        Some(expires_at) => match (expires_at - now).to_std() {
            Ok(remaining) if !remaining.is_zero() => RestoreTtl::Remaining(remaining),
            _ => RestoreTtl::Expired,
        },
    }
}

/// AAD binding a sealed snapshot to its purpose, so a storage-layer
/// envelope for some other record can't be replayed as a snapshot.
const SNAPSHOT_AAD: &[u8] = b"auth-framework:maintenance-snapshot:v1";

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

    if !storage.tracks_kv_ttl() {
        tracing::warn!(
            "This storage backend does not report KV TTLs: the snapshot cannot record them,              so every KV entry restored from it becomes permanent, including ones that were              meant to expire (one-time codes, rate-limit windows, expiring API keys)."
        );
    }

    let mut kv_keys = storage.list_kv_keys("").await?;
    kv_keys.sort();
    kv_keys.dedup();

    let mut kv_entries = Vec::with_capacity(kv_keys.len());
    for key in kv_keys {
        // The TTL is read BEFORE the value: an entry that expires in
        // between then yields a TTL and no value (skipped), never a value
        // whose expiry was lost and which restore would make permanent.
        let expires_at = match storage.get_kv_ttl(&key).await? {
            Some(remaining) => Some(
                Utc::now()
                    + chrono::Duration::from_std(remaining)
                        .map_err(|e| AuthError::internal(format!("Invalid KV TTL: {e}")))?,
            ),
            None => None,
        };
        if let Some(value) = storage.get_kv(&key).await? {
            kv_entries.push(SnapshotKvEntry {
                key,
                value_base64: BASE64_STANDARD.encode(value),
                expires_at,
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
    let encryption = snapshot_encryption(framework)?;
    backup_to_file_with(framework, output_path, dry_run, encryption.as_ref()).await
}

/// Which encryption (if any) protects snapshot files for `framework`.
///
/// A snapshot holds everything the live store does -- KV secrets, access
/// and refresh tokens, sessions, user emails -- and is usually handled
/// under weaker access control than the database. So whenever the
/// framework itself encrypts at rest (the default, for every backend that
/// persists), the whole snapshot file is sealed under the same storage
/// key. This also covers tokens and sessions, which `EncryptedStorage`
/// does not encrypt, so backing up the *stored* (already-encrypted) KV
/// form alone would still leave them readable. In-memory storage is
/// exempt, as it is for `EncryptedStorage`, and so is an explicit
/// `storage_encryption.enabled = false`. Fails closed if encryption is
/// expected but no key can be loaded.
///
/// The decision follows `config.storage`, like the storage factory does.
/// Storage handed in through `new_with_storage` / `replace_storage` /
/// `custom_storage` bypasses the factory, so a framework whose config still
/// says `Memory` but whose storage is persistent gets an UNSEALED snapshot.
fn snapshot_encryption(framework: &AuthFramework) -> Result<Option<StorageEncryption>> {
    let config = framework.config();
    if !config.storage_encryption.enabled || matches!(config.storage, StorageConfig::Memory) {
        tracing::warn!(
            "Maintenance snapshot is NOT encrypted (config.storage is Memory, or \
             storage_encryption.enabled = false): it holds tokens, sessions and KV \
             secrets in plaintext."
        );
        return Ok(None);
    }
    StorageEncryption::from_env().map(Some).map_err(|e| {
        AuthError::configuration(format!(
            "Snapshots are encrypted with the storage encryption key, but none could be \
             loaded: {e}. Configure AUTH_STORAGE_ENCRYPTION_KEY / \
             AUTH_STORAGE_ENCRYPTION_KEYS_FILE."
        ))
    })
}

async fn backup_to_file_with(
    framework: &AuthFramework,
    output_path: impl AsRef<Path>,
    dry_run: bool,
    encryption: Option<&StorageEncryption>,
) -> Result<BackupReport> {
    let output_path = output_path.as_ref().to_path_buf();
    let snapshot = collect_snapshot(framework).await?;

    if !dry_run {
        if let Some(parent) = output_path.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent).await?;
        }

        let mut data = serde_json::to_vec_pretty(&snapshot).map_err(|e| {
            AuthError::internal(format!("Failed to serialize maintenance snapshot: {e}"))
        })?;
        if let Some(encryption) = encryption {
            let sealed = encryption.encrypt_for_storage(&data, SNAPSHOT_AAD);
            data.zeroize();
            data = sealed?;
        }
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
    let encryption = snapshot_encryption(framework)?;
    restore_from_file_with(framework, input_path, dry_run, encryption.as_ref()).await
}

async fn restore_from_file_with(
    framework: &AuthFramework,
    input_path: impl AsRef<Path>,
    dry_run: bool,
    encryption: Option<&StorageEncryption>,
) -> Result<RestoreReport> {
    let input_path = input_path.as_ref().to_path_buf();
    let mut data = tokio::fs::read(&input_path).await?;
    if let Some(envelope) = StorageEncryption::parse_envelope(&data) {
        // A sealed snapshot: open it before anything is reset, so a wrong
        // or missing key leaves the live data untouched.
        let encryption = encryption.ok_or_else(|| {
            AuthError::validation(
                "Snapshot is encrypted but no storage encryption key is available to open it",
            )
        })?;
        // Snapshots were never written in format v0, so refuse it. A v1
        // snapshot (sealed by the release that introduced snapshot sealing,
        // before envelope v2) is deliberately still readable regardless of
        // `allow_legacy_v0`: it is authenticated under SNAPSHOT_AAD and the
        // storage key, and there is no migration tool for snapshot files.
        if envelope.v == 0 {
            return Err(AuthError::validation(
                "Snapshot uses an unsupported legacy encryption format",
            ));
        }
        data = encryption.decrypt(&envelope, SNAPSHOT_AAD).map_err(|e| {
            AuthError::validation(format!(
                "Failed to decrypt snapshot (wrong key or corrupted file): {e}"
            ))
        })?;
    } else if encryption.is_some() {
        // Sealing is the only thing that authenticates a snapshot (the
        // checksum is unkeyed and lives inside the file), so accepting an
        // unsealed one here would let anyone who can write the file inject
        // users, roles, tokens and secrets.
        return Err(AuthError::validation(
            "Snapshot is not encrypted but storage encryption is enabled; refusing to restore it",
        ));
    }
    let snapshot: MaintenanceSnapshot = serde_json::from_slice(&data)
        .map_err(|e| AuthError::validation(format!("Failed to parse maintenance snapshot: {e}")))?;
    validate_snapshot(&snapshot)?;

    // Decode every KV entry BEFORE anything is reset, so a bad entry
    // cannot leave the store wiped and half-restored.
    let now = Utc::now();
    let mut kv_to_restore = Vec::with_capacity(snapshot.kv_entries.len());
    for entry in &snapshot.kv_entries {
        let value = BASE64_STANDARD.decode(&entry.value_base64).map_err(|e| {
            AuthError::validation(format!(
                "Snapshot KV entry '{}' is not valid base64: {e}",
                entry.key
            ))
        })?;
        let ttl = match restore_ttl(entry.expires_at, now) {
            RestoreTtl::Forever => None,
            RestoreTtl::Remaining(remaining) => Some(remaining),
            RestoreTtl::Expired => continue,
        };
        kv_to_restore.push((entry.key.as_str(), value, ttl));
    }

    let reset_report = reset_runtime_data(framework, dry_run).await?;

    if !dry_run {
        let storage = framework.storage();

        for (key, value, ttl) in &kv_to_restore {
            storage.store_kv(key, value, *ttl).await?;
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

    const CANARY: &[u8] = b"totp-seed-PLAINTEXT-CANARY-7f3a91";

    async fn framework_with_secrets() -> (AuthFramework, String) {
        let framework = create_framework().await;
        let user_id = framework
            .users()
            .register("alice", "alice@example.com", "Password123!")
            .await
            .unwrap();
        framework
            .tokens()
            .create(&user_id, &["read"], "jwt", None)
            .await
            .unwrap();
        framework
            .storage()
            .store_kv("totp:alice", CANARY, None)
            .await
            .unwrap();
        let access_token = framework
            .tokens()
            .list_for_user(&user_id)
            .await
            .unwrap()
            .remove(0)
            .access_token;
        (framework, access_token)
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// #121: a backup written under storage encryption must not hold any
    /// recoverable plaintext -- not the KV secret (raw or base64), not a
    /// stored access token, not user PII.
    #[tokio::test]
    async fn encrypted_backup_contains_no_plaintext() {
        let (framework, access_token) = framework_with_secrets().await;
        let dir = tempdir().unwrap();

        // Positive control: an unencrypted backup of the SAME state does
        // expose each needle, so the scan below can see them.
        let plain_path = dir.path().join("plain.json");
        backup_to_file_with(&framework, &plain_path, false, None)
            .await
            .unwrap();
        let plain = tokio::fs::read(&plain_path).await.unwrap();
        let canary_b64 = BASE64_STANDARD.encode(CANARY);
        assert!(contains(&plain, canary_b64.as_bytes()));
        assert!(contains(&plain, access_token.as_bytes()));
        assert!(contains(&plain, b"alice@example.com"));

        let encryption = StorageEncryption::new_random();
        let enc_path = dir.path().join("encrypted.json");
        backup_to_file_with(&framework, &enc_path, false, Some(&encryption))
            .await
            .unwrap();
        let bytes = tokio::fs::read(&enc_path).await.unwrap();
        assert!(!contains(&bytes, CANARY), "raw KV secret in backup");
        assert!(
            !contains(&bytes, canary_b64.as_bytes()),
            "base64 KV secret in backup"
        );
        assert!(
            !contains(&bytes, access_token.as_bytes()),
            "access token in backup"
        );
        assert!(!contains(&bytes, b"alice@example.com"), "PII in backup");
    }

    #[tokio::test]
    async fn encrypted_backup_roundtrips_and_rejects_wrong_or_missing_key() {
        let (framework, _) = framework_with_secrets().await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("encrypted.json");
        let encryption = StorageEncryption::new_random();
        backup_to_file_with(&framework, &path, false, Some(&encryption))
            .await
            .unwrap();

        // A different key, and no key at all, must both refuse -- and
        // must refuse BEFORE wiping the live data.
        let other = StorageEncryption::new_random();
        assert!(
            restore_from_file_with(&framework, &path, false, Some(&other))
                .await
                .is_err()
        );
        assert!(
            restore_from_file_with(&framework, &path, false, None)
                .await
                .is_err()
        );
        assert_eq!(
            framework
                .storage()
                .get_kv("totp:alice")
                .await
                .unwrap()
                .as_deref(),
            Some(CANARY),
            "a refused restore must not have reset the live data"
        );

        reset_runtime_data(&framework, false).await.unwrap();
        assert!(
            framework
                .storage()
                .get_kv("totp:alice")
                .await
                .unwrap()
                .is_none()
        );
        restore_from_file_with(&framework, &path, false, Some(&encryption))
            .await
            .unwrap();
        assert_eq!(
            framework
                .storage()
                .get_kv("totp:alice")
                .await
                .unwrap()
                .as_deref(),
            Some(CANARY)
        );
    }

    /// With sealing expected, an unsealed snapshot is refused (it would
    /// otherwise let anyone who can write the file inject state), and the
    /// refusal happens before anything is reset.
    #[tokio::test]
    async fn restore_refuses_an_unsealed_snapshot_when_sealing_is_expected() {
        let (framework, _) = framework_with_secrets().await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("plain.json");
        backup_to_file_with(&framework, &path, false, None)
            .await
            .unwrap();

        let encryption = StorageEncryption::new_random();
        assert!(
            restore_from_file_with(&framework, &path, false, Some(&encryption))
                .await
                .is_err()
        );
        assert!(
            framework
                .storage()
                .get_kv("totp:alice")
                .await
                .unwrap()
                .is_some(),
            "a refused restore must not have reset the live data"
        );
        // Plaintext snapshots still restore where no sealing is in force.
        restore_from_file_with(&framework, &path, false, None)
            .await
            .unwrap();
    }

    /// A corrupt KV entry must be caught before the reset wipes anything.
    #[tokio::test]
    async fn restore_with_a_corrupt_kv_entry_leaves_live_data_untouched() {
        let (framework, _) = framework_with_secrets().await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("snapshot.json");
        let mut snapshot = collect_snapshot(&framework).await.unwrap();
        snapshot.kv_entries[0].value_base64 = "!!not base64!!".to_string();
        snapshot.manifest.checksum_sha256 = checksum_snapshot(
            &snapshot.users,
            &snapshot.roles,
            &snapshot.tokens,
            &snapshot.sessions,
            &snapshot.kv_entries,
        )
        .unwrap();
        tokio::fs::write(&path, serde_json::to_vec(&snapshot).unwrap())
            .await
            .unwrap();

        assert!(
            restore_from_file_with(&framework, &path, false, None)
                .await
                .is_err()
        );
        assert_eq!(
            framework
                .users()
                .list_with_query(UserListQuery::new())
                .await
                .unwrap()
                .len(),
            1,
            "a refused restore must not have reset the live data"
        );
    }

    /// #121: restore must not turn an expiring entry into a permanent one.
    #[tokio::test]
    async fn backup_restore_preserves_kv_ttl() {
        let framework = create_framework().await;
        let storage = framework.storage();
        storage
            .store_kv("otp:code", b"123456", Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        storage.store_kv("keep:forever", b"x", None).await.unwrap();
        assert!(
            storage.get_kv_ttl("otp:code").await.unwrap().is_some(),
            "precondition: the backend must report the TTL it was given"
        );

        let dir = tempdir().unwrap();
        let path = dir.path().join("snapshot.json");
        backup_to_file_with(&framework, &path, false, None)
            .await
            .unwrap();
        reset_runtime_data(&framework, false).await.unwrap();
        restore_from_file_with(&framework, &path, false, None)
            .await
            .unwrap();

        let ttl = storage.get_kv_ttl("otp:code").await.unwrap().unwrap();
        assert!(
            ttl > Duration::from_secs(3500) && ttl <= Duration::from_secs(3600),
            "restored TTL was {ttl:?}"
        );
        assert_eq!(storage.get_kv_ttl("keep:forever").await.unwrap(), None);
        assert!(storage.get_kv("keep:forever").await.unwrap().is_some());
    }

    #[test]
    fn restore_ttl_maps_expiry_to_action() {
        let now = Utc::now();
        assert_eq!(restore_ttl(None, now), RestoreTtl::Forever);
        assert_eq!(
            restore_ttl(Some(now + chrono::Duration::seconds(90)), now),
            RestoreTtl::Remaining(Duration::from_secs(90))
        );
        assert_eq!(
            restore_ttl(Some(now - chrono::Duration::seconds(1)), now),
            RestoreTtl::Expired
        );
        assert_eq!(restore_ttl(Some(now), now), RestoreTtl::Expired);
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
