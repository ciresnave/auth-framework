//! Storage adapters for role-system integration
//!
//! This module provides storage adapters that integrate role-system with
//! AuthFramework's existing storage infrastructure. It defines its own
//! serializable types (`StoredRole`, `StoredPermission`) for persistence,
//! with conversions to/from the `role_system` crate's types.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

// ── Storage-layer error types ────────────────────────────────────────────────

/// Error type for storage operations
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Not found: {0}")]
    NotFound(String),
}

/// Result alias for storage operations
pub type StorageResult<T> = Result<T, StorageError>;

// ── Serializable storage types (decoupled from role_system's private fields) ─

/// A serializable role representation for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRole {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<StoredPermission>,
}

/// A serializable permission representation for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPermission {
    pub action: String,
    pub resource: String,
    pub instance: Option<String>,
}

/// A role-to-user assignment record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub user_id: String,
    pub role_id: String,
    pub assigned_by: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// An audit log entry for authorization events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub user_id: Option<String>,
    pub action: String,
    pub resource: Option<String>,
    pub result: String,
    pub context: HashMap<String, String>,
}

// ── Conversions between storage types and role_system types ──────────────────

impl StoredRole {
    /// Convert to a `role_system::Role` (for use with the role-system engine)
    pub fn to_role_system(&self) -> role_system::Role {
        let mut role = role_system::Role::with_id(&self.id, &self.name);
        if let Some(ref desc) = self.description {
            role = role.with_description(desc);
        }
        for perm in &self.permissions {
            role = role.add_permission(perm.to_role_system());
        }
        role
    }

    /// Create from a `role_system::Role`
    pub fn from_role_system(role: &role_system::Role) -> Self {
        Self {
            id: role.id().to_string(),
            name: role.name().to_string(),
            description: role.description().map(|s| s.to_string()),
            permissions: role
                .permissions()
                .permissions()
                .iter()
                .map(StoredPermission::from_role_system)
                .collect(),
        }
    }
}

impl StoredPermission {
    /// Convert to a `role_system::Permission`
    pub fn to_role_system(&self) -> role_system::Permission {
        if let Some(ref instance) = self.instance {
            role_system::Permission::with_instance(&self.action, &self.resource, instance)
        } else {
            role_system::Permission::new(&self.action, &self.resource)
        }
    }

    /// Create from a `role_system::Permission`
    pub fn from_role_system(perm: &role_system::Permission) -> Self {
        Self {
            action: perm.action().to_string(),
            resource: perm.resource_type().to_string(),
            instance: perm.instance().map(|s| s.to_string()),
        }
    }
}

// ── Async storage trait ─────────────────────────────────────────────────────

/// Async storage trait for persisting RBAC data (roles, permissions, assignments, audit)
#[async_trait]
pub trait RoleStorage: Send + Sync {
    async fn create_role(&self, role: &StoredRole) -> StorageResult<()>;
    async fn update_role(&self, role: &StoredRole) -> StorageResult<()>;
    async fn delete_role(&self, role_id: &str) -> StorageResult<()>;
    async fn get_role(&self, role_id: &str) -> StorageResult<Option<StoredRole>>;
    async fn list_roles(&self) -> StorageResult<Vec<StoredRole>>;

    async fn store_permission(&self, id: &str, permission: &StoredPermission) -> StorageResult<()>;
    async fn get_permission(&self, permission_id: &str) -> StorageResult<Option<StoredPermission>>;

    async fn assign_role(&self, assignment: &RoleAssignment) -> StorageResult<()>;
    async fn revoke_role(&self, user_id: &str, role_id: &str) -> StorageResult<()>;
    async fn get_user_roles(&self, user_id: &str) -> StorageResult<Vec<String>>;
    async fn get_role_permissions(&self, role_id: &str) -> StorageResult<Vec<String>>;

    async fn log_audit_entry(&self, entry: &AuditEntry) -> StorageResult<()>;
}

// ── Database abstractions ───────────────────────────────────────────────────

/// Database-backed storage adapter for role-system
pub struct DatabaseStorage {
    connection: Arc<dyn DatabaseConnection>,
    role_cache: Arc<RwLock<HashMap<String, StoredRole>>>,
    permission_cache: Arc<RwLock<HashMap<String, StoredPermission>>>,
    cache_ttl: u64,
}

/// Database connection trait (abstraction over actual database)
#[async_trait]
pub trait DatabaseConnection: Send + Sync {
    async fn execute_query(
        &self,
        query: &str,
        params: &[&dyn DatabaseValue],
    ) -> Result<QueryResult, DatabaseError>;
    async fn fetch_one(
        &self,
        query: &str,
        params: &[&dyn DatabaseValue],
    ) -> Result<Row, DatabaseError>;
    async fn fetch_all(
        &self,
        query: &str,
        params: &[&dyn DatabaseValue],
    ) -> Result<Vec<Row>, DatabaseError>;
}

/// Database value trait for query parameters
pub trait DatabaseValue: Send + Sync {
    fn as_str(&self) -> Option<&str>;
    fn as_i64(&self) -> Option<i64>;
    fn as_bool(&self) -> Option<bool>;
}

impl DatabaseValue for String {
    fn as_str(&self) -> Option<&str> {
        Some(self.as_ref())
    }
    fn as_i64(&self) -> Option<i64> {
        None
    }
    fn as_bool(&self) -> Option<bool> {
        None
    }
}

impl DatabaseValue for &str {
    fn as_str(&self) -> Option<&str> {
        Some(self)
    }
    fn as_i64(&self) -> Option<i64> {
        None
    }
    fn as_bool(&self) -> Option<bool> {
        None
    }
}

impl DatabaseValue for Option<&str> {
    fn as_str(&self) -> Option<&str> {
        *self
    }
    fn as_i64(&self) -> Option<i64> {
        None
    }
    fn as_bool(&self) -> Option<bool> {
        None
    }
}

impl DatabaseValue for i64 {
    fn as_str(&self) -> Option<&str> {
        None
    }
    fn as_i64(&self) -> Option<i64> {
        Some(*self)
    }
    fn as_bool(&self) -> Option<bool> {
        None
    }
}

impl DatabaseValue for bool {
    fn as_str(&self) -> Option<&str> {
        None
    }
    fn as_i64(&self) -> Option<i64> {
        None
    }
    fn as_bool(&self) -> Option<bool> {
        Some(*self)
    }
}

/// Database query result
#[derive(Debug)]
pub struct QueryResult {
    pub rows_affected: u64,
}

/// Database row
#[derive(Debug)]
pub struct Row {
    pub columns: HashMap<String, DatabaseColumnValue>,
}

/// Database column value
#[derive(Clone)]
pub enum DatabaseColumnValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    Null,
}

impl std::fmt::Debug for DatabaseColumnValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // A column can hold anything, including a credential.
            Self::String(v) => f
                .debug_tuple("String")
                .field(&crate::utils::redact::redacted(v))
                .finish(),
            Self::Integer(v) => f.debug_tuple("Integer").field(v).finish(),
            Self::Boolean(v) => f.debug_tuple("Boolean").field(v).finish(),
            Self::Null => f.write_str("Null"),
        }
    }
}

/// Database error
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Query error: {0}")]
    Query(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl DatabaseStorage {
    /// Create new database storage adapter
    pub fn new(connection: Arc<dyn DatabaseConnection>) -> Self {
        Self {
            connection,
            role_cache: Arc::new(RwLock::new(HashMap::new())),
            permission_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: 300, // 5 minutes
        }
    }

    /// Set cache TTL
    pub fn with_cache_ttl(mut self, ttl_seconds: u64) -> Self {
        self.cache_ttl = ttl_seconds;
        self
    }

    /// Initialize database schema
    pub async fn initialize_schema(&self) -> Result<(), DatabaseError> {
        self.connection
            .execute_query(
                r#"CREATE TABLE IF NOT EXISTS roles (
                    id VARCHAR(255) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL UNIQUE,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )"#,
                &[],
            )
            .await?;

        self.connection
            .execute_query(
                r#"CREATE TABLE IF NOT EXISTS permissions (
                    id VARCHAR(255) PRIMARY KEY,
                    action VARCHAR(255) NOT NULL,
                    resource VARCHAR(255) NOT NULL,
                    instance VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(action, resource)
                )"#,
                &[],
            )
            .await?;

        self.connection
            .execute_query(
                r#"CREATE TABLE IF NOT EXISTS role_permissions (
                    role_id VARCHAR(255),
                    permission_id VARCHAR(255),
                    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (role_id, permission_id),
                    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
                )"#,
                &[],
            )
            .await?;

        self.connection
            .execute_query(
                r#"CREATE TABLE IF NOT EXISTS user_roles (
                    user_id VARCHAR(255),
                    role_id VARCHAR(255),
                    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    assigned_by VARCHAR(255),
                    expires_at TIMESTAMP NULL,
                    PRIMARY KEY (user_id, role_id),
                    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
                )"#,
                &[],
            )
            .await?;

        self.connection
            .execute_query(
                r#"CREATE TABLE IF NOT EXISTS audit_log (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    user_id VARCHAR(255),
                    action VARCHAR(255) NOT NULL,
                    resource VARCHAR(255),
                    result VARCHAR(50) NOT NULL,
                    context TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )"#,
                &[],
            )
            .await?;

        info!("Database schema initialized successfully");
        Ok(())
    }

    /// Clear caches
    async fn clear_caches(&self) {
        self.role_cache.write().await.clear();
        self.permission_cache.write().await.clear();
        debug!("Cleared authorization caches");
    }

    fn row_to_stored_role(&self, row: &Row) -> StorageResult<StoredRole> {
        let id = self.get_string_column(row, "id")?;
        let name = self.get_string_column(row, "name")?;
        let description = self.get_optional_string_column(row, "description");
        Ok(StoredRole {
            id,
            name,
            description,
            permissions: Vec::new(), // loaded via role_permissions join
        })
    }

    fn row_to_stored_permission(&self, row: &Row) -> StorageResult<StoredPermission> {
        let action = self.get_string_column(row, "action")?;
        let resource = self.get_string_column(row, "resource")?;
        let instance = self.get_optional_string_column(row, "instance");
        Ok(StoredPermission {
            action,
            resource,
            instance,
        })
    }

    fn get_string_column(&self, row: &Row, column: &str) -> StorageResult<String> {
        match row.columns.get(column) {
            Some(DatabaseColumnValue::String(value)) => Ok(value.clone()),
            Some(DatabaseColumnValue::Null) => {
                Err(StorageError::Database(format!("Column {column} is null")))
            }
            Some(_) => Err(StorageError::Database(format!(
                "Column {column} is not a string"
            ))),
            None => Err(StorageError::Database(format!("Column {column} not found"))),
        }
    }

    fn get_optional_string_column(&self, row: &Row, column: &str) -> Option<String> {
        match row.columns.get(column) {
            Some(DatabaseColumnValue::String(value)) => Some(value.clone()),
            _ => None,
        }
    }
}

#[async_trait]
impl RoleStorage for DatabaseStorage {
    async fn create_role(&self, role: &StoredRole) -> StorageResult<()> {
        self.connection
            .execute_query(
                "INSERT INTO roles (id, name, description) VALUES (?, ?, ?)",
                &[
                    &role.id as &dyn DatabaseValue,
                    &role.name as &dyn DatabaseValue,
                    &role.description.as_deref().unwrap_or("") as &dyn DatabaseValue,
                ],
            )
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.clear_caches().await;
        info!("Created role: {}", role.name);
        Ok(())
    }

    async fn update_role(&self, role: &StoredRole) -> StorageResult<()> {
        self.connection
            .execute_query(
                "UPDATE roles SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                &[
                    &role.name as &dyn DatabaseValue,
                    &role.description.as_deref().unwrap_or("") as &dyn DatabaseValue,
                    &role.id as &dyn DatabaseValue,
                ],
            )
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.role_cache
            .write()
            .await
            .insert(role.id.clone(), role.clone());
        info!("Updated role: {}", role.name);
        Ok(())
    }

    async fn delete_role(&self, role_id: &str) -> StorageResult<()> {
        self.connection
            .execute_query(
                "DELETE FROM roles WHERE id = ?",
                &[&role_id as &dyn DatabaseValue],
            )
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.role_cache.write().await.remove(role_id);
        info!("Deleted role: {}", role_id);
        Ok(())
    }

    async fn get_role(&self, role_id: &str) -> StorageResult<Option<StoredRole>> {
        {
            let cache = self.role_cache.read().await;
            if let Some(role) = cache.get(role_id) {
                return Ok(Some(role.clone()));
            }
        }
        let row = match self
            .connection
            .fetch_one(
                "SELECT id, name, description FROM roles WHERE id = ?",
                &[&role_id as &dyn DatabaseValue],
            )
            .await
        {
            Ok(row) => row,
            Err(DatabaseError::Query(_)) => return Ok(None),
            Err(e) => return Err(StorageError::Database(e.to_string())),
        };
        let role = self.row_to_stored_role(&row)?;
        self.role_cache
            .write()
            .await
            .insert(role_id.to_string(), role.clone());
        Ok(Some(role))
    }

    async fn list_roles(&self) -> StorageResult<Vec<StoredRole>> {
        let rows = self
            .connection
            .fetch_all("SELECT id, name, description FROM roles ORDER BY name", &[])
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        rows.iter().map(|r| self.row_to_stored_role(r)).collect()
    }

    async fn store_permission(&self, id: &str, permission: &StoredPermission) -> StorageResult<()> {
        self.connection
            .execute_query(
                "INSERT INTO permissions (id, action, resource, instance) VALUES (?, ?, ?, ?)",
                &[
                    &id as &dyn DatabaseValue,
                    &permission.action as &dyn DatabaseValue,
                    &permission.resource as &dyn DatabaseValue,
                    &permission.instance.as_deref() as &dyn DatabaseValue,
                ],
            )
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.permission_cache
            .write()
            .await
            .insert(id.to_string(), permission.clone());
        info!(
            "Created permission: {}:{}",
            permission.action, permission.resource
        );
        Ok(())
    }

    async fn get_permission(&self, permission_id: &str) -> StorageResult<Option<StoredPermission>> {
        {
            let cache = self.permission_cache.read().await;
            if let Some(p) = cache.get(permission_id) {
                return Ok(Some(p.clone()));
            }
        }
        let row = match self
            .connection
            .fetch_one(
                "SELECT action, resource, instance FROM permissions WHERE id = ?",
                &[&permission_id as &dyn DatabaseValue],
            )
            .await
        {
            Ok(row) => row,
            Err(DatabaseError::Query(_)) => return Ok(None),
            Err(e) => return Err(StorageError::Database(e.to_string())),
        };
        let perm = self.row_to_stored_permission(&row)?;
        self.permission_cache
            .write()
            .await
            .insert(permission_id.to_string(), perm.clone());
        Ok(Some(perm))
    }

    async fn assign_role(&self, assignment: &RoleAssignment) -> StorageResult<()> {
        self.connection
            .execute_query(
                "INSERT OR REPLACE INTO user_roles (user_id, role_id, assigned_by) VALUES (?, ?, ?)",
                &[
                    &assignment.user_id as &dyn DatabaseValue,
                    &assignment.role_id as &dyn DatabaseValue,
                    &assignment.assigned_by.as_deref() as &dyn DatabaseValue,
                ],
            )
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        info!(
            "Assigned role {} to user {}",
            assignment.role_id, assignment.user_id
        );
        Ok(())
    }

    async fn revoke_role(&self, user_id: &str, role_id: &str) -> StorageResult<()> {
        self.connection
            .execute_query(
                "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?",
                &[
                    &user_id as &dyn DatabaseValue,
                    &role_id as &dyn DatabaseValue,
                ],
            )
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        info!("Revoked role {} from user {}", role_id, user_id);
        Ok(())
    }

    async fn get_user_roles(&self, user_id: &str) -> StorageResult<Vec<String>> {
        let rows = self
            .connection
            .fetch_all(
                "SELECT role_id FROM user_roles WHERE user_id = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)",
                &[&user_id as &dyn DatabaseValue],
            )
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(rows
            .iter()
            .filter_map(|r| match r.columns.get("role_id") {
                Some(DatabaseColumnValue::String(s)) => Some(s.clone()),
                _ => None,
            })
            .collect())
    }

    async fn get_role_permissions(&self, role_id: &str) -> StorageResult<Vec<String>> {
        let rows = self
            .connection
            .fetch_all(
                "SELECT permission_id FROM role_permissions WHERE role_id = ?",
                &[&role_id as &dyn DatabaseValue],
            )
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(rows
            .iter()
            .filter_map(|r| match r.columns.get("permission_id") {
                Some(DatabaseColumnValue::String(s)) => Some(s.clone()),
                _ => None,
            })
            .collect())
    }

    async fn log_audit_entry(&self, entry: &AuditEntry) -> StorageResult<()> {
        let context_json = serde_json::to_string(&entry.context)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.connection
            .execute_query(
                "INSERT INTO audit_log (user_id, action, resource, result, context) VALUES (?, ?, ?, ?, ?)",
                &[
                    &entry.user_id.as_deref() as &dyn DatabaseValue,
                    &entry.action as &dyn DatabaseValue,
                    &entry.resource.as_deref() as &dyn DatabaseValue,
                    &entry.result as &dyn DatabaseValue,
                    &context_json as &dyn DatabaseValue,
                ],
            )
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        debug!(
            "Logged audit entry for user {:?}: {}",
            entry.user_id, entry.action
        );
        Ok(())
    }
}

// ── In-memory storage (for testing and development) ─────────────────────────

/// In-memory storage adapter for testing and development
pub struct MemoryRbacStorage {
    roles: Arc<RwLock<HashMap<String, StoredRole>>>,
    permissions: Arc<RwLock<HashMap<String, StoredPermission>>>,
    user_roles: Arc<RwLock<HashMap<String, Vec<String>>>>,
    role_permissions: Arc<RwLock<HashMap<String, Vec<String>>>>,
    audit_log: Arc<RwLock<Vec<AuditEntry>>>,
}

impl Default for MemoryRbacStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryRbacStorage {
    pub fn new() -> Self {
        Self {
            roles: Arc::new(RwLock::new(HashMap::new())),
            permissions: Arc::new(RwLock::new(HashMap::new())),
            user_roles: Arc::new(RwLock::new(HashMap::new())),
            role_permissions: Arc::new(RwLock::new(HashMap::new())),
            audit_log: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Clear all data (useful for testing)
    pub async fn clear(&self) {
        self.roles.write().await.clear();
        self.permissions.write().await.clear();
        self.user_roles.write().await.clear();
        self.role_permissions.write().await.clear();
        self.audit_log.write().await.clear();
    }
}

#[async_trait]
impl RoleStorage for MemoryRbacStorage {
    async fn create_role(&self, role: &StoredRole) -> StorageResult<()> {
        self.roles
            .write()
            .await
            .insert(role.id.clone(), role.clone());
        info!("Created role in memory: {}", role.name);
        Ok(())
    }

    async fn update_role(&self, role: &StoredRole) -> StorageResult<()> {
        self.roles
            .write()
            .await
            .insert(role.id.clone(), role.clone());
        info!("Updated role in memory: {}", role.name);
        Ok(())
    }

    async fn delete_role(&self, role_id: &str) -> StorageResult<()> {
        self.roles.write().await.remove(role_id);
        info!("Deleted role from memory: {}", role_id);
        Ok(())
    }

    async fn get_role(&self, role_id: &str) -> StorageResult<Option<StoredRole>> {
        Ok(self.roles.read().await.get(role_id).cloned())
    }

    async fn list_roles(&self) -> StorageResult<Vec<StoredRole>> {
        Ok(self.roles.read().await.values().cloned().collect())
    }

    async fn store_permission(&self, id: &str, permission: &StoredPermission) -> StorageResult<()> {
        self.permissions
            .write()
            .await
            .insert(id.to_string(), permission.clone());
        info!(
            "Created permission in memory: {}:{}",
            permission.action, permission.resource
        );
        Ok(())
    }

    async fn get_permission(&self, permission_id: &str) -> StorageResult<Option<StoredPermission>> {
        Ok(self.permissions.read().await.get(permission_id).cloned())
    }

    async fn assign_role(&self, assignment: &RoleAssignment) -> StorageResult<()> {
        self.user_roles
            .write()
            .await
            .entry(assignment.user_id.clone())
            .or_default()
            .push(assignment.role_id.clone());
        info!(
            "Assigned role in memory: {} to {}",
            assignment.role_id, assignment.user_id
        );
        Ok(())
    }

    async fn revoke_role(&self, user_id: &str, role_id: &str) -> StorageResult<()> {
        if let Some(roles) = self.user_roles.write().await.get_mut(user_id) {
            roles.retain(|r| r != role_id);
        }
        info!("Revoked role from memory: {} from {}", role_id, user_id);
        Ok(())
    }

    async fn get_user_roles(&self, user_id: &str) -> StorageResult<Vec<String>> {
        Ok(self
            .user_roles
            .read()
            .await
            .get(user_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn get_role_permissions(&self, role_id: &str) -> StorageResult<Vec<String>> {
        Ok(self
            .role_permissions
            .read()
            .await
            .get(role_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn log_audit_entry(&self, entry: &AuditEntry) -> StorageResult<()> {
        self.audit_log.write().await.push(entry.clone());
        debug!(
            "Logged audit entry in memory for user {:?}: {}",
            entry.user_id, entry.action
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_storage_basic_operations() {
        let storage = MemoryRbacStorage::new();

        let role = StoredRole {
            id: "test_role".to_string(),
            name: "Test Role".to_string(),
            description: Some("A test role".to_string()),
            permissions: Vec::new(),
        };

        storage.create_role(&role).await.unwrap();

        let retrieved = storage.get_role("test_role").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Role");

        let roles = storage.list_roles().await.unwrap();
        assert_eq!(roles.len(), 1);

        storage.delete_role("test_role").await.unwrap();
        let retrieved = storage.get_role("test_role").await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_memory_storage_permissions() {
        let storage = MemoryRbacStorage::new();

        let permission = StoredPermission {
            action: "read".to_string(),
            resource: "users".to_string(),
            instance: None,
        };

        storage
            .store_permission("test_perm", &permission)
            .await
            .unwrap();

        let retrieved = storage.get_permission("test_perm").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().action, "read");
    }

    #[tokio::test]
    async fn test_memory_storage_role_assignment() {
        let storage = MemoryRbacStorage::new();

        let assignment = RoleAssignment {
            user_id: "user1".to_string(),
            role_id: "admin".to_string(),
            assigned_by: Some("system".to_string()),
            expires_at: None,
        };

        storage.assign_role(&assignment).await.unwrap();
        let user_roles = storage.get_user_roles("user1").await.unwrap();
        assert_eq!(user_roles, vec!["admin"]);

        storage.revoke_role("user1", "admin").await.unwrap();
        let user_roles = storage.get_user_roles("user1").await.unwrap();
        assert!(user_roles.is_empty());
    }

    #[tokio::test]
    async fn test_stored_role_conversion_roundtrip() {
        let stored = StoredRole {
            id: "role1".to_string(),
            name: "Admin".to_string(),
            description: Some("Administrator role".to_string()),
            permissions: vec![StoredPermission {
                action: "read".to_string(),
                resource: "users".to_string(),
                instance: None,
            }],
        };

        let rs_role = stored.to_role_system();
        assert_eq!(rs_role.id(), "role1");
        assert_eq!(rs_role.name(), "Admin");
        assert_eq!(rs_role.description(), Some("Administrator role"));

        let back = StoredRole::from_role_system(&rs_role);
        assert_eq!(back.id, "role1");
        assert_eq!(back.name, "Admin");
        assert_eq!(back.permissions.len(), 1);
        assert_eq!(back.permissions[0].action, "read");
    }

    #[tokio::test]
    async fn test_audit_logging() {
        let storage = MemoryRbacStorage::new();

        let entry = AuditEntry {
            user_id: Some("user1".to_string()),
            action: "login".to_string(),
            resource: Some("auth".to_string()),
            result: "success".to_string(),
            context: HashMap::from([("ip".to_string(), "127.0.0.1".to_string())]),
        };

        storage.log_audit_entry(&entry).await.unwrap();
        let log = storage.audit_log.read().await;
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].action, "login");
    }
}
