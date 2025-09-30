//! Storage adapters for role-system integration
//!
//! This module provides storage adapters that integrate role-system with
//! AuthFramework's existing storage infrastructure.

use async_trait::async_trait;
// use role_system::{
//     AuditEntry, Permission, Role, RoleAssignment, RoleStorage,
//     storage::{StorageError, StorageResult},
// };
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Database-backed storage adapter for role-system
pub struct DatabaseStorage {
    /// Database connection (would be actual DB connection in real implementation)
    connection: Arc<dyn DatabaseConnection>,
    /// In-memory cache for frequently accessed data
    role_cache: Arc<RwLock<HashMap<String, Role>>>,
    permission_cache: Arc<RwLock<HashMap<String, Permission>>>,
    /// Cache TTL in seconds
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
    async fn begin_transaction(&self) -> Result<Transaction, DatabaseError>;
}

/// Database value trait for query parameters
pub trait DatabaseValue: Send + Sync {
    fn as_str(&self) -> Option<&str>;
    fn as_i64(&self) -> Option<i64>;
    fn as_bool(&self) -> Option<bool>;
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
#[derive(Debug, Clone)]
pub enum DatabaseColumnValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    Null,
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

/// Database transaction
#[async_trait]
pub trait Transaction: Send {
    async fn commit(self: Box<Self>) -> Result<(), DatabaseError>;
    async fn rollback(self: Box<Self>) -> Result<(), DatabaseError>;
    async fn execute_query(
        &mut self,
        query: &str,
        params: &[&dyn DatabaseValue],
    ) -> Result<QueryResult, DatabaseError>;
    async fn fetch_one(
        &mut self,
        query: &str,
        params: &[&dyn DatabaseValue],
    ) -> Result<Row, DatabaseError>;
    async fn fetch_all(
        &mut self,
        query: &str,
        params: &[&dyn DatabaseValue],
    ) -> Result<Vec<Row>, DatabaseError>;
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
        // Create roles table
        self.connection
            .execute_query(
                r#"
            CREATE TABLE IF NOT EXISTS roles (
                id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) NOT NULL UNIQUE,
                description TEXT,
                parent_id VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (parent_id) REFERENCES roles(id) ON DELETE SET NULL
            )
            "#,
                &[],
            )
            .await?;

        // Create permissions table
        self.connection
            .execute_query(
                r#"
            CREATE TABLE IF NOT EXISTS permissions (
                id VARCHAR(255) PRIMARY KEY,
                action VARCHAR(255) NOT NULL,
                resource VARCHAR(255) NOT NULL,
                conditions TEXT, -- JSON
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(action, resource)
            )
            "#,
                &[],
            )
            .await?;

        // Create role_permissions table
        self.connection
            .execute_query(
                r#"
            CREATE TABLE IF NOT EXISTS role_permissions (
                role_id VARCHAR(255),
                permission_id VARCHAR(255),
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                granted_by VARCHAR(255),
                PRIMARY KEY (role_id, permission_id),
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
            )
            "#,
                &[],
            )
            .await?;

        // Create user_roles table
        self.connection
            .execute_query(
                r#"
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id VARCHAR(255),
                role_id VARCHAR(255),
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                assigned_by VARCHAR(255),
                expires_at TIMESTAMP NULL,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
            )
            "#,
                &[],
            )
            .await?;

        // Create audit_log table
        self.connection
            .execute_query(
                r#"
            CREATE TABLE IF NOT EXISTS audit_log (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                user_id VARCHAR(255),
                action VARCHAR(255) NOT NULL,
                resource VARCHAR(255),
                result VARCHAR(50) NOT NULL,
                context TEXT, -- JSON
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_timestamp (user_id, timestamp),
                INDEX idx_action_timestamp (action, timestamp)
            )
            "#,
                &[],
            )
            .await?;

        info!("Database schema initialized successfully");
        Ok(())
    }

    /// Clear caches
    async fn clear_caches(&self) {
        let mut role_cache = self.role_cache.write().await;
        let mut permission_cache = self.permission_cache.write().await;
        role_cache.clear();
        permission_cache.clear();
        debug!("Cleared authorization caches");
    }
}

#[async_trait]
impl RoleStorage for DatabaseStorage {
    async fn create_role(&self, role: &Role) -> StorageResult<()> {
        let role_json =
            serde_json::to_string(role).map_err(|e| StorageError::Serialization(e.to_string()))?;

        let parent_id = role.parent.as_deref();

        self.connection
            .execute_query(
                "INSERT INTO roles (id, name, description, parent_id) VALUES (?, ?, ?, ?)",
                &[
                    &role.id,
                    &role.name,
                    &role.description.as_deref().unwrap_or(""),
                    &parent_id,
                ],
            )
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Clear cache to ensure consistency
        self.clear_caches().await;

        info!("Created role: {}", role.name);
        Ok(())
    }

    async fn update_role(&self, role: &Role) -> StorageResult<()> {
        let parent_id = role.parent.as_deref();

        self.connection.execute_query(
            "UPDATE roles SET name = ?, description = ?, parent_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            &[&role.name, &role.description.as_deref().unwrap_or(""), &parent_id, &role.id],
        ).await.map_err(|e| StorageError::Database(e.to_string()))?;

        // Update cache
        let mut cache = self.role_cache.write().await;
        cache.insert(role.id.clone(), role.clone());

        info!("Updated role: {}", role.name);
        Ok(())
    }

    async fn delete_role(&self, role_id: &str) -> StorageResult<()> {
        self.connection
            .execute_query("DELETE FROM roles WHERE id = ?", &[&role_id])
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Remove from cache
        let mut cache = self.role_cache.write().await;
        cache.remove(role_id);

        info!("Deleted role: {}", role_id);
        Ok(())
    }

    async fn get_role(&self, role_id: &str) -> StorageResult<Option<Role>> {
        // Check cache first
        {
            let cache = self.role_cache.read().await;
            if let Some(role) = cache.get(role_id) {
                debug!("Role cache hit: {}", role_id);
                return Ok(Some(role.clone()));
            }
        }

        // Fetch from database
        let row = match self
            .connection
            .fetch_one(
                "SELECT id, name, description, parent_id FROM roles WHERE id = ?",
                &[&role_id],
            )
            .await
        {
            Ok(row) => row,
            Err(DatabaseError::Query(_)) => return Ok(None), // Not found
            Err(e) => return Err(StorageError::Database(e.to_string())),
        };

        let role = self.row_to_role(row)?;

        // Update cache
        {
            let mut cache = self.role_cache.write().await;
            cache.insert(role_id.to_string(), role.clone());
        }

        Ok(Some(role))
    }

    async fn list_roles(&self) -> StorageResult<Vec<Role>> {
        let rows = self
            .connection
            .fetch_all(
                "SELECT id, name, description, parent_id FROM roles ORDER BY name",
                &[],
            )
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        let mut roles = Vec::new();
        for row in rows {
            roles.push(self.row_to_role(row)?);
        }

        debug!("Listed {} roles", roles.len());
        Ok(roles)
    }

    async fn create_permission(&self, permission: &Permission) -> StorageResult<()> {
        let conditions_json = permission
            .conditions
            .as_ref()
            .map(|c| serde_json::to_string(c))
            .transpose()
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        self.connection
            .execute_query(
                "INSERT INTO permissions (id, action, resource, conditions) VALUES (?, ?, ?, ?)",
                &[
                    &permission.id,
                    &permission.action,
                    &permission.resource,
                    &conditions_json.as_deref(),
                ],
            )
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Clear cache
        self.clear_caches().await;

        info!(
            "Created permission: {}:{}",
            permission.action, permission.resource
        );
        Ok(())
    }

    async fn get_permission(&self, permission_id: &str) -> StorageResult<Option<Permission>> {
        // Check cache first
        {
            let cache = self.permission_cache.read().await;
            if let Some(permission) = cache.get(permission_id) {
                debug!("Permission cache hit: {}", permission_id);
                return Ok(Some(permission.clone()));
            }
        }

        // Fetch from database
        let row = match self
            .connection
            .fetch_one(
                "SELECT id, action, resource, conditions FROM permissions WHERE id = ?",
                &[&permission_id],
            )
            .await
        {
            Ok(row) => row,
            Err(DatabaseError::Query(_)) => return Ok(None),
            Err(e) => return Err(StorageError::Database(e.to_string())),
        };

        let permission = self.row_to_permission(row)?;

        // Update cache
        {
            let mut cache = self.permission_cache.write().await;
            cache.insert(permission_id.to_string(), permission.clone());
        }

        Ok(Some(permission))
    }

    async fn assign_role(&self, assignment: &RoleAssignment) -> StorageResult<()> {
        self.connection.execute_query(
            "INSERT OR REPLACE INTO user_roles (user_id, role_id, assigned_by, expires_at) VALUES (?, ?, ?, ?)",
            &[&assignment.user_id, &assignment.role_id, &assignment.assigned_by.as_deref(), &assignment.expires_at.map(|t| t.timestamp())],
        ).await.map_err(|e| StorageError::Database(e.to_string()))?;

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
                &[&user_id, &role_id],
            )
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        info!("Revoked role {} from user {}", role_id, user_id);
        Ok(())
    }

    async fn get_user_roles(&self, user_id: &str) -> StorageResult<Vec<String>> {
        let rows = self.connection.fetch_all(
            "SELECT role_id FROM user_roles WHERE user_id = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)",
            &[&user_id],
        ).await.map_err(|e| StorageError::Database(e.to_string()))?;

        let mut role_ids = Vec::new();
        for row in rows {
            if let Some(DatabaseColumnValue::String(role_id)) = row.columns.get("role_id") {
                role_ids.push(role_id.clone());
            }
        }

        debug!("User {} has {} roles", user_id, role_ids.len());
        Ok(role_ids)
    }

    async fn get_role_permissions(&self, role_id: &str) -> StorageResult<Vec<String>> {
        let rows = self
            .connection
            .fetch_all(
                "SELECT permission_id FROM role_permissions WHERE role_id = ?",
                &[&role_id],
            )
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        let mut permission_ids = Vec::new();
        for row in rows {
            if let Some(DatabaseColumnValue::String(permission_id)) =
                row.columns.get("permission_id")
            {
                permission_ids.push(permission_id.clone());
            }
        }

        debug!("Role {} has {} permissions", role_id, permission_ids.len());
        Ok(permission_ids)
    }

    async fn log_audit_entry(&self, entry: &AuditEntry) -> StorageResult<()> {
        let context_json = serde_json::to_string(&entry.context)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        self.connection.execute_query(
            "INSERT INTO audit_log (user_id, action, resource, result, context) VALUES (?, ?, ?, ?, ?)",
            &[&entry.user_id.as_deref(), &entry.action, &entry.resource.as_deref(), &entry.result, &context_json],
        ).await.map_err(|e| StorageError::Database(e.to_string()))?;

        debug!(
            "Logged audit entry for user {:?}: {} on {:?}",
            entry.user_id, entry.action, entry.resource
        );
        Ok(())
    }
}

impl DatabaseStorage {
    /// Convert database row to Role
    fn row_to_role(&self, row: Row) -> StorageResult<Role> {
        let id = self.get_string_column(&row, "id")?;
        let name = self.get_string_column(&row, "name")?;
        let description = self.get_optional_string_column(&row, "description");
        let parent = self.get_optional_string_column(&row, "parent_id");

        Ok(Role {
            id,
            name,
            description,
            parent,
            permissions: Vec::new(), // Will be loaded separately if needed
        })
    }

    /// Convert database row to Permission
    fn row_to_permission(&self, row: Row) -> StorageResult<Permission> {
        let id = self.get_string_column(&row, "id")?;
        let action = self.get_string_column(&row, "action")?;
        let resource = self.get_string_column(&row, "resource")?;

        let conditions =
            if let Some(conditions_str) = self.get_optional_string_column(&row, "conditions") {
                Some(
                    serde_json::from_str(&conditions_str)
                        .map_err(|e| StorageError::Serialization(e.to_string()))?,
                )
            } else {
                None
            };

        Ok(Permission {
            id,
            action,
            resource,
            conditions,
        })
    }

    /// Get string column from row
    fn get_string_column(&self, row: &Row, column: &str) -> StorageResult<String> {
        match row.columns.get(column) {
            Some(DatabaseColumnValue::String(value)) => Ok(value.clone()),
            Some(DatabaseColumnValue::Null) => {
                Err(StorageError::Database(format!("Column {} is null", column)))
            }
            Some(_) => Err(StorageError::Database(format!(
                "Column {} is not a string",
                column
            ))),
            None => Err(StorageError::Database(format!(
                "Column {} not found",
                column
            ))),
        }
    }

    /// Get optional string column from row
    fn get_optional_string_column(&self, row: &Row, column: &str) -> Option<String> {
        match row.columns.get(column) {
            Some(DatabaseColumnValue::String(value)) => Some(value.clone()),
            _ => None,
        }
    }
}

/// In-memory storage adapter for testing and development
pub struct MemoryStorage {
    roles: Arc<RwLock<HashMap<String, Role>>>,
    permissions: Arc<RwLock<HashMap<String, Permission>>>,
    user_roles: Arc<RwLock<HashMap<String, Vec<String>>>>,
    role_permissions: Arc<RwLock<HashMap<String, Vec<String>>>>,
    audit_log: Arc<RwLock<Vec<AuditEntry>>>,
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStorage {
    /// Create new memory storage
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
        let mut roles = self.roles.write().await;
        let mut permissions = self.permissions.write().await;
        let mut user_roles = self.user_roles.write().await;
        let mut role_permissions = self.role_permissions.write().await;
        let mut audit_log = self.audit_log.write().await;

        roles.clear();
        permissions.clear();
        user_roles.clear();
        role_permissions.clear();
        audit_log.clear();
    }
}

#[async_trait]
impl RoleStorage for MemoryStorage {
    async fn create_role(&self, role: &Role) -> StorageResult<()> {
        let mut roles = self.roles.write().await;
        roles.insert(role.id.clone(), role.clone());
        info!("Created role in memory: {}", role.name);
        Ok(())
    }

    async fn update_role(&self, role: &Role) -> StorageResult<()> {
        let mut roles = self.roles.write().await;
        roles.insert(role.id.clone(), role.clone());
        info!("Updated role in memory: {}", role.name);
        Ok(())
    }

    async fn delete_role(&self, role_id: &str) -> StorageResult<()> {
        let mut roles = self.roles.write().await;
        roles.remove(role_id);
        info!("Deleted role from memory: {}", role_id);
        Ok(())
    }

    async fn get_role(&self, role_id: &str) -> StorageResult<Option<Role>> {
        let roles = self.roles.read().await;
        Ok(roles.get(role_id).cloned())
    }

    async fn list_roles(&self) -> StorageResult<Vec<Role>> {
        let roles = self.roles.read().await;
        Ok(roles.values().cloned().collect())
    }

    async fn create_permission(&self, permission: &Permission) -> StorageResult<()> {
        let mut permissions = self.permissions.write().await;
        permissions.insert(permission.id.clone(), permission.clone());
        info!(
            "Created permission in memory: {}:{}",
            permission.action, permission.resource
        );
        Ok(())
    }

    async fn get_permission(&self, permission_id: &str) -> StorageResult<Option<Permission>> {
        let permissions = self.permissions.read().await;
        Ok(permissions.get(permission_id).cloned())
    }

    async fn assign_role(&self, assignment: &RoleAssignment) -> StorageResult<()> {
        let mut user_roles = self.user_roles.write().await;
        user_roles
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
        let mut user_roles = self.user_roles.write().await;
        if let Some(roles) = user_roles.get_mut(user_id) {
            roles.retain(|r| r != role_id);
        }
        info!("Revoked role from memory: {} from {}", role_id, user_id);
        Ok(())
    }

    async fn get_user_roles(&self, user_id: &str) -> StorageResult<Vec<String>> {
        let user_roles = self.user_roles.read().await;
        Ok(user_roles.get(user_id).cloned().unwrap_or_default())
    }

    async fn get_role_permissions(&self, role_id: &str) -> StorageResult<Vec<String>> {
        let role_permissions = self.role_permissions.read().await;
        Ok(role_permissions.get(role_id).cloned().unwrap_or_default())
    }

    async fn log_audit_entry(&self, entry: &AuditEntry) -> StorageResult<()> {
        let mut audit_log = self.audit_log.write().await;
        audit_log.push(entry.clone());
        debug!(
            "Logged audit entry in memory for user {:?}: {} on {:?}",
            entry.user_id, entry.action, entry.resource
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use role_system::{Permission, Role};

    #[tokio::test]
    async fn test_memory_storage_basic_operations() {
        let storage = MemoryStorage::new();

        // Test role creation
        let role = Role {
            id: "test_role".to_string(),
            name: "Test Role".to_string(),
            description: Some("A test role".to_string()),
            parent: None,
            permissions: Vec::new(),
        };

        storage.create_role(&role).await.unwrap();

        // Test role retrieval
        let retrieved = storage.get_role("test_role").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Role");

        // Test role listing
        let roles = storage.list_roles().await.unwrap();
        assert_eq!(roles.len(), 1);

        // Test role deletion
        storage.delete_role("test_role").await.unwrap();
        let retrieved = storage.get_role("test_role").await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_memory_storage_permissions() {
        let storage = MemoryStorage::new();

        let permission = Permission {
            id: "test_perm".to_string(),
            action: "read".to_string(),
            resource: "users".to_string(),
            conditions: None,
        };

        storage.create_permission(&permission).await.unwrap();

        let retrieved = storage.get_permission("test_perm").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().action, "read");
    }
}
