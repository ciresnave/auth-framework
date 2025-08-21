use crate::errors::Result;
use crate::storage::{AuthStorage, SessionData};
use crate::tokens::AuthToken;
use async_trait::async_trait;
/// MySQL storage backend implementation for auth-framework.
#[cfg(feature = "mysql-storage")]
use sqlx::MySqlPool;

/// MySQL storage backend
#[cfg(feature = "mysql-storage")]
pub struct MySqlStorage {
    pool: MySqlPool,
}

#[cfg(feature = "mysql-storage")]
impl MySqlStorage {
    /// Create a new MySQL storage instance
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "mysql-storage")]
#[async_trait]
impl AuthStorage for MySqlStorage {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO auth_tokens (
                token_id, user_id, access_token, refresh_token, token_type,
                expires_at, scopes, issued_at, auth_method, subject, issuer,
                client_id, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                access_token = VALUES(access_token),
                refresh_token = VALUES(refresh_token),
                expires_at = VALUES(expires_at)
            "#,
        )
        .bind(&token.token_id)
        .bind(&token.user_id)
        .bind(&token.access_token)
        .bind(&token.refresh_token)
        .bind(&token.token_type)
        .bind(token.expires_at)
        .bind(serde_json::to_string(&token.scopes).unwrap_or_default())
        .bind(token.issued_at)
        .bind(&token.auth_method)
        .bind(&token.subject)
        .bind(&token.issuer)
        .bind(&token.client_id)
        .bind(serde_json::to_string(&token.metadata).unwrap_or_default())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                format!("Failed to store token: {}", e),
            ))
        })?;
        Ok(())
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        use sqlx::Row;
        let row = sqlx::query(
            r#"
            SELECT token_id, user_id, access_token, refresh_token, token_type,
                   expires_at, scopes, issued_at, auth_method, subject, issuer,
                   client_id, metadata
            FROM auth_tokens WHERE token_id = ?
            "#,
        )
        .bind(token_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                format!("Failed to fetch token: {}", e),
            ))
        })?;

        if let Some(row) = row {
            let scopes: Vec<String> = row
                .try_get::<String, _>("scopes")
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            let metadata = row
                .try_get::<String, _>("metadata")
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            Ok(Some(AuthToken {
                token_id: row.try_get("token_id").unwrap_or_default(),
                user_id: row.try_get("user_id").unwrap_or_default(),
                access_token: row.try_get("access_token").unwrap_or_default(),
                refresh_token: row.try_get("refresh_token").ok(),
                token_type: row.try_get("token_type").ok(),
                expires_at: row.try_get("expires_at").unwrap(),
                scopes,
                issued_at: row.try_get("issued_at").unwrap(),
                auth_method: row.try_get("auth_method").unwrap_or_default(),
                subject: row.try_get("subject").ok(),
                issuer: row.try_get("issuer").ok(),
                client_id: row.try_get("client_id").ok(),
                user_profile: None,
                permissions: Vec::new(), // Note: Requires user_permissions table and additional query
                roles: Vec::new(),       // Note: Requires user_roles table and additional query
                metadata,
            }))
        } else {
            Ok(None)
        }
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        use sqlx::Row;
        let row = sqlx::query(
            r#"
            SELECT token_id, user_id, access_token, refresh_token, token_type,
                   expires_at, scopes, issued_at, auth_method, subject, issuer,
                   client_id, metadata
            FROM auth_tokens WHERE access_token = ?
            "#,
        )
        .bind(access_token)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                format!("Failed to fetch token: {}", e),
            ))
        })?;

        if let Some(row) = row {
            let scopes: Vec<String> = row
                .try_get::<String, _>("scopes")
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            let metadata = row
                .try_get::<String, _>("metadata")
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            Ok(Some(AuthToken {
                token_id: row.try_get("token_id").unwrap_or_default(),
                user_id: row.try_get("user_id").unwrap_or_default(),
                access_token: row.try_get("access_token").unwrap_or_default(),
                refresh_token: row.try_get("refresh_token").ok(),
                token_type: row.try_get("token_type").ok(),
                expires_at: row.try_get("expires_at").unwrap(),
                scopes,
                issued_at: row.try_get("issued_at").unwrap(),
                auth_method: row.try_get("auth_method").unwrap_or_default(),
                subject: row.try_get("subject").ok(),
                issuer: row.try_get("issuer").ok(),
                client_id: row.try_get("client_id").ok(),
                user_profile: None,
                permissions: Vec::new(), // Note: Requires user_permissions table and additional query
                roles: Vec::new(),       // Note: Requires user_roles table and additional query
                metadata,
            }))
        } else {
            Ok(None)
        }
    }

    async fn update_token(&self, _token: &AuthToken) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE auth_tokens SET
                access_token = ?,
                refresh_token = ?,
                token_type = ?,
                expires_at = ?,
                scopes = ?,
                issued_at = ?,
                auth_method = ?,
                subject = ?,
                issuer = ?,
                client_id = ?,
                metadata = ?
            WHERE token_id = ?
            "#,
        )
        .bind(&_token.access_token)
        .bind(&_token.refresh_token)
        .bind(&_token.token_type)
        .bind(_token.expires_at)
        .bind(serde_json::to_string(&_token.scopes).unwrap_or_default())
        .bind(_token.issued_at)
        .bind(&_token.auth_method)
        .bind(&_token.subject)
        .bind(&_token.issuer)
        .bind(&_token.client_id)
        .bind(serde_json::to_string(&_token.metadata).unwrap_or_default())
        .bind(&_token.token_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                format!("Failed to update token: {}", e),
            ))
        })?;
        Ok(())
    }
    async fn delete_token(&self, token_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM auth_tokens WHERE token_id = ?")
            .bind(token_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                    format!("Failed to delete token: {}", e),
                ))
            })?;
        Ok(())
    }
    async fn list_user_tokens(&self, _user_id: &str) -> Result<Vec<AuthToken>> {
        use sqlx::Row;
        let rows = sqlx::query(
            r#"
            SELECT token_id, user_id, access_token, refresh_token, token_type,
                   expires_at, scopes, issued_at, auth_method, subject, issuer,
                   client_id, metadata
            FROM auth_tokens WHERE user_id = ?
            "#,
        )
        .bind(_user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                format!("Failed to list user tokens: {}", e),
            ))
        })?;

        let mut tokens = Vec::new();
        for row in rows {
            let scopes: Vec<String> = row
                .try_get::<String, _>("scopes")
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            let metadata = row
                .try_get::<String, _>("metadata")
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            tokens.push(AuthToken {
                token_id: row.try_get("token_id").unwrap_or_default(),
                user_id: row.try_get("user_id").unwrap_or_default(),
                access_token: row.try_get("access_token").unwrap_or_default(),
                refresh_token: row.try_get("refresh_token").ok(),
                token_type: row.try_get("token_type").ok(),
                expires_at: row.try_get("expires_at").unwrap(),
                scopes,
                issued_at: row.try_get("issued_at").unwrap(),
                auth_method: row.try_get("auth_method").unwrap_or_default(),
                subject: row.try_get("subject").ok(),
                issuer: row.try_get("issuer").ok(),
                client_id: row.try_get("client_id").ok(),
                user_profile: None,
                permissions: Vec::new(), // Note: Requires user_permissions table and additional query
                roles: Vec::new(),       // Note: Requires user_roles table and additional query
                metadata,
            });
        }
        Ok(tokens)
    }
    async fn store_session(
        &self,
        session_id: &str,
        data: &crate::storage::SessionData,
    ) -> Result<()> {
        // Store session in DB
        sqlx::query(
            r#"
            INSERT INTO sessions (session_id, user_id, created_at, expires_at, data)
            VALUES (?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE data = VALUES(data), expires_at = VALUES(expires_at)
            "#,
        )
        .bind(session_id)
        .bind(&data.user_id)
        .bind(data.created_at)
        .bind(data.expires_at)
        .bind(serde_json::to_string(&data.data).unwrap_or_default())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                format!("Failed to store session: {}", e),
            ))
        })?;
        Ok(())
    }
    async fn get_session(&self, _session_id: &str) -> Result<Option<crate::storage::SessionData>> {
        use sqlx::Row;
        let row = sqlx::query(
            r#"
            SELECT session_id, user_id, created_at, expires_at, data
            FROM sessions WHERE session_id = ?
            "#,
        )
        .bind(_session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                format!("Failed to get session: {}", e),
            ))
        })?;
        if let Some(row) = row {
            let data = row
                .try_get::<String, _>("data")
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            Ok(Some(crate::storage::SessionData {
                session_id: row.try_get("session_id").unwrap_or_default(),
                user_id: row.try_get("user_id").unwrap_or_default(),
                created_at: row.try_get("created_at").unwrap(),
                expires_at: row.try_get("expires_at").unwrap(),
                last_activity: row
                    .try_get("last_activity")
                    .unwrap_or_else(|_| row.try_get("created_at").unwrap()),
                ip_address: row.try_get("ip_address").ok(),
                user_agent: row.try_get("user_agent").ok(),
                data,
            }))
        } else {
            Ok(None)
        }
    }
    async fn delete_session(&self, _session_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE session_id = ?")
            .bind(_session_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                    format!("Failed to delete session: {}", e),
                ))
            })?;
        Ok(())
    }
    async fn store_kv(
        &self,
        key: &str,
        value: &[u8],
        _ttl: Option<std::time::Duration>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO kv_store (`key`, `value`)
            VALUES (?, ?)
            ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)
            "#,
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                format!("Failed to store kv: {}", e),
            ))
        })?;
        Ok(())
    }
    async fn get_kv(&self, _key: &str) -> Result<Option<Vec<u8>>> {
        use sqlx::Row;
        let row = sqlx::query("SELECT `value` FROM kv_store WHERE `key` = ?")
            .bind(_key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                    format!("Failed to get kv: {}", e),
                ))
            })?;
        Ok(row.and_then(|r| r.try_get("value").ok()))
    }
    async fn delete_kv(&self, _key: &str) -> Result<()> {
        sqlx::query("DELETE FROM kv_store WHERE `key` = ?")
            .bind(_key)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                    format!("Failed to delete kv: {}", e),
                ))
            })?;
        Ok(())
    }
    async fn cleanup_expired(&self) -> Result<()> {
        let now = chrono::Utc::now().naive_utc();
        let now_str = now.format("%Y-%m-%d %H:%M:%S").to_string();
        // Clean up expired tokens
        sqlx::query("DELETE FROM auth_tokens WHERE expires_at < ?")
            .bind(&now_str)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                    format!("Failed to cleanup expired tokens: {}", e),
                ))
            })?;
        // Clean up expired sessions
        sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
            .bind(&now_str)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                    format!("Failed to cleanup expired sessions: {}", e),
                ))
            })?;
        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        use sqlx::Row;
        let rows = sqlx::query(
            r#"
            SELECT session_id, user_id, data, expires_at, created_at, last_accessed
            FROM sessions
            WHERE user_id = ? AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                format!("Failed to list user sessions: {}", e),
            ))
        })?;

        let mut sessions = Vec::new();
        for row in rows {
            let data: std::collections::HashMap<String, serde_json::Value> = row
                .try_get::<String, _>("data")
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();

            sessions.push(SessionData {
                session_id: row.try_get("session_id").unwrap_or_default(),
                user_id: row.try_get("user_id").unwrap_or_default(),
                data,
                expires_at: row
                    .try_get("expires_at")
                    .unwrap_or_else(|_| chrono::Utc::now()),
                created_at: row.try_get("created_at").unwrap_or_default(),
                last_activity: row.try_get("last_activity").unwrap_or_default(),
                ip_address: row.try_get("ip_address").ok(),
                user_agent: row.try_get("user_agent").ok(),
            });
        }

        Ok(sessions)
    }

    async fn count_active_sessions(&self) -> Result<u64> {
        use sqlx::Row;
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM sessions WHERE expires_at IS NULL OR expires_at > NOW()",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                format!("Failed to count active sessions: {}", e),
            ))
        })?;

        let count: i64 = row.try_get("count").map_err(|e| {
            crate::errors::AuthError::Storage(crate::errors::StorageError::operation_failed(
                format!("Failed to parse session count: {}", e),
            ))
        })?;

        Ok(count as u64)
    }
}


