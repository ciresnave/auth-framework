/// PostgreSQL storage implementation for auth-framework.
/// This module provides a production-ready PostgreSQL backend for storing
/// authentication tokens, sessions, and audit logs.
use crate::errors::{AuthError, Result};
use crate::storage::{AuthStorage, SessionData};
use crate::tokens::AuthToken;
use async_trait::async_trait;
use sqlx::PgPool;
use sqlx::Row;
// use std::time::Duration;

/// PostgreSQL storage backend
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    /// Create a new PostgreSQL storage instance.
    ///
    /// # Example
    /// ```rust,ignore
    /// let pool = PgPool::connect("postgres://user:pass@localhost/db").await?;
    /// let storage = PostgresStorage::new(pool);
    /// ```
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Initialize database tables.
    ///
    /// Creates the `auth_tokens`, `sessions`, and `kv_store` tables together with
    /// their secondary indexes if they do not already exist.  Safe to call on every
    /// application startup (`IF NOT EXISTS` / `IF NOT EXISTS` guards are idempotent).
    ///
    /// # Errors
    /// Returns an error if any DDL statement fails (e.g. insufficient privileges).
    pub async fn migrate(&self) -> Result<()> {
        // Each statement is executed separately because sqlx::query() accepts
        // exactly one SQL statement per call.

        // --- auth_tokens table ---
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token_id    VARCHAR(255) PRIMARY KEY,
                user_id     VARCHAR(255) NOT NULL,
                access_token TEXT        NOT NULL UNIQUE,
                refresh_token TEXT,
                token_type  VARCHAR(50),
                expires_at  TIMESTAMPTZ  NOT NULL,
                scopes      TEXT[],
                issued_at   TIMESTAMPTZ  NOT NULL,
                auth_method VARCHAR(100) NOT NULL,
                subject     VARCHAR(255),
                issuer      VARCHAR(255),
                client_id   VARCHAR(255),
                metadata    JSONB,
                created_at  TIMESTAMPTZ  DEFAULT NOW()
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                "Migration failed (auth_tokens): {e}"
            )))
        })?;

        // Secondary indexes for auth_tokens (PostgreSQL requires separate CREATE INDEX statements)
        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_id ON auth_tokens (user_id)",
            "CREATE INDEX IF NOT EXISTS idx_auth_tokens_access_token ON auth_tokens (access_token)",
            "CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires_at ON auth_tokens (expires_at)",
        ] {
            sqlx::query(stmt).execute(&self.pool).await.map_err(|e| {
                AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                    "Migration failed (index): {e}"
                )))
            })?;
        }

        // --- sessions table ---
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                session_id VARCHAR(255) PRIMARY KEY,
                user_id    VARCHAR(255) NOT NULL,
                data       JSONB        NOT NULL,
                expires_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ  DEFAULT NOW()
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                "Migration failed (sessions): {e}"
            )))
        })?;

        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at)",
        ] {
            sqlx::query(stmt).execute(&self.pool).await.map_err(|e| {
                AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                    "Migration failed (index): {e}"
                )))
            })?;
        }

        // --- kv_store table ---
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS kv_store (
                key        VARCHAR(512) PRIMARY KEY,
                value      BYTEA        NOT NULL,
                expires_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ  DEFAULT NOW()
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                "Migration failed (kv_store): {e}"
            )))
        })?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_kv_store_expires_at ON kv_store (expires_at)")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                    "Migration failed (index idx_kv_store_expires_at): {e}"
                )))
            })?;

        Ok(())
    }
}

#[async_trait]
impl AuthStorage for PostgresStorage {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO auth_tokens (
                token_id, user_id, access_token, refresh_token, token_type,
                expires_at, scopes, issued_at, auth_method, subject, issuer,
                client_id, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            ON CONFLICT (token_id) DO UPDATE SET
                access_token = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                expires_at = EXCLUDED.expires_at
            "#,
        )
        .bind(&token.token_id)
        .bind(&token.user_id)
        .bind(&token.access_token)
        .bind(&token.refresh_token)
        .bind(&token.token_type)
        .bind(token.expires_at)
        .bind(&token.scopes)
        .bind(token.issued_at)
        .bind(&token.auth_method)
        .bind(&token.subject)
        .bind(&token.issuer)
        .bind(&token.client_id)
        .bind(serde_json::to_value(&token.metadata).unwrap_or_default())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                "Failed to store token: {}",
                e
            )))
        })?;

        Ok(())
    }

    // ... implement other AuthStorage methods
    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        let row =
            sqlx::query_as::<_, AuthToken>(r#"SELECT * FROM auth_tokens WHERE token_id = $1"#)
                .bind(token_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                        "Failed to fetch token: {}",
                        e
                    )))
                })?;
        Ok(row)
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        let row =
            sqlx::query_as::<_, AuthToken>(r#"SELECT * FROM auth_tokens WHERE access_token = $1"#)
                .bind(access_token)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                        "Failed to fetch token by access_token: {}",
                        e
                    )))
                })?;
        Ok(row)
    }

    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE auth_tokens SET
                access_token = $1,
                refresh_token = $2,
                token_type = $3,
                expires_at = $4,
                scopes = $5,
                issued_at = $6,
                auth_method = $7,
                subject = $8,
                issuer = $9,
                client_id = $10,
                metadata = $11
            WHERE token_id = $12
            "#,
        )
        .bind(&token.access_token)
        .bind(&token.refresh_token)
        .bind(&token.token_type)
        .bind(token.expires_at)
        .bind(&token.scopes)
        .bind(token.issued_at)
        .bind(&token.auth_method)
        .bind(&token.subject)
        .bind(&token.issuer)
        .bind(&token.client_id)
        .bind(serde_json::to_value(&token.metadata).unwrap_or_default())
        .bind(&token.token_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                "Failed to update token: {}",
                e
            )))
        })?;
        Ok(())
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        sqlx::query(r#"DELETE FROM auth_tokens WHERE token_id = $1"#)
            .bind(token_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                    "Failed to delete token: {}",
                    e
                )))
            })?;
        Ok(())
    }

    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        let tokens =
            sqlx::query_as::<_, AuthToken>(r#"SELECT * FROM auth_tokens WHERE user_id = $1"#)
                .bind(user_id)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| {
                    AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                        "Failed to list user tokens: {}",
                        e
                    )))
                })?;
        Ok(tokens)
    }

    async fn store_session(
        &self,
        session_id: &str,
        data: &crate::storage::core::SessionData,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO sessions (session_id, user_id, data, expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (session_id) DO UPDATE SET
                data = EXCLUDED.data,
                expires_at = EXCLUDED.expires_at
            "#,
        )
        .bind(session_id)
        .bind(&data.user_id)
        .bind(serde_json::to_value(data).unwrap_or_default())
        .bind(data.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                "Failed to store session: {}",
                e
            )))
        })?;
        Ok(())
    }

    async fn get_session(
        &self,
        session_id: &str,
    ) -> Result<Option<crate::storage::core::SessionData>> {
        let row = sqlx::query(r#"SELECT data FROM sessions WHERE session_id = $1"#)
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                    "Failed to fetch session: {}",
                    e
                )))
            })?;
        if let Some(row) = row {
            let data: serde_json::Value = row.try_get("data").map_err(|e| {
                AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                    "Failed to deserialize session data: {}",
                    e
                )))
            })?;
            let session: crate::storage::core::SessionData =
                serde_json::from_value(data).map_err(|e| {
                    AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                        "Failed to parse session data: {}",
                        e
                    )))
                })?;
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        sqlx::query(r#"DELETE FROM sessions WHERE session_id = $1"#)
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                    "Failed to delete session: {}",
                    e
                )))
            })?;
        Ok(())
    }

    async fn store_kv(
        &self,
        key: &str,
        value: &[u8],
        ttl: Option<std::time::Duration>,
    ) -> Result<()> {
        let expires_at = ttl.map(|d| {
            chrono::Utc::now()
                + chrono::Duration::from_std(d).unwrap_or(chrono::Duration::seconds(0))
        });
        sqlx::query(
            r#"
            INSERT INTO kv_store (key, value, expires_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (key) DO UPDATE SET
                value = EXCLUDED.value,
                expires_at = EXCLUDED.expires_at
            "#,
        )
        .bind(key)
        .bind(value)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                "Failed to store kv: {}",
                e
            )))
        })?;
        Ok(())
    }

    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query(
            r#"SELECT value FROM kv_store WHERE key = $1 AND (expires_at IS NULL OR expires_at > NOW())"#
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                "Failed to fetch kv: {}", e
            )))
        })?;
        if let Some(row) = row {
            let value: Vec<u8> = row.try_get("value").map_err(|e| {
                AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                    "Failed to deserialize kv value: {}",
                    e
                )))
            })?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    async fn get_kv_ttl(&self, key: &str) -> Result<Option<std::time::Duration>> {
        let row = sqlx::query(
            r#"SELECT EXTRACT(EPOCH FROM (expires_at - NOW()))::float8 AS seconds
               FROM kv_store
               WHERE key = $1 AND expires_at IS NOT NULL AND expires_at > NOW()"#,
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                "Failed to fetch kv ttl: {}",
                e
            )))
        })?;
        Ok(row
            .and_then(|row| row.try_get::<f64, _>("seconds").ok())
            .filter(|seconds| *seconds > 0.0)
            .map(std::time::Duration::from_secs_f64))
    }

    fn tracks_kv_ttl(&self) -> bool {
        true
    }

    async fn delete_kv(&self, key: &str) -> Result<()> {
        sqlx::query(r#"DELETE FROM kv_store WHERE key = $1"#)
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                    "Failed to delete kv: {}",
                    e
                )))
            })?;
        Ok(())
    }

    async fn list_kv_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            r#"
            SELECT key
            FROM kv_store
            WHERE key LIKE $1 AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY key
            "#,
        )
        .bind(format!("{prefix}%"))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                "Failed to list kv keys: {}",
                e
            )))
        })?;

        rows.into_iter()
            .map(|row| {
                row.try_get("key").map_err(|e| {
                    AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                        "Failed to decode kv key: {}",
                        e
                    )))
                })
            })
            .collect()
    }

    async fn cleanup_expired(&self) -> Result<()> {
        // Remove expired tokens
        sqlx::query("DELETE FROM auth_tokens WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                    "Failed to cleanup expired tokens: {}",
                    e
                )))
            })?;

        // Remove expired sessions
        sqlx::query("DELETE FROM sessions WHERE expires_at IS NOT NULL AND expires_at < NOW()")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                    "Failed to cleanup expired sessions: {}",
                    e
                )))
            })?;

        // Remove expired kv entries
        sqlx::query("DELETE FROM kv_store WHERE expires_at IS NOT NULL AND expires_at < NOW()")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                    "Failed to cleanup expired kv: {}",
                    e
                )))
            })?;

        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        let rows = sqlx::query(
            r#"
            SELECT session_id, user_id, data, expires_at, created_at, last_activity, ip_address, user_agent
            FROM sessions
            WHERE user_id = $1 AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                "Failed to list user sessions: {}",
                e
            )))
        })?;

        let sessions = rows
            .into_iter()
            .map(|row| SessionData {
                session_id: row.try_get("session_id").unwrap_or_default(),
                user_id: row.try_get("user_id").unwrap_or_default(),
                created_at: row.try_get("created_at").unwrap_or_default(),
                data: {
                    let json_value: serde_json::Value = row.try_get("data").unwrap_or_default();
                    if let serde_json::Value::Object(map) = json_value {
                        map.into_iter().collect()
                    } else {
                        std::collections::HashMap::new()
                    }
                },
                expires_at: row.try_get("expires_at").unwrap_or_default(),
                last_activity: row.try_get("last_activity").unwrap_or_default(),
                ip_address: row.try_get("ip_address").ok(),
                user_agent: row.try_get("user_agent").ok(),
            })
            .collect();

        Ok(sessions)
    }

    async fn count_active_sessions(&self) -> Result<u64> {
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM sessions WHERE expires_at IS NULL OR expires_at > NOW()",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                "Failed to count active sessions: {}",
                e
            )))
        })?;

        let count: i64 = row.try_get("count").map_err(|e| {
            AuthError::Storage(crate::errors::StorageError::operation_failed(format!(
                "Failed to parse session count: {}",
                e
            )))
        })?;

        Ok(count as u64)
    }
}
