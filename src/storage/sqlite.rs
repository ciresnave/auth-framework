use crate::errors::{AuthError, Result, StorageError};
use crate::storage::{AuthStorage, SessionData};
use crate::tokens::AuthToken;
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{Row, SqlitePool};
use std::time::Duration;

fn storage_err(error: sqlx::Error) -> AuthError {
    AuthError::Storage(StorageError::ConnectionFailed {
        message: error.to_string(),
    })
}

pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS kv_store (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL,
                expires_at INTEGER
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS auth_tokens (
                token_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                access_token TEXT NOT NULL UNIQUE,
                data TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_id ON auth_tokens(user_id)")
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_auth_tokens_access_token ON auth_tokens(access_token)",
        )
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                data TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)")
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;

        Ok(())
    }
}

#[async_trait]
impl AuthStorage for SqliteStorage {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        let data = serde_json::to_string(token).map_err(|e| AuthError::internal(e.to_string()))?;
        let expires_at = token.expires_at.timestamp();

        sqlx::query(
            "INSERT INTO auth_tokens (token_id, user_id, access_token, data, expires_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(token_id) DO UPDATE SET
             user_id=excluded.user_id,
             access_token=excluded.access_token,
             data=excluded.data,
             expires_at=excluded.expires_at",
        )
        .bind(&token.token_id)
        .bind(&token.user_id)
        .bind(&token.access_token)
        .bind(data)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;

        Ok(())
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        let row = sqlx::query("SELECT data FROM auth_tokens WHERE token_id = ?")
            .bind(token_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;

        row.map(|row| {
            let data: String = row.get("data");
            serde_json::from_str(&data).map_err(|e| AuthError::internal(e.to_string()))
        })
        .transpose()
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        let row = sqlx::query("SELECT data FROM auth_tokens WHERE access_token = ?")
            .bind(access_token)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;

        row.map(|row| {
            let data: String = row.get("data");
            serde_json::from_str(&data).map_err(|e| AuthError::internal(e.to_string()))
        })
        .transpose()
    }

    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        self.store_token(token).await
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM auth_tokens WHERE token_id = ?")
            .bind(token_id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        let rows = sqlx::query("SELECT data FROM auth_tokens WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_err)?;

        rows.into_iter()
            .map(|row| {
                let data: String = row.get("data");
                serde_json::from_str(&data).map_err(|e| AuthError::internal(e.to_string()))
            })
            .collect()
    }

    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()> {
        let json = serde_json::to_string(data).map_err(|e| AuthError::internal(e.to_string()))?;
        let expires_at = data.expires_at.timestamp();

        sqlx::query(
            "INSERT INTO sessions (session_id, user_id, data, expires_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(session_id) DO UPDATE SET
             user_id=excluded.user_id,
             data=excluded.data,
             expires_at=excluded.expires_at",
        )
        .bind(session_id)
        .bind(&data.user_id)
        .bind(json)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;

        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        let row = sqlx::query("SELECT data FROM sessions WHERE session_id = ?")
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;

        row.map(|row| {
            let json: String = row.get("data");
            serde_json::from_str(&json).map_err(|e| AuthError::internal(e.to_string()))
        })
        .transpose()
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE session_id = ?")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        let rows = sqlx::query("SELECT data FROM sessions WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_err)?;

        rows.into_iter()
            .map(|row| {
                let json: String = row.get("data");
                serde_json::from_str(&json).map_err(|e| AuthError::internal(e.to_string()))
            })
            .collect()
    }

    async fn count_active_sessions(&self) -> Result<u64> {
        let now = Utc::now().timestamp();
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM sessions WHERE expires_at > ?")
            .bind(now)
            .fetch_one(&self.pool)
            .await
            .map_err(storage_err)?;
        let count: i64 = row.get("cnt");
        Ok(count as u64)
    }

    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()> {
        let expires_at = ttl.map(|duration| Utc::now().timestamp() + duration.as_secs() as i64);

        sqlx::query(
            "INSERT INTO kv_store (key, value, expires_at)
             VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET
             value=excluded.value,
             expires_at=excluded.expires_at",
        )
        .bind(key)
        .bind(value)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;

        Ok(())
    }

    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let now = Utc::now().timestamp();
        let row = sqlx::query("SELECT value, expires_at FROM kv_store WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;

        match row {
            Some(row) => {
                let expires_at: Option<i64> = row.get("expires_at");
                if expires_at.is_some_and(|expires_at| expires_at < now) {
                    return Ok(None);
                }

                let value: Vec<u8> = row.get("value");
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    async fn get_kv_ttl(&self, key: &str) -> Result<Option<Duration>> {
        let now = Utc::now().timestamp();
        let row = sqlx::query("SELECT expires_at FROM kv_store WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(row
            .and_then(|row| row.get::<Option<i64>, _>("expires_at"))
            // `get_kv` treats `expires_at == now` as still alive, so report
            // it (as zero seconds left) rather than as "no expiry".
            .and_then(|expires_at| u64::try_from(expires_at - now).ok())
            .map(Duration::from_secs))
    }

    fn tracks_kv_ttl(&self) -> bool {
        true
    }

    async fn delete_kv(&self, key: &str) -> Result<()> {
        sqlx::query("DELETE FROM kv_store WHERE key = ?")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn list_kv_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let now = Utc::now().timestamp();
        let rows = sqlx::query(
            "SELECT key FROM kv_store WHERE key LIKE ? AND (expires_at IS NULL OR expires_at >= ?) ORDER BY key",
        )
        .bind(format!("{prefix}%"))
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;

        Ok(rows.into_iter().map(|row| row.get("key")).collect())
    }

    async fn cleanup_expired(&self) -> Result<()> {
        let now = Utc::now().timestamp();

        sqlx::query("DELETE FROM kv_store WHERE expires_at IS NOT NULL AND expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;

        sqlx::query("DELETE FROM auth_tokens WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;

        sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::TokenMetadata;
    use std::collections::HashMap;

    async fn create_test_storage() -> SqliteStorage {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let storage = SqliteStorage::new(pool);
        storage.migrate().await.unwrap();
        storage
    }

    fn create_test_token(id: &str, user_id: &str) -> AuthToken {
        AuthToken {
            token_id: id.to_string(),
            user_id: user_id.to_string(),
            access_token: format!("access_{id}"),
            token_type: Some("bearer".to_string()),
            subject: Some(user_id.to_string()),
            issuer: Some("test".to_string()),
            refresh_token: Some(format!("refresh_{id}")),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            scopes: vec!["read".to_string()].into(),
            auth_method: "password".to_string(),
            client_id: Some("test_client".to_string()),
            user_profile: None,
            permissions: vec![].into(),
            roles: vec![].into(),
            metadata: TokenMetadata {
                issued_ip: None,
                user_agent: None,
                device_id: None,
                session_id: None,
                revoked: false,
                revoked_at: None,
                revoked_reason: None,
                last_used: None,
                use_count: 0,
                custom: HashMap::new(),
            },
        }
    }

    #[tokio::test]
    async fn stores_and_fetches_tokens() {
        let storage = create_test_storage().await;
        let token = create_test_token("t1", "user1");

        storage.store_token(&token).await.unwrap();
        let loaded = storage.get_token("t1").await.unwrap().unwrap();

        assert_eq!(loaded.token_id, token.token_id);
        assert_eq!(loaded.user_id, token.user_id);
    }

    #[tokio::test]
    async fn stores_and_fetches_kv_entries() {
        let storage = create_test_storage().await;

        storage.store_kv("key", b"value", None).await.unwrap();
        let loaded = storage.get_kv("key").await.unwrap().unwrap();

        assert_eq!(loaded, b"value");
    }

    #[tokio::test]
    async fn get_kv_ttl_reports_remaining_lifetime() {
        let storage = create_test_storage().await;
        storage
            .store_kv("k:ttl", b"v", Some(Duration::from_secs(600)))
            .await
            .unwrap();
        storage.store_kv("k:forever", b"v", None).await.unwrap();
        let ttl = storage.get_kv_ttl("k:ttl").await.unwrap().unwrap();
        assert!(ttl > Duration::from_secs(590) && ttl <= Duration::from_secs(600));
        assert_eq!(storage.get_kv_ttl("k:forever").await.unwrap(), None);
        assert_eq!(storage.get_kv_ttl("k:missing").await.unwrap(), None);
    }
}
