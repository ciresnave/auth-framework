use async_trait::async_trait;
use auth_framework::errors::{AuthError, Result, StorageError};
use auth_framework::storage::{AuthStorage, SessionData};
use auth_framework::tokens::AuthToken;
use sqlx::{Row, SqlitePool};
use std::time::Duration;

fn storage_err(e: sqlx::Error) -> AuthError {
    AuthError::Storage(StorageError::ConnectionFailed {
        message: e.to_string(),
    })
}

pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    pub async fn new(connection_string: &str) -> std::result::Result<Self, sqlx::Error> {
        let pool = SqlitePool::connect(connection_string).await?;
        Self::create_tables(&pool).await?;
        Ok(Self { pool })
    }

    async fn create_tables(pool: &SqlitePool) -> std::result::Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS kv_store (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL,
                expires_at INTEGER
            );",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS tokens (
                token_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                access_token TEXT NOT NULL UNIQUE,
                data TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );",
        )
        .execute(pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);")
            .execute(pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_tokens_access_token ON tokens(access_token);")
            .execute(pool)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                data TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );",
        )
        .execute(pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);")
            .execute(pool)
            .await?;

        Ok(())
    }
}

#[async_trait]
impl AuthStorage for SqliteStorage {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        let data = serde_json::to_string(token).map_err(|e| AuthError::internal(e.to_string()))?;
        let expires_at = token.expires_at.timestamp();
        sqlx::query(
            "INSERT INTO tokens (token_id, user_id, access_token, data, expires_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(token_id) DO UPDATE SET \
             user_id=excluded.user_id, access_token=excluded.access_token, \
             data=excluded.data, expires_at=excluded.expires_at",
        )
        .bind(&token.token_id)
        .bind(&token.user_id)
        .bind(&token.access_token)
        .bind(&data)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        let row = sqlx::query("SELECT data FROM tokens WHERE token_id = ?")
            .bind(token_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        match row {
            Some(row) => {
                let data: String = row.get("data");
                let token: AuthToken =
                    serde_json::from_str(&data).map_err(|e| AuthError::internal(e.to_string()))?;
                Ok(Some(token))
            }
            None => Ok(None),
        }
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        let row = sqlx::query("SELECT data FROM tokens WHERE access_token = ?")
            .bind(access_token)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        match row {
            Some(row) => {
                let data: String = row.get("data");
                let token: AuthToken =
                    serde_json::from_str(&data).map_err(|e| AuthError::internal(e.to_string()))?;
                Ok(Some(token))
            }
            None => Ok(None),
        }
    }

    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        let data = serde_json::to_string(token).map_err(|e| AuthError::internal(e.to_string()))?;
        let expires_at = token.expires_at.timestamp();
        sqlx::query(
            "UPDATE tokens SET user_id=?, access_token=?, data=?, expires_at=? WHERE token_id=?",
        )
        .bind(&token.user_id)
        .bind(&token.access_token)
        .bind(&data)
        .bind(expires_at)
        .bind(&token.token_id)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM tokens WHERE token_id = ?")
            .bind(token_id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        let rows = sqlx::query("SELECT data FROM tokens WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_err)?;
        let mut tokens = Vec::with_capacity(rows.len());
        for row in rows {
            let data: String = row.get("data");
            let token: AuthToken =
                serde_json::from_str(&data).map_err(|e| AuthError::internal(e.to_string()))?;
            tokens.push(token);
        }
        Ok(tokens)
    }

    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()> {
        let json = serde_json::to_string(data).map_err(|e| AuthError::internal(e.to_string()))?;
        let expires_at = data.expires_at.timestamp();
        sqlx::query(
            "INSERT INTO sessions (session_id, user_id, data, expires_at) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(session_id) DO UPDATE SET \
             user_id=excluded.user_id, data=excluded.data, expires_at=excluded.expires_at",
        )
        .bind(session_id)
        .bind(&data.user_id)
        .bind(&json)
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
        match row {
            Some(row) => {
                let json: String = row.get("data");
                let session: SessionData =
                    serde_json::from_str(&json).map_err(|e| AuthError::internal(e.to_string()))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
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
        let mut sessions = Vec::with_capacity(rows.len());
        for row in rows {
            let json: String = row.get("data");
            let session: SessionData =
                serde_json::from_str(&json).map_err(|e| AuthError::internal(e.to_string()))?;
            sessions.push(session);
        }
        Ok(sessions)
    }

    async fn count_active_sessions(&self) -> Result<u64> {
        let now = chrono::Utc::now().timestamp();
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM sessions WHERE expires_at > ?")
            .bind(now)
            .fetch_one(&self.pool)
            .await
            .map_err(storage_err)?;
        let count: i64 = row.get("cnt");
        Ok(count as u64)
    }

    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()> {
        let expires_at = ttl.map(|d| chrono::Utc::now().timestamp() + d.as_secs() as i64);
        sqlx::query(
            "INSERT INTO kv_store (key, value, expires_at) VALUES (?, ?, ?) \
             ON CONFLICT(key) DO UPDATE SET value=excluded.value, expires_at=excluded.expires_at",
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
        let now = chrono::Utc::now().timestamp();
        let row = sqlx::query("SELECT value, expires_at FROM kv_store WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        match row {
            Some(row) => {
                let expires_at: Option<i64> = row.get("expires_at");
                if let Some(exp) = expires_at {
                    if exp < now {
                        return Ok(None);
                    }
                }
                let value: Vec<u8> = row.get("value");
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    async fn delete_kv(&self, key: &str) -> Result<()> {
        sqlx::query("DELETE FROM kv_store WHERE key = ?")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        sqlx::query("DELETE FROM kv_store WHERE expires_at IS NOT NULL AND expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        sqlx::query("DELETE FROM tokens WHERE expires_at < ?")
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
    use auth_framework::tokens::TokenMetadata;
    use chrono::Utc;
    use std::collections::HashMap;

    async fn create_test_storage() -> SqliteStorage {
        SqliteStorage::new("sqlite::memory:").await.unwrap()
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
            metadata: TokenMetadata::default(),
        }
    }

    fn create_test_session(session_id: &str, user_id: &str) -> SessionData {
        SessionData {
            session_id: session_id.to_string(),
            user_id: user_id.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            last_activity: Utc::now(),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            data: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_token_store_and_retrieve() {
        let storage = create_test_storage().await;
        let token = create_test_token("t1", "user1");

        storage.store_token(&token).await.unwrap();

        let retrieved = storage.get_token("t1").await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.token_id, "t1");
        assert_eq!(retrieved.user_id, "user1");
    }

    #[tokio::test]
    async fn test_token_get_by_access_token() {
        let storage = create_test_storage().await;
        let token = create_test_token("t1", "user1");
        storage.store_token(&token).await.unwrap();

        let retrieved = storage
            .get_token_by_access_token("access_t1")
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().token_id, "t1");

        let missing = storage
            .get_token_by_access_token("nonexistent")
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_token_update() {
        let storage = create_test_storage().await;
        let mut token = create_test_token("t1", "user1");
        storage.store_token(&token).await.unwrap();

        token.scopes = vec!["read".to_string(), "write".to_string()].into();
        storage.update_token(&token).await.unwrap();

        let retrieved = storage.get_token("t1").await.unwrap().unwrap();
        assert_eq!(
            retrieved.scopes,
            vec!["read".to_string(), "write".to_string()].into()
        );
    }

    #[tokio::test]
    async fn test_token_delete() {
        let storage = create_test_storage().await;
        let token = create_test_token("t1", "user1");
        storage.store_token(&token).await.unwrap();

        storage.delete_token("t1").await.unwrap();
        assert!(storage.get_token("t1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_list_user_tokens() {
        let storage = create_test_storage().await;
        storage
            .store_token(&create_test_token("t1", "user1"))
            .await
            .unwrap();
        storage
            .store_token(&create_test_token("t2", "user1"))
            .await
            .unwrap();
        storage
            .store_token(&create_test_token("t3", "user2"))
            .await
            .unwrap();

        let user1_tokens = storage.list_user_tokens("user1").await.unwrap();
        assert_eq!(user1_tokens.len(), 2);

        let user2_tokens = storage.list_user_tokens("user2").await.unwrap();
        assert_eq!(user2_tokens.len(), 1);
    }

    #[tokio::test]
    async fn test_session_store_and_retrieve() {
        let storage = create_test_storage().await;
        let session = create_test_session("s1", "user1");

        storage.store_session("s1", &session).await.unwrap();

        let retrieved = storage.get_session("s1").await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.session_id, "s1");
        assert_eq!(retrieved.user_id, "user1");
    }

    #[tokio::test]
    async fn test_session_delete() {
        let storage = create_test_storage().await;
        let session = create_test_session("s1", "user1");
        storage.store_session("s1", &session).await.unwrap();

        storage.delete_session("s1").await.unwrap();
        assert!(storage.get_session("s1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_list_user_sessions() {
        let storage = create_test_storage().await;
        storage
            .store_session("s1", &create_test_session("s1", "user1"))
            .await
            .unwrap();
        storage
            .store_session("s2", &create_test_session("s2", "user1"))
            .await
            .unwrap();

        let sessions = storage.list_user_sessions("user1").await.unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn test_count_active_sessions() {
        let storage = create_test_storage().await;
        storage
            .store_session("s1", &create_test_session("s1", "user1"))
            .await
            .unwrap();
        storage
            .store_session("s2", &create_test_session("s2", "user2"))
            .await
            .unwrap();

        let count = storage.count_active_sessions().await.unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_kv_store_and_retrieve() {
        let storage = create_test_storage().await;

        storage.store_kv("key1", b"value1", None).await.unwrap();

        let val = storage.get_kv("key1").await.unwrap();
        assert_eq!(val, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn test_kv_delete() {
        let storage = create_test_storage().await;
        storage.store_kv("key1", b"value1", None).await.unwrap();

        storage.delete_kv("key1").await.unwrap();
        assert!(storage.get_kv("key1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_kv_with_ttl_expired() {
        let storage = create_test_storage().await;
        // Insert with an expires_at in the past
        let past = chrono::Utc::now().timestamp() - 10;
        sqlx::query("INSERT INTO kv_store (key, value, expires_at) VALUES (?, ?, ?)")
            .bind("key1")
            .bind(b"value1".as_slice())
            .bind(past)
            .execute(&storage.pool)
            .await
            .unwrap();

        // Should return None because it's expired
        let val = storage.get_kv("key1").await.unwrap();
        assert!(val.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let storage = create_test_storage().await;
        // Insert with an expires_at in the past
        let past = chrono::Utc::now().timestamp() - 10;
        sqlx::query("INSERT INTO kv_store (key, value, expires_at) VALUES (?, ?, ?)")
            .bind("expired_key")
            .bind(b"val".as_slice())
            .bind(past)
            .execute(&storage.pool)
            .await
            .unwrap();

        storage.cleanup_expired().await.unwrap();

        // Verify cleanup removed the expired entry
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM kv_store")
            .fetch_one(&storage.pool)
            .await
            .unwrap();
        let count: i64 = row.get("cnt");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_get_nonexistent_token() {
        let storage = create_test_storage().await;
        assert!(storage.get_token("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_get_nonexistent_session() {
        let storage = create_test_storage().await;
        assert!(storage.get_session("nonexistent").await.unwrap().is_none());
    }
}
