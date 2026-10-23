//! One-shot copy of a [`SqliteStorage`](crate::storage::sqlite::SqliteStorage) database into any
//! other [`AuthStorage`], for moving to [`PersistantStorage`](crate::storage::persistant::PersistantStorage)
//! (needs both `sqlite-storage` and `persistant-storage`).
//!
//! The source is only read. Every row is written through the target's own `store_token`,
//! `store_session` and `store_kv`, so the target's indexes and lifetimes are built by the same code
//! that serves later requests. Rows already past their expiry are skipped (the target would drop
//! them at once), and a key-value row keeps the time it had left. Running it again is safe: each
//! write replaces the record with the same id. A failure stops the copy with an error naming the
//! table, and leaves what was copied so far in place; run it again after fixing the cause.
//!
//! Key-value values are copied byte for byte. If the source was read through an
//! [`EncryptedStorage`](crate::storage::encryption::EncryptedStorage), the bytes in the table are
//! already ciphertext: wrap the target in an `EncryptedStorage` with the same keys and they read
//! back as before. Passing the plain target of a source that held ciphertext copies ciphertext.

use crate::errors::{AuthError, Result, StorageError};
use crate::storage::core::{AuthStorage, SessionData};
use crate::tokens::AuthToken;
use sqlx::{Row, SqlitePool};
use std::time::Duration;

/// Rows per read of the source.
const PAGE: i64 = 500;

/// What a copy did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// Tokens written to the target.
    pub tokens: u64,
    /// Sessions written to the target.
    pub sessions: u64,
    /// Key-value entries written to the target.
    pub kv_entries: u64,
    /// Rows left out because they had already expired.
    pub skipped_expired: u64,
}

fn read_err(table: &str, error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(StorageError::operation_failed(format!(
        "migration: reading {table} failed: {error}"
    )))
}

/// Copy the tokens, sessions and key-value entries of `source` into `target`.
pub async fn migrate_sqlite_to_storage<T: AuthStorage + ?Sized>(
    source: &SqlitePool,
    target: &T,
) -> Result<MigrationReport> {
    let now = chrono::Utc::now().timestamp();
    let mut report = MigrationReport::default();

    let mut after = String::new();
    loop {
        let rows = sqlx::query(
            "SELECT token_id, data, expires_at FROM auth_tokens WHERE token_id > ? ORDER BY token_id LIMIT ?",
        )
        .bind(&after)
        .bind(PAGE)
        .fetch_all(source)
        .await
        .map_err(|e| read_err("auth_tokens", e))?;
        let Some(last) = rows.last() else { break };
        after = last.get("token_id");
        for row in &rows {
            if row.get::<i64, _>("expires_at") < now {
                report.skipped_expired += 1;
                continue;
            }
            let data: String = row.get("data");
            let token: AuthToken = serde_json::from_str(&data)
                .map_err(|e| read_err("auth_tokens", format!("a token does not decode: {e}")))?;
            target.store_token(&token).await?;
            report.tokens += 1;
        }
    }

    let mut after = String::new();
    loop {
        let rows = sqlx::query(
            "SELECT session_id, data, expires_at FROM sessions WHERE session_id > ? ORDER BY session_id LIMIT ?",
        )
        .bind(&after)
        .bind(PAGE)
        .fetch_all(source)
        .await
        .map_err(|e| read_err("sessions", e))?;
        let Some(last) = rows.last() else { break };
        after = last.get("session_id");
        for row in &rows {
            if row.get::<i64, _>("expires_at") < now {
                report.skipped_expired += 1;
                continue;
            }
            let session_id: String = row.get("session_id");
            let data: String = row.get("data");
            let session: SessionData = serde_json::from_str(&data)
                .map_err(|e| read_err("sessions", format!("a session does not decode: {e}")))?;
            target.store_session(&session_id, &session).await?;
            report.sessions += 1;
        }
    }

    let mut after = String::new();
    loop {
        let rows = sqlx::query(
            "SELECT key, value, expires_at FROM kv_store WHERE key > ? ORDER BY key LIMIT ?",
        )
        .bind(&after)
        .bind(PAGE)
        .fetch_all(source)
        .await
        .map_err(|e| read_err("kv_store", e))?;
        let Some(last) = rows.last() else { break };
        after = last.get("key");
        for row in &rows {
            let expires_at: Option<i64> = row.get("expires_at");
            let ttl = match expires_at {
                // The source keeps an entry through the second named by `expires_at`.
                Some(at) if at < now => {
                    report.skipped_expired += 1;
                    continue;
                }
                Some(at) => Some(Duration::from_secs((at - now) as u64 + 1)),
                None => None,
            };
            let key: String = row.get("key");
            let value: Vec<u8> = row.get("value");
            target.store_kv(&key, &value, ttl).await?;
            report.kv_entries += 1;
        }
    }

    Ok(report)
}
