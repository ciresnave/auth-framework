// SPDX-License-Identifier: MIT OR Apache-2.0
//! ADR-011 slice 4, part 2: finding the typed token and session rows written before sealing.
//!
//! Before sealing, tokens and sessions lived in each backend's own typed tables (or Redis keys).
//! The sealed layer never lists those rows: it only meets one when a caller presents its id
//! (read-through). `auth-framework-admin security encrypt-tokens` needs the complete list, so
//! each concrete backend gets a **crate-private** enumerator, chosen from `StorageConfig`.
//! Nothing here is a public `AuthStorage` change (PM ruling, 2026-11-13).
//!
//! Backends: SQLite and PostgreSQL (one `SELECT` over the typed tables), Redis (cursor `SCAN`
//! over the exact legacy key shapes). The in-memory backends have nothing another process could
//! enumerate. `auth-storage-sqlite` is built by the embedding application, not from
//! `StorageConfig`, so the CLI cannot reach it; its owner runs the sweep through the library.

use crate::errors::Result;
use crate::storage::encryption::EncryptedStorage;
use crate::storage::{AuthStorage, SessionData};
use crate::tokens::AuthToken;
use async_trait::async_trait;

/// A backend that can list every typed token and session row it holds, expired or not.
#[async_trait]
pub(crate) trait LegacyRows: AuthStorage {
    async fn legacy_tokens(&self) -> Result<Vec<AuthToken>>;
    async fn legacy_sessions(&self) -> Result<Vec<SessionData>>;
}

#[async_trait]
impl LegacyRows for crate::storage::MemoryStorage {
    async fn legacy_tokens(&self) -> Result<Vec<AuthToken>> {
        Ok(Vec::new())
    }
    async fn legacy_sessions(&self) -> Result<Vec<SessionData>> {
        Ok(Vec::new())
    }
}

#[cfg(feature = "sqlite-storage")]
#[async_trait]
impl LegacyRows for crate::storage::sqlite::SqliteStorage {
    async fn legacy_tokens(&self) -> Result<Vec<AuthToken>> {
        self.all_typed_rows("SELECT data FROM auth_tokens").await
    }
    async fn legacy_sessions(&self) -> Result<Vec<SessionData>> {
        self.all_typed_rows("SELECT data FROM sessions").await
    }
}

#[cfg(feature = "postgres-storage")]
#[async_trait]
impl LegacyRows for crate::storage::postgres::PostgresStorage {
    async fn legacy_tokens(&self) -> Result<Vec<AuthToken>> {
        self.all_typed_tokens().await
    }
    async fn legacy_sessions(&self) -> Result<Vec<SessionData>> {
        self.all_typed_sessions().await
    }
}

#[cfg(feature = "redis-storage")]
#[async_trait]
impl LegacyRows for crate::storage::RedisStorage {
    async fn legacy_tokens(&self) -> Result<Vec<AuthToken>> {
        self.scan_typed_rows("token:").await
    }
    async fn legacy_sessions(&self) -> Result<Vec<SessionData>> {
        let mut found = self.scan_typed_rows::<SessionData>("session_h:").await?;
        found.extend(self.scan_typed_rows::<SessionData>("session:").await?);
        // A session present under both names (a crash between the two writes) is one session.
        let mut seen = std::collections::HashSet::new();
        found.retain(|s| seen.insert(s.session_id.clone()));
        Ok(found)
    }
}

/// What a sweep over the legacy rows did (or, for a dry run, would do).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EncryptTokensReport {
    /// Typed token rows found.
    pub tokens_found: u64,
    /// Typed session rows found.
    pub sessions_found: u64,
    /// Rows sealed (and their legacy row deleted).
    pub sealed: u64,
    /// Expired rows deleted without sealing.
    pub expired_dropped: u64,
    /// Rows deleted without sealing because `purge` was requested (their holders must log in again).
    pub purged: u64,
    /// Typed rows still present after the sweep (always 0 after a clean real run).
    pub remaining: u64,
}

/// Seal (or, with `purge`, delete) every typed token and session row.
///
/// Order per row: the sealed copy is written first, the legacy row deleted second, so a crash
/// leaves a row in at most the legacy place, never in neither (ADR-011 section 5). A `dry_run`
/// only counts. The sealed wrapper must be built with the same backend as `source`.
pub(crate) async fn encrypt_tokens<S>(
    source: &S,
    sealed: &EncryptedStorage<std::sync::Arc<dyn AuthStorage>>,
    purge: bool,
    dry_run: bool,
) -> Result<EncryptTokensReport>
where
    S: LegacyRows + ?Sized,
{
    let mut report = EncryptTokensReport::default();
    let now = chrono::Utc::now();

    for token in source.legacy_tokens().await? {
        report.tokens_found += 1;
        if dry_run {
            continue;
        }
        if purge {
            source.delete_token(&token.token_id).await?;
            report.purged += 1;
        } else if token.is_expired() {
            source.delete_token(&token.token_id).await?;
            report.expired_dropped += 1;
        } else {
            sealed.store_token(&token).await?;
            source.delete_token(&token.token_id).await?;
            report.sealed += 1;
        }
    }

    for session in source.legacy_sessions().await? {
        report.sessions_found += 1;
        if dry_run {
            continue;
        }
        if purge {
            source.delete_session(&session.session_id).await?;
            report.purged += 1;
        } else if session.expires_at <= now {
            source.delete_session(&session.session_id).await?;
            report.expired_dropped += 1;
        } else {
            sealed.store_session(&session.session_id, &session).await?;
            source.delete_session(&session.session_id).await?;
            report.sealed += 1;
        }
    }

    report.remaining =
        (source.legacy_tokens().await?.len() + source.legacy_sessions().await?.len()) as u64;
    Ok(report)
}

#[cfg(all(test, feature = "sqlite-storage"))]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::storage::encryption::{KeyProvider, LoadedKeys, StorageEncryption};
    use crate::storage::sqlite::SqliteStorage;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct P;
    impl KeyProvider for P {
        fn load_keys(&self) -> Result<LoadedKeys> {
            let mut keys = HashMap::new();
            keys.insert("A".to_string(), [b'A'; 32]);
            Ok(LoadedKeys {
                current_key_id: "A".to_string(),
                keys,
            })
        }
    }

    fn session(id: &str, expires_in: chrono::Duration) -> SessionData {
        let now = chrono::Utc::now();
        SessionData {
            session_id: id.into(),
            user_id: "u".into(),
            created_at: now,
            expires_at: now + expires_in,
            last_activity: now,
            ip_address: None,
            user_agent: None,
            data: Default::default(),
        }
    }

    async fn setup() -> (Arc<SqliteStorage>, EncryptedStorage<Arc<dyn AuthStorage>>) {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let raw = SqliteStorage::new(pool);
        raw.migrate().await.unwrap();
        let raw = Arc::new(raw);
        raw.store_token(&AuthToken::builder("t1", "u", "access-1").build())
            .await
            .unwrap();
        raw.store_session("s1", &session("s1", chrono::Duration::hours(1)))
            .await
            .unwrap();
        raw.store_session("s-old", &session("s-old", -chrono::Duration::hours(1)))
            .await
            .unwrap();
        let as_dyn: Arc<dyn AuthStorage> = raw.clone();
        let sealed =
            EncryptedStorage::try_new(as_dyn, StorageEncryption::new(&P).unwrap(), false, false)
                .unwrap();
        (raw, sealed)
    }

    #[tokio::test]
    async fn sweep_seals_live_rows_drops_expired_and_leaves_no_typed_row() {
        let (raw, sealed) = setup().await;
        // Strict mode (no plaintext reads): the typed row is invisible through the wrapper.
        assert!(sealed.get_token("t1").await.unwrap().is_none());

        let report = encrypt_tokens(raw.as_ref(), &sealed, false, false)
            .await
            .unwrap();
        assert_eq!(
            (
                report.tokens_found,
                report.sessions_found,
                report.sealed,
                report.expired_dropped,
                report.remaining
            ),
            (1, 2, 2, 1, 0)
        );
        assert_eq!(
            sealed.get_token("t1").await.unwrap().unwrap().token_id,
            "t1"
        );
        assert!(sealed.get_session("s1").await.unwrap().is_some());
        assert!(sealed.get_session("s-old").await.unwrap().is_none());
        assert!(raw.legacy_tokens().await.unwrap().is_empty());
        assert!(raw.legacy_sessions().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn dry_run_changes_nothing() {
        let (raw, sealed) = setup().await;
        let report = encrypt_tokens(raw.as_ref(), &sealed, false, true)
            .await
            .unwrap();
        assert_eq!(
            (report.tokens_found, report.sessions_found, report.sealed),
            (1, 2, 0)
        );
        assert_eq!(report.remaining, 3);
        assert_eq!(raw.legacy_tokens().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn purge_deletes_rows_without_sealing_them() {
        let (raw, sealed) = setup().await;
        let report = encrypt_tokens(raw.as_ref(), &sealed, true, false)
            .await
            .unwrap();
        assert_eq!((report.purged, report.sealed, report.remaining), (3, 0, 0));
        assert!(sealed.get_token("t1").await.unwrap().is_none());
        assert!(sealed.get_session("s1").await.unwrap().is_none());
    }
}
