// SPDX-License-Identifier: MIT OR Apache-2.0
//! ADR-011 slice 4, part 1: re-sealing tokens and sessions under the current key after a rotation.
//!
//! Records sealed under an older key id stay readable while that key is loaded (lookups probe every
//! loaded key), but their index names are keyed by the old key. [`EncryptedStorage::reindex_sealed`]
//! rewrites each such record, and its index entries, under the current key, carrying the record's
//! remaining TTL, so the old key can then be removed.

use super::sealed_tokens::storage_err;
use super::*;

/// What [`EncryptedStorage::reindex_sealed`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReindexReport {
    /// Sealed token and session records examined.
    pub scanned: u64,
    /// Records already under the current key.
    pub current: u64,
    /// Records rewritten under the current key.
    pub resealed: u64,
    /// Records that could not be opened (key removed, or damaged); left untouched.
    pub unreadable: u64,
}

impl<T> EncryptedStorage<T>
where
    T: AuthStorage + Send + Sync,
{
    /// Re-seal every token and session record that was sealed under a key other than the current
    /// one. Safe to re-run. A record that cannot be opened is counted, not fatal, so one lost key
    /// does not stop the rest.
    pub async fn reindex_sealed(&self) -> Result<ReindexReport> {
        self.ensure_sealing_supported()?;
        let mut report = ReindexReport::default();
        for key in self.inner.list_kv_keys("tok:").await? {
            self.reindex_one(&key, true, &mut report).await?;
        }
        for key in self.inner.list_kv_keys("sess:").await? {
            self.reindex_one(&key, false, &mut report).await?;
        }
        Ok(report)
    }

    async fn reindex_one(&self, key: &str, token: bool, report: &mut ReindexReport) -> Result<()> {
        let Some(raw) = self.inner.get_kv(key).await? else {
            return Ok(()); // expired or deleted since the listing
        };
        report.scanned += 1;
        let Some(envelope) = StorageEncryption::parse_envelope(&raw) else {
            report.unreadable += 1;
            return Ok(());
        };
        if envelope.key_id == self.encryption.current_key_id() {
            report.current += 1;
            return Ok(());
        }
        let Ok(plain) = self.encryption.decrypt(&envelope, key.as_bytes()) else {
            report.unreadable += 1;
            return Ok(());
        };
        if token {
            let t: AuthToken = serde_json::from_slice(&plain)
                .map_err(|e| storage_err(format!("sealed token record is malformed: {e}")))?;
            self.reseal_token(&t, key).await?;
        } else {
            let s: SessionData = serde_json::from_slice(&plain)
                .map_err(|e| storage_err(format!("sealed session record is malformed: {e}")))?;
            self.reseal_session(&s, key).await?;
        }
        report.resealed += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use crate::storage::encryption::{KeyProvider, LoadedKeys};

    struct P {
        current: &'static str,
        ids: &'static [&'static str],
    }
    impl KeyProvider for P {
        fn load_keys(&self) -> Result<LoadedKeys> {
            let mut keys = HashMap::new();
            for id in self.ids {
                keys.insert(id.to_string(), [id.as_bytes()[0]; 32]);
            }
            Ok(LoadedKeys {
                current_key_id: self.current.to_string(),
                keys,
            })
        }
    }

    fn enc(current: &'static str, ids: &'static [&'static str]) -> StorageEncryption {
        StorageEncryption::new(&P { current, ids }).unwrap()
    }

    fn session(id: &str, user: &str) -> SessionData {
        let now = chrono::Utc::now();
        SessionData {
            session_id: id.into(),
            user_id: user.into(),
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            last_activity: now,
            ip_address: None,
            user_agent: None,
            data: Default::default(),
        }
    }

    #[tokio::test]
    async fn reindex_moves_records_to_the_current_key_so_the_old_key_can_go() {
        let a = EncryptedStorage::new(MemoryStorage::new(), enc("A", &["A"]), false, false);
        a.store_token(&AuthToken::builder("t", "u", "acc").build())
            .await
            .unwrap();
        a.store_session("s", &session("s", "u")).await.unwrap();
        let b = EncryptedStorage::new(a.into_inner(), enc("B", &["A", "B"]), false, false);

        let report = b.reindex_sealed().await.unwrap();
        assert_eq!(
            (report.scanned, report.resealed, report.unreadable),
            (2, 2, 0)
        );
        // Idempotent: a second run finds nothing to do.
        let again = b.reindex_sealed().await.unwrap();
        assert_eq!((again.scanned, again.current, again.resealed), (2, 2, 0));

        // Drop key A entirely: everything is still reachable by every lookup.
        let only_b = EncryptedStorage::new(b.into_inner(), enc("B", &["B"]), false, false);
        assert!(only_b.get_token("t").await.unwrap().is_some());
        assert!(
            only_b
                .get_token_by_access_token("acc")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(only_b.list_user_tokens("u").await.unwrap().len(), 1);
        assert!(only_b.get_session("s").await.unwrap().is_some());
        assert_eq!(only_b.list_user_sessions("u").await.unwrap().len(), 1);
        // One record and its indexes per item, nothing left keyed by A: 2 + 2 + 1 tokat.
        assert_eq!(only_b.inner.list_kv_keys("").await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn without_reindex_removing_the_old_key_loses_the_records_with_an_error() {
        let a = EncryptedStorage::new(MemoryStorage::new(), enc("A", &["A"]), false, false);
        a.store_token(&AuthToken::builder("t", "u", "acc").build())
            .await
            .unwrap();
        let only_b = EncryptedStorage::new(a.into_inner(), enc("B", &["B"]), false, false);
        // Known-bad control for the test above: the lookup finds nothing (its index is keyed by A).
        assert!(only_b.get_token("t").await.unwrap().is_none());
    }
}
