// SPDX-License-Identifier: MIT OR Apache-2.0
//! ADR-011 slice 3: sessions sealed at rest by [`EncryptedStorage`].
//!
//! ```text
//! sess:{BI(session_id)}                    sealed SessionData (JSON)   TTL = expires_at - now
//! sessuser:{BI(user_id)}:{BI(session_id)}  sealed empty value          (one key per session)
//! ```
//!
//! The same rules as for tokens (see `sealed_tokens`): index entries are hints that are verified
//! against the record they point at, a delete removes the legacy row, then the sealed record, then
//! the membership entry, and legacy rows are read through only while `allow_plaintext_reads` is true.

use super::sealed_tokens::{storage_err, ttl_until, warn_legacy_row_once_a_minute};
use super::*;

const SESS: &str = "sess:";
const SESSUSER: &str = "sessuser:";
const D_SESSION_ID: &str = "session_id";
const D_USER: &str = "user_id";

fn live(s: &SessionData) -> bool {
    s.expires_at > chrono::Utc::now()
}

impl<T> EncryptedStorage<T>
where
    T: AuthStorage + Send + Sync,
{
    fn sess_key_for(&self, kid: &str, session_id: &str) -> Option<String> {
        self.bi(kid, D_SESSION_ID, session_id)
            .map(|b| format!("{SESS}{b}"))
    }

    fn sessuser_prefix_for(&self, kid: &str, user_id: &str) -> Option<String> {
        self.bi(kid, D_USER, user_id)
            .map(|b| format!("{SESSUSER}{b}:"))
    }

    fn sessuser_key_for(&self, kid: &str, user_id: &str, session_id: &str) -> Option<String> {
        let prefix = self.sessuser_prefix_for(kid, user_id)?;
        let sid = self.bi(kid, D_SESSION_ID, session_id)?;
        Some(format!("{prefix}{sid}"))
    }

    async fn read_sealed_session(&self, session_id: &str) -> Result<Option<(SessionData, String)>> {
        for kid in self.encryption.key_ids() {
            let Some(key) = self.sess_key_for(&kid, session_id) else {
                continue;
            };
            if let Some(bytes) = self.open_sealed(&key).await? {
                let s: SessionData = serde_json::from_slice(&bytes)
                    .map_err(|e| storage_err(format!("sealed session record is malformed: {e}")))?;
                // The hint rule: the record must itself carry the queried id.
                if s.session_id == session_id {
                    return Ok(Some((s, key)));
                }
            }
        }
        Ok(None)
    }

    async fn put_sealed_session(
        &self,
        session_id: &str,
        data: &SessionData,
        old: Option<(&SessionData, &str)>,
    ) -> Result<()> {
        let Some(ttl) = ttl_until(data.expires_at) else {
            if old.is_some() {
                self.delete_sealed_session(session_id).await?;
            }
            return Ok(());
        };
        let kid = self.encryption.current_key_id().to_string();
        let key = self
            .sess_key_for(&kid, session_id)
            .ok_or_else(|| storage_err("current encryption key is missing"))?;
        let user_key = self
            .sessuser_key_for(&kid, &data.user_id, session_id)
            .ok_or_else(|| storage_err("current encryption key is missing"))?;
        let body = serde_json::to_vec(data)
            .map_err(|e| storage_err(format!("could not serialise the session: {e}")))?;
        self.put_sealed(&key, &body, ttl).await?;
        self.put_sealed(&user_key, b"", ttl).await?;
        if let Some((old_data, old_key)) = old {
            for k in self.encryption.key_ids() {
                if let Some(u) = self.sessuser_key_for(&k, &old_data.user_id, session_id)
                    && u != user_key
                {
                    self.inner.delete_kv(&u).await?;
                }
            }
            if old_key != key {
                self.inner.delete_kv(old_key).await?;
            }
        }
        Ok(())
    }

    /// Record first, then the membership entry; a record that cannot be opened still has its key
    /// deleted and its membership entry left to TTL.
    async fn delete_sealed_session(&self, session_id: &str) -> Result<()> {
        let found = self.read_sealed_session(session_id).await.ok().flatten();
        for kid in self.encryption.key_ids() {
            if let Some(k) = self.sess_key_for(&kid, session_id) {
                self.inner.delete_kv(&k).await?;
            }
        }
        if let Some((s, _)) = found {
            for kid in self.encryption.key_ids() {
                if let Some(u) = self.sessuser_key_for(&kid, &s.user_id, session_id) {
                    self.inner.delete_kv(&u).await?;
                }
            }
        }
        Ok(())
    }

    /// Rewrite an already-sealed session under the current key (reindex).
    pub(super) async fn reseal_session(&self, s: &SessionData, old_key: &str) -> Result<()> {
        self.put_sealed_session(&s.session_id, s, Some((s, old_key)))
            .await
    }

    async fn adopt_legacy_session(&self, legacy: SessionData) -> Result<Option<SessionData>> {
        if !live(&legacy) {
            self.inner.delete_session(&legacy.session_id).await?;
            return Ok(None);
        }
        let id = legacy.session_id.clone();
        self.put_sealed_session(&id, &legacy, None).await?;
        self.inner.delete_session(&id).await?;
        Ok(Some(legacy))
    }

    pub(super) async fn sealed_store_session(
        &self,
        session_id: &str,
        data: &SessionData,
    ) -> Result<()> {
        self.ensure_sealing_supported()?;
        let old = self.read_sealed_session(session_id).await?;
        self.put_sealed_session(session_id, data, old.as_ref().map(|(s, k)| (s, k.as_str())))
            .await
    }

    pub(super) async fn sealed_get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        self.ensure_sealing_supported()?;
        if let Some((s, _)) = self.read_sealed_session(session_id).await? {
            return Ok(live(&s).then_some(s));
        }
        if self.allow_plaintext_reads {
            if let Some(legacy) = self.inner.get_session(session_id).await? {
                return self.adopt_legacy_session(legacy).await;
            }
        } else if self.inner.get_session(session_id).await?.is_some() {
            warn_legacy_row_once_a_minute();
        }
        Ok(None)
    }

    pub(super) async fn sealed_delete_session(&self, session_id: &str) -> Result<()> {
        self.ensure_sealing_supported()?;
        // The legacy row first, unconditionally; the sealed record stays authoritative until the end.
        self.inner.delete_session(session_id).await?;
        self.delete_sealed_session(session_id).await
    }

    pub(super) async fn sealed_list_user_sessions(
        &self,
        user_id: &str,
    ) -> Result<Vec<SessionData>> {
        self.ensure_sealing_supported()?;
        let mut out: Vec<SessionData> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for kid in self.encryption.key_ids() {
            let Some(prefix) = self.sessuser_prefix_for(&kid, user_id) else {
                continue;
            };
            for index_key in self.inner.list_kv_keys(&prefix).await? {
                let Some(suffix) = index_key.get(prefix.len()..) else {
                    continue;
                };
                let key = format!("{SESS}{suffix}");
                match self.open_sealed(&key).await? {
                    Some(bytes) => {
                        let s: SessionData = serde_json::from_slice(&bytes).map_err(|e| {
                            storage_err(format!("sealed session record is malformed: {e}"))
                        })?;
                        if s.user_id == user_id && live(&s) && seen.insert(s.session_id.clone()) {
                            out.push(s);
                        }
                    }
                    None => {
                        let _ = self.inner.delete_kv(&index_key).await;
                    }
                }
            }
        }
        if self.allow_plaintext_reads {
            for s in self.inner.list_user_sessions(user_id).await? {
                if seen.insert(s.session_id.clone()) {
                    out.push(s);
                }
            }
        }
        Ok(out)
    }

    /// Exact count: the sealed records (a scan of the `sess:` keys; the backend's TTL keeps expired
    /// ones out) plus, while legacy reads are allowed, the legacy rows. The login path does not call
    /// this directly; it reads the per-process cached count (ADR-011 section 4.4).
    pub(super) async fn sealed_count_active_sessions(&self) -> Result<u64> {
        self.ensure_sealing_supported()?;
        let mut n = self.inner.list_kv_keys(SESS).await?.len() as u64;
        if self.allow_plaintext_reads {
            n += self.inner.count_active_sessions().await?;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    fn sess(id: &str, user: &str) -> SessionData {
        let now = chrono::Utc::now();
        SessionData {
            session_id: id.into(),
            user_id: user.into(),
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            last_activity: now,
            ip_address: Some("ip-canary".into()),
            user_agent: Some("ua-canary".into()),
            data: Default::default(),
        }
    }

    fn wrapper(plaintext_reads: bool) -> EncryptedStorage<MemoryStorage> {
        EncryptedStorage::new(
            MemoryStorage::new(),
            StorageEncryption::new_random(),
            plaintext_reads,
            false,
        )
    }

    #[tokio::test]
    async fn round_trip_list_count_and_delete() {
        let w = wrapper(false);
        w.store_session("s1", &sess("s1", "u1")).await.unwrap();
        w.store_session("s2", &sess("s2", "u1")).await.unwrap();
        w.store_session("s3", &sess("s3", "u2")).await.unwrap();
        assert_eq!(w.get_session("s1").await.unwrap().unwrap().user_id, "u1");
        assert_eq!(w.list_user_sessions("u1").await.unwrap().len(), 2);
        assert_eq!(w.count_active_sessions().await.unwrap(), 3);
        w.delete_session("s1").await.unwrap();
        assert!(w.get_session("s1").await.unwrap().is_none());
        assert_eq!(w.list_user_sessions("u1").await.unwrap().len(), 1);
        assert_eq!(w.count_active_sessions().await.unwrap(), 2);
        assert!(w.get_session("missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn canaries_are_absent_from_the_backend() {
        let w = wrapper(false);
        w.store_session("sid-canary", &sess("sid-canary", "user-canary"))
            .await
            .unwrap();
        let keys = w.inner.list_kv_keys("").await.unwrap();
        assert_eq!(keys.len(), 2);
        let mut dump = String::new();
        for k in &keys {
            dump.push_str(k);
            dump.push_str(&String::from_utf8_lossy(
                &w.inner.get_kv(k).await.unwrap().unwrap(),
            ));
        }
        for c in ["sid-canary", "user-canary", "ip-canary", "ua-canary"] {
            assert!(!dump.contains(c), "{c} leaked");
        }
        // Positive control: the legacy typed row holds them in the clear.
        w.inner
            .store_session("sid-canary", &sess("sid-canary", "user-canary"))
            .await
            .unwrap();
        let legacy =
            serde_json::to_string(&w.inner.get_session("sid-canary").await.unwrap().unwrap())
                .unwrap();
        assert!(legacy.contains("sid-canary") && legacy.contains("ip-canary"));
    }

    #[tokio::test]
    async fn expired_sessions_are_not_returned_or_counted() {
        let w = wrapper(false);
        let mut s = sess("s1", "u1");
        s.expires_at = chrono::Utc::now() - chrono::Duration::seconds(5);
        w.store_session("s1", &s).await.unwrap();
        assert!(w.get_session("s1").await.unwrap().is_none());
        assert_eq!(w.count_active_sessions().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn session_keys_are_reserved() {
        let w = wrapper(false);
        w.store_session("s1", &sess("s1", "u1")).await.unwrap();
        for k in w.inner.list_kv_keys("").await.unwrap() {
            assert!(w.get_kv(&k).await.is_err());
            assert!(w.delete_kv(&k).await.is_err());
        }
        assert!(w.list_kv_keys("").await.unwrap().is_empty());
        // A look-alike that is not under the reserved prefix stays usable.
        w.store_kv("session:x", b"v", None).await.unwrap();
    }

    #[tokio::test]
    async fn legacy_sessions_are_sealed_on_read_and_counted_while_allowed() {
        let w = wrapper(true);
        w.inner
            .store_session("old", &sess("old", "u1"))
            .await
            .unwrap();
        assert_eq!(w.count_active_sessions().await.unwrap(), 1);
        assert_eq!(w.list_user_sessions("u1").await.unwrap().len(), 1);
        assert!(w.get_session("old").await.unwrap().is_some());
        assert!(
            w.inner.get_session("old").await.unwrap().is_none(),
            "legacy row deleted"
        );
        assert_eq!(w.count_active_sessions().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn legacy_sessions_are_unreachable_but_deletable_when_reads_are_off() {
        let w = wrapper(false);
        w.inner
            .store_session("old", &sess("old", "u1"))
            .await
            .unwrap();
        assert!(w.get_session("old").await.unwrap().is_none());
        assert!(w.list_user_sessions("u1").await.unwrap().is_empty());
        w.delete_session("old").await.unwrap();
        assert!(w.inner.get_session("old").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn bulk_session_methods_go_through_the_sealed_path() {
        let w = wrapper(false);
        w.store_sessions_bulk(&[("a".into(), sess("a", "u")), ("b".into(), sess("b", "u"))])
            .await
            .unwrap();
        assert!(w.inner.get_session("a").await.unwrap().is_none());
        assert_eq!(w.list_user_sessions("u").await.unwrap().len(), 2);
        w.delete_sessions_bulk(&["a".into(), "b".into()])
            .await
            .unwrap();
        assert!(w.inner.list_kv_keys("").await.unwrap().is_empty());
    }
}
