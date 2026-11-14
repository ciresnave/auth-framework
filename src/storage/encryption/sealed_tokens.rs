// SPDX-License-Identifier: MIT OR Apache-2.0
//! ADR-011 slice 2: access tokens sealed at rest by [`EncryptedStorage`].
//!
//! A token is stored as one sealed record in the inner backend's KV space, plus two keyed-hash
//! indexes (see `docs/architecture/ADR-011-token-session-encryption-at-rest.md`):
//!
//! ```text
//! tok:{BI(token_id)}                    sealed AuthToken (JSON)       TTL = expires_at - now
//! tokat:{BI(access_token)}              sealed pointer to the tok: key (a hint)
//! tokuser:{BI(user_id)}:{BI(token_id)}  sealed empty value            (one key per token)
//! ```
//!
//! `BI` is [`StorageEncryption::blind_index`], so no access token, user id or token id appears in a
//! key name. Every index entry is a *hint*: a read opens the record it points at and checks that the
//! record itself carries the queried value, so a stale or forged index yields `None`.
//!
//! The ordering rules keep every crash or interleaving at "unreachable" or "harmless", never "wrong
//! subject" and never "revoked token still valid": a delete removes the legacy row, then the sealed
//! record, then the indexes; an update of an absent record is a no-op returning `Ok`.

use super::*;
use std::sync::atomic::{AtomicI64, Ordering};

/// Key-name prefixes reserved for sealed tokens. Hidden from callers of the KV methods.
const TOK: &str = "tok:";
const TOKAT: &str = "tokat:";
const TOKUSER: &str = "tokuser:";
const SESS: &str = "sess:";
const SESSUSER: &str = "sessuser:";

/// Domains separating the roles a blind index plays.
const D_TOKEN_ID: &str = "token_id";
const D_ACCESS: &str = "access_token";
const D_USER: &str = "user_id";

/// True when `key` falls under a reserved prefix, by the same rule a backend's prefix scan uses
/// (ASCII-case-insensitive), so a caller cannot reach a sealed key by changing its case.
pub(super) fn is_reserved_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    [TOK, TOKAT, TOKUSER, SESS, SESSUSER]
        .iter()
        .any(|p| lower.starts_with(p))
}

pub(super) fn reject_reserved(key: &str) -> Result<()> {
    if is_reserved_key(key) {
        return Err(AuthError::validation(
            "this key name is reserved for sealed token records and cannot be read or written \
             through the key-value interface",
        ));
    }
    Ok(())
}

pub(super) fn storage_err(message: impl Into<String>) -> AuthError {
    AuthError::Storage(crate::errors::StorageError::operation_failed(message))
}

/// Unix seconds of the last legacy-row warning, for a once-a-minute rate limit per process.
static LAST_LEGACY_WARN: AtomicI64 = AtomicI64::new(0);

pub(super) fn warn_legacy_row_once_a_minute() {
    let now = chrono::Utc::now().timestamp();
    let last = LAST_LEGACY_WARN.load(Ordering::Relaxed);
    if now - last >= 60
        && LAST_LEGACY_WARN
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        tracing::warn!(
            "a token stored before tokens were sealed at rest was presented but is unreachable \
             because storage_encryption.allow_plaintext_reads is false: run \
             `auth-framework-admin security encrypt-tokens` (or purge) to deal with the plaintext tail"
        );
    }
}

pub(super) fn ttl_until(expires_at: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
    let ms = (expires_at - chrono::Utc::now()).num_milliseconds();
    (ms > 0).then(|| Duration::from_millis(ms as u64))
}

fn live(token: &AuthToken) -> bool {
    token.expires_at > chrono::Utc::now()
}

impl<T> EncryptedStorage<T>
where
    T: AuthStorage + Send + Sync,
{
    /// The sealed layer is only sound on a backend that lists its KV keys and reports TTLs.
    pub(super) fn ensure_sealing_supported(&self) -> Result<()> {
        if !self.inner.lists_kv_keys() || !self.inner.tracks_kv_ttl() {
            return Err(storage_err(
                "tokens cannot be sealed at rest on this storage backend: it must list its KV \
                 keys and report KV TTLs (AuthStorage::lists_kv_keys / tracks_kv_ttl); use \
                 EncryptedStorage::try_new to refuse such a backend at construction",
            ));
        }
        Ok(())
    }

    pub(super) fn bi(&self, kid: &str, domain: &str, value: &str) -> Option<String> {
        self.encryption.blind_index(kid, domain, value)
    }

    fn tok_key_for(&self, kid: &str, token_id: &str) -> Option<String> {
        self.bi(kid, D_TOKEN_ID, token_id)
            .map(|b| format!("{TOK}{b}"))
    }

    fn tokat_key_for(&self, kid: &str, access_token: &str) -> Option<String> {
        self.bi(kid, D_ACCESS, access_token)
            .map(|b| format!("{TOKAT}{b}"))
    }

    fn tokuser_prefix_for(&self, kid: &str, user_id: &str) -> Option<String> {
        self.bi(kid, D_USER, user_id)
            .map(|b| format!("{TOKUSER}{b}:"))
    }

    fn tokuser_key_for(&self, kid: &str, user_id: &str, token_id: &str) -> Option<String> {
        let prefix = self.tokuser_prefix_for(kid, user_id)?;
        let tid = self.bi(kid, D_TOKEN_ID, token_id)?;
        Some(format!("{prefix}{tid}"))
    }

    pub(super) fn seal(&self, key: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encryption
            .encrypt_for_storage(plaintext, key.as_bytes())
    }

    /// Read and open a sealed key. A value that does not open is an error, never `None`.
    pub(super) async fn open_sealed(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let Some(raw) = self.inner.get_kv(key).await? else {
            return Ok(None);
        };
        self.encryption
            .decrypt_from_storage(&raw, key.as_bytes())
            .map(Some)
    }

    pub(super) async fn put_sealed(&self, key: &str, plaintext: &[u8], ttl: Duration) -> Result<()> {
        let sealed = self.seal(key, plaintext)?;
        self.inner.store_kv(key, &sealed, Some(ttl)).await
    }

    /// The sealed token under `token_id`, with the key it was found at.
    async fn read_sealed_token(&self, token_id: &str) -> Result<Option<(AuthToken, String)>> {
        for kid in self.encryption.key_ids() {
            let Some(key) = self.tok_key_for(&kid, token_id) else {
                continue;
            };
            if let Some(bytes) = self.open_sealed(&key).await? {
                let token: AuthToken = serde_json::from_slice(&bytes)
                    .map_err(|e| storage_err(format!("sealed token record is malformed: {e}")))?;
                // The hint rule: the record must itself carry the queried id.
                if token.token_id == token_id {
                    return Ok(Some((token, key)));
                }
            }
        }
        Ok(None)
    }

    /// Who currently holds the access-token index entry at `tokat_key`: the `token_id` of a live
    /// record whose own access token hashes to that entry, or `None` when the entry is stale.
    async fn access_owner(&self, tokat_key: &str) -> Option<String> {
        let pointer = self.open_sealed(tokat_key).await.ok()??;
        let tok_key = String::from_utf8(pointer).ok()?;
        if !tok_key.starts_with(TOK) {
            return None;
        }
        let record = self.open_sealed(&tok_key).await.ok()??;
        let token: AuthToken = serde_json::from_slice(&record).ok()?;
        let hashes_here = self
            .encryption
            .key_ids()
            .iter()
            .any(|k| self.tokat_key_for(k, &token.access_token).as_deref() == Some(tokat_key));
        (hashes_here && live(&token)).then_some(token.token_id)
    }

    /// Claim the access-token index for `token` (uniqueness, as the UNIQUE column was).
    async fn claim_access_token(
        &self,
        token: &AuthToken,
        tok_key: &str,
        ttl: Duration,
    ) -> Result<()> {
        let kid = self.encryption.current_key_id().to_string();
        let key = self
            .tokat_key_for(&kid, &token.access_token)
            .ok_or_else(|| storage_err("current encryption key is missing"))?;
        let sealed = self.seal(&key, tok_key.as_bytes())?;
        for _ in 0..2 {
            if self
                .inner
                .store_kv_if_absent(&key, &sealed, Some(ttl))
                .await?
            {
                return Ok(());
            }
            match self.access_owner(&key).await {
                Some(owner) if owner == token.token_id => {
                    // This same token (an update): rewrite so the TTL follows the record.
                    return self.inner.store_kv(&key, &sealed, Some(ttl)).await;
                }
                Some(_) => {
                    return Err(storage_err("duplicate access token"));
                }
                None => {
                    // Stale entry: remove it and try to claim once more.
                    self.inner.delete_kv(&key).await?;
                }
            }
        }
        Err(storage_err("duplicate access token"))
    }

    /// Write `token` (record and indexes). `old` is the record being replaced, if any.
    async fn put_sealed_token(
        &self,
        token: &AuthToken,
        old: Option<(&AuthToken, &str)>,
    ) -> Result<()> {
        let Some(ttl) = ttl_until(token.expires_at) else {
            // Already expired: nothing to keep, and an old record must not outlive it.
            if old.is_some() {
                self.delete_sealed_token(&token.token_id).await?;
            }
            return Ok(());
        };
        let kid = self.encryption.current_key_id().to_string();
        let tok_key = self
            .tok_key_for(&kid, &token.token_id)
            .ok_or_else(|| storage_err("current encryption key is missing"))?;
        let user_key = self
            .tokuser_key_for(&kid, &token.user_id, &token.token_id)
            .ok_or_else(|| storage_err("current encryption key is missing"))?;

        // The claim comes first so a duplicate leaves no reachable orphan; a hint written before its
        // record is harmless (it verifies to nothing and is replaced lazily).
        self.claim_access_token(token, &tok_key, ttl).await?;
        let body = serde_json::to_vec(token)
            .map_err(|e| storage_err(format!("could not serialise the token: {e}")))?;
        self.put_sealed(&tok_key, &body, ttl).await?;
        self.put_sealed(&user_key, b"", ttl).await?;

        if let Some((old_token, old_key)) = old {
            self.remove_stale_entries(old_token, old_key, &tok_key, &user_key, &token.access_token)
                .await?;
        }
        Ok(())
    }

    /// After a replacing write: drop the old index entries (and the old record key, after a key
    /// rotation) that the new write did not reuse. An access-token entry is removed only if it still
    /// points at this token.
    async fn remove_stale_entries(
        &self,
        old: &AuthToken,
        old_tok_key: &str,
        new_tok_key: &str,
        new_user_key: &str,
        new_access: &str,
    ) -> Result<()> {
        let current = self.encryption.current_key_id().to_string();
        let new_at_key = self.tokat_key_for(&current, new_access);
        for kid in self.encryption.key_ids() {
            if let Some(at_key) = self.tokat_key_for(&kid, &old.access_token)
                && Some(&at_key) != new_at_key.as_ref()
                && self.points_at(&at_key, &[old_tok_key, new_tok_key]).await
            {
                self.inner.delete_kv(&at_key).await?;
            }
            if let Some(user_key) = self.tokuser_key_for(&kid, &old.user_id, &old.token_id)
                && user_key != new_user_key
            {
                self.inner.delete_kv(&user_key).await?;
            }
        }
        if old_tok_key != new_tok_key {
            self.inner.delete_kv(old_tok_key).await?;
        }
        Ok(())
    }

    /// Whether the access-token entry at `at_key` is a pointer to one of `tok_keys`.
    async fn points_at(&self, at_key: &str, tok_keys: &[&str]) -> bool {
        match self.open_sealed(at_key).await {
            Ok(Some(p)) => String::from_utf8(p)
                .map(|p| tok_keys.contains(&p.as_str()))
                .unwrap_or(false),
            _ => false,
        }
    }

    /// Delete a sealed token: record first, then indexes (ADR-011 section 4.3). A record that cannot
    /// be opened (its key was rotated out) still has its key deleted; its indexes are left to TTL.
    async fn delete_sealed_token(&self, token_id: &str) -> Result<()> {
        let mut found: Option<(AuthToken, String)> = None;
        let mut keys = Vec::new();
        for kid in self.encryption.key_ids() {
            if let Some(k) = self.tok_key_for(&kid, token_id) {
                keys.push(k);
            }
        }
        for k in &keys {
            if let Ok(Some(bytes)) = self.open_sealed(k).await
                && let Ok(t) = serde_json::from_slice::<AuthToken>(&bytes)
                && t.token_id == token_id
            {
                found = Some((t, k.clone()));
                break;
            }
        }
        for k in &keys {
            self.inner.delete_kv(k).await?;
        }
        if let Some((t, _)) = found {
            let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
            for kid in self.encryption.key_ids() {
                if let Some(at) = self.tokat_key_for(&kid, &t.access_token)
                    && self.points_at(&at, &key_refs).await
                {
                    self.inner.delete_kv(&at).await?;
                }
                if let Some(u) = self.tokuser_key_for(&kid, &t.user_id, &t.token_id) {
                    self.inner.delete_kv(&u).await?;
                }
            }
        }
        Ok(())
    }

    /// Rewrite an already-sealed token under the current key (reindex).
    pub(super) async fn reseal_token(&self, token: &AuthToken, old_key: &str) -> Result<()> {
        self.put_sealed_token(token, Some((token, old_key))).await
    }

    /// Seal a legacy typed row and delete it (read-through migration, ADR-011 section 5 rule 2).
    async fn adopt_legacy_token(&self, legacy: AuthToken) -> Result<Option<AuthToken>> {
        if !live(&legacy) {
            self.inner.delete_token(&legacy.token_id).await?;
            return Ok(None);
        }
        self.put_sealed_token(&legacy, None).await?;
        // A delete (a revocation) that ran while this read held the legacy row has already removed
        // it: that delete won, so undo the sealed copy just written instead of resurrecting the
        // token. Only a delete removes the legacy row before the line below does.
        if self.inner.get_token(&legacy.token_id).await?.is_none() {
            self.delete_sealed_token(&legacy.token_id).await?;
            return Ok(None);
        }
        self.inner.delete_token(&legacy.token_id).await?;
        Ok(Some(legacy))
    }

    // ---- the AuthStorage token methods, sealed ----

    pub(super) async fn sealed_store_token(&self, token: &AuthToken) -> Result<()> {
        self.ensure_sealing_supported()?;
        let old = self.read_sealed_token(&token.token_id).await?;
        self.put_sealed_token(token, old.as_ref().map(|(t, k)| (t, k.as_str())))
            .await
    }

    pub(super) async fn sealed_get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        self.ensure_sealing_supported()?;
        if let Some((token, _)) = self.read_sealed_token(token_id).await? {
            return Ok(live(&token).then_some(token));
        }
        if self.allow_plaintext_reads {
            if let Some(legacy) = self.inner.get_token(token_id).await? {
                return self.adopt_legacy_token(legacy).await;
            }
        } else if self.inner.get_token(token_id).await?.is_some() {
            warn_legacy_row_once_a_minute();
        }
        Ok(None)
    }

    pub(super) async fn sealed_get_token_by_access_token(
        &self,
        access_token: &str,
    ) -> Result<Option<AuthToken>> {
        self.ensure_sealing_supported()?;
        for kid in self.encryption.key_ids() {
            let Some(at_key) = self.tokat_key_for(&kid, access_token) else {
                continue;
            };
            let Some(pointer) = self.open_sealed(&at_key).await? else {
                continue;
            };
            let Ok(tok_key) = String::from_utf8(pointer) else {
                continue;
            };
            if !tok_key.starts_with(TOK) {
                continue;
            }
            let Some(bytes) = self.open_sealed(&tok_key).await? else {
                continue;
            };
            let token: AuthToken = serde_json::from_slice(&bytes)
                .map_err(|e| storage_err(format!("sealed token record is malformed: {e}")))?;
            // The hint rule: the record itself must carry the presented access token.
            if token.access_token == access_token {
                return Ok(live(&token).then_some(token));
            }
        }
        if self.allow_plaintext_reads {
            if let Some(legacy) = self.inner.get_token_by_access_token(access_token).await? {
                return self.adopt_legacy_token(legacy).await;
            }
        } else if self
            .inner
            .get_token_by_access_token(access_token)
            .await?
            .is_some()
        {
            warn_legacy_row_once_a_minute();
        }
        Ok(None)
    }

    pub(super) async fn sealed_update_token(&self, token: &AuthToken) -> Result<()> {
        self.ensure_sealing_supported()?;
        let mut old = self.read_sealed_token(&token.token_id).await?;
        if old.is_none() {
            if self.allow_plaintext_reads {
                if let Some(legacy) = self.inner.get_token(&token.token_id).await? {
                    self.adopt_legacy_token(legacy).await?;
                    old = self.read_sealed_token(&token.token_id).await?;
                }
            } else {
                // Revocation must reach a legacy row whatever the flag says.
                self.inner.update_token(token).await?;
            }
        }
        match old {
            Some((o, k)) => self.put_sealed_token(token, Some((&o, &k))).await,
            // An update of an absent record is a no-op, never a resurrection.
            None => Ok(()),
        }
    }

    pub(super) async fn sealed_delete_token(&self, token_id: &str) -> Result<()> {
        self.ensure_sealing_supported()?;
        // The legacy row first, unconditionally: the sealed record stays authoritative until the end.
        self.inner.delete_token(token_id).await?;
        self.delete_sealed_token(token_id).await
    }

    pub(super) async fn sealed_list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        self.ensure_sealing_supported()?;
        let mut out: Vec<AuthToken> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for kid in self.encryption.key_ids() {
            let Some(prefix) = self.tokuser_prefix_for(&kid, user_id) else {
                continue;
            };
            for index_key in self.inner.list_kv_keys(&prefix).await? {
                let Some(suffix) = index_key.get(prefix.len()..) else {
                    continue;
                };
                let tok_key = format!("{TOK}{suffix}");
                match self.open_sealed(&tok_key).await? {
                    Some(bytes) => {
                        let token: AuthToken = serde_json::from_slice(&bytes).map_err(|e| {
                            storage_err(format!("sealed token record is malformed: {e}"))
                        })?;
                        if token.user_id == user_id
                            && live(&token)
                            && seen.insert(token.token_id.clone())
                        {
                            out.push(token);
                        }
                    }
                    None => {
                        // An orphaned membership entry (its record is gone): drop it lazily.
                        let _ = self.inner.delete_kv(&index_key).await;
                    }
                }
            }
        }
        if self.allow_plaintext_reads {
            for t in self.inner.list_user_tokens(user_id).await? {
                if seen.insert(t.token_id.clone()) {
                    out.push(t);
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    fn tok(id: &str, user: &str, access: &str) -> AuthToken {
        let mut t = AuthToken::builder(id, user, access).build();
        t.refresh_token = Some(format!("refresh-canary-{id}"));
        t
    }

    fn wrapper(plaintext_reads: bool) -> EncryptedStorage<MemoryStorage> {
        EncryptedStorage::new(
            MemoryStorage::new(),
            StorageEncryption::new_random(),
            plaintext_reads,
            false,
        )
    }

    /// Every key and value the backend holds, as one searchable string.
    async fn raw_dump(w: &EncryptedStorage<MemoryStorage>) -> String {
        let mut out = String::new();
        for k in w.inner.list_kv_keys("").await.unwrap() {
            out.push_str(&k);
            out.push('\n');
            if let Some(v) = w.inner.get_kv(&k).await.unwrap() {
                out.push_str(&String::from_utf8_lossy(&v));
                out.push('\n');
            }
        }
        out
    }

    #[tokio::test]
    async fn round_trip_by_id_access_token_and_user() {
        let w = wrapper(false);
        let t = tok("tid-1", "user-1", "access-1");
        w.store_token(&t).await.unwrap();
        assert_eq!(
            w.get_token("tid-1").await.unwrap().unwrap().access_token,
            "access-1"
        );
        assert_eq!(
            w.get_token_by_access_token("access-1")
                .await
                .unwrap()
                .unwrap()
                .token_id,
            "tid-1"
        );
        assert_eq!(w.list_user_tokens("user-1").await.unwrap().len(), 1);
        assert!(w.get_token("nope").await.unwrap().is_none());
        assert!(w.get_token_by_access_token("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn canaries_are_absent_from_the_backend_and_present_with_a_plain_control() {
        let w = wrapper(false);
        w.store_token(&tok("tid-canary", "user-canary", "access-canary"))
            .await
            .unwrap();
        let dump = raw_dump(&w).await;
        assert!(!dump.is_empty(), "the dump must see the sealed records");
        for c in [
            "tid-canary",
            "user-canary",
            "access-canary",
            "refresh-canary",
        ] {
            assert!(!dump.contains(c), "{c} leaked into the backend");
        }
        // Positive control: the same search over an unwrapped backend finds them.
        let plain = MemoryStorage::new();
        plain
            .store_kv("k", br#"{"a":"access-canary","t":"tid-canary"}"#, None)
            .await
            .unwrap();
        let v = String::from_utf8(plain.get_kv("k").await.unwrap().unwrap()).unwrap();
        assert!(v.contains("access-canary") && v.contains("tid-canary"));
    }

    #[tokio::test]
    async fn duplicate_access_token_is_refused_and_deleting_the_first_frees_it() {
        let w = wrapper(false);
        w.store_token(&tok("a", "u", "same")).await.unwrap();
        assert!(w.store_token(&tok("b", "u", "same")).await.is_err());
        assert!(
            w.get_token("b").await.unwrap().is_none(),
            "no orphan left behind"
        );
        w.delete_token("a").await.unwrap();
        w.store_token(&tok("b", "u", "same")).await.unwrap();
        assert_eq!(
            w.get_token_by_access_token("same")
                .await
                .unwrap()
                .unwrap()
                .token_id,
            "b"
        );
    }

    #[tokio::test]
    async fn delete_removes_record_and_indexes() {
        let w = wrapper(false);
        w.store_token(&tok("a", "u", "acc")).await.unwrap();
        w.delete_token("a").await.unwrap();
        assert!(w.get_token("a").await.unwrap().is_none());
        assert!(w.get_token_by_access_token("acc").await.unwrap().is_none());
        assert!(w.list_user_tokens("u").await.unwrap().is_empty());
        assert!(w.inner.list_kv_keys("").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn update_of_an_absent_token_is_a_noop_not_a_resurrection() {
        let w = wrapper(false);
        let t = tok("a", "u", "acc");
        w.store_token(&t).await.unwrap();
        w.delete_token("a").await.unwrap();
        w.update_token(&t).await.unwrap();
        assert!(w.get_token("a").await.unwrap().is_none());
        assert!(w.inner.list_kv_keys("").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn update_moves_the_indexes() {
        let w = wrapper(false);
        let mut t = tok("a", "u1", "old-access");
        w.store_token(&t).await.unwrap();
        t.access_token = "new-access".into();
        t.user_id = "u2".into();
        w.update_token(&t).await.unwrap();
        assert!(
            w.get_token_by_access_token("old-access")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            w.get_token_by_access_token("new-access")
                .await
                .unwrap()
                .is_some()
        );
        assert!(w.list_user_tokens("u1").await.unwrap().is_empty());
        assert_eq!(w.list_user_tokens("u2").await.unwrap().len(), 1);
        // Exactly one record, one access index, one membership entry.
        assert_eq!(w.inner.list_kv_keys("").await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn a_forged_index_pointing_at_another_users_token_yields_none() {
        let w = wrapper(false);
        w.store_token(&tok("victim", "u-victim", "victim-access"))
            .await
            .unwrap();
        let kid = w.encryption.current_key_id().to_string();
        let victim_key = w.tok_key_for(&kid, "victim").unwrap();
        let forged = w.tokat_key_for(&kid, "attacker-access").unwrap();
        let sealed = w.seal(&forged, victim_key.as_bytes()).unwrap();
        w.inner
            .store_kv(&forged, &sealed, Some(Duration::from_secs(60)))
            .await
            .unwrap();
        assert!(
            w.get_token_by_access_token("attacker-access")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn expired_tokens_are_not_returned() {
        let w = wrapper(false);
        let mut t = tok("a", "u", "acc");
        t.expires_at = chrono::Utc::now() - chrono::Duration::seconds(5);
        w.store_token(&t).await.unwrap();
        assert!(w.get_token("a").await.unwrap().is_none());
        assert!(w.list_user_tokens("u").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn reserved_keys_are_hidden_from_the_kv_interface() {
        let w = wrapper(false);
        w.store_token(&tok("a", "u", "acc")).await.unwrap();
        let sealed_keys = w.inner.list_kv_keys("").await.unwrap();
        assert_eq!(sealed_keys.len(), 3);
        for k in &sealed_keys {
            assert!(w.get_kv(k).await.is_err(), "get_kv {k}");
            assert!(w.get_kv_ttl(k).await.is_err());
            assert!(w.delete_kv(k).await.is_err());
            assert!(w.store_kv(k, b"x", None).await.is_err());
            assert!(w.store_kv_if_absent(k, b"x", None).await.is_err());
        }
        assert!(
            w.store_kv(&sealed_keys[0].to_uppercase(), b"x", None)
                .await
                .is_err()
        );
        assert!(w.list_kv_keys("").await.unwrap().is_empty());
        w.store_kv("rbac:x", b"v", None).await.unwrap();
        assert_eq!(
            w.list_kv_keys("").await.unwrap(),
            vec!["rbac:x".to_string()]
        );
    }

    #[tokio::test]
    async fn legacy_rows_are_sealed_on_read_when_plaintext_reads_are_allowed() {
        let w = wrapper(true);
        w.inner
            .store_token(&tok("old", "u", "old-acc"))
            .await
            .unwrap();
        assert!(
            w.get_token_by_access_token("old-acc")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            w.inner.get_token("old").await.unwrap().is_none(),
            "legacy row deleted"
        );
        assert!(
            w.get_token("old").await.unwrap().is_some(),
            "now served sealed"
        );
        assert!(!raw_dump(&w).await.contains("old-acc"));
    }

    /// A revocation that deletes the legacy row between a read-through's fetch and its adoption
    /// must win: the adoption undoes its sealed copy and the token stays gone.
    #[tokio::test]
    async fn an_adoption_that_lost_to_a_delete_does_not_resurrect_the_token() {
        let w = wrapper(true);
        // The row as the read fetched it; by adoption time the delete has removed it.
        let fetched = tok("gone", "u", "gone-acc");
        assert!(w.inner.get_token("gone").await.unwrap().is_none());
        assert!(w.adopt_legacy_token(fetched).await.unwrap().is_none());
        assert!(w.get_token("gone").await.unwrap().is_none());
        assert!(
            w.get_token_by_access_token("gone-acc")
                .await
                .unwrap()
                .is_none()
        );
        assert!(raw_dump(&w).await.is_empty(), "nothing left in the backend");
    }

    #[tokio::test]
    async fn legacy_rows_are_unreachable_but_still_deletable_and_revocable_when_reads_are_off() {
        let w = wrapper(false);
        w.inner
            .store_token(&tok("old", "u", "old-acc"))
            .await
            .unwrap();
        assert!(w.get_token("old").await.unwrap().is_none());
        assert!(
            w.get_token_by_access_token("old-acc")
                .await
                .unwrap()
                .is_none()
        );
        assert!(w.list_user_tokens("u").await.unwrap().is_empty());
        // An update reaches the legacy row (revocation) without sealing it.
        let mut revoked = tok("old", "u", "old-acc");
        revoked.refresh_token = Some("changed".into());
        w.update_token(&revoked).await.unwrap();
        assert_eq!(
            w.inner
                .get_token("old")
                .await
                .unwrap()
                .unwrap()
                .refresh_token
                .as_deref(),
            Some("changed")
        );
        // A delete removes it whatever the flag says.
        w.delete_token("old").await.unwrap();
        assert!(w.inner.get_token("old").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn legacy_rows_appear_in_user_lists_only_while_reads_are_allowed() {
        let w = wrapper(true);
        w.inner
            .store_token(&tok("old", "u", "old-acc"))
            .await
            .unwrap();
        w.store_token(&tok("new", "u", "new-acc")).await.unwrap();
        assert_eq!(w.list_user_tokens("u").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn rotation_keeps_old_records_reachable_and_wipes_across_keys() {
        use crate::storage::encryption::{KeyProvider, LoadedKeys};
        struct P(&'static str);
        impl KeyProvider for P {
            fn load_keys(&self) -> Result<LoadedKeys> {
                let mut keys = HashMap::new();
                keys.insert("A".to_string(), [b'A'; 32]);
                keys.insert("B".to_string(), [b'B'; 32]);
                Ok(LoadedKeys {
                    current_key_id: self.0.to_string(),
                    keys,
                })
            }
        }
        let inner = MemoryStorage::new();
        let a = EncryptedStorage::new(
            inner,
            StorageEncryption::new(&P("A")).unwrap(),
            false,
            false,
        );
        a.store_token(&tok("t", "u", "acc")).await.unwrap();
        let b = EncryptedStorage::new(
            a.into_inner(),
            StorageEncryption::new(&P("B")).unwrap(),
            false,
            false,
        );
        assert!(b.get_token_by_access_token("acc").await.unwrap().is_some());
        assert_eq!(b.list_user_tokens("u").await.unwrap().len(), 1);
        let mut t = tok("t", "u", "acc");
        t.refresh_token = Some("r2".into());
        b.update_token(&t).await.unwrap();
        // Re-sealed under B; the A-keyed entries are gone, so there is exactly one set.
        assert_eq!(b.inner.list_kv_keys("").await.unwrap().len(), 3);
        b.delete_token("t").await.unwrap();
        assert!(b.inner.list_kv_keys("").await.unwrap().is_empty());
    }
}
