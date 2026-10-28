//! [`AuthStorage`] over a PersistAnt key-value backend (`persistant-storage` feature).
//!
//! The key layout follows PersistAnt's `docs/DESIGN-AUTH-STORAGE.md` section 4.3. Every record is
//! one key; secondary lookups are index entries that hold the primary key and are written and
//! removed in the same atomic batch as the record, through [`Indexed`]:
//!
//! | Key | Value |
//! |---|---|
//! | `tok:{token_id}` | the token, as JSON |
//! | `tokat:{sha256(access_token)}` | `tok:{token_id}` |
//! | `tokuser:{base64url(user_id)}:{token_id}` | `tok:{token_id}` |
//! | `ses:{session_id}` | the session, as JSON |
//! | `sesuser:{base64url(user_id)}:{session_id}` | `ses:{session_id}` |
//! | `kv:{key}` | the bytes given to [`AuthStorage::store_kv`] |
//!
//! The access token is hashed and the user id encoded so that a key never carries the secret and a
//! user id containing `:` cannot select another user's entries. Every key of a record carries the
//! record's own time to live (`expires_at`), so they expire together; an expired record is gone at
//! once, where [`SqliteStorage`](crate::storage::sqlite::SqliteStorage) keeps returning it until
//! `cleanup_expired` runs (no caller reads a token past `expires_at`: `validate_token` checks it
//! before any lookup).
//!
//! Needs a backend with atomic batches: PersistAnt's memory backend and its SQLite, PostgreSQL and
//! MySQL/MariaDB ones; not its opendal-backed stores.

use crate::errors::{AuthError, Result, StorageError};
use crate::storage::core::{AuthStorage, SessionData};
use crate::tokens::AuthToken;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use persistant_kv::index::Indexed;
use persistant_kv::{BatchOp, KvBackend, KvError, KvOnRelational, MemoryKv};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// How many times an optimistic read-modify-write is retried before it gives up.
const ATTEMPTS: usize = 16;

/// Keys per page when listing `kv:` keys.
const PAGE: usize = 1000;

/// The shortest time to live handed to the backend: an entry that is already expired is stored so
/// that it is invisible straight away, not refused.
const MIN_TTL: Duration = Duration::from_millis(1);

fn storage_err(error: KvError) -> AuthError {
    AuthError::Storage(StorageError::operation_failed(error.to_string()))
}

fn contended(what: &str) -> AuthError {
    AuthError::Storage(StorageError::operation_failed(format!(
        "{what}: the record changed on every attempt"
    )))
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| AuthError::internal(e.to_string()))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|e| AuthError::internal(e.to_string()))
}

/// The time left until `expires_at`, never below [`MIN_TTL`].
fn ttl_until(expires_at: chrono::DateTime<chrono::Utc>) -> Duration {
    (expires_at - chrono::Utc::now())
        .to_std()
        .unwrap_or(MIN_TTL)
        .max(MIN_TTL)
}

fn token_key(token_id: &str) -> String {
    format!("tok:{token_id}")
}

fn token_by_access_key(access_token: &str) -> String {
    format!(
        "tokat:{}",
        hex::encode(Sha256::digest(access_token.as_bytes()))
    )
}

fn user_prefix(kind: &str, user_id: &str) -> String {
    format!("{kind}:{}:", URL_SAFE_NO_PAD.encode(user_id.as_bytes()))
}

fn token_indexes(token: &AuthToken) -> [String; 2] {
    [
        token_by_access_key(&token.access_token),
        format!(
            "{}{}",
            user_prefix("tokuser", &token.user_id),
            token.token_id
        ),
    ]
}

fn session_key(session_id: &str) -> String {
    format!("ses:{session_id}")
}

fn session_indexes(user_id: &str, session_id: &str) -> [String; 1] {
    [format!("{}{session_id}", user_prefix("sesuser", user_id))]
}

fn kv_key(key: &str) -> String {
    format!("kv:{key}")
}

fn refs(keys: &[String]) -> Vec<&str> {
    keys.iter().map(String::as_str).collect()
}

/// [`AuthStorage`] on any PersistAnt [`KvBackend`] that has atomic batches.
pub struct PersistantStorage<K> {
    kv: K,
}

impl<K> std::fmt::Debug for PersistantStorage<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistantStorage").finish_non_exhaustive()
    }
}

impl<K: KvBackend> PersistantStorage<K> {
    /// Store on `kv`.
    pub fn new(kv: K) -> Self {
        Self { kv }
    }

    /// The backend underneath.
    pub fn backend(&self) -> &K {
        &self.kv
    }

    /// Insert or replace the record at `primary`, moving its index entries with it.
    async fn upsert(
        &self,
        primary: &str,
        value: Vec<u8>,
        indexes: &[String],
        old_indexes: impl Fn(&[u8]) -> Result<Vec<String>>,
        ttl: Duration,
    ) -> Result<()> {
        let index = Indexed::new(&self.kv);
        for _ in 0..ATTEMPTS {
            match self.kv.get(primary).await.map_err(storage_err)? {
                None => {
                    if index
                        .insert(primary, value.clone(), &refs(indexes), Some(ttl))
                        .await
                        .map_err(storage_err)?
                    {
                        return Ok(());
                    }
                }
                Some(existing) => {
                    let old = old_indexes(&existing)?;
                    if index
                        .replace(
                            primary,
                            &existing,
                            value.clone(),
                            &refs(&old),
                            &refs(indexes),
                            Some(ttl),
                        )
                        .await
                        .map_err(storage_err)?
                    {
                        return Ok(());
                    }
                }
            }
        }
        Err(contended("upsert"))
    }

    /// Remove the record at `primary` and its index entries, whatever it holds now.
    async fn discard(
        &self,
        primary: &str,
        indexes_of: impl Fn(&[u8]) -> Result<Vec<String>>,
    ) -> Result<()> {
        let index = Indexed::new(&self.kv);
        for _ in 0..ATTEMPTS {
            let Some(existing) = self.kv.get(primary).await.map_err(storage_err)? else {
                return Ok(());
            };
            let indexes = indexes_of(&existing)?;
            if index
                .remove(primary, &existing, &refs(&indexes))
                .await
                .map_err(storage_err)?
            {
                return Ok(());
            }
        }
        Err(contended("delete"))
    }
}

impl PersistantStorage<MemoryKv> {
    /// Storage in process memory, for tests and single-process use.
    pub fn in_memory() -> Self {
        Self::new(MemoryKv::new())
    }
}

impl PersistantStorage<KvOnRelational<persistant_sqlx::SqliteBackend>> {
    /// Storage in the SQLite file at `path`, created owner-only on Unix if missing.
    pub async fn open_sqlite(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let db = persistant_sqlx::SqliteBackend::open(path)
            .await
            .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;
        let kv = KvOnRelational::open(db).await.map_err(storage_err)?;
        Ok(Self::new(kv))
    }
}

#[async_trait]
impl<K: KvBackend + 'static> AuthStorage for PersistantStorage<K> {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        let primary = token_key(&token.token_id);
        self.upsert(
            &primary,
            encode(token)?,
            &token_indexes(token),
            |old| Ok(token_indexes(&decode::<AuthToken>(old)?).to_vec()),
            ttl_until(token.expires_at),
        )
        .await
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        let token: Option<AuthToken> = self
            .kv
            .get(&token_key(token_id))
            .await
            .map_err(storage_err)?
            .map(|bytes| decode(&bytes))
            .transpose()?;
        // An expired token is not returned (the trait asks backends to honour expiry).
        Ok(token.filter(|t| !t.is_expired()))
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        let found = Indexed::new(&self.kv)
            .lookup_one(&token_by_access_key(access_token))
            .await
            .map_err(storage_err)?;
        match found {
            Some((_, bytes)) => Ok(Some(decode::<AuthToken>(&bytes)?).filter(|t| !t.is_expired())),
            None => Ok(None),
        }
    }

    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        self.store_token(token).await
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        self.discard(&token_key(token_id), |old| {
            Ok(token_indexes(&decode::<AuthToken>(old)?).to_vec())
        })
        .await
    }

    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        Indexed::new(&self.kv)
            .lookup(&user_prefix("tokuser", user_id))
            .await
            .map_err(storage_err)?
            .into_iter()
            .map(|(_, bytes)| decode(&bytes))
            .collect()
    }

    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()> {
        self.upsert(
            &session_key(session_id),
            encode(data)?,
            &session_indexes(&data.user_id, session_id),
            |old| Ok(session_indexes(&decode::<SessionData>(old)?.user_id, session_id).to_vec()),
            ttl_until(data.expires_at),
        )
        .await
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        let session: Option<SessionData> = self
            .kv
            .get(&session_key(session_id))
            .await
            .map_err(storage_err)?
            .map(|bytes| decode(&bytes))
            .transpose()?;
        Ok(session.filter(|s| s.expires_at > chrono::Utc::now()))
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        self.discard(&session_key(session_id), |old| {
            Ok(session_indexes(&decode::<SessionData>(old)?.user_id, session_id).to_vec())
        })
        .await
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        Indexed::new(&self.kv)
            .lookup(&user_prefix("sesuser", user_id))
            .await
            .map_err(storage_err)?
            .into_iter()
            .map(|(_, bytes)| decode(&bytes))
            .collect()
    }

    async fn count_active_sessions(&self) -> Result<u64> {
        self.kv.count("ses:").await.map_err(storage_err)
    }

    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()> {
        self.kv
            .put(&kv_key(key), value.to_vec(), ttl)
            .await
            .map_err(storage_err)
    }

    async fn store_kv_if_absent(
        &self,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> Result<bool> {
        self.kv
            .put_if_absent(&kv_key(key), value.to_vec(), ttl)
            .await
            .map_err(storage_err)
    }

    async fn swap_kv(
        &self,
        remove: &[String],
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> Result<bool> {
        let target = kv_key(key);
        let removing: Vec<String> = remove.iter().map(|k| kv_key(k)).collect();
        for _ in 0..ATTEMPTS {
            // One live key to require; the others are removed whether live or not. A `Require`
            // is all-of, the contract is any-of, so a batch refused because the key we picked went
            // away is re-planned from a fresh read.
            let mut live = None;
            for name in &removing {
                if let Some(held) = self.kv.get(name).await.map_err(storage_err)? {
                    live = Some((name, held));
                    break;
                }
            }
            let Some((name, held)) = live else {
                return Ok(false);
            };
            if self.kv.get(&target).await.map_err(storage_err)?.is_some() {
                return Ok(false);
            }
            let mut ops = vec![
                BatchOp::require(name.as_str(), Some(held)),
                BatchOp::require(target.as_str(), None),
            ];
            ops.extend(removing.iter().map(|k| BatchOp::delete(k.as_str())));
            ops.push(BatchOp::Put {
                key: target.clone(),
                value: value.to_vec(),
                ttl,
            });
            if self.kv.batch(&ops).await.map_err(storage_err)? {
                return Ok(true);
            }
        }
        Err(contended("swap_kv"))
    }

    fn supports_atomic_swap(&self) -> bool {
        true
    }

    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.kv.get(&kv_key(key)).await.map_err(storage_err)
    }

    async fn get_kv_ttl(&self, key: &str) -> Result<Option<Duration>> {
        self.kv
            .ttl_remaining(&kv_key(key))
            .await
            .map_err(storage_err)
    }

    fn tracks_kv_ttl(&self) -> bool {
        true
    }

    async fn delete_kv(&self, key: &str) -> Result<()> {
        self.kv.delete(&kv_key(key)).await.map_err(storage_err)
    }

    async fn list_kv_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let full = kv_key(prefix);
        let mut out = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = self
                .kv
                .prefix_list(&full, after.as_deref(), PAGE)
                .await
                .map_err(storage_err)?;
            out.extend(
                page.keys
                    .into_iter()
                    .filter_map(|k| k.strip_prefix("kv:").map(str::to_string)),
            );
            match page.next {
                Some(cursor) => after = Some(cursor),
                None => return Ok(out),
            }
        }
    }

    async fn cleanup_expired(&self) -> Result<()> {
        // Visibility is already right without it (an expired entry is invisible); this is
        // housekeeping, so a backend that cannot do it is not an error.
        match self.kv.purge_expired().await {
            Ok(_) | Err(KvError::Unsupported(_)) => Ok(()),
            Err(e) => Err(storage_err(e)),
        }
    }
}
