//! How an OAuth2 client's secret is kept in its `oauth2_client:{client_id}` record.
//!
//! A confidential client's record holds only a hash of its secret, in `client_secret_hash`
//! (Argon2id, the crate's password hasher). Records written before that change hold the secret
//! itself in `client_secret`; such a record still authenticates its client, and the first
//! successful authentication rewrites it with the hash and no plaintext (issue #90).
//!
//! Nothing in this module logs a secret or a hash.

use crate::errors::{AuthError, Result};
use crate::security::timing_protection::constant_time_string_compare;
use crate::storage::AuthStorage;
use serde_json::Value;

/// The record field that holds the Argon2id hash of the client secret.
pub(crate) const HASH_FIELD: &str = "client_secret_hash";

/// The record field of the secret itself, as written before secrets were hashed.
const LEGACY_FIELD: &str = "client_secret";

fn non_empty<'a>(record: &'a Value, field: &str) -> Option<&'a str> {
    record
        .get(field)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

/// Whether the record is that of a confidential client (it has a secret, hashed or not).
/// A client registered without one is public: it identifies itself by `client_id` alone.
pub(crate) fn is_confidential(record: &Value) -> bool {
    non_empty(record, HASH_FIELD).is_some() || non_empty(record, LEGACY_FIELD).is_some()
}

/// Hash a client secret for storage. Argon2id with 46 MiB of memory is slow on purpose, so it
/// runs on the blocking pool.
pub(crate) async fn hash_secret(secret: &str) -> Result<String> {
    let secret = secret.to_string();
    tokio::task::spawn_blocking(move || crate::utils::password::hash_password_argon2id(&secret))
        .await
        .map_err(|e| AuthError::internal(format!("Client secret hashing failed: {e}")))?
}

/// Whether `presented` is the secret of the client whose record is `record`.
///
/// A hashed record is checked against its hash. A record that still holds the plain secret is
/// checked with a constant-time comparison, and when that succeeds the record is upgraded in
/// storage; a failure to upgrade is logged and does not fail the authentication. A record
/// with no secret never authenticates here (callers decide what a public client may do).
pub(crate) async fn authenticate(
    storage: &dyn AuthStorage,
    client_id: &str,
    record: &Value,
    presented: &str,
) -> bool {
    if let Some(hash) = non_empty(record, HASH_FIELD) {
        let hash = hash.to_string();
        let presented = presented.to_string();
        return tokio::task::spawn_blocking(move || {
            crate::utils::password::verify_password_argon2id(&presented, &hash)
        })
        .await
        .ok()
        .and_then(|checked| checked.ok())
        .unwrap_or(false);
    }
    let Some(stored) = non_empty(record, LEGACY_FIELD) else {
        return false;
    };
    if !constant_time_string_compare(presented, stored) {
        return false;
    }
    if let Err(e) = upgrade(storage, client_id, record, stored).await {
        tracing::warn!("Could not hash the stored secret of client {client_id}: {e}");
    }
    true
}

/// Rewrite a legacy record with the hash of its secret and without the secret. The hash and the
/// removal of the plaintext are one write, so there is no state with neither or with a half-made
/// row; the record keeps its remaining time to live.
async fn upgrade(
    storage: &dyn AuthStorage,
    client_id: &str,
    record: &Value,
    secret: &str,
) -> Result<()> {
    let hash = hash_secret(secret).await?;
    let mut upgraded = record.clone();
    let Some(fields) = upgraded.as_object_mut() else {
        return Ok(());
    };
    fields.remove(LEGACY_FIELD);
    fields.insert(HASH_FIELD.to_string(), Value::String(hash));
    let key = format!("oauth2_client:{client_id}");
    let ttl = storage.get_kv_ttl(&key).await.ok().flatten();
    storage
        .store_kv(&key, upgraded.to_string().as_bytes(), ttl)
        .await
}
