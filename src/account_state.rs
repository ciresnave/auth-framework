//! Account-level credential cut-off.
//!
//! When an account is deactivated, deleted or has its password changed, what it was issued
//! before stops working: its sessions and stored tokens are deleted, and a not-before instant is
//! recorded so that access tokens, refresh tokens and API keys issued earlier fail validation
//! without having to be listed.

use crate::errors::{AuthError, Result};
use crate::storage::AuthStorage;

fn rejected(message: &str) -> AuthError {
    AuthError::token(message.to_string())
}

/// The storage key of the instant before which an account's credentials no longer count.
fn credentials_not_before_key(user_id: &str) -> String {
    format!("user:{user_id}:credentials_not_before")
}

/// End every credential issued to `user_id` up to now.
pub(crate) async fn revoke_user_credentials(
    storage: &dyn AuthStorage,
    user_id: &str,
) -> Result<()> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    storage
        .store_kv(
            &credentials_not_before_key(user_id),
            now_ms.to_string().as_bytes(),
            None,
        )
        .await?;
    for session in storage.list_user_sessions(user_id).await? {
        storage.delete_session(&session.session_id).await?;
    }
    for token in storage.list_user_tokens(user_id).await? {
        storage.delete_token(&token.token_id).await?;
    }
    Ok(())
}

/// Refuse a credential that was issued at or before the account's not-before instant.
/// `issued_ms` is the issue time in milliseconds since the Unix epoch (a JWT's `iat` is whole
/// seconds, so callers pass its start). An unreadable marker refuses.
pub(crate) async fn ensure_issued_after_revocation(
    storage: &dyn AuthStorage,
    user_id: &str,
    issued_ms: i64,
) -> Result<()> {
    match storage.get_kv(&credentials_not_before_key(user_id)).await {
        Ok(None) => Ok(()),
        Ok(Some(bytes)) => match String::from_utf8_lossy(&bytes).trim().parse::<i64>() {
            Ok(not_before) if issued_ms > not_before => Ok(()),
            Ok(_) => Err(rejected(
                "Credential was issued before the account's credentials were reset",
            )),
            Err(_) => Err(rejected("Unable to verify credential status")),
        },
        Err(e) => {
            tracing::error!("Could not read credential state: {}", e);
            Err(rejected("Unable to verify credential status"))
        }
    }
}

/// Refuse the credentials of an account whose record says it is deactivated, or whose record
/// cannot be read. An account with no record is not refused here (its credentials are ended by
/// the not-before instant when it is deleted).
pub(crate) async fn ensure_account_active(storage: &dyn AuthStorage, user_id: &str) -> Result<()> {
    match storage.get_kv(&format!("user:{user_id}")).await {
        Ok(None) => Ok(()),
        Ok(Some(bytes)) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(record) if record["active"].as_bool().unwrap_or(true) => Ok(()),
            Ok(_) => Err(rejected("Account has been deactivated")),
            Err(_) => Err(rejected("Unable to verify account status")),
        },
        Err(e) => {
            tracing::error!("Could not read account record: {}", e);
            Err(rejected("Unable to verify account status"))
        }
    }
}
