//! KM4: rotation with overlap, for every key kind a [`KeyStore`] holds.
//!
//! Rotation never leaves a moment with no signing key: the new key goes in `Active`
//! first, then the old one moves to `Retiring`, where it still verifies (and stays in
//! the JWKS) for the overlap window. [`retire_expired`] then destroys retiring keys
//! whose window has passed. Every step is logged through `tracing`.

use super::{KeyInfo, KeyState, KeyStore, Kid, LocalKey, Signer};
use crate::errors::{AuthError, Result};

/// Replace `current` with `next`: `next` becomes `Active` and `current`, which must be
/// `Active`, becomes `Retiring`. Fails without touching anything when `current` is not
/// active. If the second step fails both keys stay `Active` (still safe to sign with),
/// and the error says so.
pub async fn rotate(store: &dyn KeyStore, current: &Kid, next: LocalKey) -> Result<Kid> {
    let old = store.info(current).await?;
    if old.state != KeyState::Active {
        return Err(AuthError::validation(format!(
            "key {current} is {:?}: only an active key can be rotated",
            old.state
        )));
    }
    if next.kind() != old.kind {
        return Err(AuthError::validation(format!(
            "replacement is a {:?} key but {current} is {:?}",
            next.kind(),
            old.kind
        )));
    }
    let next_kid = next.kid().clone();
    store.insert(next, KeyState::Active).await?;
    store
        .set_state(current, KeyState::Retiring)
        .await
        .map_err(|e| {
            AuthError::internal(format!(
                "new key {next_kid} is active but {current} could not be retired (both stay active): {e}"
            ))
        })?;
    tracing::info!(old = %current, new = %next_kid, "key rotated: old key retiring");
    Ok(next_kid)
}

/// Destroy every `Retiring` key that has been retiring for at least `overlap_secs` at
/// `now` (Unix seconds). Returns the key ids destroyed. A key that cannot be destroyed
/// is reported in the error and the rest are still attempted first.
pub async fn retire_expired(store: &dyn KeyStore, now: u64, overlap_secs: u64) -> Result<Vec<Kid>> {
    let mut done = Vec::new();
    let mut failed = Vec::new();
    for info in store.list().await? {
        if info.state != KeyState::Retiring {
            continue;
        }
        let Some(since) = info.retiring_at else {
            continue;
        };
        if now.saturating_sub(since) < overlap_secs {
            continue;
        }
        match store.set_state(&info.kid, KeyState::Destroyed).await {
            Ok(()) => {
                tracing::info!(kid = %info.kid, "retired key destroyed after overlap");
                done.push(info.kid);
            }
            Err(e) => failed.push(format!("{}: {e}", info.kid)),
        }
    }
    if failed.is_empty() {
        Ok(done)
    } else {
        Err(AuthError::internal(format!(
            "could not destroy {} retired key(s): {}",
            failed.len(),
            failed.join("; ")
        )))
    }
}

/// `Active` keys that are `max_age_secs` old or older at `now`, oldest first: the
/// ones a scheduled rotation should replace.
pub async fn due_for_rotation(
    store: &dyn KeyStore,
    now: u64,
    max_age_secs: u64,
) -> Result<Vec<KeyInfo>> {
    let mut due: Vec<KeyInfo> = store
        .list()
        .await?
        .into_iter()
        .filter(|i| i.state == KeyState::Active && now.saturating_sub(i.created_at) >= max_age_secs)
        .collect();
    due.sort_by_key(|i| i.created_at);
    Ok(due)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyKind, MemoryKeyStore, SigningAlg, publish_jwks, unix_now};

    fn key(kind: KeyKind) -> LocalKey {
        LocalKey::generate(kind, SigningAlg::Es256, None).unwrap()
    }

    async fn seeded() -> (MemoryKeyStore, Kid) {
        let s = MemoryKeyStore::new();
        let k = key(KeyKind::JwsSigning);
        let kid = k.kid().clone();
        s.insert(k, KeyState::Active).await.unwrap();
        (s, kid)
    }

    #[tokio::test]
    async fn rotation_overlaps_old_verifies_new_signs() {
        let (s, old) = seeded().await;
        let new = rotate(&s, &old, key(KeyKind::JwsSigning)).await.unwrap();
        assert_eq!(s.info(&old).await.unwrap().state, KeyState::Retiring);
        assert_eq!(s.info(&new).await.unwrap().state, KeyState::Active);
        assert!(s.info(&old).await.unwrap().retiring_at.is_some());
        assert!(s.sign(&old, b"m").await.is_err(), "old cannot sign");
        assert!(s.sign(&new, b"m").await.is_ok(), "new signs");
        let published = publish_jwks(&s).await.unwrap().keys.len();
        assert_eq!(published, 2, "both are in the JWKS during the overlap");
    }

    #[tokio::test]
    async fn only_an_active_key_of_the_same_kind_can_be_rotated() {
        let (s, old) = seeded().await;
        assert!(rotate(&s, &old, key(KeyKind::Dpop)).await.is_err(), "kind");
        assert_eq!(
            s.list().await.unwrap().len(),
            1,
            "nothing inserted on refusal"
        );
        s.set_state(&old, KeyState::Revoked).await.unwrap();
        assert!(
            rotate(&s, &old, key(KeyKind::JwsSigning)).await.is_err(),
            "revoked"
        );
        assert!(
            rotate(&s, &Kid::new("nope").unwrap(), key(KeyKind::JwsSigning))
                .await
                .is_err()
        );
        assert_eq!(s.list().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn retire_expired_waits_for_the_overlap_window() {
        let (s, old) = seeded().await;
        let new = rotate(&s, &old, key(KeyKind::JwsSigning)).await.unwrap();
        let t = unix_now();
        assert!(
            retire_expired(&s, t, 3600).await.unwrap().is_empty(),
            "inside window"
        );
        assert_eq!(s.info(&old).await.unwrap().state, KeyState::Retiring);
        let gone = retire_expired(&s, t + 3601, 3600).await.unwrap();
        assert_eq!(gone, vec![old.clone()]);
        assert_eq!(s.info(&old).await.unwrap().state, KeyState::Destroyed);
        assert_eq!(
            s.info(&new).await.unwrap().state,
            KeyState::Active,
            "active untouched"
        );
        assert!(s.export_private_pkcs8(&old).await.is_err());
        assert_eq!(publish_jwks(&s).await.unwrap().keys.len(), 1);
    }

    #[tokio::test]
    async fn due_for_rotation_lists_only_old_active_keys_oldest_first() {
        let (s, a) = seeded().await;
        let t = unix_now();
        assert!(due_for_rotation(&s, t, 1000).await.unwrap().is_empty());
        let due = due_for_rotation(&s, t + 1000, 1000).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].kid, a);
        let b = rotate(&s, &a, key(KeyKind::JwsSigning)).await.unwrap();
        let due = due_for_rotation(&s, t + 1000, 1000).await.unwrap();
        assert_eq!(due.len(), 1, "the retiring key is not due");
        assert_eq!(due[0].kid, b);
    }

    #[tokio::test]
    async fn retiring_time_survives_a_reopen() {
        use crate::keys::FileKeyStore;
        use crate::storage::StorageEncryption;
        use crate::storage::encryption::{KeyProvider, LoadedKeys};
        use std::collections::HashMap;
        struct P;
        impl KeyProvider for P {
            fn load_keys(&self) -> Result<LoadedKeys> {
                Ok(LoadedKeys {
                    current_key_id: "k".into(),
                    keys: HashMap::from([("k".to_string(), [9u8; 32])]),
                })
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let old;
        {
            let s = FileKeyStore::open(dir.path(), StorageEncryption::new(&P).unwrap())
                .await
                .unwrap();
            let k = key(KeyKind::JwsSigning);
            old = k.kid().clone();
            s.insert(k, KeyState::Active).await.unwrap();
            rotate(&s, &old, key(KeyKind::JwsSigning)).await.unwrap();
        }
        let s = FileKeyStore::open(dir.path(), StorageEncryption::new(&P).unwrap())
            .await
            .unwrap();
        let info = s.info(&old).await.unwrap();
        assert_eq!(info.state, KeyState::Retiring);
        let since = info.retiring_at.expect("retiring time persisted");
        assert!(retire_expired(&s, since + 10, 60).await.unwrap().is_empty());
        assert_eq!(retire_expired(&s, since + 60, 60).await.unwrap().len(), 1);
    }
}
