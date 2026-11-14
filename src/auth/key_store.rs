// SPDX-License-Identifier: MIT OR Apache-2.0
//! M3 B1c: let an [`AuthFramework`] sign and verify its JWTs through a
//! [`KeyStore`](crate::keys::KeyStore).

use super::AuthFramework;
use crate::errors::Result;
use crate::keys::{KeyKind, KeyState, KeyStore, Kid, SymmetricKey, unix_now};
use crate::tokens::{KeyRing, MaintenancePolicy};
use std::sync::Arc;
use std::time::Duration;

impl AuthFramework {
    /// Sign and verify this framework's JWTs with the HMAC keys in `store`.
    ///
    /// If the store holds no `Active` HMAC key, one is created. The framework then uses a
    /// [`KeyRing`] over the store: the newest active key signs, active and retiring keys verify,
    /// and the secret in the configuration no longer applies. A background task rotates keys
    /// older than `policy.max_key_age`, destroys retired keys past `policy.overlap` and refreshes
    /// the ring every `every`; the returned handle stops it when aborted.
    ///
    /// Call this after [`initialize`](Self::initialize), which rebuilds the token manager from
    /// the configuration. Tokens signed before the switch are not accepted afterwards.
    pub async fn use_key_store(
        &mut self,
        store: Arc<dyn KeyStore>,
        policy: MaintenancePolicy,
        every: Duration,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let _guard = store.lock_rotation().await;
        let live = store
            .list()
            .await?
            .into_iter()
            .any(|k| k.kind == KeyKind::Hmac && k.state == KeyState::Active);
        if !live {
            let kid = Kid::new(format!("hmac-{}", unix_now()))?;
            let key = SymmetricKey::generate(KeyKind::Hmac, kid)?;
            store.insert_symmetric(key, KeyState::Active).await?;
        }
        drop(_guard);

        let ring = KeyRing::load(&*store).await?;
        let handle = ring.spawn_maintenance(store, every, policy);
        self.token_manager = self.token_manager.clone().with_keyring(ring);
        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use crate::keys::MemoryKeyStore;

    fn policy() -> MaintenancePolicy {
        MaintenancePolicy {
            max_key_age: Duration::from_secs(86_400),
            overlap: Duration::from_secs(86_400),
        }
    }

    fn token(f: &AuthFramework) -> String {
        f.token_manager()
            .create_jwt_token("u1", vec!["read".into()], Some(Duration::from_secs(600)))
            .unwrap()
    }

    #[tokio::test]
    async fn a_framework_on_a_key_store_signs_with_a_store_key() {
        let mut f = AuthFramework::new(AuthConfig::new());
        let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
        let h = f
            .use_key_store(store.clone(), policy(), Duration::from_secs(3600))
            .await
            .unwrap();
        let t = token(&f);
        let kid = jsonwebtoken::decode_header(&t).unwrap().kid.unwrap();
        let keys = store.list().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid.as_str(), kid);
        assert!(f.token_manager().validate_jwt_token(&t).is_ok());
        h.abort();
    }

    #[tokio::test]
    async fn an_existing_active_key_is_reused_not_replaced() {
        let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
        let kid = Kid::new("existing").unwrap();
        store
            .insert_symmetric(
                SymmetricKey::generate(KeyKind::Hmac, kid).unwrap(),
                KeyState::Active,
            )
            .await
            .unwrap();
        let mut f = AuthFramework::new(AuthConfig::new());
        let h = f
            .use_key_store(store.clone(), policy(), Duration::from_secs(3600))
            .await
            .unwrap();
        assert_eq!(store.list().await.unwrap().len(), 1);
        let t = token(&f);
        assert_eq!(
            jsonwebtoken::decode_header(&t).unwrap().kid.as_deref(),
            Some("existing")
        );
        h.abort();
    }

    #[tokio::test]
    async fn a_token_signed_with_the_configured_secret_is_refused_after_the_switch() {
        let mut f = AuthFramework::new(AuthConfig::new());
        let before = token(&f);
        let h = f
            .use_key_store(
                Arc::new(MemoryKeyStore::new()),
                policy(),
                Duration::from_secs(3600),
            )
            .await
            .unwrap();
        assert!(f.token_manager().validate_jwt_token(&before).is_err());
        h.abort();
    }
}
