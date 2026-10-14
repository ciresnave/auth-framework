//! Credentials must not be persisted as key *names*.
//!
//! `EncryptedStorage` encrypts values only, so a raw credential used as a key
//! (`api_key:{raw}`, Redis `access_token:{raw}`, `session:{id}`) is readable by
//! anyone who can read the store. These tests pin that the key names are a
//! one-way digest, that keys written under the legacy name still work (and are
//! migrated with their TTL), and that revoke/delete remove both names.
//!
//! The in-memory tests run everywhere. The Redis tests need a server and are
//! `#[ignore]`d like `tests/storage_redis.rs`:
//! `REDIS_URL=redis://127.0.0.1:6379 cargo test --test kv_key_names_hold_no_credentials \
//!  --features redis-storage -- --ignored`.

use auth_framework::auth_modular::UserManager;
use auth_framework::storage::{AuthStorage, MemoryStorage};
use std::sync::Arc;
use std::time::Duration;

fn manager(storage: Arc<dyn AuthStorage>) -> UserManager {
    UserManager::new(storage)
}

fn metadata(user_id: &str) -> Vec<u8> {
    serde_json::json!({
        "user_id": user_id,
        "created_at": chrono::Utc::now(),
        "expires_at": null,
    })
    .to_string()
    .into_bytes()
}

#[tokio::test]
async fn created_api_key_is_not_in_any_key_name() {
    let storage = Arc::new(MemoryStorage::new());
    let um = manager(storage.clone());

    let key = um.create_api_key("alice", None).await.unwrap();

    let names = storage.list_kv_keys("").await.unwrap();
    assert!(
        !names.is_empty(),
        "control: the key's metadata row must be listed, got {names:?}"
    );
    assert!(
        names.iter().all(|n| !n.contains(&key)),
        "the raw API key must not appear in any key name, got {names:?}"
    );
    // the key still authenticates
    let info = um.validate_api_key(&key).await.unwrap();
    assert_eq!(info.id, "alice");
}

#[tokio::test]
async fn legacy_api_key_name_is_migrated_and_then_gone() {
    let storage = Arc::new(MemoryStorage::new());
    let um = manager(storage.clone());
    let key = "ak_legacy_secret_value";
    let legacy = format!("api_key:{key}");
    storage
        .store_kv(&legacy, &metadata("bob"), Some(Duration::from_secs(600)))
        .await
        .unwrap();

    let info = um.validate_api_key(key).await.unwrap();
    assert_eq!(info.id, "bob", "a key minted before the fix still works");

    assert!(
        storage.get_kv(&legacy).await.unwrap().is_none(),
        "the legacy key name is deleted once migrated"
    );
    let names = storage.list_kv_keys("").await.unwrap();
    assert!(
        names.iter().all(|n| !n.contains(key)),
        "no key name holds the raw key after migration, got {names:?}"
    );
    assert_eq!(names.len(), 1, "exactly one row after migration: {names:?}");
    // second validation uses the new name
    assert_eq!(um.validate_api_key(key).await.unwrap().id, "bob");
}

#[tokio::test]
async fn revoke_removes_both_names() {
    let storage = Arc::new(MemoryStorage::new());
    let um = manager(storage.clone());

    // a key created now, and a legacy-only one
    let fresh = um.create_api_key("carol", None).await.unwrap();
    let legacy_key = "ak_legacy_only";
    storage
        .store_kv(&format!("api_key:{legacy_key}"), &metadata("dave"), None)
        .await
        .unwrap();

    um.revoke_api_key(&fresh).await.unwrap();
    um.revoke_api_key(legacy_key).await.unwrap();

    assert!(um.validate_api_key(&fresh).await.is_err());
    assert!(um.validate_api_key(legacy_key).await.is_err());
    assert!(
        storage
            .list_kv_keys("")
            .await
            .unwrap()
            .iter()
            .all(|n| n.starts_with("api_key_revoked:")),
        "revoke leaves no row under either name (only the short-lived revoke marker)"
    );
    assert!(
        um.revoke_api_key("ak_never_existed").await.is_err(),
        "revoking an unknown key is still an error"
    );
}

#[tokio::test]
async fn expired_legacy_api_key_is_rejected_and_not_migrated() {
    let storage = Arc::new(MemoryStorage::new());
    let um = manager(storage.clone());
    let key = "ak_legacy_expiring";
    // No storage TTL: the row is still present, and only its own `expires_at`
    // says it is over, so validation reaches the helper's expired-row branch.
    let row = serde_json::json!({
        "user_id": "erin",
        "created_at": chrono::Utc::now() - chrono::Duration::hours(2),
        "expires_at": chrono::Utc::now() - chrono::Duration::hours(1),
    })
    .to_string()
    .into_bytes();
    storage
        .store_kv(&format!("api_key:{key}"), &row, None)
        .await
        .unwrap();
    assert!(
        storage
            .get_kv(&format!("api_key:{key}"))
            .await
            .unwrap()
            .is_some(),
        "control: the expired row is still stored, so the storage TTL did not hide it"
    );

    assert!(um.validate_api_key(key).await.is_err());
    assert!(
        storage.list_kv_keys("api_key_h:").await.unwrap().is_empty(),
        "an expired legacy row must not be recreated under the new name"
    );
}

#[cfg(feature = "redis-storage")]
mod redis_key_names {
    use auth_framework::storage::AuthStorage;
    use auth_framework::storage::core::RedisStorage as CoreRedis;
    use auth_framework::storage::core::SessionData;
    use auth_framework::storage::redis::RedisStorage as ModRedis;
    use auth_framework::tokens::AuthToken;
    use redis::AsyncCommands;
    use std::time::Duration;

    fn url() -> String {
        std::env::var("REDIS_URL").expect("REDIS_URL must be set for the Redis tests")
    }

    async fn all_keys(prefix: &str) -> Vec<String> {
        let client = redis::Client::open(url()).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        conn.keys(format!("{prefix}*")).await.unwrap()
    }

    /// Remove everything a previous (possibly failed) run left under `prefix`.
    async fn clear(prefix: &str) {
        let client = redis::Client::open(url()).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let keys: Vec<String> = conn.keys(format!("{prefix}*")).await.unwrap();
        for key in keys {
            let _: usize = conn.del(key).await.unwrap();
        }
    }

    async fn raw_set(key: &str, value: &str, ttl_secs: u64) {
        let client = redis::Client::open(url()).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let _: () = conn.set_ex(key, value, ttl_secs).await.unwrap();
    }

    async fn raw_pttl(key: &str) -> i64 {
        let client = redis::Client::open(url()).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        conn.pttl(key).await.unwrap()
    }

    #[tokio::test]
    #[ignore]
    async fn core_redis_key_names_hold_no_raw_access_token_or_session_id() {
        let prefix = "kvkn_core:";
        clear(prefix).await;
        let storage = CoreRedis::new(&url(), prefix).unwrap();
        let access = "RAW-ACCESS-TOKEN-CANARY-core";
        let sid = "RAW-SESSION-ID-CANARY-core";
        let token = AuthToken::new("u_core", access, Duration::from_secs(600), "test");
        storage.store_token(&token).await.unwrap();
        let session = SessionData::new(sid, "u_core", Duration::from_secs(600));
        storage.store_session(sid, &session).await.unwrap();

        let keys = all_keys(prefix).await;
        assert!(
            keys.len() >= 3,
            "control: token, mapping, session keys exist: {keys:?}"
        );
        assert!(
            keys.iter().all(|k| !k.contains(access) && !k.contains(sid)),
            "no Redis key name may contain a raw credential: {keys:?}"
        );

        // behaviour is unchanged
        let by_access = storage
            .get_token_by_access_token(access)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_access.token_id, token.token_id);
        assert!(storage.get_session(sid).await.unwrap().is_some());
        assert_eq!(storage.list_user_sessions("u_core").await.unwrap().len(), 1);

        storage.delete_token(&token.token_id).await.unwrap();
        storage.delete_session(sid).await.unwrap();
        assert!(
            storage
                .get_token_by_access_token(access)
                .await
                .unwrap()
                .is_none()
        );
        assert!(storage.get_session(sid).await.unwrap().is_none());
        assert!(
            all_keys(prefix)
                .await
                .iter()
                .all(|k| k.contains("user_tokens")),
            "only the user set may remain"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn core_redis_migrates_legacy_names_with_ttl_and_delete_removes_both() {
        let prefix = "kvkn_core_legacy:";
        clear(prefix).await;
        let storage = CoreRedis::new(&url(), prefix).unwrap();
        let sid = "legacy-session-id-core";
        let session = SessionData::new(sid, "u_leg", Duration::from_secs(600));
        raw_set(
            &format!("{prefix}session:{sid}"),
            &serde_json::to_string(&session).unwrap(),
            600,
        )
        .await;

        let got = storage.get_session(sid).await.unwrap();
        assert!(
            got.is_some(),
            "a session stored under the legacy name still resolves"
        );
        let keys = all_keys(prefix).await;
        assert!(
            keys.iter().all(|k| !k.contains(sid)),
            "legacy name is gone and nothing holds the raw id: {keys:?}"
        );
        assert_eq!(keys.len(), 1, "one migrated key: {keys:?}");
        let pttl = raw_pttl(&keys[0]).await;
        assert!(
            pttl > 500_000 && pttl <= 600_000,
            "TTL carried over, got {pttl} ms"
        );

        // a legacy-only session is also removed by delete
        let sid2 = "legacy-session-two-core";
        raw_set(
            &format!("{prefix}session:{sid2}"),
            &serde_json::to_string(&SessionData::new(sid2, "u_leg", Duration::from_secs(600)))
                .unwrap(),
            600,
        )
        .await;
        storage.delete_session(sid2).await.unwrap();
        assert!(storage.get_session(sid2).await.unwrap().is_none());
        assert!(all_keys(prefix).await.iter().all(|k| !k.contains(sid2)));
        storage.delete_session(sid).await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn module_redis_key_names_hold_no_raw_access_token_or_session_id() {
        let prefix = "kvkn_mod:";
        clear(prefix).await;
        let storage = ModRedis::with_config(&url(), prefix, Duration::from_secs(600))
            .await
            .unwrap();
        let access = "RAW-ACCESS-TOKEN-CANARY-mod";
        let sid = "RAW-SESSION-ID-CANARY-mod";
        let token = AuthToken::new("u_mod", access, Duration::from_secs(600), "test");
        storage.store_token(&token).await.unwrap();
        storage
            .store_session(
                sid,
                &SessionData::new(sid, "u_mod", Duration::from_secs(600)),
            )
            .await
            .unwrap();

        let keys = all_keys(prefix).await;
        assert!(keys.len() >= 3, "control: keys exist: {keys:?}");
        assert!(
            keys.iter().all(|k| !k.contains(access) && !k.contains(sid)),
            "no Redis key name may contain a raw credential: {keys:?}"
        );
        assert!(
            storage
                .get_token_by_access_token(access)
                .await
                .unwrap()
                .is_some()
        );
        assert!(storage.get_session(sid).await.unwrap().is_some());
        storage.delete_token(&token.token_id).await.unwrap();
        storage.delete_session(sid).await.unwrap();
    }
    async fn raw_get(key: &str) -> Option<String> {
        let client = redis::Client::open(url()).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        conn.get(key).await.unwrap()
    }

    async fn raw_del(key: &str) {
        let client = redis::Client::open(url()).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let _: usize = conn.del(key).await.unwrap();
    }

    /// Turn a freshly stored access-token mapping back into the legacy layout.
    async fn demote_mapping(new_key: &str, legacy_key: &str) {
        let value = raw_get(new_key).await.expect("mapping exists");
        raw_set(legacy_key, &value, 600).await;
        raw_del(new_key).await;
    }

    #[tokio::test]
    #[ignore]
    async fn core_redis_migrates_legacy_access_token_mapping_and_delete_removes_it() {
        let prefix = "kvkn_core_map:";
        clear(prefix).await;
        let storage = CoreRedis::new(&url(), prefix).unwrap();
        let access = "legacy-access-token-core";
        let token = AuthToken::new("u_map", access, Duration::from_secs(600), "test");
        storage.store_token(&token).await.unwrap();

        let keys = all_keys(prefix).await;
        let new_key = keys
            .iter()
            .find(|k| k.contains("access_token_h:"))
            .expect("digest-named mapping")
            .clone();
        let legacy_key = format!("{prefix}access_token:{access}");
        demote_mapping(&new_key, &legacy_key).await;

        let got = storage.get_token_by_access_token(access).await.unwrap();
        assert_eq!(got.unwrap().token_id, token.token_id);
        assert!(
            raw_get(&legacy_key).await.is_none(),
            "legacy mapping is gone"
        );
        assert!(
            raw_get(&new_key).await.is_some(),
            "mapping is under the digest name"
        );

        // delete removes a mapping that is (again) only under the legacy name
        demote_mapping(&new_key, &legacy_key).await;
        storage.delete_token(&token.token_id).await.unwrap();
        assert!(raw_get(&legacy_key).await.is_none());
        assert!(
            storage
                .get_token_by_access_token(access)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    #[ignore]
    async fn module_redis_migrates_legacy_names_and_lists_a_session_once() {
        let prefix = "kvkn_mod_legacy:";
        clear(prefix).await;
        let storage = ModRedis::with_config(&url(), prefix, Duration::from_secs(600))
            .await
            .unwrap();

        // access-token mapping, legacy layout
        let access = "legacy-access-token-mod";
        let token = AuthToken::new("u_modl", access, Duration::from_secs(600), "test");
        storage.store_token(&token).await.unwrap();
        let new_key = all_keys(prefix)
            .await
            .into_iter()
            .find(|k| k.contains("access_h:"))
            .expect("digest-named mapping");
        let legacy_key = format!("{prefix}access:{access}");
        demote_mapping(&new_key, &legacy_key).await;
        let got = storage.get_token_by_access_token(access).await.unwrap();
        assert_eq!(got.unwrap().token_id, token.token_id);
        assert!(raw_get(&legacy_key).await.is_none());
        let digest_keys = all_keys(prefix).await;
        let mapping = digest_keys
            .iter()
            .find(|k| k.contains("access_h:"))
            .expect("the mapping is now stored under its digest name");
        assert_eq!(
            raw_get(mapping).await.as_deref(),
            Some(token.token_id.as_str()),
            "the digest-named mapping holds the token id"
        );
        storage.delete_token(&token.token_id).await.unwrap();

        // session, legacy layout, then the same session under both names
        let sid = "legacy-session-id-mod";
        let session = SessionData::new(sid, "u_modl", Duration::from_secs(600));
        let json = serde_json::to_string(&session).unwrap();
        raw_set(&format!("{prefix}session:{sid}"), &json, 600).await;
        assert!(storage.get_session(sid).await.unwrap().is_some());
        assert!(raw_get(&format!("{prefix}session:{sid}")).await.is_none());
        let moved = all_keys(prefix)
            .await
            .into_iter()
            .find(|k| k.contains("session_h:"))
            .expect("the session is now stored under its digest name");
        let moved_session: SessionData =
            serde_json::from_str(&raw_get(&moved).await.unwrap()).unwrap();
        assert_eq!(moved_session.user_id, "u_modl");

        raw_set(&format!("{prefix}session:{sid}"), &json, 600).await; // both names now
        let listed = storage.list_user_sessions("u_modl").await.unwrap();
        assert_eq!(listed.len(), 1, "a session under both names is listed once");
        storage.delete_session(sid).await.unwrap();
        assert!(
            all_keys(prefix).await.iter().all(|k| !k.contains(sid)),
            "delete removes both names"
        );
    }

    /// A legacy session that is only ever *listed* (never fetched by id) must
    /// not keep its raw id in key names after the upgrade: listing migrates it.
    #[tokio::test]
    #[ignore]
    async fn listing_migrates_a_legacy_session_and_keeps_its_ttl() {
        for module in [false, true] {
            let prefix = if module {
                "kvkn_list_mod:"
            } else {
                "kvkn_list_core:"
            };
            clear(prefix).await;
            let sid = if module {
                "legacy-listed-session-mod"
            } else {
                "legacy-listed-session-core"
            };
            let session = SessionData::new(sid, "u_list", Duration::from_secs(600));
            raw_set(
                &format!("{prefix}session:{sid}"),
                &serde_json::to_string(&session).unwrap(),
                600,
            )
            .await;

            let listed = if module {
                ModRedis::with_config(&url(), prefix, Duration::from_secs(600))
                    .await
                    .unwrap()
                    .list_user_sessions("u_list")
                    .await
                    .unwrap()
            } else {
                CoreRedis::new(&url(), prefix)
                    .unwrap()
                    .list_user_sessions("u_list")
                    .await
                    .unwrap()
            };
            assert_eq!(listed.len(), 1, "the legacy session is still listed");

            let keys = all_keys(prefix).await;
            assert!(
                keys.iter().all(|k| !k.contains(sid)),
                "listing left the raw session id in a key name: {keys:?}"
            );
            assert_eq!(keys.len(), 1, "one migrated key: {keys:?}");
            let pttl = raw_pttl(&keys[0]).await;
            assert!(
                pttl > 500_000 && pttl <= 600_000,
                "TTL carried over, got {pttl} ms"
            );
            clear(prefix).await;
        }
    }

    /// A record under both names (an interrupted write) is one session, and
    /// reading it by id drops the legacy twin that still holds the raw id.
    #[tokio::test]
    #[ignore]
    async fn session_under_both_names_counts_once_and_a_read_drops_the_twin() {
        let prefix = "kvkn_twin:";
        clear(prefix).await;
        let storage = CoreRedis::new(&url(), prefix).unwrap();
        let sid = "twin-session-id";
        let session = SessionData::new(sid, "u_twin", Duration::from_secs(600));
        storage.store_session(sid, &session).await.unwrap();
        raw_set(
            &format!("{prefix}session:{sid}"),
            &serde_json::to_string(&session).unwrap(),
            600,
        )
        .await;
        assert_eq!(all_keys(prefix).await.len(), 2, "control: both names exist");

        assert_eq!(
            storage.count_active_sessions().await.unwrap(),
            1,
            "one session under two names is counted once"
        );
        assert!(storage.get_session(sid).await.unwrap().is_some());
        let keys = all_keys(prefix).await;
        assert!(
            keys.iter().all(|k| !k.contains(sid)),
            "the legacy twin is dropped by a read: {keys:?}"
        );
        clear(prefix).await;
    }

    /// Under an ACL that denies scripting, a digest-named row reads normally
    /// and a legacy row is still served (unmigrated) instead of failing.
    #[tokio::test]
    #[ignore]
    async fn reads_work_when_the_acl_denies_scripting() {
        let prefix = "kvkn_acl:";
        clear(prefix).await;
        let admin = redis::Client::open(url()).unwrap();
        let mut conn = admin.get_multiplexed_async_connection().await.unwrap();
        let _: () = redis::cmd("ACL")
            .arg("SETUSER")
            .arg("kvkn_noscript")
            .arg("on")
            .arg(">pw")
            .arg("~*")
            .arg("+@all")
            .arg("-@scripting")
            .query_async(&mut conn)
            .await
            .unwrap();
        let restricted_url = url().replacen("redis://", "redis://kvkn_noscript:pw@", 1);
        let storage = CoreRedis::new(&restricted_url, prefix).unwrap();

        let fresh = "acl-fresh-session";
        storage
            .store_session(
                fresh,
                &SessionData::new(fresh, "u_acl", Duration::from_secs(600)),
            )
            .await
            .unwrap();
        assert!(
            storage.get_session(fresh).await.unwrap().is_some(),
            "a digest-named session reads without scripting"
        );

        let legacy = "acl-legacy-session";
        raw_set(
            &format!("{prefix}session:{legacy}"),
            &serde_json::to_string(&SessionData::new(legacy, "u_acl", Duration::from_secs(600)))
                .unwrap(),
            600,
        )
        .await;
        assert!(
            storage.get_session(legacy).await.unwrap().is_some(),
            "a legacy session is served when migration cannot run"
        );
        let _: () = redis::cmd("ACL")
            .arg("DELUSER")
            .arg("kvkn_noscript")
            .query_async(&mut conn)
            .await
            .unwrap();
        clear(prefix).await;
    }

    #[tokio::test]
    #[ignore]
    async fn session_count_ignores_keys_that_only_start_with_session() {
        let prefix = "kvkn_count:";
        clear(prefix).await;
        let storage = CoreRedis::new(&url(), prefix).unwrap();
        // not session records: same key prefix, names that merely begin "session"
        raw_set(&format!("{prefix}sessions:user:u1"), "x", 600).await;
        raw_set(&format!("{prefix}session_cache:abc"), "x", 600).await;
        let sid = "count-session";
        storage
            .store_session(
                sid,
                &SessionData::new(sid, "u_cnt", Duration::from_secs(600)),
            )
            .await
            .unwrap();
        assert_eq!(storage.count_active_sessions().await.unwrap(), 1);
        storage.delete_session(sid).await.unwrap();
        clear(prefix).await;
    }
}
