//! `PersistantStorage` (feature `persistant-storage`) against `SqliteStorage`: the same `AuthStorage`
//! contract, run on both, plus what only the PersistAnt layout can get wrong (index consistency under
//! `update_token`, user ids that look like other users' prefixes, concurrent writers).
#![cfg(feature = "persistant-storage")]

use auth_framework::storage::persistant::PersistantStorage;
use auth_framework::storage::{AuthStorage, SessionData};
use auth_framework::testing::helpers::create_test_token;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

fn session(id: &str, user: &str, lives: i64) -> SessionData {
    let now = chrono::Utc::now();
    SessionData {
        session_id: id.to_string(),
        user_id: user.to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::seconds(lives),
        last_activity: now,
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: None,
        data: HashMap::new(),
    }
}

/// What every backend must do. Run on `SqliteStorage` too, so a difference is a difference between
/// the two, not a mistake in the test.
async fn contract(s: Arc<dyn AuthStorage>) {
    let run = uuid::Uuid::new_v4().simple().to_string();
    let alice = format!("alice-{run}");
    let bob = format!("bob-{run}");

    // tokens: store, get by id, get by access token, list by user
    let t1 = create_test_token(&alice);
    let t2 = create_test_token(&alice);
    let t3 = create_test_token(&bob);
    for t in [&t1, &t2, &t3] {
        s.store_token(t).await.unwrap();
    }
    let got = s.get_token(&t1.token_id).await.unwrap().unwrap();
    assert_eq!(got.access_token, t1.access_token);
    let by_access = s
        .get_token_by_access_token(&t2.access_token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_access.token_id, t2.token_id);
    assert!(s.get_token_by_access_token("nope").await.unwrap().is_none());
    assert!(s.get_token("nope").await.unwrap().is_none());
    let mut mine: Vec<_> = s
        .list_user_tokens(&alice)
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.token_id)
        .collect();
    mine.sort();
    let mut want = vec![t1.token_id.clone(), t2.token_id.clone()];
    want.sort();
    assert_eq!(mine, want);
    assert_eq!(s.list_user_tokens(&bob).await.unwrap().len(), 1);

    // update_token that changes the access token: the old one stops resolving, the new one resolves
    let mut moved = t1.clone();
    moved.access_token = format!("rotated-{run}");
    s.update_token(&moved).await.unwrap();
    assert!(
        s.get_token_by_access_token(&t1.access_token)
            .await
            .unwrap()
            .is_none(),
        "the old access token still resolves"
    );
    assert_eq!(
        s.get_token_by_access_token(&moved.access_token)
            .await
            .unwrap()
            .unwrap()
            .token_id,
        t1.token_id
    );
    assert_eq!(s.list_user_tokens(&alice).await.unwrap().len(), 2);

    // delete_token removes the record and its lookups; deleting again is fine
    s.delete_token(&t2.token_id).await.unwrap();
    s.delete_token(&t2.token_id).await.unwrap();
    assert!(s.get_token(&t2.token_id).await.unwrap().is_none());
    assert!(
        s.get_token_by_access_token(&t2.access_token)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(s.list_user_tokens(&alice).await.unwrap().len(), 1);

    // sessions
    let s1 = format!("s1-{run}");
    let s2 = format!("s2-{run}");
    s.store_session(&s1, &session(&s1, &alice, 600))
        .await
        .unwrap();
    s.store_session(&s2, &session(&s2, &alice, 600))
        .await
        .unwrap();
    assert!(s.get_session(&s1).await.unwrap().is_some());
    assert_eq!(s.list_user_sessions(&alice).await.unwrap().len(), 2);
    assert!(s.list_user_sessions(&bob).await.unwrap().is_empty());
    s.delete_session(&s1).await.unwrap();
    assert!(s.get_session(&s1).await.unwrap().is_none());
    assert_eq!(s.list_user_sessions(&alice).await.unwrap().len(), 1);
    assert!(s.count_active_sessions().await.unwrap() >= 1);

    // kv: values, ttl, listing by prefix, if-absent
    let k = |n: &str| format!("pk_{run}:{n}");
    s.store_kv(&k("a"), b"1", None).await.unwrap();
    s.store_kv(&k("b"), b"2", Some(Duration::from_secs(60)))
        .await
        .unwrap();
    assert_eq!(s.get_kv(&k("a")).await.unwrap().unwrap(), b"1");
    let mut keys = s.list_kv_keys(&format!("pk_{run}:")).await.unwrap();
    keys.sort();
    assert_eq!(keys, vec![k("a"), k("b")]);
    assert!(s.tracks_kv_ttl());
    let left = s.get_kv_ttl(&k("b")).await.unwrap().unwrap();
    assert!(left > Duration::ZERO && left <= Duration::from_secs(60));
    assert_eq!(s.get_kv_ttl(&k("a")).await.unwrap(), None);
    s.delete_kv(&k("a")).await.unwrap();
    assert!(s.get_kv(&k("a")).await.unwrap().is_none());
    assert!(s.store_kv_if_absent(&k("c"), b"x", None).await.unwrap());
    assert!(!s.store_kv_if_absent(&k("c"), b"y", None).await.unwrap());
    s.cleanup_expired().await.unwrap();
}

/// A user whose id is the prefix of another's, or contains the separator, never sees the other's
/// entries (the layout encodes the user id for this).
async fn user_ids_do_not_alias(s: Arc<dyn AuthStorage>) {
    let run = uuid::Uuid::new_v4().simple().to_string();
    let a = format!("a{run}");
    let ab = format!("a{run}:b");
    let ta = create_test_token(&a);
    let tab = create_test_token(&ab);
    s.store_token(&ta).await.unwrap();
    s.store_token(&tab).await.unwrap();
    let only_a = s.list_user_tokens(&a).await.unwrap();
    assert_eq!(only_a.len(), 1);
    assert_eq!(only_a[0].token_id, ta.token_id);
    let only_ab = s.list_user_tokens(&ab).await.unwrap();
    assert_eq!(only_ab.len(), 1);
    assert_eq!(only_ab[0].token_id, tab.token_id);
}

/// Several tasks store the same token with different access tokens at once: whichever wins, exactly
/// one access token resolves afterwards and the user has one token (index and record never diverge).
async fn concurrent_updates_keep_index_and_record_together(s: Arc<dyn AuthStorage>) {
    let run = uuid::Uuid::new_v4().simple().to_string();
    let user = format!("race-{run}");
    let base = create_test_token(&user);
    s.store_token(&base).await.unwrap();
    let mut tasks = Vec::new();
    for i in 0..8 {
        let s = s.clone();
        let mut t = base.clone();
        t.access_token = format!("race-{run}-{i}");
        tasks.push(tokio::spawn(async move { s.update_token(&t).await }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    let stored = s.get_token(&base.token_id).await.unwrap().unwrap();
    let mut resolving = 0;
    for i in 0..8 {
        if s.get_token_by_access_token(&format!("race-{run}-{i}"))
            .await
            .unwrap()
            .is_some()
        {
            resolving += 1;
        }
    }
    assert_eq!(resolving, 1, "{resolving} access tokens resolve");
    assert!(
        s.get_token_by_access_token(&stored.access_token)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(s.list_user_tokens(&user).await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistant_memory_meets_the_contract() {
    let s: Arc<dyn AuthStorage> = Arc::new(PersistantStorage::in_memory());
    contract(s.clone()).await;
    user_ids_do_not_alias(s.clone()).await;
    concurrent_updates_keep_index_and_record_together(s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistant_sqlite_file_meets_the_contract() {
    let dir = tempfile::tempdir().unwrap();
    let s: Arc<dyn AuthStorage> = Arc::new(
        PersistantStorage::open_sqlite(dir.path().join("auth.sqlite"))
            .await
            .unwrap(),
    );
    contract(s.clone()).await;
    user_ids_do_not_alias(s.clone()).await;
    concurrent_updates_keep_index_and_record_together(s).await;
}

#[cfg(feature = "sqlite-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_storage_meets_the_same_contract() {
    use auth_framework::storage::sqlite::SqliteStorage;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let storage = SqliteStorage::new(pool);
    storage.migrate().await.unwrap();
    contract(Arc::new(storage)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_token_is_invisible_at_once() {
    let s = PersistantStorage::in_memory();
    let mut t = create_test_token("exp");
    t.expires_at = chrono::Utc::now() - chrono::Duration::seconds(5);
    s.store_token(&t).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(s.get_token(&t.token_id).await.unwrap().is_none());
    assert!(
        s.get_token_by_access_token(&t.access_token)
            .await
            .unwrap()
            .is_none()
    );
    assert!(s.list_user_tokens("exp").await.unwrap().is_empty());
}
