//! RBAC roles and assignments (`AuthorizationStorage`) on `PersistantStorage`, run against the
//! in-memory store as the reference, plus what only the PersistAnt layout can get wrong: ids that
//! look like other ids' prefixes, and an assignment replaced in place.
#![cfg(all(feature = "persistant-storage", feature = "sqlite-storage"))]

use auth_framework::authorization::{AbacPermission, AbacRole, AuthorizationStorage, UserRole};
use auth_framework::storage::MemoryStorage;
use auth_framework::storage::persistant::PersistantStorage;
use std::time::SystemTime;

fn role(id: &str, perm: &str) -> AbacRole {
    let mut r = AbacRole::new(id, format!("name of {id}"));
    r.permissions.insert(AbacPermission::new("docs", perm));
    r
}

fn assignment(user: &str, role: &str, by: &str) -> UserRole {
    UserRole {
        user_id: user.to_string(),
        role_id: role.to_string(),
        assigned_at: SystemTime::now(),
        expires_at: None,
        assigned_by: by.to_string(),
    }
}

fn ids(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

async fn contract<S: AuthorizationStorage>(s: &S) {
    let run = uuid::Uuid::new_v4().simple().to_string();
    let (admin, editor) = (format!("admin-{run}"), format!("editor-{run}"));
    let (alice, bob) = (format!("alice-{run}"), format!("bob-{run}"));

    s.store_role(&role(&admin, "write")).await.unwrap();
    s.store_role(&role(&editor, "read")).await.unwrap();
    let got = s.get_role(&admin).await.unwrap().unwrap();
    assert_eq!(got.id, admin);
    assert!(
        got.permissions
            .contains(&AbacPermission::new("docs", "write"))
    );
    assert!(s.get_role("no-such-role").await.unwrap().is_none());

    // update replaces
    s.update_role(&role(&admin, "delete")).await.unwrap();
    let got = s.get_role(&admin).await.unwrap().unwrap();
    assert!(
        got.permissions
            .contains(&AbacPermission::new("docs", "delete"))
    );
    assert!(
        !got.permissions
            .contains(&AbacPermission::new("docs", "write"))
    );

    let listed = ids(s
        .list_roles()
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect());
    assert!(listed.contains(&admin) && listed.contains(&editor));

    // assignments, by user and by role
    s.assign_role(&assignment(&alice, &admin, "root"))
        .await
        .unwrap();
    s.assign_role(&assignment(&alice, &editor, "root"))
        .await
        .unwrap();
    s.assign_role(&assignment(&bob, &editor, "root"))
        .await
        .unwrap();
    let alice_roles = ids(s
        .get_user_roles(&alice)
        .await
        .unwrap()
        .into_iter()
        .map(|u| u.role_id)
        .collect());
    assert_eq!(alice_roles, ids(vec![admin.clone(), editor.clone()]));
    let editors = ids(s
        .get_role_users(&editor)
        .await
        .unwrap()
        .into_iter()
        .map(|u| u.user_id)
        .collect());
    assert_eq!(editors, ids(vec![alice.clone(), bob.clone()]));

    // removing one pair touches neither the user's other role nor the role's other user
    s.remove_role(&alice, &editor).await.unwrap();
    let alice_roles = s.get_user_roles(&alice).await.unwrap();
    assert_eq!(alice_roles.len(), 1);
    assert_eq!(alice_roles[0].role_id, admin);
    let editors = s.get_role_users(&editor).await.unwrap();
    assert_eq!(editors.len(), 1);
    assert_eq!(editors[0].user_id, bob);

    // removing what is not there is not an error
    s.remove_role(&alice, &editor).await.unwrap();

    s.delete_role(&editor).await.unwrap();
    assert!(s.get_role(&editor).await.unwrap().is_none());
    assert!(!s.list_roles().await.unwrap().iter().any(|r| r.id == editor));
    s.delete_role(&editor).await.unwrap();
}

#[tokio::test]
async fn memory_storage_is_the_reference() {
    contract(&MemoryStorage::new()).await;
}

#[tokio::test]
async fn persistant_memory_meets_the_contract() {
    contract(&PersistantStorage::in_memory()).await;
}

#[tokio::test]
async fn persistant_sqlite_file_meets_the_contract() {
    let dir = tempfile::tempdir().unwrap();
    let s = PersistantStorage::open_sqlite(dir.path().join("roles.db"))
        .await
        .unwrap();
    contract(&s).await;
}

#[tokio::test]
async fn ids_that_look_like_prefixes_do_not_alias() {
    let s = PersistantStorage::in_memory();
    // "a" and "a:b" must stay separate users and roles.
    s.assign_role(&assignment("a", "r", "root")).await.unwrap();
    s.assign_role(&assignment("a:b", "r", "root"))
        .await
        .unwrap();
    s.assign_role(&assignment("a", "r:x", "root"))
        .await
        .unwrap();
    assert_eq!(s.get_user_roles("a").await.unwrap().len(), 2);
    assert_eq!(s.get_user_roles("a:b").await.unwrap().len(), 1);
    assert_eq!(s.get_role_users("r").await.unwrap().len(), 2);
    assert_eq!(s.get_role_users("r:x").await.unwrap().len(), 1);
}

#[tokio::test]
async fn assigning_the_same_pair_again_replaces_it() {
    let s = PersistantStorage::in_memory();
    s.assign_role(&assignment("u", "r", "first")).await.unwrap();
    s.assign_role(&assignment("u", "r", "second"))
        .await
        .unwrap();
    let rows = s.get_user_roles("u").await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].assigned_by, "second");
    assert_eq!(s.get_role_users("r").await.unwrap().len(), 1);
    s.remove_role("u", "r").await.unwrap();
    assert!(s.get_user_roles("u").await.unwrap().is_empty());
    assert!(s.get_role_users("r").await.unwrap().is_empty());
}
