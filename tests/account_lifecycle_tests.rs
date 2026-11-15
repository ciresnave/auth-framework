//! What an account was issued stops working when the account is deactivated, deleted or has its
//! password changed: API keys, access tokens and sessions. A later credential for a still-live
//! account works.
#![cfg(feature = "api-server")]

use auth_framework::api::validate_api_token;
use auth_framework::auth_modular::session_manager::SessionManager;
use auth_framework::{AuthConfig, AuthFramework};
use std::sync::Arc;
use std::time::Duration;

const PASSWORD: &str = "SecurePass123!x";

async fn framework() -> Arc<AuthFramework> {
    let config = AuthConfig::new()
        .secret("test_account_lifecycle_secret_key_long_enough_for_jwt".to_string())
        .token_lifetime(Duration::from_secs(3600));
    let mut f = AuthFramework::new(config);
    f.initialize().await.unwrap();
    Arc::new(f)
}

struct Held {
    id: String,
    name: String,
    api_key: String,
    access: String,
    session: String,
}

async fn issue(f: &Arc<AuthFramework>, sessions: &SessionManager) -> Held {
    let name = format!("lc_{}", uuid::Uuid::new_v4().simple());
    let id = f
        .register_user(&name, &format!("{name}@test.example.com"), PASSWORD)
        .await
        .unwrap();
    let api_key = f.create_api_key(&id, None).await.unwrap();
    let access = f
        .token_manager()
        .create_jwt_token(
            &id,
            vec!["read".to_string()],
            Some(Duration::from_secs(600)),
        )
        .unwrap();
    let session = sessions
        .create_session(&id, Duration::from_secs(600), None, None)
        .await
        .unwrap();
    Held {
        id,
        name,
        api_key,
        access,
        session,
    }
}

async fn all_work(f: &Arc<AuthFramework>, sessions: &SessionManager, h: &Held) -> bool {
    f.validate_api_key(&h.api_key).await.is_ok()
        && validate_api_token(f, &h.access).await.is_ok()
        && sessions
            .validate_session(&h.session)
            .await
            .unwrap()
            .is_some()
}

async fn assert_all_dead(f: &Arc<AuthFramework>, sessions: &SessionManager, h: &Held) {
    assert!(f.validate_api_key(&h.api_key).await.is_err(), "api key");
    assert!(validate_api_token(f, &h.access).await.is_err(), "access");
    assert!(
        sessions
            .validate_session(&h.session)
            .await
            .unwrap()
            .is_none(),
        "session"
    );
}

#[tokio::test]
async fn deactivating_an_account_ends_what_it_holds_and_reactivating_does_not_revive_it() {
    let f = framework().await;
    let sessions = SessionManager::new(f.storage());
    let h = issue(&f, &sessions).await;
    assert!(all_work(&f, &sessions, &h).await);

    f.set_user_active(&h.id, false).await.unwrap();
    assert_all_dead(&f, &sessions, &h).await;

    f.set_user_active(&h.id, true).await.unwrap();
    assert_all_dead(&f, &sessions, &h).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let key = f.create_api_key(&h.id, None).await.unwrap();
    assert!(f.validate_api_key(&key).await.is_ok());
}

#[tokio::test]
async fn deleting_an_account_ends_what_it_holds() {
    let f = framework().await;
    let sessions = SessionManager::new(f.storage());
    let h = issue(&f, &sessions).await;
    assert!(all_work(&f, &sessions, &h).await);
    f.delete_user(&h.name).await.unwrap();
    assert_all_dead(&f, &sessions, &h).await;
}

#[tokio::test]
async fn changing_the_password_ends_what_the_old_one_issued() {
    let f = framework().await;
    let sessions = SessionManager::new(f.storage());
    let h = issue(&f, &sessions).await;
    let other = issue(&f, &sessions).await;
    assert!(all_work(&f, &sessions, &h).await);

    f.update_user_password(&h.name, "AnotherPass456!y")
        .await
        .unwrap();
    assert_all_dead(&f, &sessions, &h).await;
    assert!(all_work(&f, &sessions, &other).await);

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let key = f.create_api_key(&h.id, None).await.unwrap();
    assert!(f.validate_api_key(&key).await.is_ok());
    let access = f
        .token_manager()
        .create_jwt_token(
            &h.id,
            vec!["read".to_string()],
            Some(Duration::from_secs(600)),
        )
        .unwrap();
    assert!(validate_api_token(&f, &access).await.is_ok());
}
