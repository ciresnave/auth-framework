//! What an account was issued stops working when the account is deactivated, deleted or has its
//! password changed: API keys, access and refresh tokens, stored tokens and sessions. A later
//! credential for a still-live account works.

use auth_framework::auth_modular::session_manager::SessionManager;
use auth_framework::{AuthConfig, AuthFramework};
use std::sync::Arc;
use std::time::Duration;

const PASSWORD: &str = "SecurePass123!x";

async fn framework() -> Arc<AuthFramework> {
    let config = AuthConfig::new()
        .secret("test_account_lifecycle_secret_key_long_enough_for_jwt".to_string())
        .token_lifetime(Duration::from_secs(3600))
        .refresh_token_lifetime(Duration::from_secs(86400));
    let mut f = AuthFramework::new(config);
    f.initialize().await.unwrap();
    Arc::new(f)
}

/// Everything one account holds.
struct Held {
    id: String,
    name: String,
    api_key: String,
    access: String,
    refresh: String,
    session: String,
}

async fn issue(f: &Arc<AuthFramework>, sessions: &SessionManager) -> Held {
    let name = format!("lc_{}", uuid::Uuid::new_v4().simple());
    let id = f
        .register_user(&name, &format!("{name}@test.example.com"), PASSWORD)
        .await
        .unwrap();
    let api_key = f.create_api_key(&id, None).await.unwrap();
    let tm = f.token_manager();
    let access = tm
        .create_jwt_token(
            &id,
            vec!["read".to_string()],
            Some(Duration::from_secs(600)),
        )
        .unwrap();
    let refresh = tm
        .create_refresh_jwt_token(&id, Some(Duration::from_secs(600)))
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
        refresh,
        session,
    }
}

async fn all_work(f: &Arc<AuthFramework>, sessions: &SessionManager, h: &Held) -> bool {
    f.validate_api_key(&h.api_key).await.is_ok()
        && f.validate_access_jwt(&h.access).await.is_ok()
        && sessions
            .validate_session(&h.session)
            .await
            .unwrap()
            .is_some()
}

async fn assert_all_dead(f: &Arc<AuthFramework>, sessions: &SessionManager, h: &Held) {
    assert!(f.validate_api_key(&h.api_key).await.is_err(), "api key");
    assert!(f.validate_access_jwt(&h.access).await.is_err(), "access");
    assert!(f.redeem_refresh_jwt(&h.refresh).await.is_err(), "refresh");
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
    f.redeem_refresh_jwt(&h.refresh)
        .await
        .expect("refresh works while live");
    let h2 = issue(&f, &sessions).await; // a fresh, unconsumed refresh token for the dead check

    f.set_user_active(&h2.id, false).await.unwrap();
    assert_all_dead(&f, &sessions, &h2).await;

    // Reactivated: the old credentials stay dead, a new one works.
    f.set_user_active(&h2.id, true).await.unwrap();
    assert_all_dead(&f, &sessions, &h2).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let key = f.create_api_key(&h2.id, None).await.unwrap();
    assert!(f.validate_api_key(&key).await.is_ok());
    // An untouched account is unaffected.
    assert!(all_work(&f, &sessions, &h).await);
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
    // Another account is not touched.
    assert!(all_work(&f, &sessions, &other).await);

    // A credential issued after the change works.
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
    assert!(f.validate_access_jwt(&access).await.is_ok());
}
