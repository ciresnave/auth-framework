//! Registration claims a username and an email atomically: of simultaneous registrations of the
//! same username (or email) exactly one succeeds, and concurrent registrations of different users
//! all appear in the `users:index` list. Both used to be check-then-write.

#[cfg(all(test, feature = "api-server"))]
mod registration_race_tests {
    use auth_framework::api::ApiState;
    use auth_framework::api::auth::{RegisterRequest, register};
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Json;
    use axum::extract::State;
    use std::sync::Arc;
    use std::time::Duration;

    fn strong_password() -> String {
        format!("Zq-{}-Xv9!", uuid::Uuid::new_v4().simple())
    }

    async fn framework() -> Arc<AuthFramework> {
        let config = AuthConfig::new()
            .secret("test_registration_race_secret_key_that_is_long_enough".to_string())
            .token_lifetime(Duration::from_secs(3600));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        Arc::new(f)
    }

    async fn index_len(f: &AuthFramework) -> usize {
        match f.storage().get_kv("users:index").await.unwrap() {
            Some(bytes) => serde_json::from_slice::<Vec<String>>(&bytes).unwrap().len(),
            None => 0,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn one_username_registered_concurrently_has_exactly_one_winner() {
        let f = framework().await;
        let mut worst = 0;
        for round in 0..5 {
            let name = format!("race_user_{round}");
            let mut tasks = Vec::new();
            for i in 0..8 {
                let f = f.clone();
                let name = name.clone();
                tasks.push(tokio::spawn(async move {
                    f.register_user(
                        &name,
                        &format!("{name}_{i}@example.com"),
                        &strong_password(),
                    )
                    .await
                    .is_ok()
                }));
            }
            let mut ok = 0;
            for t in tasks {
                if t.await.unwrap() {
                    ok += 1;
                }
            }
            worst = worst.max(ok);
        }
        assert_eq!(
            worst, 1,
            "up to {worst} registrations of one username succeeded"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn one_email_registered_concurrently_has_exactly_one_winner() {
        let f = framework().await;
        let mut worst = 0;
        for round in 0..5 {
            let email = format!("shared_{round}@example.com");
            let mut tasks = Vec::new();
            for i in 0..8 {
                let f = f.clone();
                let email = email.clone();
                tasks.push(tokio::spawn(async move {
                    f.register_user(
                        &format!("mail_user_{round}_{i}"),
                        &email,
                        &strong_password(),
                    )
                    .await
                    .is_ok()
                }));
            }
            let mut ok = 0;
            for t in tasks {
                if t.await.unwrap() {
                    ok += 1;
                }
            }
            worst = worst.max(ok);
        }
        assert_eq!(
            worst, 1,
            "up to {worst} registrations of one email succeeded"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_registrations_of_different_users_all_reach_the_index() {
        let f = framework().await;
        let before = index_len(&f).await;
        let mut tasks = Vec::new();
        for i in 0..16 {
            let f = f.clone();
            tasks.push(tokio::spawn(async move {
                f.register_user(
                    &format!("index_user_{i}"),
                    &format!("index_user_{i}@example.com"),
                    &strong_password(),
                )
                .await
                .is_ok()
            }));
        }
        for t in tasks {
            assert!(t.await.unwrap());
        }
        assert_eq!(index_len(&f).await, before + 16, "users:index lost entries");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn the_api_register_handler_claims_a_username_once() {
        let f = framework().await;
        let state = ApiState::new(f.clone()).await.unwrap();
        let mut tasks = Vec::new();
        for i in 0..8 {
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                register(
                    State(state),
                    Json(RegisterRequest {
                        username: "api_race_user".to_string(),
                        email: format!("api_race_{i}@example.com"),
                        password: strong_password(),
                    }),
                )
                .await
                .success
            }));
        }
        let mut ok = 0;
        for t in tasks {
            if t.await.unwrap() {
                ok += 1;
            }
        }
        assert_eq!(ok, 1, "{ok} API registrations of one username succeeded");
    }
}
