//! A refresh token redeemed by many simultaneous requests is spent exactly once.

#[cfg(all(test, feature = "axum-integration"))]
mod refresh_double_redeem_tests {
    use auth_framework::{AuthConfig, AuthFramework};
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn simultaneous_redemptions_of_one_refresh_token_succeed_once() {
        let config = AuthConfig::new()
            .secret("test_double_redeem_secret_key_that_is_long_enough_for_jwt".to_string())
            .token_lifetime(Duration::from_secs(300))
            .refresh_token_lifetime(Duration::from_secs(3600));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        let f = Arc::new(f);

        // Many rounds: the race is a narrow window, so give it many chances to show.
        for round in 0..8 {
            let name = format!("dr_{round}_{}", uuid::Uuid::new_v4().simple());
            let uid = f
                .register_user(
                    &name,
                    &format!("{name}@test.example.com"),
                    "SecurePass123!x",
                )
                .await
                .unwrap();
            let rt = f
                .token_manager()
                .create_refresh_jwt_token(&uid, Some(Duration::from_secs(600)))
                .unwrap();

            let mut tasks = Vec::new();
            for _ in 0..16 {
                let f = f.clone();
                let rt = rt.clone();
                tasks.push(tokio::spawn(async move {
                    f.redeem_refresh_jwt(&rt).await.is_ok()
                }));
            }
            let mut successes = 0;
            for t in tasks {
                if t.await.unwrap() {
                    successes += 1;
                }
            }
            assert_eq!(
                successes, 1,
                "round {round}: {successes} redemptions succeeded"
            );
        }
    }
}
