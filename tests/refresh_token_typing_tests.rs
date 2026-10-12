//! `/auth/refresh` accepts only tokens minted as refresh tokens. An access token whose scope
//! string merely contains the word "refresh" (a permission or role name that does) is not one.

#[cfg(all(test, feature = "api-server"))]
mod refresh_token_typing_tests {
    use auth_framework::api::ApiState;
    use auth_framework::api::auth::{RefreshRequest, refresh_token};
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Json;
    use axum::extract::State;
    use std::sync::Arc;
    use std::time::Duration;

    async fn state() -> (Arc<AuthFramework>, ApiState) {
        let config = AuthConfig::new()
            .secret("test_refresh_typing_secret_key_that_is_long_enough_for_jwt".to_string())
            .token_lifetime(Duration::from_secs(3600))
            .refresh_token_lifetime(Duration::from_secs(86400));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        let f = Arc::new(f);
        let state = ApiState::new(f.clone()).await.unwrap();
        (f, state)
    }

    #[tokio::test]
    async fn an_access_token_mentioning_refresh_in_its_scope_is_not_a_refresh_token() {
        let (f, state) = state().await;
        // The shapes the old substring check accepted: the bare word, a list holding it, and
        // a role/permission name that merely contains it.
        for scopes in [
            vec!["refresh"],
            vec!["read", "refresh"],
            vec!["token_refresh_manager"],
        ] {
            let jwt = f
                .token_manager()
                .create_jwt_token(
                    "user_1",
                    scopes.iter().map(|s| s.to_string()).collect(),
                    Some(Duration::from_secs(600)),
                )
                .unwrap();
            let r = refresh_token(
                State(state.clone()),
                Json(RefreshRequest { refresh_token: jwt }),
            )
            .await;
            assert!(
                !r.success,
                "scopes {scopes:?} must not be accepted as a refresh token"
            );
            assert_eq!(r.error.unwrap().code, "INVALID_TOKEN");
        }
    }
}
