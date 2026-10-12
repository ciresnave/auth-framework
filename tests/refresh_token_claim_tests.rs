//! A refresh token is a JWT minted by `create_refresh_jwt_token`; `/auth/refresh` redeems it,
//! and an access token is not one.

#[cfg(all(test, feature = "api-server"))]
mod refresh_token_claim_tests {
    use auth_framework::api::ApiState;
    use auth_framework::api::auth::{RefreshRequest, refresh_token};
    use auth_framework::tokens::JwtClaims;
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Json;
    use axum::extract::State;
    use std::sync::Arc;
    use std::time::Duration;

    async fn state() -> (Arc<AuthFramework>, ApiState) {
        let config = AuthConfig::new()
            .secret("test_refresh_claim_secret_key_that_is_long_enough_for_jwt".to_string())
            .token_lifetime(Duration::from_secs(3600))
            .refresh_token_lifetime(Duration::from_secs(86400));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        let f = Arc::new(f);
        let state = ApiState::new(f.clone()).await.unwrap();
        (f, state)
    }

    #[tokio::test]
    async fn a_minted_refresh_token_refreshes_and_is_marked_as_one() {
        let (f, state) = state().await;
        let jwt = f
            .token_manager()
            .create_refresh_jwt_token("user_1", Some(Duration::from_secs(600)))
            .unwrap();
        let claims = f.token_manager().validate_jwt_token(&jwt).unwrap();
        assert!(claims.is_refresh_token());
        assert_eq!(claims.sub, "user_1");

        let r = refresh_token(State(state), Json(RefreshRequest { refresh_token: jwt })).await;
        assert!(r.success, "{:?}", r.error);
    }

    #[tokio::test]
    async fn an_access_token_is_not_marked_and_does_not_refresh() {
        let (f, state) = state().await;
        let jwt = f
            .token_manager()
            .create_jwt_token(
                "user_1",
                vec!["read".into()],
                Some(Duration::from_secs(600)),
            )
            .unwrap();
        let claims = f.token_manager().validate_jwt_token(&jwt).unwrap();
        assert!(!claims.is_refresh_token());
        let r = refresh_token(State(state), Json(RefreshRequest { refresh_token: jwt })).await;
        assert!(!r.success);
    }

    #[test]
    fn the_claim_names_are_stable() {
        assert_eq!(JwtClaims::TOKEN_USE_CLAIM, "token_use");
        assert_eq!(JwtClaims::TOKEN_USE_REFRESH, "refresh");
    }
}
