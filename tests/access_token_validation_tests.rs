//! Every place that accepts a bearer JWT refuses revoked tokens and refresh tokens.

#[cfg(all(test, feature = "axum-integration"))]
mod access_token_validation_tests {
    use auth_framework::integrations::axum::{AuthenticatedUser, auth_middleware};
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    async fn framework() -> Arc<AuthFramework> {
        let config = AuthConfig::new()
            .secret("test_access_validation_secret_key_long_enough_for_jwt".to_string())
            .token_lifetime(Duration::from_secs(3600));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        Arc::new(f)
    }

    /// Two guarded routes: one through the `AuthenticatedUser` extractor, one through the middleware.
    fn app(f: Arc<AuthFramework>) -> Router {
        Router::new()
            .route(
                "/extractor",
                get(|user: AuthenticatedUser| async move { user.user_id }),
            )
            .route(
                "/middleware",
                get(|| async { "ok" }).layer(from_fn_with_state(f.clone(), auth_middleware)),
            )
            .with_state(f)
    }

    async fn status(app: &Router, path: &str, jwt: &str) -> StatusCode {
        app.clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("authorization", format!("Bearer {jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    async fn account(f: &AuthFramework) -> String {
        let name = format!("atv_{}", uuid::Uuid::new_v4().simple());
        f.register_user(
            &name,
            &format!("{name}@test.example.com"),
            "SecurePass123!x",
        )
        .await
        .unwrap()
    }

    fn access(f: &AuthFramework, user: &str) -> String {
        f.token_manager()
            .create_jwt_token(
                user,
                vec!["read".to_string()],
                Some(Duration::from_secs(600)),
            )
            .unwrap()
    }

    async fn revoke(f: &AuthFramework, jwt: &str) {
        let jti = f.token_manager().validate_jwt_token(jwt).unwrap().jti;
        f.storage()
            .store_kv(
                &format!("revoked_token:{jti}"),
                b"revoked",
                Some(Duration::from_secs(600)),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_valid_access_token_is_accepted_everywhere() {
        let f = framework().await;
        let app = app(f.clone());
        let jwt = access(&f, &account(&f).await);
        assert_eq!(status(&app, "/extractor", &jwt).await, StatusCode::OK);
        assert_eq!(status(&app, "/middleware", &jwt).await, StatusCode::OK);
        assert!(f.validate_access_jwt(&jwt).await.is_ok());
    }

    #[tokio::test]
    async fn a_revoked_token_is_refused_everywhere() {
        let f = framework().await;
        let app = app(f.clone());
        let jwt = access(&f, &account(&f).await);
        revoke(&f, &jwt).await;
        assert_eq!(
            status(&app, "/extractor", &jwt).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(&app, "/middleware", &jwt).await,
            StatusCode::UNAUTHORIZED
        );
        assert!(f.validate_access_jwt(&jwt).await.is_err());
    }

    #[tokio::test]
    async fn a_refresh_token_is_not_an_access_token() {
        let f = framework().await;
        let app = app(f.clone());
        let refresh = f
            .token_manager()
            .create_refresh_jwt_token(&account(&f).await, Some(Duration::from_secs(600)))
            .unwrap();
        assert_eq!(
            status(&app, "/extractor", &refresh).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(&app, "/middleware", &refresh).await,
            StatusCode::UNAUTHORIZED
        );
        assert!(f.validate_access_jwt(&refresh).await.is_err());
    }

    #[tokio::test]
    async fn the_framework_jwt_authentication_path_refuses_revoked_and_refresh_tokens() {
        use auth_framework::auth::AuthResult;
        use auth_framework::authentication::credentials::Credential;
        let f = framework().await;
        let uid = account(&f).await;
        let ok = access(&f, &uid);
        let revoked = access(&f, &uid);
        revoke(&f, &revoked).await;
        let refresh = f
            .token_manager()
            .create_refresh_jwt_token(&account(&f).await, Some(Duration::from_secs(600)))
            .unwrap();

        for (label, jwt, want_success) in [
            ("ok", ok, true),
            ("revoked", revoked, false),
            ("refresh", refresh, false),
        ] {
            let res = f.authenticate("jwt", Credential::Jwt { token: jwt }).await;
            let success = matches!(res, Ok(AuthResult::Success(_)));
            assert_eq!(success, want_success, "{label}");
        }
    }
}
