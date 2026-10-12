//! The axum integration's login route authenticates against the user store.

#[cfg(all(test, feature = "axum-integration"))]
mod axum_login_route_tests {
    use auth_framework::integrations::axum::AuthRouter;
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    const PASSWORD: &str = "SecurePass123!x";

    async fn framework() -> Arc<AuthFramework> {
        let config = AuthConfig::new()
            .secret("test_axum_login_secret_key_that_is_long_enough_for_jwt".to_string());
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        Arc::new(f)
    }

    async fn login(
        f: &Arc<AuthFramework>,
        username: &str,
        password: &str,
    ) -> (StatusCode, serde_json::Value) {
        let app = AuthRouter::new().build().with_state(f.clone());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"username": username, "password": password}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    #[tokio::test]
    async fn unknown_users_and_wrong_passwords_get_no_token() {
        let f = framework().await;
        let name = format!("lr_{}", uuid::Uuid::new_v4().simple());
        f.register_user(&name, &format!("{name}@test.example.com"), PASSWORD)
            .await
            .unwrap();

        let (status, body) = login(&f, "nobody-registered", "whatever").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert!(body.get("access_token").is_none());

        let (status, body) = login(&f, &name, "not-the-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert!(body.get("access_token").is_none());
    }

    #[tokio::test]
    async fn the_right_password_gets_an_access_and_a_refresh_token() {
        let f = framework().await;
        let name = format!("lr_{}", uuid::Uuid::new_v4().simple());
        let uid = f
            .register_user(&name, &format!("{name}@test.example.com"), PASSWORD)
            .await
            .unwrap();

        let (status, body) = login(&f, &name, PASSWORD).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["user"]["id"], uid);
        let access = body["access_token"].as_str().unwrap();
        assert!(f.validate_access_jwt(access).await.is_ok());
        let refresh = body["refresh_token"].as_str().unwrap();
        assert!(f.redeem_refresh_jwt(refresh).await.is_ok());
    }

    #[tokio::test]
    async fn an_account_that_needs_a_second_factor_gets_no_token_here() {
        let f = framework().await;
        let name = format!("lr_{}", uuid::Uuid::new_v4().simple());
        let uid = f
            .register_user(&name, &format!("{name}@test.example.com"), PASSWORD)
            .await
            .unwrap();
        f.storage()
            .store_kv(&format!("mfa_enabled:{uid}"), b"true", None)
            .await
            .unwrap();
        let (status, body) = login(&f, &name, PASSWORD).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert!(body.get("access_token").is_none());
    }
}
