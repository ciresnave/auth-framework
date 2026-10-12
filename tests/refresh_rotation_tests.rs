//! Refresh tokens are single-use: redeeming one issues the next, and presenting one that
//! was already redeemed is refused and ends the whole chain.

#[cfg(all(test, feature = "axum-integration"))]
mod refresh_rotation_tests {
    use auth_framework::api::ApiState;
    use auth_framework::api::auth::{LoginRequest, RefreshRequest, login, refresh_token};
    use auth_framework::integrations::axum::AuthRouter;
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Json;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{HeaderMap, Request, StatusCode};
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    const PASSWORD: &str = "SecurePass123!x";

    async fn setup() -> (ApiState, Arc<AuthFramework>) {
        let config = AuthConfig::new()
            .secret("test_refresh_rotation_secret_key_long_enough_for_jwt".to_string())
            .token_lifetime(Duration::from_secs(3600))
            .refresh_token_lifetime(Duration::from_secs(86400));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        let f = Arc::new(f);
        (ApiState::new(f.clone()).await.unwrap(), f)
    }

    async fn logged_in(state: &ApiState, f: &AuthFramework) -> (String, String, String) {
        let username = format!("rr_{}", uuid::Uuid::new_v4().simple());
        let id = f
            .register_user(&username, &format!("{username}@test.example.com"), PASSWORD)
            .await
            .unwrap();
        let resp = login(
            State(state.clone()),
            HeaderMap::new(),
            Json(LoginRequest {
                username,
                password: PASSWORD.to_string(),
                challenge_id: None,
                mfa_code: None,
                remember_me: false,
            }),
        )
        .await;
        let data = resp.data.expect("login");
        (id, data.access_token, data.refresh_token)
    }

    async fn refresh(
        state: &ApiState,
        token: &str,
    ) -> auth_framework::api::ApiResponse<auth_framework::api::auth::RefreshResponse> {
        refresh_token(
            State(state.clone()),
            Json(RefreshRequest {
                refresh_token: token.to_string(),
            }),
        )
        .await
    }

    #[tokio::test]
    async fn redeeming_a_refresh_token_issues_the_next_one_and_ends_the_old() {
        let (state, f) = setup().await;
        let (_id, _access, rt1) = logged_in(&state, &f).await;

        let first = refresh(&state, &rt1).await;
        assert!(first.success, "{:?}", first.error);
        let first = first.data.unwrap();
        assert!(!first.refresh_token.is_empty());
        assert_ne!(first.refresh_token, rt1);

        // the chain continues with the new token ...
        let second = refresh(&state, &first.refresh_token).await;
        assert!(second.success, "{:?}", second.error);

        // ... and the redeemed one is dead
        let replay = refresh(&state, &rt1).await;
        assert!(
            !replay.success,
            "a redeemed refresh token must not work again"
        );
    }

    #[tokio::test]
    async fn presenting_a_redeemed_token_also_ends_the_chain() {
        let (state, f) = setup().await;
        let (_id, _access, rt1) = logged_in(&state, &f).await;
        let rt2 = refresh(&state, &rt1).await.data.unwrap().refresh_token;

        // someone replays the old token: refused ...
        assert!(!refresh(&state, &rt1).await.success);
        // ... and the chain it belonged to (the newest token) is revoked too
        assert!(
            !refresh(&state, &rt2).await.success,
            "reuse of a redeemed token must revoke the rest of the chain"
        );
    }

    #[tokio::test]
    async fn a_deactivated_or_deleted_account_cannot_redeem_a_refresh_token() {
        let (state, f) = setup().await;

        let (uid, _, rt) = logged_in(&state, &f).await;
        let key = format!("user:{uid}");
        let mut rec: serde_json::Value =
            serde_json::from_slice(&f.storage().get_kv(&key).await.unwrap().unwrap()).unwrap();
        rec["active"] = serde_json::json!(false);
        f.storage()
            .store_kv(&key, rec.to_string().as_bytes(), None)
            .await
            .unwrap();
        assert!(!refresh(&state, &rt).await.success, "deactivated");

        let (uid2, _, rt2) = logged_in(&state, &f).await;
        f.storage()
            .delete_kv(&format!("user:{uid2}"))
            .await
            .unwrap();
        assert!(!refresh(&state, &rt2).await.success, "deleted");
    }

    #[tokio::test]
    async fn logging_out_with_a_refresh_token_ends_its_whole_chain() {
        use auth_framework::api::auth::{LogoutRequest, logout};
        let (state, f) = setup().await;
        let (uid, access, rt1) = logged_in(&state, &f).await;
        // the chain moves on: rt1 is spent, rt2 is the live token
        let rt2 = refresh(&state, &rt1).await.data.unwrap().refresh_token;

        // logout presents the (older) refresh token it knows about
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {access}").parse().unwrap());
        let out = logout(
            State(state.clone()),
            headers,
            Json(LogoutRequest {
                refresh_token: Some(rt1),
            }),
        )
        .await;
        assert!(out.success, "{:?}", out.error);
        let _ = uid;

        // a copy of the newer token does not survive the logout
        let resp = refresh(&state, &rt2).await;
        assert!(!resp.success, "the rest of the chain must be dead");
        assert_eq!(resp.error.map(|e| e.code).as_deref(), Some("INVALID_TOKEN"));
    }

    #[tokio::test]
    async fn the_integration_refresh_route_takes_only_a_refresh_token() {
        let (state, f) = setup().await;
        let (uid, _, _) = logged_in(&state, &f).await;
        let app = AuthRouter::new().build().with_state(f.clone());
        let post = |bearer: String| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/auth/refresh")
                        .header("authorization", format!("Bearer {bearer}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };
        let access = f
            .token_manager()
            .create_jwt_token(&uid, vec!["read".into()], Some(Duration::from_secs(600)))
            .unwrap();
        let refresh = f
            .token_manager()
            .create_refresh_jwt_token(&uid, Some(Duration::from_secs(600)))
            .unwrap();

        // an access token cannot mint a new access token
        assert_eq!(post(access).await.status(), StatusCode::UNAUTHORIZED);

        // a refresh token can, once, and yields the next refresh token
        let ok = post(refresh.clone()).await;
        assert_eq!(ok.status(), StatusCode::OK);
        let body = axum::body::to_bytes(ok.into_body(), 1 << 20).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body["access_token"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(
            body["refresh_token"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );

        assert_eq!(post(refresh).await.status(), StatusCode::UNAUTHORIZED);
    }
}
