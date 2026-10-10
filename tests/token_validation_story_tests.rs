//! One token-validation story: a deactivated account's tokens stop working everywhere,
//! `validate_token` honours revocation, and an unreadable revocation list fails closed.

#[cfg(all(test, feature = "axum-integration"))]
mod token_validation_story_tests {
    use async_trait::async_trait;
    use auth_framework::integrations::axum::{AuthenticatedUser, auth_middleware};
    use auth_framework::storage::{AuthStorage, MemoryStorage, SessionData};
    use auth_framework::tokens::AuthToken;
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tower::ServiceExt;

    type R<T> = auth_framework::errors::Result<T>;

    /// Delegates to memory storage but can be told to fail every revocation-list read.
    struct FlakyRevocationList {
        inner: MemoryStorage,
        fail_revocation_reads: AtomicBool,
    }

    #[async_trait]
    impl AuthStorage for FlakyRevocationList {
        async fn store_token(&self, t: &AuthToken) -> R<()> {
            self.inner.store_token(t).await
        }
        async fn get_token(&self, id: &str) -> R<Option<AuthToken>> {
            self.inner.get_token(id).await
        }
        async fn get_token_by_access_token(&self, a: &str) -> R<Option<AuthToken>> {
            self.inner.get_token_by_access_token(a).await
        }
        async fn update_token(&self, t: &AuthToken) -> R<()> {
            self.inner.update_token(t).await
        }
        async fn delete_token(&self, id: &str) -> R<()> {
            self.inner.delete_token(id).await
        }
        async fn list_user_tokens(&self, u: &str) -> R<Vec<AuthToken>> {
            self.inner.list_user_tokens(u).await
        }
        async fn store_session(&self, id: &str, d: &SessionData) -> R<()> {
            self.inner.store_session(id, d).await
        }
        async fn get_session(&self, id: &str) -> R<Option<SessionData>> {
            self.inner.get_session(id).await
        }
        async fn delete_session(&self, id: &str) -> R<()> {
            self.inner.delete_session(id).await
        }
        async fn list_user_sessions(&self, u: &str) -> R<Vec<SessionData>> {
            self.inner.list_user_sessions(u).await
        }
        async fn count_active_sessions(&self) -> R<u64> {
            self.inner.count_active_sessions().await
        }
        async fn store_kv(&self, k: &str, v: &[u8], ttl: Option<Duration>) -> R<()> {
            self.inner.store_kv(k, v, ttl).await
        }
        async fn get_kv(&self, k: &str) -> R<Option<Vec<u8>>> {
            if k.starts_with("revoked_token:") && self.fail_revocation_reads.load(Ordering::SeqCst)
            {
                return Err(auth_framework::errors::AuthError::internal("storage down"));
            }
            self.inner.get_kv(k).await
        }
        async fn delete_kv(&self, k: &str) -> R<()> {
            self.inner.delete_kv(k).await
        }
        async fn cleanup_expired(&self) -> R<()> {
            self.inner.cleanup_expired().await
        }
    }

    async fn framework() -> Arc<AuthFramework> {
        let config = AuthConfig::new()
            .secret("test_token_story_secret_key_that_is_long_enough_for_jwt".to_string())
            .token_lifetime(Duration::from_secs(3600));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        Arc::new(f)
    }

    async fn flaky_framework() -> (Arc<AuthFramework>, Arc<FlakyRevocationList>) {
        let storage = Arc::new(FlakyRevocationList {
            inner: MemoryStorage::new(),
            fail_revocation_reads: AtomicBool::new(false),
        });
        let config = AuthConfig::new()
            .secret("test_token_story_secret_key_that_is_long_enough_for_jwt".to_string())
            .token_lifetime(Duration::from_secs(3600));
        let mut f = AuthFramework::new_with_storage(config, storage.clone());
        f.initialize().await.unwrap();
        (Arc::new(f), storage)
    }

    fn app(f: Arc<AuthFramework>) -> Router {
        Router::new()
            .route(
                "/extractor",
                get(|u: AuthenticatedUser| async move { u.user_id }),
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

    async fn account(f: &AuthFramework, active: bool) -> String {
        let name = format!("ts_{}", uuid::Uuid::new_v4().simple());
        let id = f
            .register_user(
                &name,
                &format!("{name}@test.example.com"),
                "SecurePass123!x",
            )
            .await
            .unwrap();
        if !active {
            let key = format!("user:{id}");
            let mut rec: serde_json::Value =
                serde_json::from_slice(&f.storage().get_kv(&key).await.unwrap().unwrap()).unwrap();
            rec["active"] = serde_json::json!(false);
            f.storage()
                .store_kv(&key, rec.to_string().as_bytes(), None)
                .await
                .unwrap();
        }
        id
    }

    fn jwt_for(f: &AuthFramework, user: &str) -> String {
        f.token_manager()
            .create_jwt_token(user, vec!["read".into()], Some(Duration::from_secs(600)))
            .unwrap()
    }

    #[tokio::test]
    async fn a_deactivated_accounts_token_is_refused_everywhere() {
        let f = framework().await;
        let app = app(f.clone());
        let active = account(&f, true).await;
        let inactive = account(&f, false).await;

        let good = jwt_for(&f, &active);
        assert_eq!(status(&app, "/extractor", &good).await, StatusCode::OK);
        assert_eq!(status(&app, "/middleware", &good).await, StatusCode::OK);

        let bad = jwt_for(&f, &inactive);
        assert_eq!(
            status(&app, "/extractor", &bad).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(&app, "/middleware", &bad).await,
            StatusCode::UNAUTHORIZED
        );
        assert!(f.validate_access_jwt(&bad).await.is_err());
    }

    #[tokio::test]
    async fn validate_token_honours_revocation() {
        let f = framework().await;
        let uid = account(&f, true).await;
        let token = f
            .token_manager()
            .create_auth_token(&uid, vec!["read".to_string()], "jwt", None)
            .unwrap();
        f.storage().store_token(&token).await.unwrap();
        assert!(f.validate_token(&token).await.unwrap());

        // revoked through the logout / revocation marker
        let jti = f
            .token_manager()
            .validate_jwt_token(&token.access_token)
            .unwrap()
            .jti;
        f.storage()
            .store_kv(
                &format!("revoked_token:{jti}"),
                b"revoked",
                Some(Duration::from_secs(600)),
            )
            .await
            .unwrap();
        assert!(!f.validate_token(&token).await.unwrap());

        // revoked through the library API
        let second = f
            .token_manager()
            .create_auth_token(&uid, vec!["read".to_string()], "jwt", None)
            .unwrap();
        f.storage().store_token(&second).await.unwrap();
        assert!(f.validate_token(&second).await.unwrap());
        f.revoke_token(&second).await.unwrap();
        assert!(!f.validate_token(&second).await.unwrap());
    }

    #[tokio::test]
    async fn an_unreadable_revocation_list_rejects_instead_of_accepting() {
        let (f, storage) = flaky_framework().await;
        let app = app(f.clone());
        let uid = account(&f, true).await;
        let jwt = jwt_for(&f, &uid);
        assert_eq!(status(&app, "/extractor", &jwt).await, StatusCode::OK);

        storage.fail_revocation_reads.store(true, Ordering::SeqCst);
        assert_eq!(
            status(&app, "/extractor", &jwt).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(&app, "/middleware", &jwt).await,
            StatusCode::UNAUTHORIZED
        );
        assert!(f.validate_access_jwt(&jwt).await.is_err());
        let token = f
            .token_manager()
            .create_auth_token(&uid, vec!["read".to_string()], "jwt", None)
            .unwrap();
        f.storage().store_token(&token).await.unwrap();
        assert!(!f.validate_token(&token).await.unwrap_or(false));
    }

    /// `validate_token` / `refresh_token` take an `AuthToken` value from the caller: its fields must
    /// agree with the signed JWT it carries.
    #[tokio::test]
    async fn a_caller_supplied_token_value_must_agree_with_its_jwt() {
        let f = framework().await;
        let victim = account(&f, true).await;
        let other = account(&f, true).await;
        let token = f
            .token_manager()
            .create_auth_token(&victim, vec!["read".to_string()], "jwt", None)
            .unwrap();
        f.storage().store_token(&token).await.unwrap();
        assert!(f.validate_token(&token).await.unwrap());

        // the same JWT presented in a value that names another user
        let mut forged = token.clone();
        forged.user_id = other.clone();
        assert!(!f.validate_token(&forged).await.unwrap_or(false));
        assert!(
            f.refresh_token(&forged).await.is_err(),
            "a forged value must not be refreshed into a token for another user"
        );

        // refreshing a revoked token is refused; refreshing a valid one still works
        let second = f
            .token_manager()
            .create_auth_token(&victim, vec!["read".to_string()], "jwt", None)
            .unwrap();
        f.storage().store_token(&second).await.unwrap();
        f.revoke_token(&second).await.unwrap();
        assert!(f.refresh_token(&second).await.is_err());
        let fresh = f.refresh_token(&token).await.unwrap();
        assert_eq!(fresh.user_id, victim);
    }

    /// A federated subject (no local account, never had one) may authenticate with a JWT
    /// credential; the token of a local account that was DELETED may not.
    #[tokio::test]
    async fn a_deleted_accounts_jwt_no_longer_authenticates_but_a_federated_one_does() {
        use auth_framework::auth::AuthResult;
        use auth_framework::authentication::credentials::Credential;
        let f = framework().await;
        let name = format!("del_{}", uuid::Uuid::new_v4().simple());
        let uid = f
            .register_user(
                &name,
                &format!("{name}@test.example.com"),
                "SecurePass123!x",
            )
            .await
            .unwrap();
        let local = jwt_for(&f, &uid);
        let federated = jwt_for(&f, "federated|someone");

        let ok = |r: &auth_framework::errors::Result<AuthResult>| {
            matches!(r, Ok(AuthResult::Success(_)))
        };
        assert!(ok(&f
            .authenticate(
                "jwt",
                Credential::Jwt {
                    token: local.clone()
                }
            )
            .await));
        assert!(ok(&f
            .authenticate(
                "jwt",
                Credential::Jwt {
                    token: federated.clone()
                }
            )
            .await));

        f.delete_user(&name).await.unwrap();
        assert!(
            !ok(&f
                .authenticate("jwt", Credential::Jwt { token: local })
                .await),
            "a deleted account's token must stop authenticating"
        );
        assert!(ok(&f
            .authenticate("jwt", Credential::Jwt { token: federated })
            .await));
    }
}
