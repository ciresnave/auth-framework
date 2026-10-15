//! Users API Integration Tests
//!
//! Covers the `PUT /users/profile`, `POST /users/change-password`, and related user endpoints.

#[cfg(all(test, feature = "api-server"))]
mod users_api_tests {
    use auth_framework::api::ApiState;
    use auth_framework::api::admin::{self, CreateUserRequest};
    use auth_framework::api::auth::{self as auth_handlers};
    use auth_framework::api::mfa::{self, MfaVerifyRequest};
    use auth_framework::api::users::{self, ChangePasswordRequest, UpdateProfileRequest};
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Json;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION};
    use axum::response::IntoResponse;
    use std::sync::Arc;

    async fn setup_api_state() -> ApiState {
        let config =
            AuthConfig::new().secret("test_users_api_secret_key_that_is_long_enough".to_string());
        let mut auth_framework = AuthFramework::new(config);
        auth_framework.initialize().await.unwrap();
        ApiState::new(Arc::new(auth_framework)).await.unwrap()
    }

    fn unique_registration_password() -> String {
        format!("UsersApi!A9{}", uuid::Uuid::new_v4().simple())
    }

    /// Register a test user and return a Bearer HeaderMap.
    async fn make_auth_headers(state: &ApiState, suffix: &str) -> (String, HeaderMap) {
        let username = format!("test_user_{}", suffix);
        let email = format!("{}@test.example.com", username);

        let user_id = state
            .auth_framework
            .register_user(&username, &email, "SecurePass123!")
            .await
            .expect("test user registration should succeed");

        let token = state
            .auth_framework
            .token_manager()
            .create_auth_token(
                &user_id,
                vec!["read".to_string(), "write".to_string()],
                "test",
                None,
            )
            .expect("token creation should succeed");

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token.access_token))
                .expect("valid header value"),
        );
        (user_id, headers)
    }

    /// Register an admin user, set their role to "admin" in KV, and return a Bearer HeaderMap.
    async fn make_admin_headers(state: &ApiState, suffix: &str) -> HeaderMap {
        let username = format!("test_admin_{}", suffix);
        let email = format!("{}@test.example.com", username);

        let user_id = state
            .auth_framework
            .register_user(&username, &email, "SecurePass123!")
            .await
            .expect("admin user registration should succeed");

        // Elevate to admin role so the admin endpoint authorization check passes.
        state
            .auth_framework
            .update_user_roles(&user_id, &["admin".to_string()])
            .await
            .expect("role update should succeed");

        let token = state
            .auth_framework
            .token_manager()
            .create_auth_token(
                &user_id,
                vec!["read".to_string(), "write".to_string()],
                "test",
                None,
            )
            .expect("token creation should succeed");

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token.access_token))
                .expect("valid header value"),
        );
        headers
    }

    fn current_totp(secret_b32: &str) -> String {
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32)
            .expect("TOTP secret should be valid base32");
        let now = chrono::Utc::now().timestamp() as u64;
        totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &secret_bytes, now)
    }

    async fn enable_mfa(state: &ApiState, headers: HeaderMap) -> String {
        let setup = mfa::setup_mfa(State(state.clone()), headers.clone()).await;
        assert!(setup.success, "MFA setup should succeed");
        let setup_data = setup.data.expect("MFA setup should return secret data");
        let totp_code = current_totp(&setup_data.secret);

        let verify = mfa::verify_mfa(
            State(state.clone()),
            headers,
            Json(MfaVerifyRequest { totp_code }),
        )
        .await;
        assert!(verify.success, "MFA verification should succeed");

        setup_data.secret
    }

    // -------------------------------------------------------------------------
    // PUT /users/profile — email validation
    // -------------------------------------------------------------------------

    /// Valid profile updates (with a well-formed email) must succeed.
    #[tokio::test]
    async fn test_update_profile_valid_email_accepted() {
        let state = setup_api_state().await;
        let (_uid, headers) = make_auth_headers(&state, "valid_email").await;

        let req = UpdateProfileRequest {
            email: Some("new.valid@example.com".to_string()),
            first_name: None,
            last_name: None,
        };

        let response = users::update_profile(State(state), headers, Json(req))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Valid profile update should succeed"
        );
    }

    /// A profile update with a malformed email must be rejected with 422.
    #[tokio::test]
    async fn test_update_profile_rejects_invalid_email() {
        let state = setup_api_state().await;
        let (_uid, headers) = make_auth_headers(&state, "invalid_email").await;

        let req = UpdateProfileRequest {
            email: Some("not-an-email".to_string()),
            first_name: None,
            last_name: None,
        };

        let response = users::update_profile(State(state), headers, Json(req))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Malformed email in profile update should return 400"
        );
    }

    /// A profile update missing an email field (only name fields) must succeed —
    /// the email validation path must not be triggered when the field is absent.
    #[tokio::test]
    async fn test_update_profile_no_email_succeeds() {
        let state = setup_api_state().await;
        let (_uid, headers) = make_auth_headers(&state, "no_email").await;

        let req = UpdateProfileRequest {
            email: None,
            first_name: Some("Alice".to_string()),
            last_name: Some("Smith".to_string()),
        };

        let response = users::update_profile(State(state), headers, Json(req))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Profile update with no email change should succeed"
        );
    }

    /// An unauthenticated request to update profile must return 401.
    #[tokio::test]
    async fn test_update_profile_requires_auth() {
        let state = setup_api_state().await;

        let req = UpdateProfileRequest {
            email: Some("whatever@example.com".to_string()),
            first_name: None,
            last_name: None,
        };

        let response = users::update_profile(State(state), HeaderMap::new(), Json(req))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Missing auth token should return 401"
        );
    }

    // -------------------------------------------------------------------------
    // POST /admin/users — email validation (M-2)
    // -------------------------------------------------------------------------

    /// Admin create-user with a valid email must succeed.
    #[tokio::test]
    async fn test_admin_create_user_valid_email_accepted() {
        let state = setup_api_state().await;
        let headers = make_admin_headers(&state, "cvu_valid").await;

        let req = CreateUserRequest {
            username: "newuser_valid".to_string(),
            password: "SecurePass123!".to_string(),
            email: "newuser@example.com".to_string(),
            first_name: None,
            last_name: None,
            roles: vec![],
            active: true,
        };

        let response = admin::create_user(State(state), headers, Json(req))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Admin create-user with valid email should succeed"
        );
    }

    /// Admin create-user with a malformed email must be rejected before storage.
    #[tokio::test]
    async fn test_admin_create_user_rejects_invalid_email() {
        let state = setup_api_state().await;
        let headers = make_admin_headers(&state, "cvu_invalid").await;

        let req = CreateUserRequest {
            username: "newuser_invalid".to_string(),
            password: "SecurePass123!".to_string(),
            email: "not-an-email".to_string(),
            first_name: None,
            last_name: None,
            roles: vec![],
            active: true,
        };

        let response = admin::create_user(State(state), headers, Json(req))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Admin create-user with malformed email should return 400"
        );
    }

    // -------------------------------------------------------------------------
    // POST /users/change-password — password complexity (CRITICAL-2)
    // -------------------------------------------------------------------------

    /// `change_password` must reject passwords that do not satisfy the complexity policy.
    #[tokio::test]
    async fn test_change_password_rejects_weak_password() {
        let state = setup_api_state().await;
        let (_uid, headers) = make_auth_headers(&state, "cp_weak").await;

        let req = ChangePasswordRequest {
            current_password: "SecurePass123!".to_string(),
            new_password: "weak".to_string(), // too short, no complexity
        };

        let response = users::change_password(State(state), headers, Json(req))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Weak new password should be rejected with 400"
        );
    }

    /// `change_password` must accept a strong password that meets the complexity policy.
    #[tokio::test]
    async fn test_change_password_accepts_strong_password() {
        let state = setup_api_state().await;
        let (_uid, headers) = make_auth_headers(&state, "cp_strong").await;

        let req = ChangePasswordRequest {
            current_password: "SecurePass123!".to_string(),
            new_password: "NewStr0ng!Pass#2".to_string(),
        };

        let response = users::change_password(State(state), headers, Json(req))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Strong new password should be accepted"
        );
    }

    // -------------------------------------------------------------------------
    // POST /users/profile — name field length limits (HIGH-2)
    // -------------------------------------------------------------------------

    /// Profile update with an oversized first_name must be rejected.
    #[tokio::test]
    async fn test_update_profile_rejects_long_first_name() {
        let state = setup_api_state().await;
        let (_uid, headers) = make_auth_headers(&state, "long_fname").await;

        let req = UpdateProfileRequest {
            email: None,
            first_name: Some("a".repeat(101)),
            last_name: None,
        };

        let response = users::update_profile(State(state), headers, Json(req))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "First name longer than 100 characters should be rejected"
        );
    }

    /// Profile update with an oversized last_name must be rejected.
    #[tokio::test]
    async fn test_update_profile_rejects_long_last_name() {
        let state = setup_api_state().await;
        let (_uid, headers) = make_auth_headers(&state, "long_lname").await;

        let req = UpdateProfileRequest {
            email: None,
            first_name: None,
            last_name: Some("z".repeat(101)),
        };

        let response = users::update_profile(State(state), headers, Json(req))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Last name longer than 100 characters should be rejected"
        );
    }

    // -------------------------------------------------------------------------
    // POST /auth/refresh — revocation check (CRITICAL-1)
    // -------------------------------------------------------------------------

    /// A refresh token that has been revoked via logout must be rejected when passed
    /// to the refresh endpoint.
    #[tokio::test]
    async fn test_refresh_rejects_revoked_token() {
        use auth_framework::api::auth::{LogoutRequest, RefreshRequest};

        let state = setup_api_state().await;

        // Register a user and obtain tokens.
        let user_id = state
            .auth_framework
            .register_user(
                "refresh_test_user",
                "refresh@test.example.com",
                "SecurePass123!",
            )
            .await
            .expect("registration should succeed");

        // Create an access token.
        let access_token_pair = state
            .auth_framework
            .token_manager()
            .create_auth_token(&user_id, vec![], "test", None)
            .expect("access token creation should succeed");

        // Create a refresh token (scope = ["refresh"], 7-day lifetime).
        let refresh_token = state
            .auth_framework
            .token_manager()
            .create_jwt_token(
                &user_id,
                vec!["refresh".to_string()],
                Some(std::time::Duration::from_secs(86400 * 7)),
            )
            .expect("refresh token creation should succeed");

        // Logout — this should revoke the refresh token.
        let mut access_headers = HeaderMap::new();
        access_headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", access_token_pair.access_token))
                .expect("valid header"),
        );

        let logout_req = LogoutRequest {
            refresh_token: Some(refresh_token.clone()),
        };

        let logout_resp =
            auth_handlers::logout(State(state.clone()), access_headers, Json(logout_req))
                .await
                .into_response();

        assert_eq!(
            logout_resp.status(),
            StatusCode::OK,
            "Logout should succeed"
        );

        // Now attempt to use the just-revoked refresh token.
        let refresh_req = RefreshRequest { refresh_token };

        let refresh_resp = auth_handlers::refresh_token(State(state), Json(refresh_req))
            .await
            .into_response();

        assert_eq!(
            refresh_resp.status(),
            StatusCode::UNAUTHORIZED,
            "Revoked refresh token should be rejected with 401"
        );
    }

    // -------------------------------------------------------------------------
    // POST /auth/register — username validation (HIGH-1)
    // -------------------------------------------------------------------------

    /// Registration with a username starting with a digit must be rejected.
    #[tokio::test]
    async fn test_register_rejects_username_starting_with_digit() {
        use auth_framework::api::auth::RegisterRequest;

        let state = setup_api_state().await;

        let req = RegisterRequest {
            username: "0invalid".to_string(),
            password: "SecurePass123!".to_string(),
            email: "0invalid@example.com".to_string(),
        };

        let response = auth_handlers::register(State(state), Json(req))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Username starting with a digit should be rejected"
        );
    }

    /// Registration with special characters in the username must be rejected.
    #[tokio::test]
    async fn test_register_rejects_username_with_special_chars() {
        use auth_framework::api::auth::RegisterRequest;

        let state = setup_api_state().await;

        let req = RegisterRequest {
            username: "user!@#name".to_string(),
            password: "SecurePass123!".to_string(),
            email: "special@example.com".to_string(),
        };

        let response = auth_handlers::register(State(state), Json(req))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Username with special characters should be rejected"
        );
    }

    // -------------------------------------------------------------------------
    // POST /admin/users — username and name-length validation (HIGH-3)
    // -------------------------------------------------------------------------

    /// Admin create-user with an invalid username format must be rejected.
    #[tokio::test]
    async fn test_admin_create_user_rejects_invalid_username() {
        let state = setup_api_state().await;
        let headers = make_admin_headers(&state, "bad_uname").await;

        let req = CreateUserRequest {
            username: "0bad_username".to_string(),
            password: "SecurePass123!".to_string(),
            email: "baduser@example.com".to_string(),
            first_name: None,
            last_name: None,
            roles: vec![],
            active: true,
        };

        let response = admin::create_user(State(state), headers, Json(req))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Admin create-user with invalid username should return 400"
        );
    }

    /// Admin create-user with an oversized first_name must be rejected.
    #[tokio::test]
    async fn test_admin_create_user_rejects_long_first_name() {
        let state = setup_api_state().await;
        let headers = make_admin_headers(&state, "long_fn").await;

        let req = CreateUserRequest {
            username: "newuser_longfn".to_string(),
            password: "SecurePass123!".to_string(),
            email: "longfn@example.com".to_string(),
            first_name: Some("a".repeat(101)),
            last_name: None,
            roles: vec![],
            active: true,
        };

        let response = admin::create_user(State(state), headers, Json(req))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Admin create-user with oversized first_name should return 400"
        );
    }

    // -------------------------------------------------------------------------
    // Audit cycle 19 — security regression tests
    // -------------------------------------------------------------------------

    /// HIGH-1: Login response must include the user's actual assigned roles.
    #[tokio::test]
    async fn test_login_response_includes_roles() {
        use auth_framework::api::auth::LoginRequest;

        let state = setup_api_state().await;

        let user_id = state
            .auth_framework
            .register_user(
                "login_roles_user",
                "login_roles_user@test.example.com",
                "SecurePass123!",
            )
            .await
            .expect("registration should succeed");

        state
            .auth_framework
            .update_user_roles(&user_id, &["viewer".to_string()])
            .await
            .expect("role assignment should succeed");

        let req = LoginRequest {
            username: "login_roles_user".to_string(),
            password: "SecurePass123!".to_string(),
            challenge_id: None,
            mfa_code: None,
            remember_me: false,
        };

        let api_resp = auth_handlers::login(State(state), HeaderMap::new(), Json(req)).await;

        assert!(api_resp.success, "login should succeed");
        let login_data = api_resp.data.expect("login response should contain data");
        assert!(
            !login_data.user.roles.is_empty(),
            "login response must include non-empty roles"
        );
        assert!(
            login_data.user.roles.contains(&"viewer".to_string()),
            "login response must include the assigned viewer role"
        );
    }

    /// CRITICAL-2: A user must not be able to revoke another user's session.
    #[tokio::test]
    async fn test_revoke_session_requires_ownership() {
        use auth_framework::storage::core::SessionData;
        use axum::extract::Path;

        let state = setup_api_state().await;

        // Create two distinct users.
        let (_uid_a, headers_a) = make_auth_headers(&state, "revoke_a").await;
        let (uid_b, _headers_b) = make_auth_headers(&state, "revoke_b").await;

        // Store a session that belongs to user_b.
        let session_id = "test-session-owned-by-b".to_string();
        let session_data = SessionData {
            session_id: session_id.clone(),
            user_id: uid_b.clone(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            last_activity: chrono::Utc::now(),
            ip_address: None,
            user_agent: None,
            data: Default::default(),
        };
        state
            .auth_framework
            .storage()
            .store_session(&session_id, &session_data)
            .await
            .expect("session storage should succeed");

        // User A tries to revoke user B's session — must be forbidden.
        let response = users::revoke_session(State(state), headers_a, Path(session_id.clone()))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "User A must not be able to revoke user B's session"
        );
    }

    /// HIGH-4: Registration conflict error must not reveal whether the username
    /// or the email was the conflicting field.
    #[tokio::test]
    async fn test_register_conflict_message_is_generic() {
        use auth_framework::api::auth::RegisterRequest;

        let state = setup_api_state().await;
        let password = unique_registration_password();

        let req1 = RegisterRequest {
            username: "conflict_reg_user".to_string(),
            email: "conflict_reg@example.com".to_string(),
            password: password.clone(),
        };
        let resp1 = auth_handlers::register(State(state.clone()), Json(req1)).await;
        assert!(resp1.success, "initial registration should succeed");

        // Same username, different email — must fail without mentioning "username".
        let req2 = RegisterRequest {
            username: "conflict_reg_user".to_string(),
            email: "conflict_reg2@example.com".to_string(),
            password: password.clone(),
        };
        let api_resp2 = auth_handlers::register(State(state.clone()), Json(req2)).await;
        assert!(
            !api_resp2.success,
            "duplicate-username registration must fail"
        );
        let err2 = api_resp2.error.expect("error field should be present");
        assert!(
            !err2.message.to_lowercase().contains("username"),
            "conflict error must not reveal 'username'"
        );
        assert!(
            !err2.message.to_lowercase().contains("email"),
            "conflict error must not reveal 'email'"
        );

        // Different username, same email — must fail without mentioning "email".
        let req3 = RegisterRequest {
            username: "conflict_reg_user2".to_string(),
            email: "conflict_reg@example.com".to_string(),
            password,
        };
        let api_resp3 = auth_handlers::register(State(state), Json(req3)).await;
        assert!(!api_resp3.success, "duplicate-email registration must fail");
        let err3 = api_resp3.error.expect("error field should be present");
        assert!(
            !err3.message.to_lowercase().contains("username"),
            "duplicate-email error must not reveal 'username'"
        );
        assert!(
            !err3.message.to_lowercase().contains("email"),
            "duplicate-email error must not reveal 'email'"
        );
    }

    /// MEDIUM-1: Changing a user's email via `update_profile` must maintain the
    /// email reverse-lookup index so that:
    ///   (a) the old email becomes available for new registrations, and
    ///   (b) the new email blocks duplicate registrations.
    #[tokio::test]
    async fn test_update_profile_maintains_email_index() {
        use auth_framework::api::auth::RegisterRequest;

        let state = setup_api_state().await;
        let old_email_password = unique_registration_password();
        let reclaim_password = unique_registration_password();
        let new_email_password = unique_registration_password();

        // Register a user with email_a.
        let (uid, headers) = make_auth_headers(&state, "email_idx").await;
        // The email assigned by make_auth_headers follows the pattern used in that helper.
        let old_email = "test_user_email_idx@test.example.com".to_string();
        let new_email = "email_idx_new@test.example.com".to_string();

        // Confirm the old email is currently blocked.
        let dup_old = RegisterRequest {
            username: "email_idx_dup_old".to_string(),
            email: old_email.clone(),
            password: old_email_password,
        };
        let dup_old_resp = auth_handlers::register(State(state.clone()), Json(dup_old)).await;
        assert!(
            !dup_old_resp.success,
            "old email should be unavailable before the profile update"
        );

        // Update user's email to new_email.
        let update_req = UpdateProfileRequest {
            email: Some(new_email.clone()),
            first_name: None,
            last_name: None,
        };
        let update_resp = users::update_profile(State(state.clone()), headers, Json(update_req))
            .await
            .into_response();
        assert_eq!(
            update_resp.status(),
            StatusCode::OK,
            "profile email update should succeed"
        );

        // (a) old email must now be available for a new registration.
        let reclaim_old = RegisterRequest {
            username: "email_idx_reclaim".to_string(),
            email: old_email.clone(),
            password: reclaim_password,
        };
        let reclaim_resp = auth_handlers::register(State(state.clone()), Json(reclaim_old)).await;
        assert!(
            reclaim_resp.success,
            "old email should become available after profile email change (uid={})",
            uid
        );

        // (b) new email must block a duplicate registration.
        let dup_new = RegisterRequest {
            username: "email_idx_dup_new".to_string(),
            email: new_email.clone(),
            password: new_email_password,
        };
        let dup_new_resp = auth_handlers::register(State(state), Json(dup_new)).await;
        assert!(
            !dup_new_resp.success,
            "new email should be unavailable for a second registration"
        );
    }

    // -------------------------------------------------------------------------
    // Audit cycle 20 — admin GET /users/{user_id}/profile tests
    // -------------------------------------------------------------------------

    /// Admin can view another user's profile and gets non-empty roles.
    #[tokio::test]
    async fn test_admin_get_user_profile_loads_roles() {
        use axum::extract::Path;

        let state = setup_api_state().await;

        // Create a regular user and assign them a specific role.
        let (target_uid, _headers) = make_auth_headers(&state, "profile_target").await;
        state
            .auth_framework
            .update_user_roles(&target_uid, &["editor".to_string()])
            .await
            .expect("role assignment should succeed");

        let admin_headers = make_admin_headers(&state, "profile_admin").await;

        let response =
            users::get_user_profile(State(state), admin_headers, Path(target_uid.clone())).await;

        assert!(response.success, "admin get_user_profile should succeed");
        let profile = response.data.expect("response should contain profile data");
        assert!(
            profile.roles.contains("editor"),
            "admin get_user_profile must return the target user's actual roles, got: {:?}",
            profile.roles
        );
    }

    /// Non-admin users must be denied when calling GET /users/{user_id}/profile.
    #[tokio::test]
    async fn test_admin_get_user_profile_requires_admin_role() {
        use axum::extract::Path;

        let state = setup_api_state().await;
        let (target_uid, _) = make_auth_headers(&state, "prof_target2").await;
        let (_uid, non_admin_headers) = make_auth_headers(&state, "prof_nonadmin").await;

        let response =
            users::get_user_profile(State(state), non_admin_headers, Path(target_uid.clone()))
                .await
                .into_response();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Non-admin user must receive 403 when viewing another user's profile"
        );
    }

    /// GET /users/{user_id}/profile for a non-existent user returns a non-200 response.
    #[tokio::test]
    async fn test_admin_get_user_profile_not_found() {
        use axum::extract::Path;

        let state = setup_api_state().await;
        let admin_headers = make_admin_headers(&state, "prof_admin2").await;

        let response = users::get_user_profile(
            State(state),
            admin_headers,
            Path("user_nonexistent_000000000000000000000000000000".to_string()),
        )
        .await
        .into_response();

        assert_ne!(
            response.status(),
            StatusCode::OK,
            "Admin get_user_profile for non-existent user must not return 200"
        );
    }

    // -------------------------------------------------------------------------
    // Audit cycle 21 — duplicate-email and deactivated-user-refresh tests
    // -------------------------------------------------------------------------

    /// update_profile must reject an email that is already claimed by another user.
    #[tokio::test]
    async fn test_update_profile_rejects_duplicate_email() {
        let state = setup_api_state().await;

        // Create two users with distinct emails.
        let (_uid_a, headers_a) = make_auth_headers(&state, "dup_email_a").await;
        let (_uid_b, _headers_b) = make_auth_headers(&state, "dup_email_b").await;

        // User A tries to change their email to User B's email.
        let response = users::update_profile(
            State(state.clone()),
            headers_a,
            Json(UpdateProfileRequest {
                first_name: None,
                last_name: None,
                email: Some("test_user_dup_email_b@test.example.com".to_string()),
            }),
        )
        .await
        .into_response();

        assert_ne!(
            response.status(),
            StatusCode::OK,
            "update_profile must reject an email that already belongs to another user"
        );
    }

    /// update_profile must allow setting the same email the user already has (idempotent).
    #[tokio::test]
    async fn test_update_profile_allows_own_email() {
        let state = setup_api_state().await;
        let (_uid, headers) = make_auth_headers(&state, "own_email").await;

        let response = users::update_profile(
            State(state.clone()),
            headers,
            Json(UpdateProfileRequest {
                first_name: None,
                last_name: None,
                email: Some("test_user_own_email@test.example.com".to_string()),
            }),
        )
        .await;

        assert!(
            response.success,
            "update_profile should succeed when the user sets their existing email"
        );
    }

    /// MFA-enabled users must not receive tokens until they complete the MFA step.
    #[tokio::test]
    async fn test_login_requires_mfa_for_enabled_user() {
        use auth_framework::api::auth::LoginRequest;

        let state = setup_api_state().await;
        let (_uid, headers) = make_auth_headers(&state, "mfa_required").await;
        let _secret = enable_mfa(&state, headers).await;

        let response = auth_handlers::login(
            State(state),
            HeaderMap::new(),
            Json(LoginRequest {
                username: "test_user_mfa_required".to_string(),
                password: "SecurePass123!".to_string(),
                challenge_id: None,
                mfa_code: None,
                remember_me: false,
            }),
        )
        .await;

        assert!(
            !response.success,
            "Login should require MFA after MFA is enabled"
        );
        let error = response
            .error
            .expect("MFA-required response should include an error");
        assert_eq!(error.code, "MFA_REQUIRED");
        let details = error
            .details
            .expect("MFA-required response should include details");
        assert!(
            details
                .get("challenge_id")
                .and_then(|value| value.as_str())
                .is_some(),
            "MFA-required response should include a challenge ID"
        );
    }

    /// MFA-enabled users can complete login when they provide the current TOTP code.
    #[tokio::test]
    async fn test_login_completes_with_valid_mfa_code() {
        use auth_framework::api::auth::LoginRequest;

        let state = setup_api_state().await;
        let (_uid, headers) = make_auth_headers(&state, "mfa_complete").await;
        let secret = enable_mfa(&state, headers).await;

        let first_response = auth_handlers::login(
            State(state.clone()),
            HeaderMap::new(),
            Json(LoginRequest {
                username: "test_user_mfa_complete".to_string(),
                password: "SecurePass123!".to_string(),
                challenge_id: None,
                mfa_code: None,
                remember_me: false,
            }),
        )
        .await;

        let challenge_id = first_response
            .error
            .expect("First MFA login response should include an error")
            .details
            .expect("First MFA login response should include details")["challenge_id"]
            .as_str()
            .expect("Challenge ID should be a string")
            .to_string();

        let second_response = auth_handlers::login(
            State(state),
            HeaderMap::new(),
            Json(LoginRequest {
                username: "test_user_mfa_complete".to_string(),
                password: "SecurePass123!".to_string(),
                challenge_id: Some(challenge_id),
                mfa_code: Some(current_totp(&secret)),
                remember_me: false,
            }),
        )
        .await;

        assert!(
            second_response.success,
            "Login should succeed with a valid MFA code"
        );
        let login_data = second_response
            .data
            .expect("Successful MFA login should return tokens");
        assert!(!login_data.access_token.is_empty());
        assert!(!login_data.refresh_token.is_empty());
    }
}
