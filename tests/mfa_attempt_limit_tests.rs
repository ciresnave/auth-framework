//! MFA code guessing is bounded: a challenge allows a few attempts, failures count toward
//! the account lockout, and a TOTP code is accepted once.

#[cfg(all(test, feature = "api-server"))]
mod mfa_attempt_limit_tests {
    use auth_framework::api::auth::{LoginRequest, login};
    use auth_framework::api::{ApiResponse, ApiState};
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Json;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use std::sync::Arc;
    use std::time::Duration;

    const PASSWORD: &str = "SecurePass123!x";
    const SECRET_B32: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    struct Account {
        id: String,
        username: String,
    }

    async fn setup() -> (ApiState, Arc<AuthFramework>) {
        let config = AuthConfig::new()
            .secret("test_mfa_attempt_secret_key_that_is_long_enough_for_jwt".to_string())
            .token_lifetime(Duration::from_secs(3600));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        let f = Arc::new(f);
        (ApiState::new(f.clone()).await.unwrap(), f)
    }

    /// A user with TOTP enrolled.
    async fn enrolled(f: &AuthFramework) -> Account {
        let username = format!("mfa_{}", uuid::Uuid::new_v4().simple());
        let id = f
            .register_user(&username, &format!("{username}@test.example.com"), PASSWORD)
            .await
            .unwrap();
        f.storage()
            .store_kv(&format!("mfa_secret:{id}"), SECRET_B32.as_bytes(), None)
            .await
            .unwrap();
        f.storage()
            .store_kv(&format!("mfa_enabled:{id}"), b"true", None)
            .await
            .unwrap();
        Account { id, username }
    }

    fn totp_now() -> String {
        let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, SECRET_B32)
            .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, SECRET_B32))
            .unwrap();
        let now = chrono::Utc::now().timestamp() as u64;
        totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &secret, now)
    }

    /// A 6-digit code that is NOT valid in the current window.
    fn wrong_code() -> String {
        let right = totp_now();
        let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, SECRET_B32)
            .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, SECRET_B32))
            .unwrap();
        let now = chrono::Utc::now().timestamp() as u64;
        let valid: Vec<String> = [now, now + 30, now.saturating_sub(30)]
            .iter()
            .map(|t| totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &secret, *t))
            .collect();
        (0..1_000_000u32)
            .map(|n| format!("{n:06}"))
            .find(|c| *c != right && !valid.contains(c))
            .unwrap()
    }

    async fn password_login(
        state: &ApiState,
        a: &Account,
    ) -> ApiResponse<auth_framework::api::auth::LoginResponse> {
        login(
            State(state.clone()),
            HeaderMap::new(),
            Json(LoginRequest {
                username: a.username.clone(),
                password: PASSWORD.to_string(),
                challenge_id: None,
                mfa_code: None,
                remember_me: false,
            }),
        )
        .await
    }

    async fn challenge_for(state: &ApiState, a: &Account) -> Option<String> {
        let r = password_login(state, a).await;
        r.error
            .and_then(|e| e.details)
            .and_then(|d| d["challenge_id"].as_str().map(String::from))
    }

    async fn submit(
        state: &ApiState,
        username: &str,
        challenge_id: &str,
        code: &str,
    ) -> ApiResponse<auth_framework::api::auth::LoginResponse> {
        login(
            State(state.clone()),
            HeaderMap::new(),
            Json(LoginRequest {
                username: username.to_string(),
                password: PASSWORD.to_string(),
                challenge_id: Some(challenge_id.to_string()),
                mfa_code: Some(code.to_string()),
                remember_me: false,
            }),
        )
        .await
    }

    #[tokio::test]
    async fn a_challenge_allows_a_few_wrong_codes_then_dies() {
        let (state, f) = setup().await;
        let a = enrolled(&f).await;

        // Four wrong guesses leave the fifth attempt available ...
        let id = challenge_for(&state, &a).await.expect("MFA challenge");
        for _ in 0..4 {
            assert!(f.complete_mfa_by_id(&id, &wrong_code()).await.is_err());
        }
        assert!(f.complete_mfa_by_id(&id, &totp_now()).await.is_ok());

        // ... but once the budget is spent the challenge is dead, even for the right code.
        let b = enrolled(&f).await;
        let id = challenge_for(&state, &b).await.expect("MFA challenge");
        for _ in 0..5 {
            assert!(f.complete_mfa_by_id(&id, &wrong_code()).await.is_err());
        }
        assert!(
            f.complete_mfa_by_id(&id, &totp_now()).await.is_err(),
            "the correct code must not work after the attempt budget is spent"
        );
    }

    #[tokio::test]
    async fn wrong_codes_lock_the_account_out_of_new_challenges() {
        let (state, f) = setup().await;
        let a = enrolled(&f).await;
        let id = challenge_for(&state, &a).await.expect("MFA challenge");

        // Guesses are attributed to the challenge's owner whatever username is sent.
        for _ in 0..5 {
            let r = submit(&state, "someone-else", &id, &wrong_code()).await;
            assert!(!r.success);
        }
        let r = password_login(&state, &a).await;
        let code = r.error.as_ref().map(|e| e.code.clone()).unwrap_or_default();
        assert_eq!(
            code, "ACCOUNT_LOCKED",
            "a fresh challenge must not be issued"
        );
        // and the old challenge no longer accepts the right code
        let r = submit(&state, &a.username, &id, &totp_now()).await;
        assert!(!r.success);
    }

    #[tokio::test]
    async fn a_totp_code_is_accepted_once() {
        let (state, f) = setup().await;
        let a = enrolled(&f).await;
        let code = totp_now();

        let id1 = challenge_for(&state, &a).await.expect("first challenge");
        let first = submit(&state, &a.username, &id1, &code).await;
        assert!(first.success, "{:?}", first.error);

        let id2 = challenge_for(&state, &a).await.expect("second challenge");
        let replay = submit(&state, &a.username, &id2, &code).await;
        assert!(!replay.success, "the same TOTP code must not log in twice");
    }

    #[tokio::test]
    async fn the_token_belongs_to_the_challenges_user_not_the_callers_copy() {
        use auth_framework::methods::{MfaChallenge, MfaType};
        let (state, f) = setup().await;
        let victim = enrolled(&f).await;
        let id = challenge_for(&state, &victim).await.expect("challenge");
        // the caller presents a copy of the challenge that names someone else
        let now = chrono::Utc::now();
        let tampered = MfaChallenge {
            id,
            mfa_type: MfaType::MultiMethod,
            user_id: "user_someone_else".to_string(),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            attempts: 0,
            max_attempts: 5,
            code_hash: None,
            message: None,
            data: Default::default(),
        };
        let token = f.complete_mfa(tampered, &totp_now()).await.unwrap();
        assert_eq!(token.user_id, victim.id);
    }

    #[tokio::test]
    async fn a_user_keeps_only_a_few_pending_challenges() {
        let (state, f) = setup().await;
        let a = enrolled(&f).await;
        let mut ids = Vec::new();
        for _ in 0..4 {
            ids.push(challenge_for(&state, &a).await.expect("challenge"));
        }
        // the oldest was retired, so minting challenges does not multiply guesses
        assert!(f.complete_mfa_by_id(&ids[0], &totp_now()).await.is_err());
        assert!(f.complete_mfa_by_id(&ids[3], &totp_now()).await.is_ok());
    }

    #[tokio::test]
    async fn a_lockout_reached_through_one_challenge_stops_the_others() {
        let (state, f) = setup().await;
        let a = enrolled(&f).await;
        let first = challenge_for(&state, &a).await.expect("challenge");
        let second = challenge_for(&state, &a).await.expect("challenge");
        for _ in 0..5 {
            let _ = submit(&state, &a.username, &first, &wrong_code()).await;
        }
        let r = submit(&state, &a.username, &second, &totp_now()).await;
        assert!(
            !r.success,
            "the right code must not work while the account is locked"
        );
        assert_eq!(r.error.map(|e| e.code).as_deref(), Some("ACCOUNT_LOCKED"));
    }

    #[tokio::test]
    async fn a_successful_mfa_login_clears_the_failure_count() {
        let (state, f) = setup().await;
        let a = enrolled(&f).await;
        let id = challenge_for(&state, &a).await.expect("challenge");
        for _ in 0..3 {
            let _ = submit(&state, &a.username, &id, &wrong_code()).await;
        }
        let key = format!("mfa_attempt:{}:0", a.id);
        assert!(f.storage().get_kv(&key).await.unwrap().is_some());
        let ok = submit(&state, &a.username, &id, &totp_now()).await;
        assert!(ok.success, "{:?}", ok.error);
        assert!(f.storage().get_kv(&key).await.unwrap().is_none());
    }

    /// Of many simultaneous submissions of one TOTP code exactly one is accepted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn simultaneous_submissions_of_one_totp_code_succeed_once() {
        use auth_framework::auth_modular::mfa::totp::TotpManager;
        let (_state, f) = setup().await;
        let a = enrolled(&f).await;
        let totp = Arc::new(TotpManager::new(f.storage().clone()));
        let code = totp_now();
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let totp = totp.clone();
            let (uid, code) = (a.id.clone(), code.clone());
            tasks.push(tokio::spawn(async move {
                totp.verify_login_code(&uid, &code).await.unwrap()
            }));
        }
        let mut accepted = 0;
        for t in tasks {
            if t.await.unwrap() {
                accepted += 1;
            }
        }
        assert_eq!(
            accepted, 1,
            "{accepted} concurrent submissions were accepted"
        );
    }

    /// A burst of parallel wrong guesses across the user's live challenges is bounded by the
    /// account budget (5), not by 5 per challenge.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_parallel_burst_of_wrong_codes_is_bounded_by_the_account_budget() {
        let (state, f) = setup().await;
        let a = enrolled(&f).await;
        let mut ids = Vec::new();
        for _ in 0..3 {
            ids.push(challenge_for(&state, &a).await.expect("challenge"));
        }
        let mut tasks = Vec::new();
        for i in 0..15 {
            let (state, id, username) = (state.clone(), ids[i % 3].clone(), a.username.clone());
            let code = wrong_code();
            tasks.push(tokio::spawn(async move {
                let r = submit(&state, &username, &id, &code).await;
                r.error.map(|e| e.code).unwrap_or_default()
            }));
        }
        let (mut checked, mut locked) = (0, 0);
        for t in tasks {
            match t.await.unwrap().as_str() {
                "MFA_INVALID_CODE" => checked += 1,
                "ACCOUNT_LOCKED" => locked += 1,
                other => panic!("unexpected {other}"),
            }
        }
        assert!(
            checked <= 5,
            "{checked} wrong codes were checked, budget is 5"
        );
        assert_eq!(checked + locked, 15);
        // the whole budget was claimed (and nothing beyond it)
        for slot in 0..5 {
            assert!(
                f.storage()
                    .get_kv(&format!("mfa_attempt:{}:{slot}", a.id))
                    .await
                    .unwrap()
                    .is_some(),
                "slot {slot}"
            );
        }
    }
}
