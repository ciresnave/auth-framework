//! Email-verification tokens are a proof of inbox control: they are delivered to the
//! mailbox through the configured sender and are never present in an HTTP response.

#[cfg(all(test, feature = "api-server"))]
mod email_verification_delivery_tests {
    use auth_framework::api::email_verification::{
        EmailVerificationSender, ResendVerificationRequest, VerifyEmailRequest,
        resend_verification, send_verification, verify_email,
    };
    use auth_framework::api::{ApiResponse, ApiState};
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Json;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Records what the mailbox would receive.
    #[derive(Default)]
    struct Mailbox {
        sent: Mutex<Vec<(String, String, String)>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl EmailVerificationSender for Mailbox {
        async fn send_verification_token(
            &self,
            email: &str,
            user_id: &str,
            token: &str,
        ) -> auth_framework::errors::Result<()> {
            self.sent
                .lock()
                .unwrap()
                .push((email.into(), user_id.into(), token.into()));
            if self.fail {
                return Err(auth_framework::errors::AuthError::internal("smtp down"));
            }
            Ok(())
        }
    }

    async fn framework() -> Arc<AuthFramework> {
        let config = AuthConfig::new()
            .secret("test_email_verification_secret_key_long_enough_for_jwt".to_string())
            .token_lifetime(Duration::from_secs(3600));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        Arc::new(f)
    }

    async fn state_with(mailbox: Arc<Mailbox>) -> (ApiState, Arc<AuthFramework>) {
        let f = framework().await;
        let state = ApiState::new(f.clone())
            .await
            .unwrap()
            .with_email_verification_sender(mailbox);
        (state, f)
    }

    async fn account(f: &AuthFramework) -> (String, String) {
        let email = format!("{}@mail.example.com", uuid::Uuid::new_v4().simple());
        let uid = f
            .register_user(
                &format!("ev_{}", uuid::Uuid::new_v4().simple()),
                &email,
                "SecurePass123!x",
            )
            .await
            .unwrap();
        (uid, email)
    }

    /// Delivery happens off the request path; wait until `n` messages have arrived.
    async fn settle(mailbox: &Mailbox, n: usize) -> Vec<(String, String, String)> {
        for _ in 0..100 {
            if mailbox.sent.lock().unwrap().len() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // let any unexpected extra message show up
        tokio::time::sleep(Duration::from_millis(100)).await;
        mailbox.sent.lock().unwrap().clone()
    }

    fn json<T: serde::Serialize>(resp: &ApiResponse<T>) -> serde_json::Value {
        serde_json::to_value(resp).unwrap()
    }

    async fn resend(state: &ApiState, email: &str) -> ApiResponse<impl serde::Serialize> {
        resend_verification(
            State(state.clone()),
            Json(ResendVerificationRequest {
                email: email.to_string(),
            }),
        )
        .await
    }

    fn bearer(f: &AuthFramework, uid: &str) -> HeaderMap {
        let jwt = f
            .token_manager()
            .create_jwt_token(
                uid,
                vec!["user".to_string()],
                Some(Duration::from_secs(600)),
            )
            .unwrap();
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {jwt}").parse().unwrap());
        h
    }

    #[tokio::test]
    async fn the_token_is_never_in_the_response_and_reaches_the_mailbox() {
        let mailbox = Arc::new(Mailbox::default());
        let (state, f) = state_with(mailbox.clone()).await;
        let (_uid, email) = account(&f).await;

        let body = json(&resend(&state, &email).await);
        let sent = settle(&mailbox, 1).await;
        assert_eq!(sent.len(), 1, "exactly one message is delivered: {sent:?}");
        assert_eq!(sent[0].0, email);
        let token = &sent[0].2;
        assert!(
            !body.to_string().contains(token.as_str()),
            "the token must not appear anywhere in the response: {body}"
        );
        assert!(
            body["data"].get("verification_token").is_none(),
            "no token field in the response: {body}"
        );
    }

    #[tokio::test]
    async fn the_delivered_token_verifies_the_account() {
        let mailbox = Arc::new(Mailbox::default());
        let (state, f) = state_with(mailbox.clone()).await;
        let (uid, email) = account(&f).await;

        let _ = resend(&state, &email).await;
        let token = settle(&mailbox, 1).await[0].2.clone();

        let ok = verify_email(State(state.clone()), Json(VerifyEmailRequest { token })).await;
        assert!(ok.success, "{:?}", ok.error);
        let rec = f
            .storage()
            .get_kv(&format!("user:{uid}"))
            .await
            .unwrap()
            .unwrap();
        let rec: serde_json::Value = serde_json::from_slice(&rec).unwrap();
        assert_eq!(rec["email_verified"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn unknown_unverified_and_verified_addresses_get_identical_responses() {
        let mailbox = Arc::new(Mailbox::default());
        let (state, f) = state_with(mailbox.clone()).await;
        let (_u1, unverified) = account(&f).await;
        let (u2, verified) = account(&f).await;
        // mark the second account verified
        let key = format!("user:{u2}");
        let mut rec: serde_json::Value =
            serde_json::from_slice(&f.storage().get_kv(&key).await.unwrap().unwrap()).unwrap();
        rec["email_verified"] = serde_json::json!(true);
        f.storage()
            .store_kv(&key, rec.to_string().as_bytes(), None)
            .await
            .unwrap();

        let unknown = json(&resend(&state, "nobody@nowhere.example.com").await);
        let a = json(&resend(&state, &unverified).await);
        let b = json(&resend(&state, &verified).await);
        assert_eq!(unknown, a, "unknown vs unverified differ");
        assert_eq!(unknown, b, "unknown vs already-verified differ");
        // and only the unverified account was mailed
        let sent = settle(&mailbox, 1).await;
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].0, unverified);
    }

    #[tokio::test]
    async fn a_failing_mailbox_is_not_revealed_to_the_requester() {
        let mailbox = Arc::new(Mailbox {
            fail: true,
            ..Default::default()
        });
        let (state, f) = state_with(mailbox.clone()).await;
        let (_uid, email) = account(&f).await;
        let failing = json(&resend(&state, &email).await);
        let unknown = json(&resend(&state, "nobody@nowhere.example.com").await);
        assert_eq!(failing, unknown);
        let token = settle(&mailbox, 1).await[0].2.clone();
        assert!(!failing.to_string().contains(&token));
    }

    #[tokio::test]
    async fn a_token_only_verifies_the_address_it_was_mailed_to() {
        let mailbox = Arc::new(Mailbox::default());
        let (state, f) = state_with(mailbox.clone()).await;
        let (uid, email) = account(&f).await;

        let _ = resend(&state, &email).await;
        let token = settle(&mailbox, 1).await[0].2.clone();

        // The account's address changes after the message was sent.
        let key = format!("user:{uid}");
        let mut rec: serde_json::Value =
            serde_json::from_slice(&f.storage().get_kv(&key).await.unwrap().unwrap()).unwrap();
        rec["email"] = serde_json::json!("moved@elsewhere.example.com");
        f.storage()
            .store_kv(&key, rec.to_string().as_bytes(), None)
            .await
            .unwrap();

        let resp = verify_email(State(state.clone()), Json(VerifyEmailRequest { token })).await;
        assert!(
            !resp.success,
            "a token for the old address must not verify the new one"
        );
        let rec: serde_json::Value =
            serde_json::from_slice(&f.storage().get_kv(&key).await.unwrap().unwrap()).unwrap();
        assert_ne!(rec["email_verified"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn changing_the_email_address_clears_verification() {
        use auth_framework::api::users::{UpdateProfileRequest, update_profile};
        let mailbox = Arc::new(Mailbox::default());
        let (state, f) = state_with(mailbox).await;
        let (uid, _email) = account(&f).await;
        let key = format!("user:{uid}");
        let mut rec: serde_json::Value =
            serde_json::from_slice(&f.storage().get_kv(&key).await.unwrap().unwrap()).unwrap();
        rec["email_verified"] = serde_json::json!(true);
        f.storage()
            .store_kv(&key, rec.to_string().as_bytes(), None)
            .await
            .unwrap();

        let resp = update_profile(
            State(state.clone()),
            bearer(&f, &uid),
            Json(UpdateProfileRequest {
                first_name: None,
                last_name: None,
                email: Some(format!("{}@new.example.com", uuid::Uuid::new_v4().simple())),
            }),
        )
        .await;
        assert!(resp.success, "{:?}", resp.error);
        let rec: serde_json::Value =
            serde_json::from_slice(&f.storage().get_kv(&key).await.unwrap().unwrap()).unwrap();
        assert_ne!(
            rec["email_verified"],
            serde_json::json!(true),
            "a new, unproven address must not inherit the old verification"
        );
    }

    #[tokio::test]
    async fn the_authenticated_send_path_also_withholds_the_token() {
        let mailbox = Arc::new(Mailbox::default());
        let (state, f) = state_with(mailbox.clone()).await;
        let (uid, email) = account(&f).await;

        let resp = send_verification(State(state.clone()), bearer(&f, &uid)).await;
        let body = json(&resp);
        assert!(resp.success, "{:?}", resp.error);
        let sent = settle(&mailbox, 1).await;
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].0, email);
        assert!(
            !body.to_string().contains(&sent[0].2),
            "the token must not appear in the response: {body}"
        );
        assert!(body["data"].get("verification_token").is_none(), "{body}");
    }
}
