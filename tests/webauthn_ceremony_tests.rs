//! Access-control tests for the WebAuthn registration / authentication
//! ceremonies served by the API router.
//!
//! Registering a credential is an account-security operation: it must be
//! done by the account's own authenticated session (or an admin), and a
//! successful assertion must resolve to the REAL account, never to a
//! caller-chosen string.

#[cfg(all(test, feature = "api-server"))]
mod webauthn_ceremony_tests {
    use auth_framework::api::ApiServer;
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tower::ServiceExt;

    struct Env {
        fw: Arc<AuthFramework>,
        app: Router,
    }

    async fn env() -> Env {
        let config = AuthConfig::new().secret("test_webauthn_ceremony_secret_long_enough_32");
        let mut fw = AuthFramework::new(config);
        fw.initialize().await.unwrap();
        let fw = Arc::new(fw);
        let app = ApiServer::new(fw.clone()).build_router().await.unwrap();
        Env { fw, app }
    }

    /// Registers a user; returns (user_id, bearer token).
    async fn user(env: &Env, username: &str) -> (String, String) {
        let user_id = env
            .fw
            .register_user(
                username,
                &format!("{username}@test.example.com"),
                "SecurePass123!",
            )
            .await
            .unwrap();
        let token = env
            .fw
            .token_manager()
            .create_auth_token(&user_id, vec![], "test", None)
            .unwrap()
            .access_token;
        (user_id, token)
    }

    async fn admin(env: &Env, username: &str) -> String {
        let (user_id, _) = user(env, username).await;
        env.fw
            .update_user_roles(&user_id, &["admin".to_string()])
            .await
            .unwrap();
        // Mint AFTER the role change so the token reflects the record.
        env.fw
            .token_manager()
            .create_auth_token(&user_id, vec![], "test", None)
            .unwrap()
            .access_token
    }

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        bearer: Option<&str>,
        body: Value,
    ) -> Value {
        let mut req = Request::builder()
            .method(method)
            .uri(format!("/api/v1{uri}"))
            .header("content-type", "application/json");
        if let Some(token) = bearer {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let response = app
            .clone()
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes)}))
    }

    fn error_code(v: &Value) -> &str {
        v["error"]["code"].as_str().unwrap_or("")
    }

    fn error_message(v: &Value) -> String {
        v["error"]["message"].as_str().unwrap_or("").to_lowercase()
    }

    fn client_data(kind: &str, challenge: &str, origin: Option<&str>) -> String {
        let mut cd = json!({"type": kind, "challenge": challenge});
        if let Some(origin) = origin {
            cd["origin"] = json!(origin);
        }
        B64.encode(cd.to_string())
    }

    fn complete_body(
        session_id: &str,
        cred_id: &str,
        pubkey: &str,
        client_data_json: String,
    ) -> Value {
        json!({
            "session_id": session_id,
            "credential_id": cred_id,
            "credential_public_key": pubkey,
            "attestation_object": "bm9uZQ",
            "client_data_json": client_data_json,
            "authenticator_data": "AA",
            "signature": "AA",
        })
    }

    struct Authenticator {
        pair: EcdsaKeyPair,
    }

    impl Authenticator {
        fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            Self { pair }
        }

        fn public_key(&self) -> String {
            B64.encode(self.pair.public_key().as_ref())
        }

        /// (authenticator_data, client_data_json, signature), all base64url.
        fn assertion(&self, challenge: &str, counter: u32) -> (String, String, String) {
            let mut auth_data = vec![0u8; 37];
            auth_data[32] = 0x01; // user present
            auth_data[33..37].copy_from_slice(&counter.to_be_bytes());
            let cd = client_data("webauthn.get", challenge, Some("https://localhost"));
            let cd_bytes = B64.decode(&cd).unwrap();
            let mut msg = auth_data.clone();
            msg.extend_from_slice(&Sha256::digest(&cd_bytes));
            let sig = self.pair.sign(&SystemRandom::new(), &msg).unwrap();
            (B64.encode(&auth_data), cd, B64.encode(sig.as_ref()))
        }
    }

    /// Full, legitimate registration of `authenticator` for `username` by
    /// `bearer`. Returns the credential id.
    async fn register_credential(
        env: &Env,
        bearer: &str,
        username: &str,
        authenticator: &Authenticator,
    ) -> String {
        let init = call(
            &env.app,
            "POST",
            "/webauthn/registration/init",
            Some(bearer),
            json!({"username": username}),
        )
        .await;
        assert_eq!(init["success"], true, "legitimate init must work: {init}");
        let session_id = init["data"]["session_id"].as_str().unwrap();
        let challenge = init["data"]["challenge"].as_str().unwrap();
        let cred_id = format!("cred-{username}");
        let done = call(
            &env.app,
            "POST",
            "/webauthn/registration/complete",
            Some(bearer),
            complete_body(
                session_id,
                &cred_id,
                &authenticator.public_key(),
                client_data("webauthn.create", challenge, Some("https://localhost")),
            ),
        )
        .await;
        assert_eq!(
            done["success"], true,
            "legitimate complete must work: {done}"
        );
        cred_id
    }

    /// Runs a full assertion for `username`; returns the API response.
    async fn authenticate(
        env: &Env,
        username: &str,
        cred_id: &str,
        authenticator: &Authenticator,
        counter: u32,
    ) -> Value {
        let init = call(
            &env.app,
            "POST",
            "/webauthn/authentication/init",
            None,
            json!({"username": username}),
        )
        .await;
        let session_id = init["data"]["session_id"].as_str().unwrap().to_string();
        let challenge = init["data"]["challenge"].as_str().unwrap().to_string();
        let (auth_data, cd, sig) = authenticator.assertion(&challenge, counter);
        call(
            &env.app,
            "POST",
            "/webauthn/authentication/complete",
            None,
            json!({
                "session_id": session_id,
                "credential_id": cred_id,
                "authenticator_data": auth_data,
                "client_data_json": cd,
                "signature": sig,
            }),
        )
        .await
    }

    #[tokio::test]
    async fn registration_init_requires_a_bearer_token() {
        let env = env().await;
        user(&env, "alice").await;
        let resp = call(
            &env.app,
            "POST",
            "/webauthn/registration/init",
            None,
            json!({"username": "alice"}),
        )
        .await;
        assert_eq!(
            resp["success"], false,
            "unauthenticated init must be refused: {resp}"
        );
        assert_eq!(error_code(&resp), "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn registration_init_for_another_user_is_forbidden() {
        let env = env().await;
        let (_, alice_token) = user(&env, "alice").await;
        user(&env, "bobby").await;
        let resp = call(
            &env.app,
            "POST",
            "/webauthn/registration/init",
            Some(&alice_token),
            json!({"username": "bobby"}),
        )
        .await;
        assert_eq!(resp["success"], false, "A must not register for B: {resp}");
        assert_eq!(error_code(&resp), "FORBIDDEN");
    }

    #[tokio::test]
    async fn registration_init_for_a_nonexistent_user_is_forbidden() {
        let env = env().await;
        let (_, alice_token) = user(&env, "alice").await;
        let resp = call(
            &env.app,
            "POST",
            "/webauthn/registration/init",
            Some(&alice_token),
            json!({"username": "ghost"}),
        )
        .await;
        assert_eq!(resp["success"], false, "{resp}");
        assert_eq!(error_code(&resp), "FORBIDDEN");
    }

    #[tokio::test]
    async fn owner_and_admin_can_start_registration() {
        let env = env().await;
        let (_, alice_token) = user(&env, "alice").await;
        let admin_token = admin(&env, "root_admin").await;
        for (token, who) in [(&alice_token, "owner"), (&admin_token, "admin")] {
            let resp = call(
                &env.app,
                "POST",
                "/webauthn/registration/init",
                Some(token),
                json!({"username": "alice"}),
            )
            .await;
            assert_eq!(resp["success"], true, "{who} must be allowed: {resp}");
        }
    }

    #[tokio::test]
    async fn registration_complete_requires_the_session_owner() {
        let env = env().await;
        let (_, alice_token) = user(&env, "alice").await;
        let (_, bobby_token) = user(&env, "bobby").await;
        let auth = Authenticator::new();
        let init = call(
            &env.app,
            "POST",
            "/webauthn/registration/init",
            Some(&alice_token),
            json!({"username": "alice"}),
        )
        .await;
        let session_id = init["data"]["session_id"].as_str().unwrap();
        let challenge = init["data"]["challenge"].as_str().unwrap();
        let body = complete_body(
            session_id,
            "cred-x",
            &auth.public_key(),
            client_data("webauthn.create", challenge, Some("https://localhost")),
        );

        let anon = call(
            &env.app,
            "POST",
            "/webauthn/registration/complete",
            None,
            body.clone(),
        )
        .await;
        assert_eq!(
            anon["success"], false,
            "anonymous complete must be refused: {anon}"
        );
        assert_eq!(error_code(&anon), "UNAUTHORIZED");

        let other = call(
            &env.app,
            "POST",
            "/webauthn/registration/complete",
            Some(&bobby_token),
            body,
        )
        .await;
        assert_eq!(
            other["success"], false,
            "another user's session must be refused: {other}"
        );
        assert_eq!(error_code(&other), "FORBIDDEN");
    }

    #[tokio::test]
    async fn registration_complete_refuses_client_data_without_origin() {
        let env = env().await;
        let (_, alice_token) = user(&env, "alice").await;
        let auth = Authenticator::new();
        let init = call(
            &env.app,
            "POST",
            "/webauthn/registration/init",
            Some(&alice_token),
            json!({"username": "alice"}),
        )
        .await;
        let session_id = init["data"]["session_id"].as_str().unwrap();
        let challenge = init["data"]["challenge"].as_str().unwrap();
        let resp = call(
            &env.app,
            "POST",
            "/webauthn/registration/complete",
            Some(&alice_token),
            complete_body(
                session_id,
                "cred-no-origin",
                &auth.public_key(),
                client_data("webauthn.create", challenge, None),
            ),
        )
        .await;
        assert_eq!(
            resp["success"], false,
            "missing origin must be refused: {resp}"
        );
        assert!(error_message(&resp).contains("origin"), "{resp}");
    }

    #[tokio::test]
    async fn authentication_complete_refuses_client_data_without_origin() {
        let env = env().await;
        let init = call(
            &env.app,
            "POST",
            "/webauthn/authentication/init",
            None,
            json!({"username": "alice"}),
        )
        .await;
        let session_id = init["data"]["session_id"].as_str().unwrap().to_string();
        let challenge = init["data"]["challenge"].as_str().unwrap().to_string();
        let resp = call(
            &env.app,
            "POST",
            "/webauthn/authentication/complete",
            None,
            json!({
                "session_id": session_id,
                "credential_id": "whatever",
                "authenticator_data": "AA",
                "client_data_json": client_data("webauthn.get", &challenge, None),
                "signature": "AA",
            }),
        )
        .await;
        assert_eq!(resp["success"], false, "{resp}");
        assert!(error_message(&resp).contains("origin"), "{resp}");
    }

    /// Positive control for the flow the fix must keep working, and the
    /// core of the fix: the token is for the REAL account id.
    #[tokio::test]
    async fn legitimate_ceremony_yields_a_token_for_the_real_user_id() {
        let env = env().await;
        let (user_id, alice_token) = user(&env, "alice").await;
        let auth = Authenticator::new();
        let cred_id = register_credential(&env, &alice_token, "alice", &auth).await;

        let resp = authenticate(&env, "alice", &cred_id, &auth, 1).await;
        assert_eq!(resp["success"], true, "{resp}");
        let token = resp["data"]["access_token"].as_str().unwrap();
        let claims = env.fw.token_manager().validate_jwt_token(token).unwrap();
        assert_eq!(
            claims.sub, user_id,
            "sub must be the account id, not the username"
        );

        // The owner can list their own credentials by username.
        let list = call(
            &env.app,
            "GET",
            "/webauthn/credentials/alice",
            Some(&alice_token),
            json!({}),
        )
        .await;
        assert_eq!(list["success"], true, "{list}");
        assert_eq!(list["data"].as_array().map(|a| a.len()), Some(1), "{list}");
    }

    #[tokio::test]
    async fn authentication_for_a_deactivated_user_is_refused() {
        let env = env().await;
        let (user_id, alice_token) = user(&env, "alice").await;
        let auth = Authenticator::new();
        let cred_id = register_credential(&env, &alice_token, "alice", &auth).await;
        env.fw.set_user_active(&user_id, false).await.unwrap();

        let resp = authenticate(&env, "alice", &cred_id, &auth, 1).await;
        assert_eq!(
            resp["success"], false,
            "deactivated user must not get a token: {resp}"
        );
    }

    /// A credential record for a username that has no account (planted
    /// directly, as a pre-fix attacker could have via the old open
    /// registration) must never mint a token.
    #[tokio::test]
    async fn authentication_for_a_nonexistent_user_is_refused() {
        let env = env().await;
        let auth = Authenticator::new();
        let storage = env.fw.storage();
        storage
            .store_kv(
                "webauthn_credential:ghost:cred-ghost",
                json!({
                    "credential_id": "cred-ghost",
                    "credential_public_key": auth.public_key(),
                    "username": "ghost",
                    "sign_count": 0u64
                })
                .to_string()
                .as_bytes(),
                None,
            )
            .await
            .unwrap();
        storage
            .store_kv(
                "webauthn_creds_index:ghost",
                json!(["cred-ghost"]).to_string().as_bytes(),
                None,
            )
            .await
            .unwrap();

        let resp = authenticate(&env, "ghost", "cred-ghost", &auth, 1).await;
        assert_eq!(resp["success"], false, "no account => no token: {resp}");
    }

    #[tokio::test]
    async fn list_and_delete_follow_owner_admin_stranger_rules() {
        let env = env().await;
        let (_, alice_token) = user(&env, "alice").await;
        let (_, bobby_token) = user(&env, "bobby").await;
        let admin_token = admin(&env, "root_admin").await;
        let auth = Authenticator::new();
        let cred_id = register_credential(&env, &alice_token, "alice", &auth).await;

        // A stranger can neither list nor delete.
        let list = call(
            &env.app,
            "GET",
            "/webauthn/credentials/alice",
            Some(&bobby_token),
            json!({}),
        )
        .await;
        assert_eq!(list["success"], false, "{list}");
        assert_eq!(error_code(&list), "FORBIDDEN");
        let uri = format!("/webauthn/credentials/alice/{cred_id}");
        let del = call(&env.app, "DELETE", &uri, Some(&bobby_token), json!({})).await;
        assert_eq!(del["success"], false, "{del}");
        assert_eq!(error_code(&del), "FORBIDDEN");

        // An admin may list a nonexistent name (empty), and delete for the owner.
        let ghost = call(
            &env.app,
            "GET",
            "/webauthn/credentials/ghost",
            Some(&admin_token),
            json!({}),
        )
        .await;
        assert_eq!(ghost["success"], true, "{ghost}");
        assert_eq!(ghost["data"].as_array().map(|a| a.len()), Some(0));
        let del = call(&env.app, "DELETE", &uri, Some(&admin_token), json!({})).await;
        assert_eq!(del["success"], true, "{del}");

        // The deleted credential can no longer sign in.
        let resp = authenticate(&env, "alice", &cred_id, &auth, 1).await;
        assert_eq!(resp["success"], false, "{resp}");
    }

    #[tokio::test]
    async fn registration_session_is_single_use_and_unknown_sessions_are_refused() {
        let env = env().await;
        let (_, alice_token) = user(&env, "alice").await;
        let auth = Authenticator::new();
        let init = call(
            &env.app,
            "POST",
            "/webauthn/registration/init",
            Some(&alice_token),
            json!({"username": "alice"}),
        )
        .await;
        let session_id = init["data"]["session_id"].as_str().unwrap();
        let challenge = init["data"]["challenge"].as_str().unwrap();
        let body = complete_body(
            session_id,
            "cred-once",
            &auth.public_key(),
            client_data("webauthn.create", challenge, Some("https://localhost")),
        );
        let first = call(
            &env.app,
            "POST",
            "/webauthn/registration/complete",
            Some(&alice_token),
            body.clone(),
        )
        .await;
        assert_eq!(first["success"], true, "{first}");
        let replay = call(
            &env.app,
            "POST",
            "/webauthn/registration/complete",
            Some(&alice_token),
            body,
        )
        .await;
        assert_eq!(
            replay["success"], false,
            "a session must not be replayable: {replay}"
        );

        let unknown = call(
            &env.app,
            "POST",
            "/webauthn/registration/complete",
            Some(&alice_token),
            complete_body(
                "webauthn_does-not-exist",
                "cred-x",
                &auth.public_key(),
                client_data("webauthn.create", challenge, Some("https://localhost")),
            ),
        )
        .await;
        assert_eq!(unknown["success"], false, "{unknown}");
    }

    #[tokio::test]
    async fn registration_complete_refuses_after_mid_ceremony_deactivation() {
        let env = env().await;
        let (user_id, alice_token) = user(&env, "alice").await;
        let auth = Authenticator::new();
        let init = call(
            &env.app,
            "POST",
            "/webauthn/registration/init",
            Some(&alice_token),
            json!({"username": "alice"}),
        )
        .await;
        let session_id = init["data"]["session_id"].as_str().unwrap();
        let challenge = init["data"]["challenge"].as_str().unwrap();
        env.fw.set_user_active(&user_id, false).await.unwrap();
        let resp = call(
            &env.app,
            "POST",
            "/webauthn/registration/complete",
            Some(&alice_token),
            complete_body(
                session_id,
                "cred-late",
                &auth.public_key(),
                client_data("webauthn.create", challenge, Some("https://localhost")),
            ),
        )
        .await;
        assert_eq!(resp["success"], false, "{resp}");
    }

    /// Credential records keyed by username (what the old open
    /// registration produced) must not authenticate anyone, even for a
    /// real account.
    #[tokio::test]
    async fn username_keyed_legacy_credentials_are_ignored() {
        let env = env().await;
        user(&env, "alice").await;
        let auth = Authenticator::new();
        let storage = env.fw.storage();
        storage
            .store_kv(
                "webauthn_credential:alice:cred-legacy",
                json!({
                    "credential_id": "cred-legacy",
                    "credential_public_key": auth.public_key(),
                    "username": "alice",
                    "sign_count": 0u64
                })
                .to_string()
                .as_bytes(),
                None,
            )
            .await
            .unwrap();
        let resp = authenticate(&env, "alice", "cred-legacy", &auth, 1).await;
        assert_eq!(resp["success"], false, "{resp}");
    }

    /// Sign-in must not reveal whether a username is a real, active
    /// account: an unknown name and a real account with an unknown
    /// credential get the identical answer.
    #[tokio::test]
    async fn authentication_complete_does_not_reveal_which_usernames_exist() {
        let env = env().await;
        user(&env, "alice").await;
        let auth = Authenticator::new();
        let real = authenticate(&env, "alice", "no-such-credential", &auth, 1).await;
        let unknown = authenticate(&env, "nobody_here", "no-such-credential", &auth, 1).await;
        assert_eq!(real["success"], false);
        assert_eq!(unknown["success"], false);
        assert_eq!(real["error"], unknown["error"], "{real} vs {unknown}");
    }
}
