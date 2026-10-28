//! The OAuth2 introspection and revocation endpoints leave an audit-trail record (issue #91),
//! queryable through `AuthFramework::audit().query_events`: who asked, what came of it, and
//! whose token it was; never the token or a secret.

#[cfg(all(test, feature = "axum-integration"))]
mod oauth_audit_trail_tests {
    use auth_framework::api::ApiState;
    use auth_framework::api::oauth_advanced::{IntrospectRequest, introspect_token};
    use auth_framework::api::oauth2::{RevokeRequest, revoke};
    use auth_framework::audit::{AuditEvent, AuditEventType, AuditQuery, EventOutcome};
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Form;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
    use base64::Engine;
    use std::sync::Arc;
    use std::time::Duration;

    struct Env {
        state: ApiState,
        fw: Arc<AuthFramework>,
        user: String,
    }

    async fn env() -> Env {
        let config = AuthConfig::new()
            .secret("test_oauth_audit_trail_secret_key_long_enough_for_jwt".to_string())
            .token_lifetime(Duration::from_secs(300));
        let mut f = AuthFramework::new(config);
        f.initialize().await.unwrap();
        let fw = Arc::new(f);
        let state = ApiState::new(fw.clone()).await.unwrap();
        let name = format!("au_{}", uuid::Uuid::new_v4().simple());
        let user = fw
            .register_user(
                &name,
                &format!("{name}@test.example.com"),
                "SecurePass123!x",
            )
            .await
            .unwrap();
        fw.storage()
            .store_kv(
                "oauth2_client:audited-rs",
                serde_json::json!({"client_id": "audited-rs", "client_secret": "rs-secret-value"})
                    .to_string()
                    .as_bytes(),
                None,
            )
            .await
            .unwrap();
        Env { state, fw, user }
    }

    async fn introspect(env: &Env, secret: &str, token: &str) -> bool {
        let mut headers = HeaderMap::new();
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("audited-rs:{secret}"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {basic}")).unwrap(),
        );
        introspect_token(
            State(env.state.clone()),
            headers,
            Form(IntrospectRequest {
                token: token.to_string(),
                token_type_hint: None,
                client_id: None,
                client_secret: None,
            }),
        )
        .await
        .is_ok()
    }

    async fn events(env: &Env, kind: AuditEventType) -> Vec<AuditEvent> {
        env.fw
            .audit()
            .query_events(
                &AuditQuery::builder()
                    .event_types(vec![kind])
                    .limit(100)
                    .build(),
            )
            .await
            .expect("the default audit storage can be queried")
    }

    #[tokio::test]
    async fn introspection_requests_are_recorded() {
        let env = env().await;
        let jwt = env
            .fw
            .token_manager()
            .create_jwt_token(
                &env.user,
                vec!["read".into()],
                Some(Duration::from_secs(300)),
            )
            .unwrap();

        // An active token.
        assert!(introspect(&env, "rs-secret-value", &jwt).await);
        // A token that is not one.
        assert!(introspect(&env, "rs-secret-value", "garbage").await);
        // A wrong client secret.
        assert!(!introspect(&env, "wrong-secret", &jwt).await);

        let recorded = events(&env, AuditEventType::TokenIntrospected).await;
        assert_eq!(recorded.len(), 3, "{recorded:#?}");
        let by_result = |r: &str| {
            recorded
                .iter()
                .find(|e| e.details.get("result").map(String::as_str) == Some(r))
                .unwrap_or_else(|| panic!("no event with result {r}: {recorded:#?}"))
        };

        let active = by_result("active");
        assert_eq!(active.outcome, EventOutcome::Success);
        assert_eq!(active.actor.actor_id, "audited-rs");
        assert_eq!(active.user_id.as_deref(), Some(env.user.as_str()));
        assert!(active.details.contains_key("jti"));

        let inactive = by_result("inactive_invalid");
        assert_eq!(inactive.outcome, EventOutcome::Success);
        assert_eq!(inactive.actor.actor_id, "audited-rs");

        let refused = by_result("client_authentication_failed");
        assert_eq!(refused.outcome, EventOutcome::Failure);
        assert_eq!(refused.actor.actor_id, "audited-rs");

        // Neither the token nor a secret is in any record.
        let everything = format!("{recorded:?}");
        assert!(!everything.contains(&jwt));
        assert!(!everything.contains("rs-secret-value"));
        assert!(!everything.contains("wrong-secret"));
    }

    #[tokio::test]
    async fn revocations_are_recorded() {
        let env = env().await;
        let jwt = env
            .fw
            .token_manager()
            .create_jwt_token(
                &env.user,
                vec!["read".into()],
                Some(Duration::from_secs(300)),
            )
            .unwrap();

        let resp = revoke(
            State(env.state.clone()),
            HeaderMap::new(),
            axum::Json(RevokeRequest {
                token: jwt.clone(),
                token_type_hint: Some("access_token".to_string()),
                client_id: None,
                client_secret: None,
            }),
        )
        .await;
        assert!(resp.success);

        let recorded = events(&env, AuditEventType::TokenRevoked).await;
        let event = recorded
            .iter()
            .find(|e| e.user_id.as_deref() == Some(env.user.as_str()))
            .unwrap_or_else(|| panic!("no revocation event for the user: {recorded:#?}"));
        assert_eq!(event.outcome, EventOutcome::Success);
        assert!(event.details.contains_key("jti"));
        assert!(event.details.contains_key("token_fingerprint"));
        assert!(!format!("{recorded:?}").contains(&jwt));
    }
}
