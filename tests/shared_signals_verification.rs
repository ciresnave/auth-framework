//! **A security event is only believed if it was signed by a key the operator configured.**
//!
//! `SharedSignalsManager::receive_event` acts on `session_revoked`, `account_disabled` and
//! `credential_change`. With verification on (the default) it used to accept (a) an event whose
//! data carries no `jwt` at all, and (b) a JWT signed with a constant published in the source,
//! whenever `SHARED_SIGNALS_VERIFICATION_KEY` was unset.

use auth_framework::server::oidc::oidc_extensions::{
    EventSeverity, SecurityEvent, SharedSignalsConfig, SharedSignalsManager,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;

const PUBLISHED_DEV_KEY: &str = "shared_signals_development_key_not_for_production";

fn event(data: serde_json::Value) -> SecurityEvent {
    SecurityEvent {
        event_id: "evt-1".into(),
        event_type: "session_revoked".into(),
        timestamp: chrono::Utc::now(),
        subject: "victim".into(),
        data,
        severity: EventSeverity::Info,
    }
}

fn jwt_signed_with(secret: &str) -> String {
    let claims = json!({ "exp": chrono::Utc::now().timestamp() + 600 });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

// One test: the cases share the process environment, so they run in sequence.
#[tokio::test]
async fn events_are_accepted_only_when_signed_by_the_configured_key() {
    assert!(
        std::env::var("SHARED_SIGNALS_VERIFICATION_KEY").is_err(),
        "precondition: no verification key configured"
    );
    let manager = SharedSignalsManager::new(SharedSignalsConfig::default());

    // No key configured: nothing is believed.
    assert!(
        manager.receive_event(event(json!({}))).await.is_err(),
        "an event with no signature at all was accepted"
    );
    assert!(
        manager
            .receive_event(event(json!({ "jwt": jwt_signed_with(PUBLISHED_DEV_KEY) })))
            .await
            .is_err(),
        "a JWT signed with the constant published in the source was accepted"
    );

    // Key configured: the right key is accepted (positive control), another key is not.
    let configured = "a-key-the-operator-configured-0123456789";
    // SAFETY: the only test in this binary; nothing reads the environment concurrently.
    unsafe { std::env::set_var("SHARED_SIGNALS_VERIFICATION_KEY", configured) };
    assert!(
        manager
            .receive_event(event(json!({ "jwt": jwt_signed_with(configured) })))
            .await
            .is_ok(),
        "an event signed by the configured key was refused"
    );
    assert!(
        manager
            .receive_event(event(
                json!({ "jwt": jwt_signed_with("someone-elses-key-0123456789abcdef") })
            ))
            .await
            .is_err()
    );
    assert!(
        manager.receive_event(event(json!({}))).await.is_err(),
        "an unsigned event was accepted with a key configured"
    );
    unsafe { std::env::remove_var("SHARED_SIGNALS_VERIFICATION_KEY") };
}
