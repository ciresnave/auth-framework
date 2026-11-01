//! The `client_credentials` grant of `OAuth2Server` leaves an audit-trail record (issue #91): which
//! client asked, for which scopes, and whether a token was issued; never a secret or a token.

use async_trait::async_trait;
use auth_framework::audit::{
    AuditEvent, AuditEventType, AuditQuery, AuditStatistics, AuditStorage, EventOutcome, StatsQuery,
};
use auth_framework::errors::{AuthError, Result};
use auth_framework::server::oauth::oauth2_server::{OAuth2Config, OAuth2Server, TokenRequest};
use auth_framework::tokens::TokenManager;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

const SECRET: &str = "cc-secret-value-0123456789-abcdefghij-KLMN";

#[derive(Default)]
struct Recorder(Mutex<Vec<AuditEvent>>);

#[async_trait]
impl AuditStorage for Recorder {
    async fn store_event(&self, event: &AuditEvent) -> Result<()> {
        self.0.lock().unwrap().push(event.clone());
        Ok(())
    }
    async fn query_events(&self, _: &AuditQuery) -> Result<Vec<AuditEvent>> {
        Ok(self.0.lock().unwrap().clone())
    }
    async fn get_event(&self, _: &str) -> Result<Option<AuditEvent>> {
        Err(AuthError::internal("not used"))
    }
    async fn count_events(&self, _: &AuditQuery) -> Result<u64> {
        Err(AuthError::internal("not used"))
    }
    async fn delete_old_events(&self, _: SystemTime) -> Result<u64> {
        Err(AuthError::internal("not used"))
    }
    async fn get_statistics(&self, _: &StatsQuery) -> Result<AuditStatistics> {
        Err(AuthError::internal("not used"))
    }
}

async fn server(recorder: Option<Arc<Recorder>>) -> OAuth2Server {
    let token_manager = Arc::new(TokenManager::new_hmac(
        b"test_secret_key_32_bytes_long!!!!",
        "test_issuer",
        "test_audience",
    ));
    let mut server = OAuth2Server::new(OAuth2Config::default(), token_manager)
        .await
        .unwrap();
    if let Some(r) = recorder {
        server = server.with_audit_storage(r);
    }
    server
        .register_confidential_client(
            "cc-1".to_string(),
            SECRET,
            vec!["https://app.example.com/cb".to_string()],
            vec!["read".to_string(), "write".to_string()],
            vec!["client_credentials".to_string()],
        )
        .await
        .unwrap();
    server
}

fn request(secret: &str, scope: &str) -> TokenRequest {
    TokenRequest {
        scope: Some(scope.to_string()),
        ..TokenRequest::client_credentials("cc-1", secret)
    }
}

#[tokio::test]
async fn an_issued_client_credentials_token_is_recorded_without_the_secret_or_the_token() {
    let recorder = Arc::new(Recorder::default());
    let server = server(Some(recorder.clone())).await;

    let response = server
        .token_exchange(request(SECRET, "read"))
        .await
        .unwrap();

    let events = recorder.0.lock().unwrap().clone();
    assert_eq!(events.len(), 1, "one grant, one record");
    let e = &events[0];
    assert_eq!(e.event_type, AuditEventType::TokenIssued);
    assert_eq!(e.outcome, EventOutcome::Success);
    assert_eq!(e.actor.actor_id, "cc-1");
    assert_eq!(
        e.details.get("requested_scope").map(String::as_str),
        Some("read")
    );
    assert_eq!(
        e.details.get("granted_scope").map(String::as_str),
        Some("read")
    );
    let dump = format!("{e:?}");
    assert!(
        !dump.contains(SECRET),
        "the client secret must not be recorded"
    );
    assert!(
        !dump.contains(&response.access_token),
        "the access token must not be recorded"
    );
}

#[tokio::test]
async fn a_refused_client_credentials_grant_is_recorded_as_a_failure() {
    let recorder = Arc::new(Recorder::default());
    let server = server(Some(recorder.clone())).await;

    let wrong = "not-the-secret-9876543210-zyxwvutsrq-ABCD";
    assert!(server.token_exchange(request(wrong, "read")).await.is_err());

    let events = recorder.0.lock().unwrap().clone();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, AuditEventType::TokenIssued);
    assert_eq!(events[0].outcome, EventOutcome::Failure);
    assert_eq!(events[0].actor.actor_id, "cc-1");
    let dump = format!("{:?}", events[0]);
    assert!(
        !dump.contains(wrong),
        "a presented secret must not be recorded"
    );
    assert!(!dump.contains(SECRET));
}

#[tokio::test]
async fn without_an_audit_storage_the_grant_still_works_and_records_nothing() {
    // Control: the recorder above is what makes the records appear, not the grant itself.
    let server = server(None).await;
    assert!(server.token_exchange(request(SECRET, "read")).await.is_ok());
}
