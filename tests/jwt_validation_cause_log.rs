//! `TokenManager::validate_jwt_token` reports every decode failure to the caller as the same
//! opaque `Invalid token format`, so a client learns nothing about why a token was refused.
//! The operator still needs the reason: it must reach the logs without reaching the caller.

use auth_framework::{
    AuthConfig, AuthFramework,
    errors::{AuthError, TokenError},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use std::io;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

const SECRET: &str = "q7Xv2LmP9aRt4WnZ8cYb1HdKf6GjS3uE5oIx";

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[derive(Serialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    nbf: i64,
    jti: String,
    scope: String,
}

fn claims_for_audience(aud: &str) -> Claims {
    let now = Utc::now().timestamp();
    Claims {
        sub: "user-1".into(),
        iss: "auth-framework".into(),
        aud: aud.into(),
        exp: (Utc::now() + Duration::hours(1)).timestamp(),
        iat: now,
        nbf: now,
        jti: "jti-1".into(),
        scope: "read".into(),
    }
}

async fn framework() -> AuthFramework {
    let config = AuthConfig::new()
        .secret(SECRET.to_string())
        .issuer("auth-framework".to_string())
        .audience("auth-framework".to_string());
    // `new()` keeps a temporary secret until `initialize()` installs the configured one.
    let mut fw = AuthFramework::new(config);
    fw.initialize().await.unwrap();
    fw
}

/// Run `f` with a DEBUG-level subscriber on this thread and return what it logged.
fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
    let sink = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let out = tracing::subscriber::with_default(subscriber, f);
    (out, sink.text())
}

fn invalid_message(result: auth_framework::Result<auth_framework::tokens::JwtClaims>) -> String {
    match result {
        Err(AuthError::Token(TokenError::Invalid { message })) => message,
        other => panic!("expected TokenError::Invalid, got {other:?}"),
    }
}

#[tokio::test]
async fn wrong_audience_logs_its_cause_but_returns_the_opaque_message() {
    let fw = framework().await;
    let jwt = encode(
        &Header::default(),
        &claims_for_audience("someone-else"),
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap();

    let (result, logs) = capture_logs(|| fw.token_manager().validate_jwt_token(&jwt));

    let message = invalid_message(result);
    assert_eq!(message, "Invalid token format", "public message must not change");
    assert!(
        logs.contains("InvalidAudience"),
        "the cause must be logged, got: {logs:?}"
    );
    assert!(
        !message.contains("Audience"),
        "the cause must not reach the caller"
    );
    assert!(!logs.contains(&jwt), "the token itself must not be logged");
}

#[tokio::test]
async fn malformed_token_logs_its_cause_but_returns_the_opaque_message() {
    let fw = framework().await;

    let (result, logs) = capture_logs(|| fw.token_manager().validate_jwt_token("not.a.jwt"));

    assert_eq!(invalid_message(result), "Invalid token format");
    assert!(
        logs.contains("JWT validation failed"),
        "the failure must be logged, got: {logs:?}"
    );
    assert!(!logs.contains("not.a.jwt"), "the token itself must not be logged");
}
