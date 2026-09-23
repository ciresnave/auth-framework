//! CAEP (Continuous Access Evaluation Protocol) implementation.
//!
//! Implements the Shared Signals and Events (SSE) Framework with CAEP event types
//! for continuous access evaluation, session revocation, and compliance signalling.
//!
//! # References
//!
//! - [CAEP spec](https://openid.net/specs/openid-caep-specification-1_0.html)
//! - [SSE Framework](https://openid.net/specs/openid-sse-framework-1_0.html)
//! - [SET (Security Event Token) RFC 8417](https://www.rfc-editor.org/rfc/rfc8417)

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

// ── Event types (CAEP §3) ───────────────────────────────────────────

/// Well-known CAEP event type URIs.
pub mod event_types {
    pub const SESSION_REVOKED: &str =
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    pub const TOKEN_CLAIMS_CHANGE: &str =
        "https://schemas.openid.net/secevent/caep/event-type/token-claims-change";
    pub const CREDENTIAL_CHANGE: &str =
        "https://schemas.openid.net/secevent/caep/event-type/credential-change";
    pub const ASSURANCE_LEVEL_CHANGE: &str =
        "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";
    pub const DEVICE_COMPLIANCE_CHANGE: &str =
        "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change";
}

// ── Subject identifiers (SSE §3) ───────────────────────────────────

/// Subject identifier formats per the SSE Framework.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "format")]
pub enum SubjectIdentifier {
    /// Email-based subject.
    #[serde(rename = "email")]
    Email { email: String },
    /// Issuer + subject pair.
    #[serde(rename = "iss_sub")]
    IssSub { iss: String, sub: String },
    /// Opaque identifier.
    #[serde(rename = "opaque")]
    Opaque { id: String },
    /// Phone number (+E.164).
    #[serde(rename = "phone_number")]
    PhoneNumber { phone_number: String },
    /// Session ID.
    #[serde(rename = "session_id")]
    SessionId {
        session_id: String,
        #[serde(default)]
        iss: Option<String>,
    },
}

// ── CAEP Event ──────────────────────────────────────────────────────

/// The reason/initiating entity for a CAEP event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventReasonAdmin {
    /// Policy-driven.
    Policy,
    /// Admin-initiated.
    Admin,
    /// User-initiated.
    User,
}

/// Change type for credential/compliance events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    Create,
    Revoke,
    Update,
    Delete,
}

/// A CAEP event (carried as a Security Event Token — SET).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaepEvent {
    /// Unique event ID (jti).
    pub jti: String,
    /// Issuer.
    pub iss: String,
    /// Issued-at (Unix timestamp).
    pub iat: u64,
    /// Event type URI.
    pub event_type: String,
    /// Subject identifier.
    pub subject: SubjectIdentifier,
    /// Initiating entity.
    #[serde(default)]
    pub initiating_entity: Option<EventReasonAdmin>,
    /// Reason string for the event.
    #[serde(default)]
    pub reason_admin: Option<String>,
    /// Reason string shown to the user.
    #[serde(default)]
    pub reason_user: Option<String>,
    /// Additional event-specific claims.
    #[serde(default)]
    pub properties: HashMap<String, serde_json::Value>,
}

impl CaepEvent {
    /// Build a new CAEP event with generated ID and timestamp.
    pub fn new(iss: &str, event_type: &str, subject: SubjectIdentifier) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            jti: Uuid::new_v4().to_string(),
            iss: iss.to_string(),
            iat: now,
            event_type: event_type.to_string(),
            subject,
            initiating_entity: None,
            reason_admin: None,
            reason_user: None,
            properties: HashMap::new(),
        }
    }

    /// Set the initiating entity.
    pub fn with_initiating_entity(mut self, entity: EventReasonAdmin) -> Self {
        self.initiating_entity = Some(entity);
        self
    }

    /// Set the admin reason.
    pub fn with_reason_admin(mut self, reason: &str) -> Self {
        self.reason_admin = Some(reason.to_string());
        self
    }

    /// Set the user-facing reason.
    pub fn with_reason_user(mut self, reason: &str) -> Self {
        self.reason_user = Some(reason.to_string());
        self
    }

    /// Add an event-specific property.
    pub fn with_property(mut self, key: &str, value: serde_json::Value) -> Self {
        self.properties.insert(key.to_string(), value);
        self
    }

    /// Encode the event as a SET (Security Event Token) claims payload.
    pub fn to_set_claims(&self) -> serde_json::Value {
        let mut events: HashMap<String, serde_json::Value> = HashMap::new();
        let mut event_body = serde_json::json!({
            "subject": self.subject,
        });
        if let Some(ref entity) = self.initiating_entity {
            // Hand-encode instead of `serde_json::to_value(entity).unwrap()`: this
            // method returns `Value` (not `Result`), and a fallible conversion
            // here would need a breaking API change. Encoding the fieldless enum
            // directly removes the failure mode entirely rather than assuming it
            // away.
            let encoded = match entity {
                EventReasonAdmin::Policy => "policy",
                EventReasonAdmin::Admin => "admin",
                EventReasonAdmin::User => "user",
            };
            event_body["initiating_entity"] = serde_json::Value::String(encoded.to_string());
        }
        if let Some(ref r) = self.reason_admin {
            event_body["reason_admin"] = serde_json::json!({"en": r});
        }
        if let Some(ref r) = self.reason_user {
            event_body["reason_user"] = serde_json::json!({"en": r});
        }
        for (k, v) in &self.properties {
            event_body[k] = v.clone();
        }
        events.insert(self.event_type.clone(), event_body);

        serde_json::json!({
            "jti": self.jti,
            "iss": self.iss,
            "iat": self.iat,
            "events": events,
        })
    }
}

// ── Stream configuration (SSE §6) ──────────────────────────────────

/// SSE stream delivery method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryMethod {
    /// Push via HTTP POST.
    Push,
    /// Poll (receiver calls GET).
    Poll,
}

/// SSE stream configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    /// Issuer URL.
    pub iss: String,
    /// Audience for events on this stream.
    pub aud: Vec<String>,
    /// Supported event types.
    pub events_supported: Vec<String>,
    /// Delivery method.
    pub delivery_method: DeliveryMethod,
    /// Endpoint URL (push: receiver's endpoint; poll: transmitter's endpoint).
    pub endpoint_url: String,
}

impl StreamConfig {
    /// Create a builder for an event stream configuration.
    pub fn builder(iss: impl Into<String>, endpoint_url: impl Into<String>) -> StreamConfigBuilder {
        StreamConfigBuilder {
            iss: iss.into(),
            aud: Vec::new(),
            events_supported: Vec::new(),
            delivery_method: DeliveryMethod::Push,
            endpoint_url: endpoint_url.into(),
        }
    }

    /// Create a poll-based stream configuration builder.
    pub fn poll(iss: impl Into<String>, endpoint_url: impl Into<String>) -> StreamConfigBuilder {
        Self::builder(iss, endpoint_url).delivery_method(DeliveryMethod::Poll)
    }

    /// Create a push-based stream configuration builder.
    pub fn push(iss: impl Into<String>, endpoint_url: impl Into<String>) -> StreamConfigBuilder {
        Self::builder(iss, endpoint_url).delivery_method(DeliveryMethod::Push)
    }
}

/// Builder for CAEP stream configuration.
pub struct StreamConfigBuilder {
    iss: String,
    aud: Vec<String>,
    events_supported: Vec<String>,
    delivery_method: DeliveryMethod,
    endpoint_url: String,
}

impl StreamConfigBuilder {
    /// Add a single audience to the stream.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.aud.push(audience.into());
        self
    }

    /// Add multiple audiences to the stream.
    pub fn audiences<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.aud.extend(audiences.into_iter().map(Into::into));
        self
    }

    /// Add a supported event type to the stream.
    pub fn supports_event(mut self, event_type: impl Into<String>) -> Self {
        self.events_supported.push(event_type.into());
        self
    }

    /// Add multiple supported event types.
    pub fn events_supported<I, S>(mut self, events: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.events_supported
            .extend(events.into_iter().map(Into::into));
        self
    }

    /// Set the delivery method.
    pub fn delivery_method(mut self, delivery_method: DeliveryMethod) -> Self {
        self.delivery_method = delivery_method;
        self
    }

    /// Build the stream configuration.
    pub fn build(self) -> StreamConfig {
        StreamConfig {
            iss: self.iss,
            aud: self.aud,
            events_supported: self.events_supported,
            delivery_method: self.delivery_method,
            endpoint_url: self.endpoint_url,
        }
    }
}

/// Stream status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamStatus {
    Enabled,
    Paused,
    Disabled,
}

// ── Event transmitter ───────────────────────────────────────────────

/// A registered event stream with its buffered events.
struct EventStream {
    config: StreamConfig,
    status: StreamStatus,
    events: Vec<CaepEvent>,
}

/// CAEP event transmitter — manages streams and dispatches events.
pub struct CaepTransmitter {
    issuer: String,
    streams: Arc<RwLock<HashMap<String, EventStream>>>,
}

impl CaepTransmitter {
    pub fn new(issuer: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            streams: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new event stream. Returns the stream ID.
    pub async fn create_stream(&self, config: StreamConfig) -> String {
        let stream_id = Uuid::new_v4().to_string();
        self.streams.write().await.insert(
            stream_id.clone(),
            EventStream {
                config,
                status: StreamStatus::Enabled,
                events: Vec::new(),
            },
        );
        stream_id
    }

    /// Get stream configuration.
    pub async fn get_stream_config(&self, stream_id: &str) -> Option<StreamConfig> {
        self.streams
            .read()
            .await
            .get(stream_id)
            .map(|s| s.config.clone())
    }

    /// Update stream status.
    pub async fn set_stream_status(&self, stream_id: &str, status: StreamStatus) -> Result<()> {
        let mut streams = self.streams.write().await;
        let stream = streams
            .get_mut(stream_id)
            .ok_or_else(|| AuthError::validation("Stream not found"))?;
        stream.status = status;
        Ok(())
    }

    /// Get stream status.
    pub async fn get_stream_status(&self, stream_id: &str) -> Option<StreamStatus> {
        self.streams
            .read()
            .await
            .get(stream_id)
            .map(|s| s.status.clone())
    }

    /// Delete a stream.
    pub async fn delete_stream(&self, stream_id: &str) -> bool {
        self.streams.write().await.remove(stream_id).is_some()
    }

    /// Emit a session-revoked event to all enabled streams.
    pub async fn emit_session_revoked(
        &self,
        subject: SubjectIdentifier,
        reason: Option<&str>,
    ) -> Result<CaepEvent> {
        let mut event = CaepEvent::new(&self.issuer, event_types::SESSION_REVOKED, subject);
        if let Some(r) = reason {
            event = event.with_reason_admin(r);
        }
        self.dispatch_event(&event).await;
        Ok(event)
    }

    /// Emit a credential-change event.
    pub async fn emit_credential_change(
        &self,
        subject: SubjectIdentifier,
        change_type: ChangeType,
    ) -> Result<CaepEvent> {
        let change_type_value = serde_json::to_value(&change_type).map_err(|e| {
            AuthError::internal(format!("Failed to serialize CAEP change_type: {e}"))
        })?;
        let event = CaepEvent::new(&self.issuer, event_types::CREDENTIAL_CHANGE, subject)
            .with_property("change_type", change_type_value);
        self.dispatch_event(&event).await;
        Ok(event)
    }

    /// Emit a device-compliance-change event.
    pub async fn emit_device_compliance_change(
        &self,
        subject: SubjectIdentifier,
        previous_status: &str,
        current_status: &str,
    ) -> Result<CaepEvent> {
        let event = CaepEvent::new(&self.issuer, event_types::DEVICE_COMPLIANCE_CHANGE, subject)
            .with_property("previous_status", serde_json::json!(previous_status))
            .with_property("current_status", serde_json::json!(current_status));
        self.dispatch_event(&event).await;
        Ok(event)
    }

    /// Emit a token-claims-change event.
    ///
    /// Signals that one or more claims in a previously issued token have changed.
    pub async fn emit_token_claims_change(
        &self,
        subject: SubjectIdentifier,
        claims: HashMap<String, serde_json::Value>,
    ) -> Result<CaepEvent> {
        let mut event = CaepEvent::new(&self.issuer, event_types::TOKEN_CLAIMS_CHANGE, subject);
        let claims_value = serde_json::to_value(&claims)
            .map_err(|e| AuthError::internal(format!("Failed to serialize CAEP claims: {e}")))?;
        event = event.with_property("claims", claims_value);
        self.dispatch_event(&event).await;
        Ok(event)
    }

    /// Emit an assurance-level-change event.
    ///
    /// Signals that the authentication assurance level for a subject has changed.
    pub async fn emit_assurance_level_change(
        &self,
        subject: SubjectIdentifier,
        current_level: &str,
        previous_level: &str,
        change_direction: &str,
    ) -> Result<CaepEvent> {
        let event = CaepEvent::new(&self.issuer, event_types::ASSURANCE_LEVEL_CHANGE, subject)
            .with_property("current_level", serde_json::json!(current_level))
            .with_property("previous_level", serde_json::json!(previous_level))
            .with_property("change_direction", serde_json::json!(change_direction));
        self.dispatch_event(&event).await;
        Ok(event)
    }

    /// Poll events for a stream (for pull-based delivery).
    pub async fn poll_events(&self, stream_id: &str) -> Result<Vec<CaepEvent>> {
        let mut streams = self.streams.write().await;
        let stream = streams
            .get_mut(stream_id)
            .ok_or_else(|| AuthError::validation("Stream not found"))?;

        if stream.status != StreamStatus::Enabled {
            return Err(AuthError::validation("Stream is not enabled"));
        }

        let events = std::mem::take(&mut stream.events);
        Ok(events)
    }

    /// Dispatch an event to all enabled streams.
    async fn dispatch_event(&self, event: &CaepEvent) {
        let mut streams = self.streams.write().await;
        for stream in streams.values_mut() {
            if stream.status != StreamStatus::Enabled {
                continue;
            }
            // Check if this stream accepts the event type
            if stream.config.events_supported.is_empty()
                || stream
                    .config
                    .events_supported
                    .iter()
                    .any(|e| e == &event.event_type)
            {
                stream.events.push(event.clone());
            }
        }
    }

    /// Count active (enabled) streams.
    pub async fn active_stream_count(&self) -> usize {
        self.streams
            .read()
            .await
            .values()
            .filter(|s| s.status == StreamStatus::Enabled)
            .count()
    }
}

// ── Event receiver ──────────────────────────────────────────────────

/// Callback type for handling received CAEP events.
pub type EventHandler = Arc<dyn Fn(&CaepEvent) + Send + Sync>;

/// CAEP event receiver — processes incoming events.
pub struct CaepReceiver {
    handlers: Arc<RwLock<HashMap<String, Vec<EventHandler>>>>,
    received_jtis: Arc<RwLock<std::collections::HashSet<String>>>,
}

impl CaepReceiver {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(HashMap::new())),
            received_jtis: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    /// Register a handler for a specific event type.
    pub async fn on_event(&self, event_type: &str, handler: EventHandler) {
        self.handlers
            .write()
            .await
            .entry(event_type.to_string())
            .or_default()
            .push(handler);
    }

    /// Process a received CAEP event.
    ///
    /// Deduplicates by jti and invokes registered handlers.
    pub async fn process_event(&self, event: &CaepEvent) -> Result<bool> {
        // Deduplicate
        {
            let mut jtis = self.received_jtis.write().await;
            if !jtis.insert(event.jti.clone()) {
                return Ok(false); // Already processed
            }
        }

        // Invoke handlers
        let handlers = self.handlers.read().await;
        if let Some(handler_list) = handlers.get(&event.event_type) {
            for handler in handler_list {
                handler(event);
            }
        }

        Ok(true)
    }

    /// Check if an event was already processed.
    pub async fn was_processed(&self, jti: &str) -> bool {
        self.received_jtis.read().await.contains(jti)
    }
}

impl Default for CaepReceiver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Subject identifiers ─────────────────────────────────────

    #[test]
    fn test_subject_email_serialization() {
        let sub = SubjectIdentifier::Email {
            email: "user@example.com".to_string(),
        };
        let json = serde_json::to_value(&sub).unwrap();
        assert_eq!(json["format"], "email");
        assert_eq!(json["email"], "user@example.com");
    }

    #[test]
    fn test_subject_iss_sub_serialization() {
        let sub = SubjectIdentifier::IssSub {
            iss: "https://issuer.example".to_string(),
            sub: "user-123".to_string(),
        };
        let json = serde_json::to_value(&sub).unwrap();
        assert_eq!(json["format"], "iss_sub");
    }

    #[test]
    fn test_subject_session_id_serialization() {
        let sub = SubjectIdentifier::SessionId {
            session_id: "sess-001".to_string(),
            iss: Some("https://issuer.example".to_string()),
        };
        let json = serde_json::to_value(&sub).unwrap();
        assert_eq!(json["format"], "session_id");
        assert_eq!(json["session_id"], "sess-001");
    }

    #[test]
    fn test_subject_roundtrip() {
        let sub = SubjectIdentifier::Opaque {
            id: "opaque-id-42".to_string(),
        };
        let serialized = serde_json::to_string(&sub).unwrap();
        let deserialized: SubjectIdentifier = serde_json::from_str(&serialized).unwrap();
        assert_eq!(sub, deserialized);
    }

    // ── CaepEvent construction ──────────────────────────────────

    #[test]
    fn test_event_creation() {
        let event = CaepEvent::new(
            "https://issuer.example",
            event_types::SESSION_REVOKED,
            SubjectIdentifier::Email {
                email: "user@x.com".to_string(),
            },
        );
        assert!(!event.jti.is_empty());
        assert!(event.iat > 0);
        assert_eq!(event.event_type, event_types::SESSION_REVOKED);
    }

    #[test]
    fn test_event_builder_chain() {
        let event = CaepEvent::new(
            "https://issuer.example",
            event_types::CREDENTIAL_CHANGE,
            SubjectIdentifier::Email {
                email: "u@x.com".to_string(),
            },
        )
        .with_initiating_entity(EventReasonAdmin::Admin)
        .with_reason_admin("Password reset")
        .with_reason_user("Your password was reset by admin")
        .with_property("change_type", serde_json::json!("revoke"));

        assert_eq!(event.initiating_entity, Some(EventReasonAdmin::Admin));
        assert_eq!(event.reason_admin.as_deref(), Some("Password reset"));
        assert!(event.properties.contains_key("change_type"));
    }

    #[test]
    fn test_event_to_set_claims() {
        let event = CaepEvent::new(
            "https://iss.example",
            event_types::SESSION_REVOKED,
            SubjectIdentifier::Email {
                email: "u@x.com".to_string(),
            },
        )
        .with_reason_admin("Policy violation");

        let claims = event.to_set_claims();
        assert_eq!(claims["iss"], "https://iss.example");
        assert!(claims["events"][event_types::SESSION_REVOKED].is_object());
        let ev = &claims["events"][event_types::SESSION_REVOKED];
        assert!(ev["subject"].is_object());
        assert_eq!(ev["reason_admin"]["en"], "Policy violation");
    }

    // ── Transmitter ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_transmitter_create_stream() {
        let tx = CaepTransmitter::new("https://issuer.example");
        let config =
            StreamConfig::poll("https://issuer.example", "https://receiver.example/events")
                .audience("https://receiver.example")
                .supports_event(event_types::SESSION_REVOKED)
                .build();
        let stream_id = tx.create_stream(config.clone()).await;
        assert!(!stream_id.is_empty());
        assert_eq!(tx.active_stream_count().await, 1);

        let retrieved = tx.get_stream_config(&stream_id).await.unwrap();
        assert_eq!(retrieved.iss, config.iss);
    }

    #[tokio::test]
    async fn test_transmitter_stream_status() {
        let tx = CaepTransmitter::new("https://iss.example");
        let id = tx
            .create_stream(StreamConfig::poll("https://iss.example", "").build())
            .await;

        assert_eq!(tx.get_stream_status(&id).await, Some(StreamStatus::Enabled));

        tx.set_stream_status(&id, StreamStatus::Paused)
            .await
            .unwrap();
        assert_eq!(tx.get_stream_status(&id).await, Some(StreamStatus::Paused));
        assert_eq!(tx.active_stream_count().await, 0);
    }

    #[tokio::test]
    async fn test_transmitter_delete_stream() {
        let tx = CaepTransmitter::new("https://iss.example");
        let id = tx.create_stream(StreamConfig::push("", "").build()).await;

        assert!(tx.delete_stream(&id).await);
        assert!(!tx.delete_stream(&id).await); // second delete → false
        assert_eq!(tx.active_stream_count().await, 0);
    }

    #[tokio::test]
    async fn test_transmitter_emit_session_revoked() {
        let tx = CaepTransmitter::new("https://iss.example");
        let id = tx
            .create_stream(
                StreamConfig::poll("", "")
                    .supports_event(event_types::SESSION_REVOKED)
                    .build(),
            )
            .await;

        let event = tx
            .emit_session_revoked(
                SubjectIdentifier::Email {
                    email: "u@x.com".to_string(),
                },
                Some("Security policy"),
            )
            .await
            .unwrap();

        assert_eq!(event.event_type, event_types::SESSION_REVOKED);

        let events = tx.poll_events(&id).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].jti, event.jti);

        // Second poll should be empty (events consumed)
        let events2 = tx.poll_events(&id).await.unwrap();
        assert!(events2.is_empty());
    }

    #[tokio::test]
    async fn test_transmitter_event_filtering() {
        let tx = CaepTransmitter::new("https://iss.example");

        // Stream only wants session-revoked events
        let id = tx
            .create_stream(
                StreamConfig::poll("", "")
                    .supports_event(event_types::SESSION_REVOKED)
                    .build(),
            )
            .await;

        // Emit a credential_change event — should NOT appear
        tx.emit_credential_change(
            SubjectIdentifier::Email {
                email: "u@x.com".to_string(),
            },
            ChangeType::Revoke,
        )
        .await
        .unwrap();

        let events = tx.poll_events(&id).await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_transmitter_paused_stream_no_events() {
        let tx = CaepTransmitter::new("https://iss.example");
        let id = tx.create_stream(StreamConfig::poll("", "").build()).await;

        tx.set_stream_status(&id, StreamStatus::Paused)
            .await
            .unwrap();

        tx.emit_session_revoked(
            SubjectIdentifier::Email {
                email: "u@x.com".to_string(),
            },
            None,
        )
        .await
        .unwrap();

        // Paused streams can't be polled
        assert!(tx.poll_events(&id).await.is_err());
    }

    // ── Receiver ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_receiver_process_event() {
        let rx = CaepReceiver::new();
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called_clone = called.clone();

        rx.on_event(
            event_types::SESSION_REVOKED,
            Arc::new(move |_event| {
                called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            }),
        )
        .await;

        let event = CaepEvent::new(
            "https://iss.example",
            event_types::SESSION_REVOKED,
            SubjectIdentifier::Email {
                email: "u@x.com".to_string(),
            },
        );

        let processed = rx.process_event(&event).await.unwrap();
        assert!(processed);
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_stream_config_builder() {
        let config =
            StreamConfig::poll("https://issuer.example", "https://receiver.example/events")
                .audience("https://receiver.example")
                .audiences(["https://backup.example"])
                .supports_event(event_types::SESSION_REVOKED)
                .events_supported([event_types::CREDENTIAL_CHANGE])
                .build();

        assert_eq!(config.delivery_method, DeliveryMethod::Poll);
        assert_eq!(config.aud.len(), 2);
        assert_eq!(config.events_supported.len(), 2);
    }

    #[tokio::test]
    async fn test_receiver_deduplication() {
        let rx = CaepReceiver::new();
        let event = CaepEvent::new(
            "https://iss.example",
            event_types::CREDENTIAL_CHANGE,
            SubjectIdentifier::Opaque {
                id: "x".to_string(),
            },
        );

        let first = rx.process_event(&event).await.unwrap();
        assert!(first);

        let second = rx.process_event(&event).await.unwrap();
        assert!(!second); // duplicate

        assert!(rx.was_processed(&event.jti).await);
    }

    #[tokio::test]
    async fn test_receiver_unhandled_event_type() {
        let rx = CaepReceiver::new();
        let event = CaepEvent::new(
            "https://iss.example",
            "custom:unknown-event",
            SubjectIdentifier::Opaque {
                id: "x".to_string(),
            },
        );
        // Should succeed even without a registered handler
        let processed = rx.process_event(&event).await.unwrap();
        assert!(processed);
    }

    // ── Delivery method serialization ───────────────────────────

    #[test]
    fn test_delivery_method_serialization() {
        assert_eq!(
            serde_json::to_string(&DeliveryMethod::Push).unwrap(),
            r#""push""#
        );
        assert_eq!(
            serde_json::to_string(&DeliveryMethod::Poll).unwrap(),
            r#""poll""#
        );
    }
}
