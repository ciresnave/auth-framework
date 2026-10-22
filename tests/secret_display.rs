//! `Debug` and `Display` output that reaches a log line or a terminal must not carry a secret.
//!
//! Each test builds a value around a marker string and checks the marker is not in what the value
//! prints.

const MARKER: &str = "SECRET-MARKER-5c1d9e";

#[test]
fn slack_config_debug_hides_the_webhook_url() {
    let slack = auth_framework::deployment::monitoring::SlackConfig {
        api_url: format!("https://hooks.slack.com/services/T000/B000/{MARKER}"),
        channel: "#alerts".to_string(),
        username: "auth-framework".to_string(),
        title: "title".to_string(),
        text: "text".to_string(),
    };
    let shown = format!("{slack:?}");
    assert!(!shown.contains(MARKER), "{shown}");
    // Control: the rest of the value is still printed.
    assert!(shown.contains("#alerts"), "{shown}");
}

#[cfg(feature = "role-system")]
#[test]
fn authorization_context_debug_hides_custom_attribute_values() {
    use auth_framework::authorization_enhanced::context::{
        AuthorizationContext, ConnectionType, DayType, DeviceType, SecurityLevel, TimeOfDay,
    };
    let context = AuthorizationContext {
        user_id: "user-1".to_string(),
        roles: Vec::new(),
        session_id: None,
        method: "GET".to_string(),
        path: "/".to_string(),
        ip_address: None,
        user_agent: None,
        request_time: chrono::Utc::now(),
        time_of_day: TimeOfDay::BusinessHours,
        day_type: DayType::Weekday,
        device_type: DeviceType::Unknown,
        connection_type: ConnectionType::Unknown,
        security_level: SecurityLevel::Low,
        risk_score: 0,
        custom_attributes: [("token".to_string(), MARKER.to_string())].into(),
    };
    let shown = format!("{context:?}");
    assert!(!shown.contains(MARKER), "{shown}");
    // Control: the attribute names are still printed.
    assert!(shown.contains("token"), "{shown}");
}

#[test]
fn step_up_context_debug_hides_custom_attribute_values() {
    use auth_framework::server::core::stepped_up_auth::{AuthenticationLevel, StepUpContext};
    let context = StepUpContext {
        user_id: "user-1".to_string(),
        resource: "/admin".to_string(),
        resource_metadata: Default::default(),
        risk_score: None,
        location: None,
        session_id: "session-1".to_string(),
        current_auth_level: AuthenticationLevel::Basic,
        auth_time: chrono::Utc::now(),
        custom_attributes: [("token".to_string(), serde_json::json!(MARKER))].into(),
    };
    let shown = format!("{context:?}");
    assert!(!shown.contains(MARKER), "{shown}");
    // Control: the attribute names are still printed.
    assert!(shown.contains("token"), "{shown}");
}
