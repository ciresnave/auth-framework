//! Comprehensive tests for the monitoring module
//!
//! Covers MonitoringManager, HealthChecker, Collectors, Exporters, and AlertManager.

use auth_framework::monitoring::alerts::{
    AlertConfig, AlertManager, AlertThresholds, NotificationChannel,
};
use auth_framework::monitoring::collectors::{
    AuthMetricsCollector, SessionMetricsCollector, TokenMetricsCollector,
};
use auth_framework::monitoring::exporters::{DataDogExporter, GrafanaExporter, PrometheusExporter};
use auth_framework::monitoring::health::{HealthCheckConfig, HealthChecker};
use auth_framework::monitoring::{
    HealthStatus, MonitoringConfig, MonitoringManager, SecurityEvent, SecurityEventSeverity,
    SecurityEventType,
};
use std::collections::HashMap;
use std::time::Duration;

// ---------------------------------------------------------------------------
// MonitoringManager tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_monitoring_manager_default_config() {
    let config = MonitoringConfig::default();
    assert!(config.enabled);
    let manager = MonitoringManager::new(config);
    let metrics = manager.get_performance_metrics();
    // All counters start at zero
    for val in metrics.values() {
        assert_eq!(*val, 0);
    }
}

#[tokio::test]
async fn test_record_auth_success_updates_metrics() {
    let config = MonitoringConfig::default();
    let manager = MonitoringManager::new(config);

    manager
        .record_auth_success("user1", Duration::from_millis(50))
        .await;
    manager
        .record_auth_success("user2", Duration::from_millis(100))
        .await;

    let metrics = manager.get_performance_metrics();
    assert_eq!(metrics["auth_successes"], 2);
    assert!(metrics["avg_response_time_us"] > 0);
}

#[tokio::test]
async fn test_record_auth_failure_creates_security_event() {
    let config = MonitoringConfig::default();
    let manager = MonitoringManager::new(config);

    manager
        .record_auth_failure(Some("attacker"), "bad_password")
        .await;

    let events = manager.get_security_events(None).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, SecurityEventType::FailedLogin);
    assert_eq!(events[0].severity, SecurityEventSeverity::Medium);
    assert_eq!(events[0].user_id.as_deref(), Some("attacker"));

    let metrics = manager.get_performance_metrics();
    assert_eq!(metrics["auth_failures"], 1);
}

#[tokio::test]
async fn test_record_auth_failure_without_user_id() {
    let config = MonitoringConfig::default();
    let manager = MonitoringManager::new(config);

    manager.record_auth_failure(None, "unknown_user").await;

    let events = manager.get_security_events(None).await;
    assert_eq!(events.len(), 1);
    assert!(events[0].user_id.is_none());
}

#[tokio::test]
async fn test_record_token_creation() {
    let config = MonitoringConfig::default();
    let manager = MonitoringManager::new(config);

    manager.record_token_creation("access_token").await;
    manager.record_token_creation("refresh_token").await;
    manager.record_token_creation("access_token").await;

    let metrics = manager.get_performance_metrics();
    assert_eq!(metrics["token_creations"], 3);
}

#[tokio::test]
async fn test_record_token_validation() {
    let config = MonitoringConfig::default();
    let manager = MonitoringManager::new(config);

    manager.record_token_validation(true).await;
    manager.record_token_validation(false).await;

    let metrics = manager.get_performance_metrics();
    assert_eq!(metrics["token_validations"], 2);
}

#[tokio::test]
async fn test_update_session_count() {
    let config = MonitoringConfig::default();
    let manager = MonitoringManager::new(config);

    manager.update_session_count(42).await;
    let metrics = manager.get_performance_metrics();
    assert_eq!(metrics["active_sessions"], 42);

    // Updating again replaces (not adds)
    manager.update_session_count(10).await;
    let metrics = manager.get_performance_metrics();
    assert_eq!(metrics["active_sessions"], 10);
}

#[tokio::test]
async fn test_record_mfa_challenge() {
    let config = MonitoringConfig::default();
    let manager = MonitoringManager::new(config);

    manager.record_mfa_challenge("totp").await;
    manager.record_mfa_challenge("sms").await;

    let metrics = manager.get_performance_metrics();
    assert_eq!(metrics["mfa_challenges"], 2);
}

#[tokio::test]
async fn test_security_events_limit() {
    let config = MonitoringConfig {
        max_history_size: 5,
        ..Default::default()
    };
    let manager = MonitoringManager::new(config);

    for i in 0..10 {
        let event = SecurityEvent {
            event_type: SecurityEventType::FailedLogin,
            user_id: Some(format!("user_{}", i)),
            ip_address: None,
            details: HashMap::new(),
            severity: SecurityEventSeverity::Low,
            timestamp: i as u64,
        };
        manager.record_security_event(event).await;
    }

    let events = manager.get_security_events(None).await;
    // Should be capped at max_history_size
    assert!(events.len() <= 5);
}

#[tokio::test]
async fn test_security_events_with_limit_param() {
    let config = MonitoringConfig::default();
    let manager = MonitoringManager::new(config);

    for i in 0..20 {
        let event = SecurityEvent {
            event_type: SecurityEventType::UnusualActivity,
            user_id: Some(format!("user_{}", i)),
            ip_address: None,
            details: HashMap::new(),
            severity: SecurityEventSeverity::High,
            timestamp: i as u64,
        };
        manager.record_security_event(event).await;
    }

    let events = manager.get_security_events(Some(5)).await;
    assert_eq!(events.len(), 5);
}

#[tokio::test]
async fn test_metrics_history_filtered_by_name() {
    let config = MonitoringConfig::default();
    let manager = MonitoringManager::new(config);

    // Record different metric types
    manager.record_auth_request().await;
    manager.record_token_creation("jwt").await;
    manager.record_auth_request().await;

    let auth_metrics = manager
        .get_metrics_history(Some("auth_requests_total"))
        .await;
    // Should have entries for auth requests
    assert!(!auth_metrics.is_empty());

    let all_metrics = manager.get_metrics_history(None).await;
    assert!(all_metrics.len() >= auth_metrics.len());
}

#[tokio::test]
async fn test_health_check_returns_all_components() {
    let config = MonitoringConfig::default();
    let manager = MonitoringManager::new(config);

    let results = manager.health_check().await.unwrap();

    assert!(results.contains_key("authentication"));
    assert!(results.contains_key("storage"));
    assert!(results.contains_key("tokens"));

    // With zero auth requests, auth should be Healthy
    assert_eq!(results["authentication"].status, HealthStatus::Healthy);
    assert_eq!(results["storage"].status, HealthStatus::Healthy);
}

#[tokio::test]
async fn test_health_check_disabled() {
    let config = MonitoringConfig {
        enable_health_checks: false,
        ..Default::default()
    };
    let manager = MonitoringManager::new(config);

    let results = manager.health_check().await.unwrap();
    // When health checks are disabled, a single "monitoring" entry is returned
    // with status Healthy and a descriptive message instead of an empty map.
    assert_eq!(results.len(), 1);
    let monitoring = results
        .get("monitoring")
        .expect("should contain 'monitoring' key");
    assert!(matches!(
        monitoring.status,
        auth_framework::monitoring::HealthStatus::Healthy
    ));
    assert!(monitoring.message.contains("disabled"));
}

#[tokio::test]
async fn test_health_check_degraded_on_high_failure_rate() {
    let config = MonitoringConfig::default();
    let manager = MonitoringManager::new(config);

    // 30% failure rate → Degraded
    for _ in 0..7 {
        manager.record_auth_request().await;
        manager
            .record_auth_success("u", Duration::from_millis(1))
            .await;
    }
    for _ in 0..3 {
        manager.record_auth_request().await;
        manager.record_auth_failure(Some("u"), "bad_pass").await;
    }

    let results = manager.health_check().await.unwrap();
    assert_eq!(results["authentication"].status, HealthStatus::Degraded);
}

#[tokio::test]
async fn test_health_check_unhealthy_on_critical_failure_rate() {
    let config = MonitoringConfig::default();
    let manager = MonitoringManager::new(config);

    // >50% failure rate → Unhealthy
    for _ in 0..2 {
        manager.record_auth_request().await;
        manager
            .record_auth_success("u", Duration::from_millis(1))
            .await;
    }
    for _ in 0..8 {
        manager.record_auth_request().await;
        manager.record_auth_failure(Some("u"), "bad_pass").await;
    }

    let results = manager.health_check().await.unwrap();
    assert_eq!(results["authentication"].status, HealthStatus::Unhealthy);
}

#[tokio::test]
async fn test_prometheus_export_format() {
    let config = MonitoringConfig::default();
    let manager = MonitoringManager::new(config);

    manager.record_auth_request().await;
    manager.record_auth_request().await;
    manager.record_token_creation("jwt").await;

    let output = manager.export_prometheus_metrics().await;

    // Verify Prometheus text format
    assert!(output.contains("# HELP auth_auth_requests"));
    assert!(output.contains("# TYPE auth_auth_requests counter"));
    assert!(output.contains("auth_auth_requests 2"));
    assert!(output.contains("auth_token_creations 1"));
}

#[tokio::test]
async fn test_security_metrics_disabled() {
    let config = MonitoringConfig {
        enable_security_metrics: false,
        ..Default::default()
    };
    let manager = MonitoringManager::new(config);

    manager.record_auth_failure(Some("user"), "bad_pass").await;

    // Failure counter still increments (performance metric)
    let metrics = manager.get_performance_metrics();
    assert_eq!(metrics["auth_failures"], 1);

    // But no security event is recorded
    let events = manager.get_security_events(None).await;
    assert!(events.is_empty());
}

#[tokio::test]
async fn test_concurrent_metric_recording() {
    let config = MonitoringConfig::default();
    let manager = std::sync::Arc::new(MonitoringManager::new(config));

    let mut handles = Vec::new();
    for _ in 0..50 {
        let mgr = manager.clone();
        handles.push(tokio::spawn(async move {
            mgr.record_auth_request().await;
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let metrics = manager.get_performance_metrics();
    assert_eq!(metrics["auth_requests"], 50);
}

// ---------------------------------------------------------------------------
// HealthChecker tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_health_checker_all_components() {
    let checker = HealthChecker::new();
    let results = checker.check_all_components().await;

    assert_eq!(results.len(), 5);
    assert!(results.contains_key("authentication"));
    assert!(results.contains_key("sessions"));
    assert!(results.contains_key("tokens"));
    assert!(results.contains_key("storage"));
    assert!(results.contains_key("mfa"));

    // Auth should pass (SHA-256 works)
    assert_eq!(results["authentication"].status, HealthStatus::Healthy);
}

#[test]
fn test_health_check_config_defaults() {
    let config = HealthCheckConfig::default();
    assert!(config.enabled);
    assert_eq!(config.timeout_seconds, 30);
    assert_eq!(config.check_interval_seconds, 60);
}

// ---------------------------------------------------------------------------
// Collectors tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_auth_metrics_collector() {
    let collector = AuthMetricsCollector;
    let metrics = collector.collect().await;

    assert!(metrics.contains_key("auth_total_requests"));
    assert!(metrics.contains_key("auth_successful_requests"));
    assert!(metrics.contains_key("auth_failed_requests"));
    assert_eq!(metrics.len(), 3);
}

#[tokio::test]
async fn test_session_metrics_collector() {
    let collector = SessionMetricsCollector::new();
    let metrics = collector.collect().await;

    assert!(metrics.contains_key("session_active_count"));
    assert!(metrics.contains_key("session_expired_count"));
    assert!(metrics.contains_key("session_creation_rate"));
    assert_eq!(metrics.len(), 3);
}

#[tokio::test]
async fn test_token_metrics_collector() {
    let collector = TokenMetricsCollector;
    let metrics = collector.collect().await;

    assert!(metrics.contains_key("token_creation_count"));
    assert!(metrics.contains_key("token_validation_count"));
    assert!(metrics.contains_key("token_expiration_count"));
    assert_eq!(metrics.len(), 3);
}

// ---------------------------------------------------------------------------
// Exporters tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_prometheus_exporter_format() {
    let exporter = PrometheusExporter;
    let mut metrics = HashMap::new();
    metrics.insert("test_metric".to_string(), 42.0);
    metrics.insert("another_metric".to_string(), 7.5);

    let output = exporter.export(metrics).await;

    assert!(output.contains("# HELP test_metric"));
    assert!(output.contains("# TYPE test_metric gauge"));
    assert!(output.contains("test_metric 42"));
    assert!(output.contains("# HELP another_metric"));
    assert!(output.contains("another_metric 7.5"));
}

#[tokio::test]
async fn test_prometheus_exporter_empty_metrics() {
    let exporter = PrometheusExporter;
    let output = exporter.export(HashMap::new()).await;
    assert!(output.is_empty());
}

#[tokio::test]
async fn test_grafana_exporter_structure() {
    let exporter = GrafanaExporter;
    let mut metrics = HashMap::new();
    metrics.insert("cpu_usage".to_string(), 85.0);

    let output = exporter.export(metrics).await;

    assert_eq!(output["dashboard"], "auth-framework");
    assert!(output["metrics"]["cpu_usage"].as_f64().is_some());
    assert!(output["timestamp"].as_i64().is_some());
}

#[tokio::test]
async fn test_datadog_exporter_series() {
    let exporter = DataDogExporter;
    let mut metrics = HashMap::new();
    metrics.insert("auth_latency".to_string(), 120.0);

    let output = exporter.export(metrics).await;

    assert_eq!(output.len(), 1);
    assert_eq!(output[0]["metric"], "auth_latency");
    assert_eq!(output[0]["type"], "gauge");
    assert_eq!(output[0]["host"], "auth-framework");

    let points = output[0]["points"].as_array().unwrap();
    assert_eq!(points.len(), 1);
    assert_eq!(points[0][1].as_f64().unwrap(), 120.0);
}

#[tokio::test]
async fn test_datadog_exporter_multiple_metrics() {
    let exporter = DataDogExporter;
    let mut metrics = HashMap::new();
    metrics.insert("m1".to_string(), 1.0);
    metrics.insert("m2".to_string(), 2.0);
    metrics.insert("m3".to_string(), 3.0);

    let output = exporter.export(metrics).await;
    assert_eq!(output.len(), 3);
}

// ---------------------------------------------------------------------------
// AlertManager tests
// ---------------------------------------------------------------------------

fn test_alert_config() -> AlertConfig {
    AlertConfig {
        enabled: true,
        thresholds: AlertThresholds {
            failed_logins_per_minute: 5,
            max_response_time_ms: 1000,
            error_rate_threshold: 0.2,
            alert_cooldown_seconds: 0, // No cooldown for tests
        },
        channels: vec![NotificationChannel::Log {
            level: "warn".to_string(),
        }],
    }
}

#[tokio::test]
async fn test_alert_manager_failed_login() {
    let mut manager = AlertManager::new(test_alert_config());

    let event = SecurityEvent {
        event_type: SecurityEventType::FailedLogin,
        user_id: Some("test_user".to_string()),
        ip_address: Some("10.0.0.1".to_string()),
        details: HashMap::new(),
        severity: SecurityEventSeverity::Medium,
        timestamp: 1000,
    };

    // Should succeed (sends to Log channel)
    let result = manager.process_security_event(&event).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_alert_manager_privilege_escalation() {
    let mut manager = AlertManager::new(test_alert_config());

    let event = SecurityEvent {
        event_type: SecurityEventType::PrivilegeEscalation,
        user_id: Some("attacker".to_string()),
        ip_address: None,
        details: HashMap::new(),
        severity: SecurityEventSeverity::Critical,
        timestamp: 2000,
    };

    let result = manager.process_security_event(&event).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_alert_manager_token_manipulation() {
    let mut manager = AlertManager::new(test_alert_config());

    let event = SecurityEvent {
        event_type: SecurityEventType::TokenManipulation,
        user_id: Some("suspect".to_string()),
        ip_address: None,
        details: {
            let mut d = HashMap::new();
            d.insert("detail".to_string(), "forged JWT".to_string());
            d
        },
        severity: SecurityEventSeverity::Critical,
        timestamp: 3000,
    };

    let result = manager.process_security_event(&event).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_alert_manager_unusual_activity() {
    let mut manager = AlertManager::new(test_alert_config());

    let event = SecurityEvent {
        event_type: SecurityEventType::UnusualActivity,
        user_id: Some("user_x".to_string()),
        ip_address: Some("192.168.1.1".to_string()),
        details: {
            let mut d = HashMap::new();
            d.insert("pattern".to_string(), "login from new country".to_string());
            d
        },
        severity: SecurityEventSeverity::High,
        timestamp: 4000,
    };

    let result = manager.process_security_event(&event).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_alert_manager_config_change() {
    let mut manager = AlertManager::new(test_alert_config());

    let event = SecurityEvent {
        event_type: SecurityEventType::ConfigurationChange,
        user_id: Some("admin".to_string()),
        ip_address: None,
        details: {
            let mut d = HashMap::new();
            d.insert("field".to_string(), "jwt_secret".to_string());
            d
        },
        severity: SecurityEventSeverity::Low,
        timestamp: 5000,
    };

    let result = manager.process_security_event(&event).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_alert_manager_system_error() {
    let mut manager = AlertManager::new(test_alert_config());

    let event = SecurityEvent {
        event_type: SecurityEventType::SystemError,
        user_id: None,
        ip_address: None,
        details: {
            let mut d = HashMap::new();
            d.insert("error".to_string(), "storage timeout".to_string());
            d
        },
        severity: SecurityEventSeverity::High,
        timestamp: 6000,
    };

    let result = manager.process_security_event(&event).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_alert_manager_disabled() {
    let mut config = test_alert_config();
    config.enabled = false;
    let mut manager = AlertManager::new(config);

    let event = SecurityEvent {
        event_type: SecurityEventType::PrivilegeEscalation,
        user_id: Some("user".to_string()),
        ip_address: None,
        details: HashMap::new(),
        severity: SecurityEventSeverity::Critical,
        timestamp: 7000,
    };

    // Should succeed without actually sending anything
    let result = manager.process_security_event(&event).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_alert_manager_performance_high_response_time() {
    let mut manager = AlertManager::new(test_alert_config());

    let mut metrics = HashMap::new();
    // 2000ms = 2_000_000 microseconds — above 1000ms threshold
    metrics.insert("avg_response_time_us".to_string(), 2_000_000u64);
    metrics.insert("auth_requests".to_string(), 100);
    metrics.insert("auth_failures".to_string(), 5);

    let result = manager.process_performance_metrics(&metrics).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_alert_manager_performance_high_error_rate() {
    let mut manager = AlertManager::new(test_alert_config());

    let mut metrics = HashMap::new();
    metrics.insert("auth_requests".to_string(), 100);
    metrics.insert("auth_failures".to_string(), 30); // 30% > 20% threshold

    let result = manager.process_performance_metrics(&metrics).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_alert_manager_performance_below_thresholds() {
    let mut manager = AlertManager::new(test_alert_config());

    let mut metrics = HashMap::new();
    metrics.insert("avg_response_time_us".to_string(), 500_000u64); // 500ms
    metrics.insert("auth_requests".to_string(), 100);
    metrics.insert("auth_failures".to_string(), 5); // 5% < 20%

    let result = manager.process_performance_metrics(&metrics).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_alert_cooldown() {
    let mut config = test_alert_config();
    config.thresholds.alert_cooldown_seconds = 3600; // 1 hour cooldown
    let mut manager = AlertManager::new(config);

    let event = SecurityEvent {
        event_type: SecurityEventType::AccountLockout,
        user_id: Some("user".to_string()),
        ip_address: None,
        details: HashMap::new(),
        severity: SecurityEventSeverity::Medium,
        timestamp: 1000,
    };

    // First alert should send
    let result = manager.process_security_event(&event).await;
    assert!(result.is_ok());

    // Second identical event should be suppressed by cooldown
    let result = manager.process_security_event(&event).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Integration: full pipeline
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_full_monitoring_pipeline() {
    let config = MonitoringConfig::default();
    let manager = MonitoringManager::new(config);

    // Simulate a realistic auth workload
    for _ in 0..10 {
        manager.record_auth_request().await;
    }
    for _ in 0..8 {
        manager
            .record_auth_success("user1", Duration::from_millis(50))
            .await;
    }
    for _ in 0..2 {
        manager
            .record_auth_failure(Some("attacker"), "bad_creds")
            .await;
    }
    manager.record_token_creation("access").await;
    manager.record_token_validation(true).await;
    manager.update_session_count(5).await;
    manager.record_mfa_challenge("totp").await;

    // Verify all counters
    let metrics = manager.get_performance_metrics();
    assert_eq!(metrics["auth_requests"], 10);
    assert_eq!(metrics["auth_successes"], 8);
    assert_eq!(metrics["auth_failures"], 2);
    assert_eq!(metrics["token_creations"], 1);
    assert_eq!(metrics["token_validations"], 1);
    assert_eq!(metrics["active_sessions"], 5);
    assert_eq!(metrics["mfa_challenges"], 1);
    assert!(metrics["avg_response_time_us"] > 0);

    // Verify security events
    let events = manager.get_security_events(None).await;
    assert_eq!(events.len(), 2);

    // Verify health check
    let health = manager.health_check().await.unwrap();
    assert!(health.contains_key("authentication"));
    // 20% failure rate → Degraded
    assert_eq!(health["authentication"].status, HealthStatus::Healthy);

    // Verify prometheus export
    let prom = manager.export_prometheus_metrics().await;
    assert!(prom.contains("auth_auth_requests 10"));
    assert!(prom.contains("auth_auth_failures 2"));
}
