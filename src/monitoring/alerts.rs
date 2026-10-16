//! Alerting system for security and performance monitoring

use super::{SecurityEvent, SecurityEventSeverity, SecurityEventType};
use crate::errors::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable alerting
    pub enabled: bool,
    /// Alert thresholds
    pub thresholds: AlertThresholds,
    /// Notification channels
    pub channels: Vec<NotificationChannel>,
}

/// Alert threshold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    /// Failed login attempts per minute
    pub failed_logins_per_minute: u64,
    /// Maximum response time in milliseconds
    pub max_response_time_ms: u64,
    /// Error rate threshold (0.0 - 1.0)
    pub error_rate_threshold: f64,
    /// Minimum time between duplicate alerts in seconds
    pub alert_cooldown_seconds: u64,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            failed_logins_per_minute: 10,
            max_response_time_ms: 5000,
            error_rate_threshold: 0.1,   // 10%
            alert_cooldown_seconds: 300, // 5 minutes
        }
    }
}

/// Notification channel types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationChannel {
    /// Email notifications
    Email { recipients: Vec<String> },
    /// Slack webhook
    Slack { webhook_url: String },
    /// Microsoft Teams webhook
    Teams { webhook_url: String },
    /// Generic webhook
    Webhook {
        url: String,
        headers: HashMap<String, String>,
    },
    /// Log-based alerts
    Log { level: String },
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Alert message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Alert ID
    pub id: String,
    /// Alert title
    pub title: String,
    /// Alert message
    pub message: String,
    /// Severity level
    pub severity: AlertSeverity,
    /// Source component
    pub source: String,
    /// Related metrics
    pub metrics: HashMap<String, f64>,
    /// Timestamp
    pub timestamp: u64,
}

/// Alert manager
pub struct AlertManager {
    /// Configuration
    config: AlertConfig,
    /// Recent alerts for cooldown tracking
    recent_alerts: HashMap<String, u64>,
}

impl AlertManager {
    /// Create new alert manager
    pub fn new(config: AlertConfig) -> Self {
        Self {
            config,
            recent_alerts: HashMap::new(),
        }
    }

    /// Process security event and generate alerts if needed
    pub async fn process_security_event(&mut self, event: &SecurityEvent) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let alert = match event.event_type {
            SecurityEventType::FailedLogin => {
                if event.severity >= SecurityEventSeverity::High {
                    Some(Alert {
                        id: format!("failed_login_{}", event.timestamp),
                        title: "High volume of failed login attempts detected".to_string(),
                        message: format!(
                            "Multiple failed login attempts detected for user {:?} from IP {:?}",
                            event.user_id, event.ip_address
                        ),
                        severity: AlertSeverity::Warning,
                        source: "authentication".to_string(),
                        metrics: HashMap::new(),
                        timestamp: event.timestamp,
                    })
                } else {
                    None
                }
            }
            SecurityEventType::AccountLockout => Some(Alert {
                id: format!("account_lockout_{}", event.timestamp),
                title: "Account lockout triggered".to_string(),
                message: format!(
                    "Account {:?} has been locked due to security policy",
                    event.user_id
                ),
                severity: AlertSeverity::Warning,
                source: "security".to_string(),
                metrics: HashMap::new(),
                timestamp: event.timestamp,
            }),
            SecurityEventType::PrivilegeEscalation => Some(Alert {
                id: format!("privilege_escalation_{}", event.timestamp),
                title: "Privilege escalation attempt detected".to_string(),
                message: format!("Privilege escalation attempt by user {:?}", event.user_id),
                severity: AlertSeverity::Critical,
                source: "authorization".to_string(),
                metrics: HashMap::new(),
                timestamp: event.timestamp,
            }),
            _ => None,
        };

        if let Some(alert) = alert {
            self.send_alert(alert).await?;
        }

        Ok(())
    }

    /// Process performance metrics and generate alerts
    pub async fn process_performance_metrics(
        &mut self,
        metrics: &HashMap<String, u64>,
    ) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check response time threshold
        if let Some(&response_time) = metrics.get("avg_response_time_us") {
            let response_time_ms = response_time / 1000; // Convert to milliseconds

            if response_time_ms > self.config.thresholds.max_response_time_ms {
                let alert = Alert {
                    id: format!(
                        "high_response_time_{}",
                        crate::monitoring::current_timestamp()
                    ),
                    title: "High response time detected".to_string(),
                    message: format!(
                        "Average response time is {}ms, which exceeds the threshold of {}ms",
                        response_time_ms, self.config.thresholds.max_response_time_ms
                    ),
                    severity: AlertSeverity::Warning,
                    source: "performance".to_string(),
                    metrics: {
                        let mut m = HashMap::new();
                        m.insert("response_time_ms".to_string(), response_time_ms as f64);
                        m.insert(
                            "threshold_ms".to_string(),
                            self.config.thresholds.max_response_time_ms as f64,
                        );
                        m
                    },
                    timestamp: crate::monitoring::current_timestamp(),
                };

                self.send_alert(alert).await?;
            }
        }

        // Check error rate
        if let (Some(&auth_requests), Some(&auth_failures)) =
            (metrics.get("auth_requests"), metrics.get("auth_failures"))
            && auth_requests > 0
        {
            let error_rate = auth_failures as f64 / auth_requests as f64;

            if error_rate > self.config.thresholds.error_rate_threshold {
                let alert = Alert {
                    id: format!("high_error_rate_{}", crate::monitoring::current_timestamp()),
                    title: "High authentication error rate".to_string(),
                    message: format!(
                        "Authentication error rate is {:.1}%, which exceeds the threshold of {:.1}%",
                        error_rate * 100.0,
                        self.config.thresholds.error_rate_threshold * 100.0
                    ),
                    severity: AlertSeverity::Critical,
                    source: "authentication".to_string(),
                    metrics: {
                        let mut m = HashMap::new();
                        m.insert("error_rate".to_string(), error_rate);
                        m.insert(
                            "threshold".to_string(),
                            self.config.thresholds.error_rate_threshold,
                        );
                        m.insert("total_requests".to_string(), auth_requests as f64);
                        m.insert("failed_requests".to_string(), auth_failures as f64);
                        m
                    },
                    timestamp: crate::monitoring::current_timestamp(),
                };

                self.send_alert(alert).await?;
            }
        }

        Ok(())
    }

    /// Send alert through configured channels
    async fn send_alert(&mut self, alert: Alert) -> Result<()> {
        // Check cooldown
        if let Some(&last_alert_time) = self.recent_alerts.get(&alert.id) {
            let current_time = crate::monitoring::current_timestamp();
            if current_time - last_alert_time < self.config.thresholds.alert_cooldown_seconds {
                tracing::debug!("Alert {} is in cooldown period, skipping", alert.id);
                return Ok(());
            }
        }

        // Update recent alerts tracking
        self.recent_alerts.insert(alert.id.clone(), alert.timestamp);

        // Send to all configured channels
        for channel in &self.config.channels {
            self.send_to_channel(&alert, channel).await?;
        }

        tracing::info!(
            "Alert sent: {} - {} (Severity: {:?})",
            alert.title,
            alert.message,
            alert.severity
        );

        Ok(())
    }

    /// Send alert to specific channel
    async fn send_to_channel(&self, alert: &Alert, channel: &NotificationChannel) -> Result<()> {
        match channel {
            NotificationChannel::Email { recipients } => {
                // In production: Send email using SMTP or email service API
                tracing::info!(
                    "EMAIL ALERT to {:?}: {} - {}",
                    recipients,
                    alert.title,
                    alert.message
                );
            }
            NotificationChannel::Slack { webhook_url } => {
                // In production: Send POST request to Slack webhook
                tracing::info!(
                    "SLACK ALERT to {}: {} - {}",
                    webhook_url,
                    alert.title,
                    alert.message
                );
            }
            NotificationChannel::Teams { webhook_url } => {
                // In production: Send POST request to Teams webhook
                tracing::info!(
                    "TEAMS ALERT to {}: {} - {}",
                    webhook_url,
                    alert.title,
                    alert.message
                );
            }
            NotificationChannel::Webhook { url, headers: _ } => {
                // In production: Send POST request to generic webhook
                tracing::info!(
                    "WEBHOOK ALERT to {}: {} - {}",
                    url,
                    alert.title,
                    alert.message
                );
            }
            NotificationChannel::Log { level } => match level.as_str() {
                "error" => tracing::error!("ALERT: {} - {}", alert.title, alert.message),
                "warn" => tracing::warn!("ALERT: {} - {}", alert.title, alert.message),
                _ => tracing::info!("ALERT: {} - {}", alert.title, alert.message),
            },
        }

        Ok(())
    }

    /// Clean up old alert tracking data
    pub fn cleanup_alert_history(&mut self, max_age_seconds: u64) {
        let current_time = crate::monitoring::current_timestamp();
        self.recent_alerts
            .retain(|_, &mut timestamp| current_time - timestamp < max_age_seconds);
    }
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            thresholds: AlertThresholds::default(),
            channels: vec![NotificationChannel::Log {
                level: "warn".to_string(),
            }],
        }
    }
}
