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
#[derive(Clone, Serialize, Deserialize)]
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

impl std::fmt::Debug for NotificationChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::utils::redact::redacted;
        match self {
            Self::Email { recipients } => f
                .debug_struct("Email")
                .field("recipients", recipients)
                .finish(),
            Self::Slack { webhook_url } => f
                .debug_struct("Slack")
                .field("webhook_url", &redacted(webhook_url))
                .finish(),
            Self::Teams { webhook_url } => f
                .debug_struct("Teams")
                .field("webhook_url", &redacted(webhook_url))
                .finish(),
            // Webhook URLs embed their access token and the headers may carry an Authorization value.
            Self::Webhook { url, headers } => f
                .debug_struct("Webhook")
                .field("url", &redacted(url))
                .field("headers", &headers.keys().collect::<Vec<_>>())
                .finish(),
            Self::Log { level } => f.debug_struct("Log").field("level", level).finish(),
        }
    }
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
            SecurityEventType::UnusualActivity => Some(Alert {
                id: format!("unusual_activity_{}", event.timestamp),
                title: "Unusual activity detected".to_string(),
                message: format!(
                    "Unusual activity pattern for user {:?}: {:?}",
                    event.user_id, event.details
                ),
                severity: AlertSeverity::Warning,
                source: "security".to_string(),
                metrics: HashMap::new(),
                timestamp: event.timestamp,
            }),
            SecurityEventType::TokenManipulation => Some(Alert {
                id: format!("token_manipulation_{}", event.timestamp),
                title: "Token manipulation attempt".to_string(),
                message: format!(
                    "Token manipulation detected for user {:?}: {:?}",
                    event.user_id, event.details
                ),
                severity: AlertSeverity::Critical,
                source: "security".to_string(),
                metrics: HashMap::new(),
                timestamp: event.timestamp,
            }),
            SecurityEventType::ConfigurationChange => Some(Alert {
                id: format!("config_change_{}", event.timestamp),
                title: "Security configuration changed".to_string(),
                message: format!(
                    "Configuration change by user {:?}: {:?}",
                    event.user_id, event.details
                ),
                severity: AlertSeverity::Info,
                source: "configuration".to_string(),
                metrics: HashMap::new(),
                timestamp: event.timestamp,
            }),
            SecurityEventType::SystemError => Some(Alert {
                id: format!("system_error_{}", event.timestamp),
                title: "System error in security subsystem".to_string(),
                message: format!("System error: {:?}", event.details),
                severity: AlertSeverity::Warning,
                source: "system".to_string(),
                metrics: HashMap::new(),
                timestamp: event.timestamp,
            }),
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
                self.send_email_alert(alert, recipients).await;
            }
            NotificationChannel::Slack { webhook_url } => {
                let payload = serde_json::json!({
                    "text": format!(
                        "*[{:?}]* {} — {}",
                        alert.severity, alert.title, alert.message
                    )
                });
                let client = reqwest::Client::new();
                if let Err(e) = client.post(webhook_url).json(&payload).send().await {
                    tracing::error!(
                        webhook_url = %webhook_url,
                        error = %e,
                        "Failed to send Slack alert"
                    );
                } else {
                    tracing::info!(webhook_url = %webhook_url, "Slack alert sent: {}", alert.title);
                }
            }
            NotificationChannel::Teams { webhook_url } => {
                // Microsoft Teams Incoming Webhook message card format.
                let payload = serde_json::json!({
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "themeColor": match alert.severity {
                        AlertSeverity::Critical => "FF0000",
                        AlertSeverity::Warning  => "FFA500",
                        AlertSeverity::Info     => "0078D7",
                    },
                    "summary": &alert.title,
                    "sections": [{
                        "activityTitle": &alert.title,
                        "activityText": &alert.message,
                        "facts": [
                            { "name": "Severity", "value": format!("{:?}", alert.severity) },
                            { "name": "Source",   "value": &alert.source },
                        ]
                    }]
                });
                let client = reqwest::Client::new();
                if let Err(e) = client.post(webhook_url).json(&payload).send().await {
                    tracing::error!(
                        webhook_url = %webhook_url,
                        error = %e,
                        "Failed to send Teams alert"
                    );
                } else {
                    tracing::info!(webhook_url = %webhook_url, "Teams alert sent: {}", alert.title);
                }
            }
            NotificationChannel::Webhook { url, headers } => {
                let payload = serde_json::json!({
                    "id":       &alert.id,
                    "title":    &alert.title,
                    "message":  &alert.message,
                    "severity": format!("{:?}", alert.severity),
                    "source":   &alert.source,
                    "metrics":  &alert.metrics,
                    "timestamp": alert.timestamp,
                });
                let client = reqwest::Client::new();
                let mut req = client.post(url).json(&payload);
                for (k, v) in headers {
                    req = req.header(k, v);
                }
                if let Err(e) = req.send().await {
                    tracing::error!(url = %url, error = %e, "Failed to send webhook alert");
                } else {
                    tracing::info!(url = %url, "Webhook alert sent: {}", alert.title);
                }
            }
            NotificationChannel::Log { level } => match level.as_str() {
                "error" => tracing::error!("ALERT: {} - {}", alert.title, alert.message),
                "warn" => tracing::warn!("ALERT: {} - {}", alert.title, alert.message),
                _ => tracing::info!("ALERT: {} - {}", alert.title, alert.message),
            },
        }

        Ok(())
    }

    /// Deliver an alert by SMTP (configured through `AUTH_SMTP_*` environment variables).
    #[cfg(feature = "smtp")]
    async fn send_email_alert(&self, alert: &Alert, recipients: &[String]) {
        use lettre::{
            AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox,
            transport::smtp::authentication::Credentials,
        };

        // SMTP is configured via environment variables so no credentials are
        // embedded in the AlertConfig serialisation:
        //   AUTH_SMTP_HOST     — required; disables email channel if unset
        //   AUTH_SMTP_PORT     — optional (default 587, STARTTLS)
        //   AUTH_SMTP_FROM     — optional (default "alerts@<host>")
        //   AUTH_SMTP_USERNAME — optional
        //   AUTH_SMTP_PASSWORD — optional
        let smtp_host = match std::env::var("AUTH_SMTP_HOST") {
            Ok(h) => h,
            Err(_) => {
                tracing::warn!(
                    recipients = ?recipients,
                    title = %alert.title,
                    severity = ?alert.severity,
                    "EMAIL ALERT: set AUTH_SMTP_HOST to enable SMTP delivery"
                );
                return;
            }
        };
        let smtp_port: u16 = std::env::var("AUTH_SMTP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(587);
        let from_addr =
            std::env::var("AUTH_SMTP_FROM").unwrap_or_else(|_| format!("alerts@{}", smtp_host));

        let from_mailbox: Mailbox = match from_addr.parse() {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(from = %from_addr, error = %e, "Invalid AUTH_SMTP_FROM address");
                return;
            }
        };

        let mut builder = match AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_host) {
            Ok(b) => b.port(smtp_port),
            Err(e) => {
                tracing::error!(host = %smtp_host, error = %e, "Failed to create SMTP transport");
                return;
            }
        };
        if let (Ok(user), Ok(pass)) = (
            std::env::var("AUTH_SMTP_USERNAME"),
            std::env::var("AUTH_SMTP_PASSWORD"),
        ) {
            builder = builder.credentials(Credentials::new(user, pass));
        }
        let mailer = builder.build();

        let subject = format!("[{:?}] {}", alert.severity, alert.title);
        let body = format!(
            "Alert: {}\nSeverity: {:?}\nSource: {}\nMessage: {}\nTimestamp: {}",
            alert.title, alert.severity, alert.source, alert.message, alert.timestamp
        );

        for recipient in recipients {
            let to_mailbox: Mailbox = match recipient.parse() {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!(
                        recipient = %recipient, error = %e,
                        "Invalid recipient address — skipping"
                    );
                    continue;
                }
            };
            match Message::builder()
                .from(from_mailbox.clone())
                .to(to_mailbox)
                .subject(&subject)
                .body(body.clone())
            {
                Ok(email) => {
                    if let Err(e) = mailer.send(email).await {
                        tracing::error!(
                            recipient = %recipient, error = %e,
                            "Failed to send email alert"
                        );
                    } else {
                        tracing::info!(
                            recipient = %recipient,
                            "Email alert sent: {}", alert.title
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        recipient = %recipient, error = %e,
                        "Failed to build email message"
                    );
                }
            }
        }
    }

    /// Without the `smtp` feature there is no SMTP stack: say so loudly instead of dropping the alert.
    #[cfg(not(feature = "smtp"))]
    async fn send_email_alert(&self, alert: &Alert, recipients: &[String]) {
        tracing::error!(
            recipients = ?recipients,
            title = %alert.title,
            severity = ?alert.severity,
            "EMAIL ALERT NOT SENT: this build has no SMTP support; enable the `smtp` feature"
        );
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
