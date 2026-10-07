//! Comprehensive administration module for AuthFramework management.
//!
//! This module provides multiple administrative interfaces for monitoring,
//! configuring, and managing AuthFramework deployments. It includes both
//! interactive and programmatic interfaces suitable for different operational
//! environments.
//!
//! # Administrative Interfaces
//!
//! - **CLI (Command Line Interface)**: Scriptable command-line administration
//! - **TUI (Terminal User Interface)**: Interactive terminal dashboard
//! - **Web Interface**: Browser-based administrative console
//! - **API**: RESTful API for programmatic management
//!
//! # Core Capabilities
//!
//! - **Real-time Monitoring**: Live metrics and health status
//! - **Configuration Management**: Configuration inspection and disk-backed reloads
//! - **User Management**: User account and permission administration
//! - **Security Monitoring**: Threat detection and incident response
//! - **Audit Logging**: Comprehensive activity tracking
//! - **Performance Analytics**: System performance and optimization
//!
//! # Security Features
//!
//! - **Role-based Access**: Admin, operator, and read-only roles
//! - **Audit Trail**: All administrative actions are logged
//! - **Secure Sessions**: Encrypted admin sessions
//! - **MFA Enforcement**: Multi-factor authentication for admins
//! - **IP Whitelisting**: Restrict admin access by network
//!
//! # Monitoring Dashboard
//!
//! The administrative interfaces provide comprehensive monitoring:
//! - Active user sessions
//! - Authentication success/failure rates
//! - Security alerts and incidents
//! - System performance metrics
//! - Error rates and debugging information
//!
//! # Configuration Management
//!
//! - **Configuration Inspection**: Review current effective settings
//! - **Disk-Backed Reloads**: Reload configuration from the configured sources
//! - **Validation**: Real-time configuration validation
//! - **Backup/Restore**: Configuration versioning and rollback
//! - **Environment Management**: Dev, staging, production configs
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use auth_framework::admin::{AdminInterface, AppState};
//!
//! // Create administrative interface
//! let app_state = AppState::new(config_manager).await?;
//! let admin = AdminInterface::new(app_state);
//!
//! // Start web interface
//! admin.start_web_interface("127.0.0.1:8080").await?;
//!
//! // Start TUI interface
//! admin.start_tui_interface().await?;
//! ```
//!
//! # Deployment Scenarios
//!
//! - **Development**: TUI for local development and testing
//! - **Production**: Web interface for remote administration
//! - **Automation**: CLI for scripted operations and CI/CD
//! - **Monitoring**: API integration with external monitoring systems
//!
//! # Integration
//!
//! Integrates with external systems:
//! - Prometheus metrics export
//! - Grafana dashboard templates
//! - SIEM system integration
//! - Log aggregation systems

use crate::{config::AuthFrameworkSettings, errors::Result};
use chrono;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Server-side admin GUI session metadata.
///
/// Tracks an authenticated admin session with CSRF protection.
/// Sessions expire after `expires_at` is passed.
///
/// # Example
/// ```rust,ignore
/// let session = AdminSessionRecord {
///     username: "admin".into(),
///     created_at: chrono::Utc::now(),
///     expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
///     last_activity: chrono::Utc::now(),
///     csrf_token: "random-token".into(),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct AdminSessionRecord {
    pub username: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    /// Per-session CSRF token (Synchronizer Token Pattern).
    pub csrf_token: String,
}

/// In-memory login throttling state for the admin GUI.
///
/// Tracks failed login attempts to mitigate brute force attacks
/// on the administrative interface.
#[derive(Debug, Clone)]
pub struct AdminLoginAttemptRecord {
    pub failed_attempts: u32,
    pub first_failed_at: chrono::DateTime<chrono::Utc>,
    pub last_failed_at: chrono::DateTime<chrono::Utc>,
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
}

/// Shared application state.
///
/// # Example
/// ```rust,ignore
/// let state = AppState::new(settings)?;
/// ```
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<AuthFrameworkSettings>>,
    pub config_manager: crate::config::ConfigManager,
    pub health_status: HealthStatus,
    pub server_status: Arc<RwLock<ServerStatus>>,
    /// Active admin GUI sessions keyed by random session token.
    ///
    /// Using a `Mutex`-guarded map so the same `AppState` clone shared across
    /// all Axum handlers can atomically validate, renew, and revoke sessions
    /// without requiring an async lock at the middleware site.
    pub admin_sessions:
        Arc<std::sync::Mutex<std::collections::HashMap<String, AdminSessionRecord>>>,
    /// Failed admin GUI login attempts keyed by username.
    pub admin_login_attempts:
        Arc<std::sync::Mutex<std::collections::HashMap<String, AdminLoginAttemptRecord>>>,
    /// Optional reference to the running AuthFramework instance.
    /// When present, web/API handlers can query live storage data (users, events, etc.).
    pub auth_framework: Option<Arc<crate::AuthFramework>>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("health_status", &self.health_status)
            .field("auth_framework_present", &self.auth_framework.is_some())
            .finish_non_exhaustive()
    }
}

/// Current running state of the server
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRunState {
    /// Server is actively running and accepting connections
    Running,
    /// Server is stopped
    Stopped,
    /// Server is paused
    Paused,
}

/// Server status information
#[derive(Debug, Clone)]
pub struct ServerStatus {
    pub web_server_state: ServerRunState,
    pub web_server_port: Option<u16>,
    pub last_config_update: Option<chrono::DateTime<chrono::Utc>>,
    pub active_sessions: u32,
    pub health_status: HealthStatus,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

pub(crate) fn format_uptime_since(
    started_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let elapsed = now.signed_duration_since(started_at);
    if elapsed < chrono::Duration::zero() {
        return "0m".to_string();
    }

    let seconds = elapsed.num_seconds() as u64;
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;

    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}
/// System health status
#[derive(Debug, Clone)]
pub enum HealthStatus {
    Healthy,
    Warning(String),
    Critical(String),
}

/// Server information for TUI display
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub version: String,
    pub uptime: String,
    pub status: String,
    pub port: Option<u16>,
    pub active_sessions: u32,
}

/// User statistics for TUI display
#[derive(Debug, Clone)]
pub struct UserStatistics {
    pub total_users: u32,
    pub active_sessions: u32,
    pub failed_logins_today: u32,
    pub new_registrations_today: u32,
}

/// Security event for TUI display
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub description: String,
    pub ip_address: Option<String>,
    pub user_id: Option<String>,
}

impl AppState {
    pub fn new(settings: AuthFrameworkSettings) -> Result<Self> {
        let config = Arc::new(RwLock::new(settings));
        let config_manager = crate::config::ConfigManager::new()?;

        let server_status = ServerStatus {
            web_server_state: ServerRunState::Stopped,
            web_server_port: None,
            last_config_update: None,
            active_sessions: 0,
            health_status: HealthStatus::Healthy,
            started_at: chrono::Utc::now(),
        };

        Ok(Self {
            config,
            config_manager,
            health_status: HealthStatus::Healthy,
            server_status: Arc::new(RwLock::new(server_status)),
            admin_sessions: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            admin_login_attempts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            auth_framework: None,
        })
    }

    /// Attach a running [`crate::AuthFramework`] instance so that admin GUI
    /// handlers can query live storage data (users, audit events, etc.).
    ///
    /// # Example
    /// ```rust,ignore
    /// let state = state.with_auth_framework(fw.clone());
    /// ```
    pub fn with_auth_framework(mut self, af: Arc<crate::AuthFramework>) -> Self {
        self.auth_framework = Some(af);
        self
    }

    pub async fn get_health_status(&self) -> HealthStatus {
        // Check storage connectivity if auth_framework is available
        if let Some(ref af) = self.auth_framework {
            let storage = af.storage();
            // Attempt a lightweight storage operation to verify connectivity
            match storage.get_kv("health_check_ping").await {
                Ok(_) => {
                    let status = self.server_status.read().await;
                    match status.web_server_state {
                        ServerRunState::Running => HealthStatus::Healthy,
                        _ => HealthStatus::Warning("Web server not running".to_string()),
                    }
                }
                Err(e) => HealthStatus::Critical(format!("Storage unavailable: {}", e)),
            }
        } else {
            HealthStatus::Warning("AuthFramework not attached".to_string())
        }
    }

    pub async fn reload_config(&self) -> Result<()> {
        // Re-read configuration from sources
        let new_settings = self.config_manager.get_auth_settings()?;
        {
            let mut config = self.config.write().await;
            *config = new_settings;
        }
        let mut status = self.server_status.write().await;
        status.last_config_update = Some(chrono::Utc::now());
        Ok(())
    }

    pub async fn update_server_status(&self, state: ServerRunState, port: Option<u16>) {
        let mut status = self.server_status.write().await;
        status.web_server_state = state;
        status.web_server_port = port;
    }

    /// Get server information for display in TUI.
    ///
    /// # Example
    /// ```rust,ignore
    /// let info = state.get_server_info().await?;
    /// println!("version: {}", info.version);
    /// ```
    pub async fn get_server_info(&self) -> Result<ServerInfo> {
        let status = self.server_status.read().await;
        let uptime = format_uptime_since(status.started_at, chrono::Utc::now());
        Ok(ServerInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime,
            status: match status.web_server_state {
                ServerRunState::Running => "Running",
                ServerRunState::Stopped => "Stopped",
                ServerRunState::Paused => "Paused",
            }
            .to_string(),
            port: status.web_server_port,
            active_sessions: status.active_sessions,
        })
    }

    /// Get user statistics for display in TUI.
    ///
    /// # Example
    /// ```rust,ignore
    /// let stats = state.get_user_statistics().await?;
    /// println!("total users: {}", stats.total_users);
    /// ```
    pub async fn get_user_statistics(&self) -> Result<UserStatistics> {
        if let Some(ref af) = self.auth_framework {
            let storage = af.storage();

            // Count total users from the users:index list.
            let total_users = match storage.get_kv("users:index").await {
                Ok(Some(bytes)) => serde_json::from_slice::<Vec<String>>(&bytes)
                    .map(|v| v.len() as u32)
                    .unwrap_or(0),
                _ => 0,
            };

            let status = self.server_status.read().await;
            let (failed_logins, new_regs) = match af.get_security_audit_stats().await {
                Ok(stats) => (
                    stats.failed_logins_24h as u32,
                    stats.password_resets_24h as u32,
                ),
                Err(_) => (0, 0),
            };
            Ok(UserStatistics {
                total_users,
                active_sessions: status.active_sessions,
                failed_logins_today: failed_logins,
                new_registrations_today: new_regs,
            })
        } else {
            let status = self.server_status.read().await;
            Ok(UserStatistics {
                total_users: 0,
                active_sessions: status.active_sessions,
                failed_logins_today: 0,
                new_registrations_today: 0,
            })
        }
    }

    /// Get recent security events for display in TUI.
    ///
    /// # Example
    /// ```rust,ignore
    /// let events = state.get_recent_security_events().await?;
    /// ```
    pub async fn get_recent_security_events(&self) -> Result<Vec<SecurityEvent>> {
        if let Some(ref af) = self.auth_framework {
            let logs = af
                .get_permission_audit_logs(None, None, None, Some(20))
                .await?;
            let events = logs
                .into_iter()
                .map(|log_line| {
                    // Log format: "[timestamp] EventType user=uid outcome=Outcome - description"
                    let (ts, rest) = log_line
                        .strip_prefix('[')
                        .and_then(|s| s.split_once("] "))
                        .unwrap_or(("", &log_line));
                    let event_type = rest.split_whitespace().next().unwrap_or("Unknown");
                    let user_id = rest
                        .split("user=")
                        .nth(1)
                        .and_then(|s| s.split_whitespace().next())
                        .map(|s| s.to_string());
                    let timestamp = chrono::DateTime::parse_from_rfc3339(ts)
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .unwrap_or_else(|_| chrono::Utc::now());
                    SecurityEvent {
                        timestamp,
                        event_type: event_type.to_string(),
                        description: rest.to_string(),
                        ip_address: None,
                        user_id,
                    }
                })
                .collect();
            Ok(events)
        } else {
            Ok(vec![])
        }
    }
} // Command line interface types and functions
#[cfg(feature = "cli")]
pub mod cli;

#[cfg(feature = "tui")]
pub mod tui;

#[cfg(feature = "web-gui")]
pub mod web;

// CLI command types
#[derive(Debug, Clone, clap::Subcommand)]
pub enum CliCommand {
    /// Configuration management commands
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// User management commands
    Users {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Server management commands
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// Security management commands
    Security {
        #[command(subcommand)]
        action: SecurityAction,
    },
    /// Maintenance operations for backup, restore, reset, and migration generation
    Maintenance {
        #[command(subcommand)]
        action: MaintenanceAction,
    },
    /// Show system status
    Status {
        /// Show detailed information
        #[arg(long)]
        detailed: bool,
        /// Output format (json, yaml, table)
        #[arg(long, default_value = "table")]
        format: String,
    },
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum MaintenanceAction {
    /// Export a logical maintenance snapshot to disk
    Backup {
        /// Output snapshot path
        output_path: String,
        /// Preview the operation without writing the snapshot
        #[arg(long)]
        dry_run: bool,
    },
    /// Restore a logical maintenance snapshot from disk
    Restore {
        /// Input snapshot path
        backup_path: String,
        /// Confirm destructive overwrite
        #[arg(long)]
        confirm: bool,
        /// Preview the restore without mutating storage
        #[arg(long)]
        dry_run: bool,
    },
    /// Reset logical auth data in the configured backend
    Reset {
        /// Confirm destructive deletion
        #[arg(long)]
        confirm: bool,
        /// Preview the reset without deleting data
        #[arg(long)]
        dry_run: bool,
    },
    /// Create a backend-specific migration template
    CreateMigration {
        /// Human-readable migration name
        name: String,
    },
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum ConfigAction {
    /// Show configuration
    Show {
        /// Configuration section to show
        section: Option<String>,
        /// Output format (json, yaml, table)
        #[arg(long, default_value = "table")]
        format: String,
    },
    /// Set configuration value
    Set {
        /// Configuration key
        key: String,
        /// Configuration value
        value: String,
        /// Apply hot reload
        #[arg(long)]
        hot_reload: bool,
    },
    /// Reset configuration to defaults
    Reset,
    /// Validate configuration
    Validate {
        /// Configuration file to validate
        file: Option<String>,
    },
    /// Get configuration value
    Get {
        /// Configuration key
        key: String,
    },
    /// Reload configuration
    Reload {
        /// Show configuration differences
        #[arg(long)]
        show_diff: bool,
    },
    /// Generate configuration template
    Template {
        /// Output file path
        output: Option<String>,
        /// Generate complete template with all options
        #[arg(long)]
        complete: bool,
    },
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum UserAction {
    /// List users
    List {
        /// Maximum number of users to show
        limit: Option<u32>,
        /// Show only active users
        #[arg(long)]
        active: bool,
    },
    /// Create new user
    Create {
        /// User email address
        email: String,
        /// User password (will prompt if not provided)
        password: Option<String>,
        /// Grant admin privileges
        #[arg(long)]
        admin: bool,
    },
    /// Delete user
    Delete {
        /// User to delete (email or ID)
        user: String,
        /// Force deletion without confirmation
        #[arg(long)]
        force: bool,
    },
    /// Set user role
    SetRole {
        /// User email
        email: String,
        /// Role to assign
        role: String,
    },
    /// Update user properties
    Update {
        /// User to update (email or ID)
        user: String,
        /// New email address
        #[arg(long)]
        email: Option<String>,
        /// Set active status
        #[arg(long)]
        active: Option<bool>,
    },
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum ServerAction {
    /// Show server status
    Status,
    /// Start the server
    Start {
        /// Port to bind to
        port: Option<u16>,
        /// Run as daemon
        #[arg(long)]
        daemon: bool,
    },
    /// Stop the server
    Stop {
        /// Force stop without graceful shutdown
        #[arg(long)]
        force: bool,
    },
    /// Restart the server
    Restart {
        /// Port to bind to
        port: Option<u16>,
    },
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum SecurityAction {
    /// Show audit log
    AuditLog,
    /// Generate threat report
    ThreatReport,
    /// Force user logout
    ForceLogout {
        /// User ID to logout
        user_id: String,
    },
    /// Run security audit
    Audit {
        /// Number of days to audit
        #[arg(long, default_value = "7")]
        days: u32,
        /// Show detailed information
        #[arg(long)]
        detailed: bool,
    },
    /// Manage user sessions
    Sessions {
        /// Filter by specific user
        #[arg(long)]
        user: Option<String>,
        /// Terminate specific session
        #[arg(long)]
        terminate: Option<String>,
    },
    /// Threat intelligence operations
    ThreatIntel {
        /// Update threat intelligence database
        #[arg(long)]
        update: bool,
        /// Check specific IP address
        #[arg(long)]
        check_ip: Option<String>,
    },
    /// Encrypt any plaintext KV-layer values at rest (for data written
    /// before encryption was enabled). Safe to re-run: already-encrypted
    /// values are left untouched; a value that fails to decrypt is
    /// skipped and reported by name, not treated as fatal.
    ///
    /// WARNING: this re-stores every migrated value with no TTL, even if
    /// the original had one (OAuth codes, email-verification tokens,
    /// MFA/SMS codes, WebAuthn challenges, rate-limit windows, and
    /// expiring API keys all lose their expiry). Scope `--prefix` to a
    /// durable-secret namespace; an empty prefix touches everything and
    /// requires `--confirm`.
    ///
    /// A value in the original (pre-redesign) format-version-0 shape has
    /// no AAD, so decrypting it cannot verify that its plaintext actually
    /// belongs to the record it's filed under -- upgrading one is never
    /// a silent side effect of running this command; pass
    /// `--accept-legacy-v0` to actually upgrade any found, after
    /// understanding that risk.
    EncryptKv {
        /// Only operate on keys starting with this prefix (default: all keys).
        #[arg(long, default_value = "")]
        prefix: String,
        /// Preview what would change without writing anything.
        #[arg(long)]
        dry_run: bool,
        /// Required when --prefix is empty and this is NOT a dry run,
        /// acknowledging the TTL-loss warning above. Not needed for
        /// --dry-run, which makes no changes.
        #[arg(long)]
        confirm: bool,
        /// Required to actually rewrite a format-version-0 envelope to
        /// the current format. Without it, such envelopes are detected
        /// and reported but left untouched. See the WARNING above about
        /// what this upgrade can and cannot verify.
        #[arg(long)]
        accept_legacy_v0: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_status_default_fields() {
        let status = ServerStatus {
            web_server_state: ServerRunState::Stopped,
            web_server_port: None,
            last_config_update: None,
            active_sessions: 0,
            health_status: HealthStatus::Healthy,
            started_at: chrono::Utc::now(),
        };
        assert_eq!(status.web_server_state, ServerRunState::Stopped);
        assert_eq!(status.active_sessions, 0);
        assert!(status.web_server_port.is_none());
    }

    #[test]
    fn test_health_status_variants() {
        let h = HealthStatus::Healthy;
        assert!(matches!(h, HealthStatus::Healthy));

        let w = HealthStatus::Warning("low memory".to_string());
        assert!(matches!(w, HealthStatus::Warning(_)));

        let c = HealthStatus::Critical("storage down".to_string());
        assert!(matches!(c, HealthStatus::Critical(_)));
    }

    #[test]
    fn test_server_info_creation() {
        let info = ServerInfo {
            version: "0.5.0".to_string(),
            uptime: "1h 30m".to_string(),
            status: "running".to_string(),
            port: Some(8080),
            active_sessions: 5,
        };
        assert_eq!(info.version, "0.5.0");
        assert_eq!(info.active_sessions, 5);
        assert_eq!(info.port, Some(8080));
    }

    #[test]
    fn test_user_statistics_creation() {
        let stats = UserStatistics {
            total_users: 100,
            active_sessions: 20,
            failed_logins_today: 3,
            new_registrations_today: 5,
        };
        assert_eq!(stats.total_users, 100);
        assert_eq!(stats.failed_logins_today, 3);
    }

    #[test]
    fn test_security_event_creation() {
        let event = SecurityEvent {
            timestamp: chrono::Utc::now(),
            event_type: "LoginFailure".to_string(),
            description: "Failed login attempt".to_string(),
            ip_address: Some("192.168.1.1".to_string()),
            user_id: Some("user123".to_string()),
        };
        assert_eq!(event.event_type, "LoginFailure");
        assert!(event.ip_address.is_some());
        assert!(event.user_id.is_some());
    }

    #[test]
    fn test_format_uptime_since() {
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-03-21T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let now = chrono::DateTime::parse_from_rfc3339("2026-03-21T12:45:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        assert_eq!(format_uptime_since(started_at, now), "2h 45m");
    }
}
