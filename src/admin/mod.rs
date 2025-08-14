//! Administration Module
//!
//! This module provides administrative functionality for the auth-framework,
//! including CLI, TUI, and Web interfaces.

use crate::{config::AuthFrameworkSettings, errors::Result};
use chrono;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared application state
#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Arc<RwLock<AuthFrameworkSettings>>,
    pub config_manager: crate::config::ConfigManager,
    pub health_status: HealthStatus,
    pub server_status: Arc<RwLock<ServerStatus>>,
}

/// Server status information
#[derive(Debug, Clone)]
pub struct ServerStatus {
    pub web_server_running: bool,
    pub web_server_port: Option<u16>,
    pub last_config_update: Option<chrono::DateTime<chrono::Utc>>,
    pub active_sessions: u32,
    pub health_status: HealthStatus,
}

/// System health status
#[derive(Debug, Clone)]
pub enum HealthStatus {
    Healthy,
    Warning(String),
    Critical(String),
}

impl AppState {
    pub fn new(settings: AuthFrameworkSettings) -> Result<Self> {
        let config = Arc::new(RwLock::new(settings));
        let config_manager = crate::config::ConfigManager::new()?;

        let server_status = ServerStatus {
            web_server_running: false,
            web_server_port: None,
            last_config_update: None,
            active_sessions: 0,
            health_status: HealthStatus::Healthy,
        };

        Ok(Self {
            config,
            config_manager,
            health_status: HealthStatus::Healthy,
            server_status: Arc::new(RwLock::new(server_status)),
        })
    }

    pub async fn get_health_status(&self) -> HealthStatus {
        // Simplified health check - in a real implementation this would
        // check database connections, external services, etc.
        HealthStatus::Healthy
    }

    pub async fn reload_config(&self) -> Result<()> {
        // Reload configuration logic here
        // For now, just update the timestamp
        let mut status = self.server_status.write().await;
        status.last_config_update = Some(chrono::Utc::now());
        Ok(())
    }

    pub async fn update_server_status(&self, running: bool, port: Option<u16>) {
        let mut status = self.server_status.write().await;
        status.web_server_running = running;
        status.web_server_port = port;
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
}
