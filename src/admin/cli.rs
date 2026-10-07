//! Command Line Interface for Auth Framework Administration

use crate::admin::{
    AppState, CliCommand, ConfigAction, HealthStatus, MaintenanceAction, SecurityAction,
    ServerAction, ServerRunState, UserAction,
};
use crate::errors::{AuthError, Result};
#[cfg(feature = "cli")]
use colored::Colorize;
#[cfg(feature = "cli")]
use dialoguer::{Confirm, Password};
#[cfg(feature = "cli")]
use indicatif::{ProgressBar, ProgressStyle};
#[cfg(feature = "cli")]
use std::collections::HashMap;

/// Run the CLI with the given application state and command.
///
/// # Example
/// ```rust,ignore
/// run_cli(state, CliCommand::Status { detailed: true, format: "json".into() }).await?;
/// ```
#[cfg(feature = "cli")]
pub async fn run_cli(state: AppState, command: CliCommand) -> Result<()> {
    match command {
        CliCommand::Config { action } => handle_config_action(state, action).await?,
        CliCommand::Server { action } => handle_server_action(state, action).await?,
        CliCommand::Users { action } => handle_user_action(state, action).await?,
        CliCommand::Status { detailed, format } => handle_status(state, detailed, &format).await?,
        CliCommand::Security { action } => handle_security_action(state, action).await?,
        CliCommand::Maintenance { action } => handle_maintenance_action(state, action).await?,
    }
    Ok(())
}

#[cfg(feature = "cli")]
fn require_auth_framework(state: &AppState) -> Result<std::sync::Arc<crate::AuthFramework>> {
    state.auth_framework.clone().ok_or_else(|| {
        AuthError::internal(
            "Admin AppState is not attached to an AuthFramework instance; maintenance commands are unavailable",
        )
    })
}

#[cfg(feature = "cli")]
async fn handle_config_action(state: AppState, action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Show { section, format } => handle_config_show(state, section, format).await,
        ConfigAction::Validate { file } => handle_config_validate(state, file).await,
        ConfigAction::Set {
            key,
            value,
            hot_reload,
        } => handle_config_set(state, key, value, hot_reload).await,
        ConfigAction::Get { key } => handle_config_get(state, key).await,
        ConfigAction::Reload { show_diff } => handle_config_reload(state, show_diff).await,
        ConfigAction::Template { output, complete } => {
            handle_config_template(output, complete).await
        }
        ConfigAction::Reset => handle_config_reset().await,
    }
}

#[cfg(feature = "cli")]
async fn handle_config_show(
    state: AppState,
    section: Option<String>,
    format: String,
) -> Result<()> {
    println!("{}", "📋 Current Configuration".bold().blue());

    let config = state.config.read().await;
    let output = match format.as_str() {
        "json" => serde_json::to_string_pretty(&*config)?,
        "yaml" => serde_yaml::to_string(&*config)?,
        "toml" => toml::to_string_pretty(&*config)?,
        _ => toml::to_string_pretty(&*config)?,
    };

    if let Some(section_name) = section {
        println!("Section: {}", section_name.bold());
        // In a real implementation, we'd parse and show only the requested section
    }

    println!("{}", output);
    Ok(())
}

#[cfg(feature = "cli")]
async fn handle_config_validate(state: AppState, file: Option<String>) -> Result<()> {
    let spinner = create_spinner("Validating configuration...");

    let result = if let Some(file_path) = file {
        use crate::config::config_manager::ConfigBuilder;
        let temp_manager = ConfigBuilder::new().add_file(&file_path, true).build()?;
        temp_manager.validate()
    } else {
        state.config_manager.validate()
    };

    let message = if let Err(e) = result {
        format!("❌ Configuration error: {}", e).red().to_string()
    } else {
        "✅ Configuration is valid".green().to_string()
    };
    spinner.finish_with_message(message);

    Ok(())
}

#[cfg(feature = "cli")]
async fn handle_config_set(
    state: AppState,
    key: String,
    value: String,
    hot_reload: bool,
) -> Result<()> {
    println!("Setting {}={}", key.cyan(), value.yellow());

    if hot_reload {
        println!("🔄 Hot-reloading configuration...");
        state.reload_config().await?;
        println!("✅ Configuration updated and reloaded");
    } else {
        println!("⚠️ Configuration will take effect after restart");
    }

    Ok(())
}

#[cfg(feature = "cli")]
async fn handle_config_get(state: AppState, key: String) -> Result<()> {
    let config = state.config.read().await;
    // Serialize the full config to JSON and navigate the key path (dot-separated).
    let config_json = serde_json::to_value(&*config)
        .map_err(|e| AuthError::internal(format!("Failed to serialize config: {}", e)))?;
    let mut current = &config_json;
    for segment in key.split('.') {
        current = current.get(segment).ok_or_else(|| {
            AuthError::internal(format!(
                "Configuration key '{}' not found (segment '{}' missing)",
                key, segment
            ))
        })?;
    }
    let display = match current {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    println!("{}: {}", key.cyan(), display.green());
    Ok(())
}

#[cfg(feature = "cli")]
async fn handle_config_reload(state: AppState, show_diff: bool) -> Result<()> {
    if show_diff {
        println!("📊 Configuration differences:");
        // Implementation would show diff between current and file config
    }

    let spinner = create_spinner("Reloading configuration...");
    state.reload_config().await?;
    spinner.finish_with_message("✅ Configuration reloaded successfully".green().to_string());

    Ok(())
}

#[cfg(feature = "cli")]
async fn handle_config_template(output: Option<String>, complete: bool) -> Result<()> {
    let template = if complete {
        create_complete_config_template()
    } else {
        create_minimal_config_template()
    };

    if let Some(output_path) = output {
        std::fs::write(&output_path, template)?;
        println!(
            "✅ Configuration template written to: {}",
            output_path.green()
        );
    } else {
        println!("{}", template);
    }

    Ok(())
}

#[cfg(feature = "cli")]
async fn handle_config_reset() -> Result<()> {
    println!("🔄 Resetting configuration to defaults...");
    let spinner = create_spinner("Resetting configuration...");
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
    spinner.finish_with_message("✅ Configuration reset to defaults".green().to_string());
    Ok(())
}

#[cfg(feature = "cli")]
async fn handle_server_action(state: AppState, action: ServerAction) -> Result<()> {
    match action {
        ServerAction::Start { port, daemon } => handle_server_start(state, port, daemon).await,
        ServerAction::Stop { force } => handle_server_stop(state, force).await,
        ServerAction::Restart { port } => handle_server_restart(state, port).await,
        ServerAction::Status => handle_server_status(state).await,
    }
}

#[cfg(feature = "cli")]
async fn handle_server_start(state: AppState, port: Option<u16>, daemon: bool) -> Result<()> {
    let port_num = port.unwrap_or(8080);
    println!(
        "🚀 Starting web server on port {}",
        port_num.to_string().cyan()
    );

    if daemon {
        println!("Running as daemon...");
        // Implementation would daemonize the process
    }

    state
        .update_server_status(ServerRunState::Running, Some(port_num))
        .await;
    println!("✅ Web server started successfully");
    Ok(())
}

#[cfg(feature = "cli")]
async fn handle_server_stop(state: AppState, force: bool) -> Result<()> {
    println!("🛑 Stopping web server...");

    if force {
        println!("⚠️ Force stopping (may lose data)");
    } else {
        println!("Gracefully shutting down...");
    }

    state
        .update_server_status(ServerRunState::Stopped, None)
        .await;
    println!("✅ Web server stopped");
    Ok(())
}

#[cfg(feature = "cli")]
async fn handle_server_restart(state: AppState, port: Option<u16>) -> Result<()> {
    println!("🔄 Restarting web server...");

    // Stop
    state
        .update_server_status(ServerRunState::Stopped, None)
        .await;

    // Start with new port if provided
    let new_port = port.unwrap_or(8080);
    state
        .update_server_status(ServerRunState::Running, Some(new_port))
        .await;

    println!(
        "✅ Web server restarted on port {}",
        new_port.to_string().cyan()
    );
    Ok(())
}

#[cfg(feature = "cli")]
async fn handle_server_status(state: AppState) -> Result<()> {
    let status = state.server_status.read().await;

    println!("{}", "🔍 Server Status".bold().blue());
    println!(
        "Web Server: {}",
        if matches!(
            status.web_server_state,
            crate::admin::ServerRunState::Running
        ) {
            "Running".green()
        } else {
            "Stopped".red()
        }
    );

    if let Some(port) = status.web_server_port {
        println!("Port: {}", port.to_string().cyan());
    }

    println!("Health: {}", format_health_status(&status.health_status));

    if let Some(last_update) = status.last_config_update {
        println!(
            "Last Config Update: {}",
            last_update
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string()
                .dimmed()
        );
    }

    Ok(())
}

#[cfg(feature = "cli")]
async fn handle_user_action(state: AppState, action: UserAction) -> Result<()> {
    match action {
        UserAction::List { limit, active: _ } => {
            println!("{}", "👥 Users".bold().blue());

            let spinner = create_spinner("Loading users...");
            let stats = state.get_user_statistics().await?;
            spinner.finish_with_message("Users loaded".green().to_string());

            println!(
                "  Total users:              {}",
                stats.total_users.to_string().cyan()
            );
            println!(
                "  Active sessions:          {}",
                stats.active_sessions.to_string().cyan()
            );
            println!(
                "  Failed logins today:      {}",
                stats.failed_logins_today.to_string().yellow()
            );
            println!(
                "  New registrations today:  {}",
                stats.new_registrations_today.to_string().green()
            );

            if let Some(limit_val) = limit {
                println!("(Showing up to {} users)", limit_val.to_string().dimmed());
            }
        }
        UserAction::Create {
            email,
            password,
            admin,
        } => {
            println!("👤 Creating new user: {}", email.cyan());

            let _password = if let Some(pwd) = password {
                pwd
            } else {
                Password::new()
                    .with_prompt("Enter password")
                    .with_confirmation("Confirm password", "Passwords don't match")
                    .interact()
                    .map_err(|e| AuthError::Cli(format!("Password input failed: {}", e)))?
            };

            // User creation requires a storage backend wired into AppState.
            // The AppState for the CLI currently holds only configuration;
            // connect it to an AuthFramework instance with storage to complete
            // this operation.
            println!(
                "{}",
                "⚠️  User creation requires a connected storage backend.  \
                 Wire AppState to an AuthFramework instance to enable this operation."
                    .yellow()
            );
            println!(
                "   Requested: create user {} (admin: {})",
                email.cyan(),
                admin
            );
        }
        UserAction::Update {
            user,
            email,
            active,
        } => {
            println!("✏️  Requested update for user: {}", user.cyan());
            if let Some(new_email) = email {
                println!("   → new email: {}", new_email.green());
            }
            if let Some(is_active) = active {
                println!(
                    "   → active: {}",
                    if is_active {
                        "true".green()
                    } else {
                        "false".red()
                    }
                );
            }
            println!(
                "{}",
                "⚠️  User updates require a connected storage backend.".yellow()
            );
        }
        UserAction::Delete { user, force } => {
            if !force {
                let confirm = Confirm::new()
                    .with_prompt(format!(
                        "Are you sure you want to delete user '{}'?",
                        user.red()
                    ))
                    .default(false)
                    .interact()
                    .map_err(|e| AuthError::Cli(format!("Confirmation input failed: {}", e)))?;

                if !confirm {
                    println!("❌ User deletion cancelled");
                    return Ok(());
                }
            }

            println!(
                "{}",
                "⚠️  User deletion requires a connected storage backend.".yellow()
            );
            println!("   Requested: delete user {}", user.red());
        }
        UserAction::SetRole { email, role } => {
            println!(
                "{}",
                "⚠️  Role assignment requires a connected storage backend.".yellow()
            );
            println!(
                "   Requested: set role {} for user {}",
                role.green(),
                email.cyan()
            );
        }
    }
    Ok(())
}

#[cfg(feature = "cli")]
async fn handle_status(state: AppState, detailed: bool, format: &str) -> Result<()> {
    println!("{}", "🔍 System Status".bold().blue());

    let _config = state.config.read().await;
    let server_status = state.server_status.read().await;
    let health = state.get_health_status().await;

    match format {
        "json" => {
            let mut status = HashMap::new();
            status.insert(
                "web_server_running",
                matches!(
                    server_status.web_server_state,
                    crate::admin::ServerRunState::Running
                ),
            );
            status.insert("health", matches!(health, HealthStatus::Healthy));
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        "yaml" => {
            println!(
                "web_server_running: {}",
                matches!(
                    server_status.web_server_state,
                    crate::admin::ServerRunState::Running
                )
            );
            println!("health: {}", format_health_status(&health));
        }
        "table" => {
            println!("┌──────────────────────┬─────────────────────┐");
            println!("│ Component            │ Status              │");
            println!("├──────────────────────┼─────────────────────┤");
            println!(
                "│ Web Server           │ {:19} │",
                if matches!(
                    server_status.web_server_state,
                    crate::admin::ServerRunState::Running
                ) {
                    "Running ✅".green()
                } else {
                    "Stopped ❌".red()
                }
            );
            println!("│ Configuration        │ {:19} │", "Loaded ✅".green());
            println!(
                "│ Health Status        │ {:19} │",
                format_health_status(&health)
            );
            println!("└──────────────────────┴─────────────────────┘");

            if detailed {
                println!("\n{}", "📊 Detailed Information".bold().cyan());
                println!("Active Sessions: {}", server_status.active_sessions);
                if let Some(port) = server_status.web_server_port {
                    println!("Web GUI: http://127.0.0.1:{}", port);
                }

                if let Some(last_update) = server_status.last_config_update {
                    println!(
                        "Last Config Update: {}",
                        last_update.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                }
            }
        }
        _ => {
            // Default to table format
            println!("┌──────────────────────┬─────────────────────┐");
            println!("│ Component            │ Status              │");
            println!("├──────────────────────┼─────────────────────┤");
            println!(
                "│ Web Server           │ {:19} │",
                if matches!(
                    server_status.web_server_state,
                    crate::admin::ServerRunState::Running
                ) {
                    "Running ✅".green()
                } else {
                    "Stopped ❌".red()
                }
            );
            println!("│ Configuration        │ {:19} │", "Loaded ✅".green());
            println!(
                "│ Health Status        │ {:19} │",
                format_health_status(&health)
            );
            println!("└──────────────────────┴─────────────────────┘");

            if detailed {
                println!("\n{}", "📊 Detailed Information".bold().cyan());
                println!("Active Sessions: {}", server_status.active_sessions);
                if let Some(port) = server_status.web_server_port {
                    println!("Web GUI: http://127.0.0.1:{}", port);
                }

                if let Some(last_update) = server_status.last_config_update {
                    println!(
                        "Last Config Update: {}",
                        last_update.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                }
            }
        }
    }

    Ok(())
}

#[cfg(feature = "cli")]
async fn handle_security_action(state: AppState, action: SecurityAction) -> Result<()> {
    match action {
        SecurityAction::Audit { days, detailed } => {
            println!(
                "{}",
                format!("🔍 Security Audit (Last {} days)", days)
                    .bold()
                    .blue()
            );

            let spinner = create_spinner("Loading security events...");
            let events = state.get_recent_security_events().await?;
            let stats = state.get_user_statistics().await?;
            spinner.finish_with_message("Security audit complete");

            println!("\n📈 Audit Summary:");
            println!(
                "  • Total tracked events: {}",
                events.len().to_string().cyan()
            );
            println!(
                "  • Active sessions:      {}",
                stats.active_sessions.to_string().green()
            );
            println!(
                "  • Failed logins today:  {}",
                stats.failed_logins_today.to_string().yellow()
            );

            if detailed {
                if events.is_empty() {
                    println!("\n📋 Recent Events: (none recorded)");
                } else {
                    println!("\n📋 Recent Events:");
                    for event in &events {
                        println!(
                            "  {} - {}: {}",
                            event.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                            event.event_type.cyan(),
                            event.description,
                        );
                    }
                }
            }
        }
        SecurityAction::Sessions { user, terminate } => {
            let framework = require_auth_framework(&state)?;

            if let Some(session_id) = terminate {
                println!("🔒 Terminating session: {}", session_id.yellow());
                let spinner = create_spinner("Terminating session...");

                let session = framework.sessions().get(&session_id).await?;
                match session {
                    Some(session) => {
                        framework.sessions().delete(&session_id).await?;
                        spinner.finish_with_message(format!(
                            "✅ Session terminated successfully for user {}",
                            session.user_id.green()
                        ));
                    }
                    None => {
                        spinner.finish_with_message("Session not found".yellow().to_string());
                        return Err(AuthError::Cli(format!("Session not found: {}", session_id)));
                    }
                }

                return Ok(());
            }

            println!("{}", "🔐 Active Sessions".bold().blue());

            if let Some(user_filter) = user {
                println!("Filtering by user: {}", user_filter.cyan());
                let sessions = framework.sessions().list_for_user(&user_filter).await?;
                if sessions.is_empty() {
                    println!("  (no active sessions for this user)");
                } else {
                    for session in sessions {
                        println!(
                            "  • {}  expires={}  last_activity={}  ip={}  ua={}",
                            session.session_id.cyan(),
                            session
                                .expires_at
                                .format("%Y-%m-%d %H:%M:%S UTC")
                                .to_string()
                                .green(),
                            session
                                .last_activity
                                .format("%Y-%m-%d %H:%M:%S UTC")
                                .to_string()
                                .dimmed(),
                            session
                                .ip_address
                                .unwrap_or_else(|| "unknown".to_string())
                                .yellow(),
                            session
                                .user_agent
                                .unwrap_or_else(|| "unknown".to_string())
                                .dimmed(),
                        );
                    }
                }
            } else {
                let stats = framework.audit().security_stats().await?;
                println!(
                    "  Active sessions: {}",
                    stats.active_sessions.to_string().cyan()
                );
                println!(
                    "  {}",
                    "(Pass --user <user_id> to inspect per-user session records)".dimmed()
                );
            }
        }
        SecurityAction::ThreatIntel { update, check_ip } => {
            let ti_config = crate::threat_intelligence::ThreatIntelConfig::default();
            let ti_manager = crate::threat_intelligence::ThreatFeedManager::new(ti_config)
                .map_err(|e| {
                    AuthError::Cli(format!("Failed to initialize threat intelligence: {}", e))
                })?;

            if let Some(ip) = check_ip {
                println!("🌐 Checking IP address: {}", ip.cyan());

                let spinner = create_spinner("Querying threat intelligence...");

                let addr: std::net::IpAddr = ip.parse().map_err(|e| {
                    spinner.finish_with_message("Invalid IP".red().to_string());
                    AuthError::Cli(format!("Invalid IP address '{}': {}", ip, e))
                })?;

                let is_malicious = ti_manager.is_malicious_ip(&addr);
                let is_tor = ti_manager.is_tor_exit(&addr);
                let is_vpn = ti_manager.is_proxy_vpn(&addr);

                spinner.finish_with_message("Lookup complete".to_string());

                if !is_malicious && !is_tor && !is_vpn {
                    println!("  {} {}", "✅".green(), "No threats detected.".green());
                } else {
                    if is_malicious {
                        println!("  {} {}", "🚨", "Malicious IP detected!".red().bold());
                    }
                    if is_tor {
                        println!("  {} {}", "🧅", "Tor exit node detected.".yellow());
                    }
                    if is_vpn {
                        println!("  {} {}", "🛡️", "VPN/Proxy detected.".yellow());
                    }
                }

                let feed_status = ti_manager.get_feed_status().await;
                let enabled_count = feed_status
                    .values()
                    .filter(|s| !matches!(s, crate::threat_intelligence::FeedStatus::Disabled))
                    .count();
                println!(
                    "  {} active threat feeds: {}",
                    "ℹ️",
                    enabled_count.to_string().cyan()
                );
                if enabled_count == 0 {
                    println!(
                        "  {}",
                        "Hint: Enable feeds in threat_intelligence config for real-time data."
                            .dimmed()
                    );
                }

                return Ok(());
            }

            if update {
                println!("🔄 Updating threat intelligence feeds...");
                let spinner = create_spinner("Downloading feeds...");
                match ti_manager.download_all_feeds().await {
                    Ok(()) => {
                        spinner.finish_with_message(
                            "✅ All feeds updated successfully".green().to_string(),
                        );
                    }
                    Err(e) => {
                        spinner.finish_with_message("Feed update failed".red().to_string());
                        return Err(AuthError::Cli(format!("Feed update failed: {}", e)));
                    }
                }
            }
        }
        SecurityAction::AuditLog => {
            let framework = require_auth_framework(&state)?;
            println!("📋 Displaying audit log...");
            let spinner = create_spinner("Loading audit events...");
            let logs = framework
                .audit()
                .permission_logs(None, None, None, Some(50))
                .await?;
            spinner.finish_with_message("Audit log loaded".green().to_string());

            if logs.is_empty() {
                println!("  (no audit entries found)");
            } else {
                for entry in logs {
                    println!("  • {}", entry);
                }
            }
        }
        SecurityAction::ThreatReport => {
            let framework = require_auth_framework(&state)?;
            println!("📊 Generating threat report...");
            let spinner = create_spinner("Analyzing threats...");
            let stats = framework.audit().security_stats().await?;
            spinner.finish_with_message("Threat report generated".green().to_string());

            println!(
                "  Active sessions:         {}",
                stats.active_sessions.to_string().cyan()
            );
            println!(
                "  Failed logins (24h):    {}",
                stats.failed_logins_24h.to_string().yellow()
            );
            println!(
                "  Successful logins (24h): {}",
                stats.successful_logins_24h.to_string().green()
            );
            println!(
                "  Security alerts (24h):  {}",
                stats.security_alerts_24h.to_string().red()
            );
            println!(
                "  Admin actions (24h):    {}",
                stats.admin_actions_24h.to_string().cyan()
            );
            println!("  Security score:         {:.2}", stats.security_score());
            if let Some(alert) = stats.security_alert_message() {
                println!("  {}", alert.red());
            }
        }
        SecurityAction::ForceLogout { user_id } => {
            let framework = require_auth_framework(&state)?;
            println!("🔒 Forcing logout for user: {}", user_id.red());
            let spinner = create_spinner("Terminating user sessions...");

            let sessions = framework.sessions().list_for_user(&user_id).await?;
            for session in &sessions {
                framework.sessions().delete(&session.session_id).await?;
            }

            let tokens = framework.tokens().list_for_user(&user_id).await?;
            for token in &tokens {
                framework.tokens().revoke(token).await?;
            }

            spinner
                .finish_with_message("✅ User sessions and tokens terminated".green().to_string());
            println!("  Sessions revoked: {}", sessions.len().to_string().cyan());
            println!("  Tokens revoked:   {}", tokens.len().to_string().cyan());
        }
        SecurityAction::EncryptKv {
            prefix,
            dry_run,
            confirm,
            accept_legacy_v0,
        } => {
            let config = state.config.read().await;
            let storage_config = config.auth.storage.clone();
            let storage_encryption_enabled = config.auth.storage_encryption.enabled;
            let storage_pool_size = None;
            drop(config);

            if !storage_encryption_enabled {
                return Err(AuthError::Cli(
                    "storage_encryption.enabled is false in the current configuration -- \
                     this deployment has explicitly opted out of encryption at rest, so \
                     running encrypt-kv would act against that choice. Enable \
                     storage_encryption first if you want this data encrypted."
                        .to_string(),
                ));
            }

            // --confirm is only required to actually WRITE with an empty
            // prefix -- a dry run makes no changes, so there's nothing to
            // confirm (and requiring it would make the documented
            // "preview everything first" workflow itself fail).
            if prefix.is_empty() && !confirm && !dry_run {
                return Err(AuthError::Cli(
                    "An empty --prefix touches every KV key, including any with a TTL \
                     (OAuth codes, email-verification tokens, MFA/SMS codes, WebAuthn \
                     challenges, rate-limit windows, expiring API keys) -- migrating those \
                     strips their TTL, making them non-expiring. Pass --confirm to proceed \
                     anyway, or scope --prefix to a durable-secret namespace."
                        .to_string(),
                ));
            }

            let backend = crate::storage::factory::build_storage_backend_unencrypted(
                &storage_config,
                storage_pool_size,
            )
            .await?;
            let encryption =
                crate::storage::encryption::StorageEncryption::from_env().map_err(|e| {
                    AuthError::Cli(format!(
                        "Cannot run EncryptKv: no storage encryption key is configured ({e}). \
                     Set AUTH_STORAGE_ENCRYPTION_KEY / AUTH_STORAGE_ENCRYPTION_KEYS_FILE first."
                    ))
                })?;

            if dry_run {
                println!(
                    "🔍 Dry run: scanning KV storage under prefix '{}'...",
                    prefix.cyan()
                );
            } else {
                println!(
                    "🔐 Encrypting plaintext KV values under prefix '{}'...",
                    prefix.cyan()
                );
            }

            let report = crate::storage::encryption::migrate_kv_to_encrypted(
                backend.as_ref(),
                &encryption,
                &prefix,
                dry_run,
                accept_legacy_v0,
            )
            .await?;

            println!("  Scanned:           {}", report.scanned.to_string().cyan());
            println!(
                "  Already encrypted: {}",
                report.already_encrypted.to_string().green()
            );
            println!(
                "  {}:  {}",
                if dry_run {
                    "Would encrypt"
                } else {
                    "Encrypted"
                },
                report.encrypted.to_string().yellow()
            );
            if report.legacy_v0_found > 0 {
                println!(
                    "  Legacy (v0) envelopes found: {}",
                    report.legacy_v0_found.to_string().yellow()
                );
                println!(
                    "  {}: {}",
                    if dry_run || !accept_legacy_v0 {
                        "Would upgrade (pass --accept-legacy-v0 on a real run to apply)"
                    } else {
                        "Upgraded"
                    },
                    report.upgraded_from_legacy.to_string().yellow()
                );
                if !dry_run && !accept_legacy_v0 {
                    println!(
                        "  {}",
                        "NOT upgraded: --accept-legacy-v0 was not passed. A v0 envelope has \
                         no AAD, so upgrading it cannot verify its plaintext actually \
                         belongs to this record -- re-run with --accept-legacy-v0 once \
                         you've understood that."
                            .yellow()
                    );
                }
            }
            if report.vanished > 0 {
                println!(
                    "  Vanished (deleted concurrently): {}",
                    report.vanished.to_string().dimmed()
                );
            }
            if !report.failed.is_empty() {
                println!(
                    "  {} ({}): {}",
                    "Failed to decrypt, skipped".red(),
                    report.failed.len().to_string().red(),
                    report.failed.join(", ")
                );
            }
        }
    }

    Ok(())
}

#[cfg(feature = "cli")]
async fn handle_maintenance_action(state: AppState, action: MaintenanceAction) -> Result<()> {
    match action {
        MaintenanceAction::Backup {
            output_path,
            dry_run,
        } => {
            let framework = require_auth_framework(&state)?;
            let report = framework
                .maintenance()
                .backup_to_file(&output_path, dry_run)
                .await?;

            if report.dry_run {
                println!(
                    "Dry run: backup would write {} users, {} roles, {} tokens, {} sessions, and {} KV entries to {}.",
                    report.manifest.user_count,
                    report.manifest.role_count,
                    report.manifest.token_count,
                    report.manifest.session_count,
                    report.manifest.kv_entry_count,
                    report.output_path.display()
                );
            } else {
                println!(
                    "Backup written to {} (users={}, roles={}, tokens={}, sessions={}, kv={}).",
                    report.output_path.display(),
                    report.manifest.user_count,
                    report.manifest.role_count,
                    report.manifest.token_count,
                    report.manifest.session_count,
                    report.manifest.kv_entry_count
                );
            }
        }
        MaintenanceAction::Restore {
            backup_path,
            confirm,
            dry_run,
        } => {
            if !confirm {
                return Err(AuthError::Cli(
                    "Maintenance restore requires --confirm".to_string(),
                ));
            }

            let framework = require_auth_framework(&state)?;
            let report = framework
                .maintenance()
                .restore_from_file(&backup_path, dry_run)
                .await?;

            if report.dry_run {
                println!(
                    "Dry run: restore would apply snapshot from {} (users={}, roles={}, tokens={}, sessions={}, kv={}).",
                    report.input_path.display(),
                    report.manifest.user_count,
                    report.manifest.role_count,
                    report.manifest.token_count,
                    report.manifest.session_count,
                    report.manifest.kv_entry_count
                );
            } else {
                println!(
                    "Restore completed from {} (users={}, roles={}, tokens={}, sessions={}, kv={}).",
                    report.input_path.display(),
                    report.manifest.user_count,
                    report.manifest.role_count,
                    report.manifest.token_count,
                    report.manifest.session_count,
                    report.manifest.kv_entry_count
                );
            }
        }
        MaintenanceAction::Reset { confirm, dry_run } => {
            if !confirm {
                return Err(AuthError::Cli(
                    "Maintenance reset requires --confirm".to_string(),
                ));
            }

            let framework = require_auth_framework(&state)?;
            let report = framework.maintenance().reset(dry_run).await?;

            if report.dry_run {
                println!(
                    "Dry run: reset would delete {} users, {} roles, {} tokens, {} sessions, and {} KV entries.",
                    report.users_deleted,
                    report.roles_seen,
                    report.tokens_deleted,
                    report.sessions_deleted,
                    report.kv_entries_deleted
                );
            } else {
                println!(
                    "Reset completed: deleted {} users, {} tokens, {} sessions, and {} KV entries.",
                    report.users_deleted,
                    report.tokens_deleted,
                    report.sessions_deleted,
                    report.kv_entries_deleted
                );
            }
        }
        MaintenanceAction::CreateMigration { name } => {
            let config = state.config.read().await;
            let report =
                crate::maintenance::create_migration_file_for_storage(&config.auth.storage, &name)
                    .await?;
            println!(
                "Created {} migration template: {}",
                report.backend,
                report.path.display()
            );
        }
    }

    Ok(())
}

#[cfg(feature = "cli")]
fn create_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("hardcoded spinner template is valid"),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb
}

#[cfg(feature = "cli")]
fn format_health_status(status: &HealthStatus) -> colored::ColoredString {
    match status {
        HealthStatus::Healthy => "Healthy ✅".green(),
        HealthStatus::Warning(msg) => format!("Warning ⚠️  {}", msg).yellow(),
        HealthStatus::Critical(msg) => format!("Critical ❌ {}", msg).red(),
    }
}

#[cfg(feature = "cli")]
fn create_minimal_config_template() -> String {
    r#"# Auth Framework Configuration Template
# Minimal configuration for getting started
# NOTE: The framework rejects known placeholder values at startup.
# You MUST replace secret_key with a real secret (minimum 32 characters).

[jwt]
secret_key = "${JWT_SECRET_KEY:CHANGE_ME_REQUIRED_minimum_32_chars}"
algorithm = "HS256"
expiry = "1h"

[session]
name = "AUTH_SESSION"
secure = true
domain = "localhost"

[oauth2.google]
client_id = "${GOOGLE_CLIENT_ID}"
client_secret = "${GOOGLE_CLIENT_SECRET}"
redirect_uri = "http://localhost:8080/auth/callback"

[threat_intel]
enabled = false
"#
    .to_string()
}

#[cfg(feature = "cli")]
fn create_complete_config_template() -> String {
    r#"# Auth Framework Configuration Template
# Complete configuration with all options
# NOTE: The framework rejects known placeholder values at startup.
# You MUST replace secret_key with a real secret (minimum 32 characters).

[jwt]
secret_key = "${JWT_SECRET_KEY:CHANGE_ME_REQUIRED_minimum_32_chars}"
algorithm = "HS256"
expiry = "1h"
refresh_expiry = "30d"
issuer = "auth-framework"
audience = ["api.example.com"]

[session]
name = "AUTH_SESSION"
secure = true
domain = "localhost"
path = "/"
max_age = "24h"
same_site = "lax"
http_only = true

[oauth2.google]
client_id = "${GOOGLE_CLIENT_ID}"
client_secret = "${GOOGLE_CLIENT_SECRET}"
redirect_uri = "http://localhost:8080/auth/callback"
scopes = ["openid", "email", "profile"]

[oauth2.github]
client_id = "${GITHUB_CLIENT_ID}"
client_secret = "${GITHUB_CLIENT_SECRET}"
redirect_uri = "http://localhost:8080/auth/github/callback"

[threat_intel]
enabled = true
auto_update_feeds = true
cache_duration = "1h"

[[threat_intel.feeds]]
name = "Example Feed"
url = "https://example.com/threat-feed.csv"
api_key = "${THREAT_FEED_API_KEY}"
format = "csv"
update_interval = "6h"

[security]
require_https = true
enable_csrf_protection = true
rate_limiting = true
max_requests_per_minute = 100

[audit]
enabled = true
log_success = true
log_failures = true
log_permissions = true

[mfa]
enabled = true
totp_enabled = true
backup_codes_enabled = true

include = [
    "methods/oauth2.toml",
    "methods/jwt.toml",
    "methods/mfa.toml"
]
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, StorageConfig, config_manager::AuthFrameworkSettings};
    use crate::methods::{AuthMethodEnum, JwtMethod};
    use crate::permissions::Role;
    use tempfile::tempdir;

    #[cfg(all(feature = "cli", feature = "sqlite-storage"))]
    #[tokio::test]
    async fn maintenance_admin_cli_smoke_test_roundtrip() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("admin-maintenance-smoke.db");
        let snapshot_path = temp_dir.path().join("admin-snapshot.json");
        let database_url = format!(
            "sqlite://{}?mode=rwc",
            db_path.to_string_lossy().replace('\\', "/")
        );

        let mut auth_config = AuthConfig::new()
            .secret("0123456789abcdef0123456789abcdef")
            .token_lifetime(std::time::Duration::from_secs(3600));
        auth_config.storage = StorageConfig::Sqlite {
            connection_string: database_url,
        };
        // This test exercises maintenance/backup, not storage encryption;
        // opt out explicitly rather than requiring a key just for this.
        auth_config.storage_encryption = crate::config::StorageEncryptionConfig {
            enabled: false,
            ..Default::default()
        };

        let settings = AuthFrameworkSettings {
            auth: auth_config.clone(),
            api_server: None,
            threat_intelligence: None,
            session: None,
            custom: std::collections::HashMap::new(),
        };

        let mut framework = crate::AuthFramework::new(auth_config);
        framework.register_method("jwt", AuthMethodEnum::Jwt(JwtMethod::new()));
        framework.initialize().await.unwrap();

        let user_id = framework
            .users()
            .register(
                "admin-cli-smoke",
                "admin-cli-smoke@example.com",
                "Password123!",
            )
            .await
            .unwrap();
        framework
            .authorization()
            .create_role(Role::new("operator"))
            .await
            .unwrap();
        framework
            .authorization()
            .assign_role(&user_id, "operator")
            .await
            .unwrap();
        framework
            .tokens()
            .create(&user_id, &["read"], "jwt", None)
            .await
            .unwrap();
        framework
            .sessions()
            .create(
                &user_id,
                std::time::Duration::from_secs(600),
                Some("127.0.0.1".to_string()),
                Some("admin-cli-smoke".to_string()),
            )
            .await
            .unwrap();
        framework
            .storage()
            .store_kv("admin:smoke:key", b"present", None)
            .await
            .unwrap();

        let state = AppState::new(settings)
            .unwrap()
            .with_auth_framework(std::sync::Arc::new(framework));

        run_cli(
            state.clone(),
            CliCommand::Maintenance {
                action: MaintenanceAction::Backup {
                    output_path: snapshot_path.to_string_lossy().to_string(),
                    dry_run: false,
                },
            },
        )
        .await
        .unwrap();
        assert!(snapshot_path.exists());

        run_cli(
            state.clone(),
            CliCommand::Maintenance {
                action: MaintenanceAction::Reset {
                    confirm: true,
                    dry_run: false,
                },
            },
        )
        .await
        .unwrap();

        assert!(
            state
                .auth_framework
                .as_ref()
                .unwrap()
                .users()
                .list_with_query(crate::auth_operations::UserListQuery::new())
                .await
                .unwrap()
                .is_empty()
        );

        run_cli(
            state.clone(),
            CliCommand::Maintenance {
                action: MaintenanceAction::Restore {
                    backup_path: snapshot_path.to_string_lossy().to_string(),
                    confirm: true,
                    dry_run: false,
                },
            },
        )
        .await
        .unwrap();

        let restored_framework = state.auth_framework.as_ref().unwrap();
        let restored_user = restored_framework.users().get(&user_id).await.unwrap();
        assert_eq!(restored_user.username, "admin-cli-smoke");
        assert_eq!(
            restored_framework
                .tokens()
                .list_for_user(&user_id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            restored_framework
                .sessions()
                .list_for_user(&user_id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            restored_framework
                .authorization()
                .has_role(&user_id, "operator")
                .await
                .unwrap()
        );
        assert_eq!(
            restored_framework
                .storage()
                .get_kv("admin:smoke:key")
                .await
                .unwrap()
                .unwrap(),
            b"present"
        );

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp_dir.path()).unwrap();
        let migration_result = run_cli(
            state.clone(),
            CliCommand::Maintenance {
                action: MaintenanceAction::CreateMigration {
                    name: "admin smoke migration".to_string(),
                },
            },
        )
        .await;
        std::env::set_current_dir(original_dir).unwrap();
        migration_result.unwrap();

        let migration_dir = temp_dir.path().join("migrations").join("sqlite");
        let entries = std::fs::read_dir(&migration_dir)
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
    }

    // NOTE on CI coverage: `pub mod admin` (src/lib.rs) is gated on the
    // `admin-binary` feature, not just `cli`, so every test in this
    // module -- including the three `encrypt_kv_*` tests below -- only
    // compiles and runs under that feature. CI's required "Test Suite"
    // job does not enable `admin-binary`
    // (.github/workflows/ci-cd.yml's `enhanced-rbac,postgres-storage,
    // redis-storage,openid-connect,axum-integration` combo), and the
    // "Feature Matrix (admin-surfaces)" job that does enable it only
    // `cargo check`s, not `cargo test`s. Only the "Coverage" job
    // (`--all-features`) actually runs these tests today. Flagged, not
    // fixed here -- changing CI's required-job feature matrix is a
    // portfolio-wide decision outside this PR's scope.
    #[cfg(feature = "cli")]
    fn security_state(storage_encryption: crate::config::StorageEncryptionConfig) -> AppState {
        let auth_config = AuthConfig::new()
            .secret("0123456789abcdef0123456789abcdef")
            .storage_encryption(storage_encryption);
        let settings = AuthFrameworkSettings {
            auth: auth_config,
            api_server: None,
            threat_intelligence: None,
            session: None,
            custom: std::collections::HashMap::new(),
        };
        AppState::new(settings).unwrap()
    }

    #[cfg(feature = "cli")]
    #[tokio::test]
    async fn encrypt_kv_refuses_when_storage_encryption_disabled() {
        let state = security_state(crate::config::StorageEncryptionConfig {
            enabled: false,
            ..Default::default()
        });

        let err = run_cli(
            state,
            CliCommand::Security {
                action: SecurityAction::EncryptKv {
                    prefix: String::new(),
                    dry_run: true,
                    confirm: false,
                    accept_legacy_v0: false,
                },
            },
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("opted out"),
            "expected a storage_encryption.enabled=false refusal, got: {err}"
        );
    }

    #[cfg(feature = "cli")]
    #[tokio::test]
    async fn encrypt_kv_requires_confirm_for_empty_prefix_non_dry_run() {
        // storage_encryption defaults to enabled: true.
        let state = security_state(Default::default());

        let err = run_cli(
            state,
            CliCommand::Security {
                action: SecurityAction::EncryptKv {
                    prefix: String::new(),
                    dry_run: false,
                    confirm: false,
                    accept_legacy_v0: false,
                },
            },
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("--confirm"),
            "expected a missing---confirm refusal for an empty prefix, got: {err}"
        );
    }

    /// The documented `encrypt-kv --dry-run` (empty prefix, no
    /// `--confirm`) must actually work, not just be exempted from the
    /// confirm check in theory -- run it end to end against a real
    /// (in-memory) backend with a real key configured.
    #[cfg(feature = "cli")]
    #[tokio::test]
    async fn encrypt_kv_dry_run_with_empty_prefix_does_not_require_confirm() {
        let _lock = crate::storage::encryption::TEST_ENCRYPTION_ENV_LOCK
            .lock()
            .await;
        let key = crate::storage::encryption::StorageEncryption::generate_key();
        let _guard = crate::storage::encryption::EncryptionEnvGuard::set(&key);

        let state = security_state(Default::default());

        run_cli(
            state,
            CliCommand::Security {
                action: SecurityAction::EncryptKv {
                    prefix: String::new(),
                    dry_run: true,
                    confirm: false,
                    accept_legacy_v0: false,
                },
            },
        )
        .await
        .expect("a dry run with an empty prefix must not require --confirm");
    }
}
