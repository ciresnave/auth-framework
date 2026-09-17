/// Minimal CLI progress bar using terminal output.
/// For richer progress bars, consider the `indicatif` crate.
///
/// The CLI delegates database migrations to `MigrationCli` and uses the core
/// `AuthFramework` APIs for user, role, status, health, audit, and session management.
/// Destructive database maintenance flows are implemented as logical snapshot
/// export/import operations backed by the maintenance module.
pub struct CliProgressBar {}

impl CliProgressBar {
    pub fn new(msg: &str) -> Self {
        // Example: print message for progress bar init
        println!("[ProgressBar] Starting: {}", msg);
        Self {}
    }
    pub fn set_progress(&self, percent: u64) {
        // Example: print progress update
        println!("[ProgressBar] Progress: {}%", percent);
    }
    pub fn finish(&self) {
        // Example: print finish message
        println!("[ProgressBar] Finished");
    }
}

pub fn format_cli_output(msg: &str) -> String {
    // Example: blue bold formatting
    format!("\x1b[1;34m[auth-framework]\x1b[0m {}", msg)
}
#[cfg(feature = "cli")]
use crate::AppConfig;
#[cfg(feature = "cli")]
use crate::auth_operations::UserListQuery;
#[cfg(feature = "cli")]
use crate::migrations::MigrationCli;
#[cfg(feature = "cli")]
use crate::permissions::{Permission, Role};
#[cfg(feature = "cli")]
use clap::{Parser, Subcommand};
#[cfg(feature = "cli")]
use std::{io, process};

#[cfg(feature = "cli")]
#[derive(Parser)]
#[command(name = "auth-framework")]
#[command(about = "Auth Framework CLI - Manage authentication and authorization")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(short, long, default_value = "auth.toml")]
    pub config: String,

    #[arg(long)]
    pub verbose: bool,

    #[arg(short, long)]
    pub dry_run: bool,
}

#[cfg(feature = "cli")]
#[derive(Subcommand)]
pub enum Commands {
    /// Database operations
    Db {
        #[command(subcommand)]
        command: DbCommands,
    },
    /// User management
    User {
        #[command(subcommand)]
        command: UserCommands,
    },
    /// Role and permission management
    Role {
        #[command(subcommand)]
        command: RoleCommands,
    },
    /// System administration
    System {
        #[command(subcommand)]
        command: SystemCommands,
    },
    /// Security operations
    Security {
        #[command(subcommand)]
        command: SecurityCommands,
    },
}

#[cfg(feature = "cli")]
#[derive(Subcommand)]
pub enum DbCommands {
    /// Run database migrations
    Migrate,
    /// Show migration status
    Status,
    /// Reset database (WARNING: destructive)
    Reset {
        #[arg(long)]
        confirm: bool,
    },
    /// Create a new migration file
    CreateMigration { name: String },
}

#[cfg(feature = "cli")]
#[derive(Subcommand)]
pub enum UserCommands {
    /// List users
    List {
        #[arg(short, long)]
        limit: Option<usize>,
        #[arg(short, long)]
        offset: Option<usize>,
        #[arg(long)]
        active_only: bool,
    },
    /// Create a new user
    Create {
        email: String,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        admin: bool,
    },
    /// Update user
    Update {
        user_id: String,
        #[arg(short, long)]
        email: Option<String>,
        #[arg(short, long)]
        active: Option<bool>,
    },
    /// Delete user
    Delete {
        user_id: String,
        #[arg(long)]
        confirm: bool,
    },
    /// Reset user password
    ResetPassword {
        user_id: String,
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Show user details
    Show { user_id: String },
}

#[cfg(feature = "cli")]
#[derive(Subcommand)]
pub enum RoleCommands {
    /// List roles
    List,
    /// Create role
    Create {
        name: String,
        #[arg(short, long)]
        description: Option<String>,
    },
    /// Assign role to user
    Assign { user_id: String, role_name: String },
    /// Remove role from user
    Remove { user_id: String, role_name: String },
    /// List permissions for role
    Permissions { role_name: String },
    /// Add permission to role
    AddPermission {
        role_name: String,
        permission: String,
    },
}

#[cfg(feature = "cli")]
#[derive(Subcommand)]
pub enum SystemCommands {
    /// Show system status
    Status,
    /// Health check
    Health,
    /// Generate configuration template
    Config {
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Backup system data
    Backup { output_path: String },
    /// Restore system data
    Restore {
        backup_path: String,
        #[arg(long)]
        confirm: bool,
    },
}

#[cfg(feature = "cli")]
#[derive(Subcommand)]
pub enum SecurityCommands {
    /// Show security audit
    Audit {
        #[arg(short, long)]
        days: Option<u32>,
    },
    /// List active sessions
    Sessions {
        #[arg(short, long)]
        user_id: Option<String>,
    },
    /// Terminate session
    TerminateSession {
        session_id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Lock user account
    LockUser {
        user_id: String,
        #[arg(short, long)]
        reason: Option<String>,
    },
    /// Unlock user account
    UnlockUser { user_id: String },
}

#[cfg(feature = "cli")]
pub struct CliHandler {
    config: AppConfig,
    dry_run: bool,
    // storage: Option<PostgresStorage>, // Removed unused field
}

#[cfg(feature = "cli")]
impl CliHandler {
    pub async fn new(config: AppConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Removed unused storage variable
        Ok(Self {
            config,
            dry_run: false,
        })
    }

    async fn framework(&self) -> Result<crate::AuthFramework, Box<dyn std::error::Error>> {
        Ok(self.config.build_auth_framework().await?)
    }

    fn prompt_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
        let password = rpassword::prompt_password(prompt)?;
        if password.is_empty() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "Password cannot be empty").into(),
            );
        }
        Ok(password)
    }

    fn default_username_from_email(email: &str) -> String {
        email
            .split('@')
            .next()
            .filter(|value| !value.is_empty())
            .unwrap_or("user")
            .to_string()
    }

    fn print_user_summary(user: &crate::auth::UserInfo) {
        let roles = if user.roles.is_empty() {
            "-".to_string()
        } else {
            user.roles.join(", ")
        };
        let email = user.email.as_deref().unwrap_or("-");
        println!(
            "{}\t{}\t{}\tactive={}\troles={}",
            user.id, user.username, email, user.active, roles
        );
    }

    fn print_role_permissions(role: &Role) {
        let mut permissions: Vec<String> =
            role.permissions.iter().map(ToString::to_string).collect();
        permissions.sort();

        println!("Role: {}", role.name);
        if let Some(description) = &role.description {
            println!("Description: {}", description);
        }
        println!("Active: {}", role.active);
        println!("Permissions:");
        if permissions.is_empty() {
            println!("  (none)");
        } else {
            for permission in permissions {
                println!("  {}", permission);
            }
        }
    }

    pub async fn handle_command(&mut self, cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
        self.dry_run = cli.dry_run;
        match cli.command {
            Some(Commands::Db { command }) => self.handle_db_command(command).await?,
            Some(Commands::User { command }) => self.handle_user_command(command).await?,
            Some(Commands::Role { command }) => self.handle_role_command(command).await?,
            Some(Commands::System { command }) => self.handle_system_command(command).await?,
            Some(Commands::Security { command }) => self.handle_security_command(command).await?,
            None => {
                eprintln!("No command provided. Use --help for usage.");
            }
        }
        Ok(())
    }

    async fn handle_db_command(
        &mut self,
        command: DbCommands,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match command {
            DbCommands::Migrate => {
                println!("Running database migrations...");
                MigrationCli::run(&self.config.database.url, "migrate").await?;
            }
            DbCommands::Status => {
                MigrationCli::run(&self.config.database.url, "status").await?;
            }
            DbCommands::Reset { confirm } => {
                if !confirm {
                    eprintln!("ERROR: Database reset requires --confirm flag");
                    eprintln!("WARNING: This will destroy all data!");
                    process::exit(1);
                }
                let framework = self.framework().await?;
                let report = framework.maintenance().reset(self.dry_run).await?;
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
            DbCommands::CreateMigration { name } => {
                let report = crate::maintenance::create_migration_file(&self.config, &name).await?;
                println!(
                    "Created {} migration template: {}",
                    report.backend,
                    report.path.display()
                );
            }
        }
        Ok(())
    }

    async fn handle_user_command(
        &mut self,
        command: UserCommands,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match command {
            UserCommands::List {
                limit,
                offset,
                active_only,
            } => {
                let framework = self.framework().await?;
                let mut query = UserListQuery::new();
                if let Some(l) = limit {
                    query = query.limit(l);
                }
                if let Some(o) = offset {
                    query = query.offset(o);
                }
                if active_only {
                    query = query.active_only();
                }
                let users = framework.users().list_with_query(query).await?;
                if users.is_empty() {
                    println!("No users found.");
                } else {
                    for user in users {
                        Self::print_user_summary(&user);
                    }
                }
            }
            UserCommands::Create {
                email,
                username,
                password,
                admin,
            } => {
                let framework = self.framework().await?;
                let username =
                    username.unwrap_or_else(|| Self::default_username_from_email(&email));
                let password = match password {
                    Some(password) => password,
                    None => Self::prompt_password("Password: ")?,
                };
                let user_id = framework
                    .users()
                    .register(&username, &email, &password)
                    .await?;
                if admin {
                    framework
                        .authorization()
                        .assign_role(&user_id, "admin")
                        .await?;
                }
                println!("Created user '{}' with ID {}", username, user_id);
            }
            UserCommands::Show { user_id } => {
                let framework = self.framework().await?;
                let user = framework.users().get(&user_id).await?;
                Self::print_user_summary(&user);
            }
            UserCommands::Update {
                user_id,
                email,
                active,
            } => {
                if email.is_none() && active.is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Provide --email and/or --active when updating a user",
                    )
                    .into());
                }

                let framework = self.framework().await?;
                if let Some(email) = email {
                    framework.users().update_email(&user_id, &email).await?;
                }
                if let Some(active) = active {
                    framework
                        .users()
                        .set_status(&user_id, active.into())
                        .await?;
                }
                println!("Updated user {}", user_id);
            }
            UserCommands::Delete { user_id, confirm } => {
                if !confirm {
                    eprintln!("ERROR: User deletion requires --confirm flag");
                    eprintln!("WARNING: This will permanently delete the user!");
                    process::exit(1);
                }
                let framework = self.framework().await?;
                framework.users().delete_by_id(&user_id).await?;
                println!("Deleted user {}", user_id);
            }
            UserCommands::ResetPassword { user_id, password } => {
                let framework = self.framework().await?;
                let password = match password {
                    Some(password) => password,
                    None => Self::prompt_password("New password: ")?,
                };
                framework
                    .users()
                    .update_password_by_id(&user_id, &password)
                    .await?;
                println!("Password updated for user {}", user_id);
            }
        }

        Ok(())
    }

    async fn handle_role_command(
        &mut self,
        command: RoleCommands,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match command {
            RoleCommands::List => {
                let framework = self.framework().await?;
                let mut roles = framework.authorization().list_roles().await;
                roles.sort_by(|left, right| left.name.cmp(&right.name));
                if roles.is_empty() {
                    println!("No roles found.");
                } else {
                    for role in roles {
                        println!(
                            "{}\tactive={}\tpermissions={}",
                            role.name,
                            role.active,
                            role.permissions.len()
                        );
                    }
                }
            }
            RoleCommands::AddPermission {
                role_name,
                permission,
            } => {
                let framework = self.framework().await?;
                let permission = Permission::parse(&permission)?;
                framework
                    .authorization()
                    .add_role_permission(&role_name, permission)
                    .await?;
                println!("Added permission to role {}", role_name);
            }
            RoleCommands::Create { name, description } => {
                let framework = self.framework().await?;
                let role = match description {
                    Some(description) => Role::new(&name).with_description(description),
                    None => Role::new(&name),
                };
                framework.authorization().create_role(role).await?;
                println!("Created role {}", name);
            }
            RoleCommands::Assign { user_id, role_name } => {
                let framework = self.framework().await?;
                framework
                    .authorization()
                    .assign_role(&user_id, &role_name)
                    .await?;
                println!("Assigned role {} to {}", role_name, user_id);
            }
            RoleCommands::Remove { user_id, role_name } => {
                let framework = self.framework().await?;
                framework
                    .authorization()
                    .remove_role(&user_id, &role_name)
                    .await?;
                println!("Removed role {} from {}", role_name, user_id);
            }
            RoleCommands::Permissions { role_name } => {
                let framework = self.framework().await?;
                let role = framework.authorization().role(&role_name).await?;
                Self::print_role_permissions(&role);
            }
        }

        Ok(())
    }

    async fn handle_system_command(
        &mut self,
        command: SystemCommands,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match command {
            SystemCommands::Status => {
                let framework = self.framework().await?;
                let stats = framework.monitoring().stats().await?;
                let audit = framework.audit().security_stats().await?;
                println!(
                    "Registered methods: {}",
                    stats.registered_methods.join(", ")
                );
                println!("Active sessions: {}", stats.active_sessions);
                println!("Active MFA challenges: {}", stats.active_mfa_challenges);
                println!("Authentication attempts: {}", stats.auth_attempts);
                println!("Security score: {:.2}", audit.security_score());
            }
            SystemCommands::Health => {
                let framework = self.framework().await?;
                let health = framework.monitoring().health_check().await?;
                for (component, result) in health {
                    println!(
                        "{}\t{:?}\t{}\t{}ms",
                        component, result.status, result.message, result.response_time
                    );
                }
            }
            SystemCommands::Config { output } => {
                let template = include_str!("../config/auth.toml.template");
                if let Some(path) = output {
                    std::fs::write(&path, template)?;
                    println!("Configuration template written to: {}", path);
                } else {
                    println!("{}", template);
                }
            }
            SystemCommands::Backup { output_path } => {
                let framework = self.framework().await?;
                let report = framework
                    .maintenance()
                    .backup_to_file(&output_path, self.dry_run)
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
            SystemCommands::Restore {
                backup_path,
                confirm,
            } => {
                if !confirm {
                    eprintln!("ERROR: Database restore requires --confirm flag");
                    eprintln!("WARNING: This will overwrite existing data!");
                    process::exit(1);
                }
                let framework = self.framework().await?;
                let report = framework
                    .maintenance()
                    .restore_from_file(&backup_path, self.dry_run)
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
        }
        Ok(())
    }

    async fn handle_security_command(
        &mut self,
        command: SecurityCommands,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match command {
            SecurityCommands::Audit { days } => {
                let framework = self.framework().await?;
                let stats = framework.audit().security_stats().await?;
                let logs = framework
                    .audit()
                    .permission_logs(None, None, None, Some(20))
                    .await?;
                println!(
                    "Security audit summary for the last {} day(s):",
                    days.unwrap_or(1)
                );
                println!("  active_sessions={}", stats.active_sessions);
                println!("  failed_logins_24h={}", stats.failed_logins_24h);
                println!("  successful_logins_24h={}", stats.successful_logins_24h);
                println!("  security_alerts_24h={}", stats.security_alerts_24h);
                if logs.is_empty() {
                    println!("Recent permission audit logs: none");
                } else {
                    println!("Recent permission audit logs:");
                    for log in logs {
                        println!("  {}", log);
                    }
                }
            }
            SecurityCommands::Sessions { user_id } => {
                let framework = self.framework().await?;
                if let Some(user_id) = user_id {
                    let sessions = framework.sessions().list_for_user(&user_id).await?;
                    if sessions.is_empty() {
                        println!("No sessions found for user {}", user_id);
                    } else {
                        for session in sessions {
                            println!(
                                "{}\tuser={}\texpires={}\tip={}",
                                session.session_id,
                                session.user_id,
                                session.expires_at,
                                session.ip_address.as_deref().unwrap_or("-")
                            );
                        }
                    }
                } else {
                    let users = framework
                        .users()
                        .list_with_query(UserListQuery::new())
                        .await?;
                    let mut found_any = false;
                    for user in users {
                        let sessions = framework.sessions().list_for_user(&user.id).await?;
                        for session in sessions {
                            found_any = true;
                            println!(
                                "{}\tuser={}\texpires={}\tip={}",
                                session.session_id,
                                session.user_id,
                                session.expires_at,
                                session.ip_address.as_deref().unwrap_or("-")
                            );
                        }
                    }
                    if !found_any {
                        println!("No active sessions found.");
                    }
                }
            }
            SecurityCommands::LockUser { user_id, reason } => {
                let framework = self.framework().await?;
                framework
                    .users()
                    .set_status(&user_id, crate::auth_operations::UserStatus::Inactive)
                    .await?;
                if let Some(reason) = reason {
                    println!("Locked user {}: {}", user_id, reason);
                } else {
                    println!("Locked user {}", user_id);
                }
            }
            SecurityCommands::TerminateSession { session_id, reason } => {
                let framework = self.framework().await?;
                framework.sessions().delete(&session_id).await?;
                if let Some(reason) = reason {
                    println!("Terminated session {}: {}", session_id, reason);
                } else {
                    println!("Terminated session {}", session_id);
                }
            }
            SecurityCommands::UnlockUser { user_id } => {
                let framework = self.framework().await?;
                framework
                    .users()
                    .set_status(&user_id, crate::auth_operations::UserStatus::Active)
                    .await?;
                println!("Unlocked user {}", user_id);
            }
        }

        Ok(())
    }
}

#[cfg(feature = "cli")]
/// Entry point for the CLI application
pub async fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Load configuration
    let config = AppConfig::from_env()?;

    // Initialize handler and run command
    let mut handler = CliHandler::new(config).await?;
    handler.handle_command(cli).await?;

    Ok(())
}

// Place tests at the end of the file to avoid clippy warning
#[cfg(all(test, feature = "cli"))]
mod tests {
    use super::{
        Cli, CliHandler, CliProgressBar, Commands, DbCommands, SystemCommands, format_cli_output,
    };
    use crate::auth_operations::UserListQuery;
    use crate::config::app_config::AppConfig;
    use crate::methods::{AuthMethodEnum, JwtMethod};
    use crate::permissions::Role;
    use tempfile::tempdir;

    #[test]
    fn test_progress_bar() {
        let pb = CliProgressBar::new("Test");
        pb.set_progress(50);
        pb.finish();
    }
    #[test]
    fn test_terminal_formatting() {
        let msg = format_cli_output("Hello");
        assert!(msg.contains("[auth-framework]"));
    }

    #[cfg(all(feature = "cli", feature = "sqlite-storage"))]
    #[tokio::test]
    async fn maintenance_cli_smoke_test_roundtrip() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("maintenance-smoke.db");
        let snapshot_path = temp_dir.path().join("snapshot.json");

        let database_url = format!(
            "sqlite://{}?mode=rwc",
            db_path.to_string_lossy().replace('\\', "/")
        );

        let mut config = AppConfig::default();
        config.database.url = database_url;

        let mut seed_framework = config.build_auth_framework().await.unwrap();
        seed_framework.register_method("jwt", AuthMethodEnum::Jwt(JwtMethod::new()));

        let user_id = seed_framework
            .users()
            .register("cli-smoke", "cli-smoke@example.com", "Password123!")
            .await
            .unwrap();
        seed_framework
            .authorization()
            .create_role(Role::new("operator"))
            .await
            .unwrap();
        seed_framework
            .authorization()
            .assign_role(&user_id, "operator")
            .await
            .unwrap();
        seed_framework
            .tokens()
            .create(&user_id, &["read"], "jwt", None)
            .await
            .unwrap();
        seed_framework
            .sessions()
            .create(
                &user_id,
                std::time::Duration::from_secs(600),
                Some("127.0.0.1".to_string()),
                Some("cli-smoke".to_string()),
            )
            .await
            .unwrap();
        seed_framework
            .storage()
            .store_kv("smoke:key", b"present", None)
            .await
            .unwrap();
        drop(seed_framework);

        let mut handler = CliHandler::new(config.clone()).await.unwrap();
        handler
            .handle_command(Cli {
                command: Some(Commands::System {
                    command: SystemCommands::Backup {
                        output_path: snapshot_path.to_string_lossy().to_string(),
                    },
                }),
                config: "auth.toml".to_string(),
                verbose: false,
                dry_run: false,
            })
            .await
            .unwrap();
        assert!(snapshot_path.exists());

        handler
            .handle_command(Cli {
                command: Some(Commands::Db {
                    command: DbCommands::Reset { confirm: true },
                }),
                config: "auth.toml".to_string(),
                verbose: false,
                dry_run: false,
            })
            .await
            .unwrap();

        let reset_framework = config.build_auth_framework().await.unwrap();
        assert!(
            reset_framework
                .users()
                .list_with_query(UserListQuery::new())
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            reset_framework
                .storage()
                .get_kv("smoke:key")
                .await
                .unwrap()
                .is_none()
        );
        drop(reset_framework);

        handler
            .handle_command(Cli {
                command: Some(Commands::System {
                    command: SystemCommands::Restore {
                        backup_path: snapshot_path.to_string_lossy().to_string(),
                        confirm: true,
                    },
                }),
                config: "auth.toml".to_string(),
                verbose: false,
                dry_run: false,
            })
            .await
            .unwrap();

        let restored_framework = config.build_auth_framework().await.unwrap();
        let restored_user = restored_framework.users().get(&user_id).await.unwrap();
        assert_eq!(restored_user.username, "cli-smoke");
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
                .get_kv("smoke:key")
                .await
                .unwrap()
                .unwrap(),
            b"present"
        );
        drop(restored_framework);

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp_dir.path()).unwrap();
        let migration_result = handler
            .handle_command(Cli {
                command: Some(Commands::Db {
                    command: DbCommands::CreateMigration {
                        name: "smoke test migration".to_string(),
                    },
                }),
                config: "auth.toml".to_string(),
                verbose: false,
                dry_run: false,
            })
            .await;
        std::env::set_current_dir(original_dir).unwrap();
        migration_result.unwrap();

        let migration_dir = temp_dir.path().join("migrations").join("sqlite");
        let entries = std::fs::read_dir(&migration_dir)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
    }
}
