//! Command Line Authentication Tool
//!
//! This example demonstrates how to use auth_framework in a CLI application
//! for user authentication, token management, and session handling.

use auth_framework::{
    AuthConfig, AuthFramework, AuthToken,
    config::SecurityConfig,
    methods::{AuthMethodEnum, JwtMethod},
    providers::UserProfile,
    storage::{AuthStorage, MemoryStorage, SessionData},
};
use chrono::Utc;
use std::{
    collections::HashMap,
    io::{self, Write},
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;

struct AuthCli {
    auth: AuthFramework,
    storage: Arc<MemoryStorage>,
    current_user: Option<AuthToken>,
}

impl AuthCli {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize auth framework with security configuration
        let security_config = SecurityConfig::development();

        let config = AuthConfig::new()
            .token_lifetime(Duration::from_secs(3600))
            .refresh_token_lifetime(Duration::from_secs(86400))
            .security(SecurityConfig {
                secret_key: Some("cli-demo-secret-key-32-chars-long!".to_string()),
                ..security_config
            });

        let mut auth = AuthFramework::new(config);

        // Register JWT method
        let jwt_method = JwtMethod::new()
            .secret_key("cli-demo-secret-key-32-chars-long!")
            .issuer("auth-cli-demo");

        auth.register_method("jwt", AuthMethodEnum::Jwt(jwt_method));
        auth.initialize().await?;

        let storage = Arc::new(MemoryStorage::new());

        Ok(Self {
            auth,
            storage,
            current_user: None,
        })
    }

    async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🔐 Auth Framework CLI Demo");
        println!("==========================\n");

        // Create some demo users
        self.create_demo_users().await?;

        loop {
            self.display_menu();

            print!("\nEnter your choice: ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            match input.trim() {
                "1" => self.login().await?,
                "2" => self.show_profile().await?,
                "3" => self.list_tokens().await?,
                "4" => self.create_session().await?,
                "5" => self.list_sessions().await?,
                "6" => self.logout().await?,
                "7" => self.admin_panel().await?,
                "8" => {
                    println!("👋 Goodbye!");
                    break;
                }
                _ => println!("❌ Invalid choice. Please try again."),
            }
        }

        Ok(())
    }

    fn display_menu(&self) {
        println!("\n📋 Available Commands:");
        println!("1. Login");
        println!("2. Show Profile");
        println!("3. List My Tokens");
        println!("4. Create Session");
        println!("5. List My Sessions");
        println!("6. Logout");
        println!("7. Admin Panel");
        println!("8. Exit");

        if let Some(ref token) = self.current_user {
            println!("\n✅ Logged in as: {}", token.user_id);
        } else {
            println!("\n❌ Not logged in");
        }
    }

    async fn create_demo_users(&self) -> Result<(), Box<dyn std::error::Error>> {
        let users = vec![
            (
                "admin",
                "Admin User",
                "admin@example.com",
                vec!["read".to_string(), "write".to_string(), "admin".to_string()],
            ),
            (
                "alice",
                "Alice Smith",
                "alice@example.com",
                vec!["read".to_string(), "write".to_string()],
            ),
            (
                "bob",
                "Bob Johnson",
                "bob@example.com",
                vec!["read".to_string(), "write".to_string()],
            ),
        ];

        for (username, name, email, scopes) in users {
            let user_id = format!("user_{}", username);

            // Create a user profile with complete information
            let user_profile = UserProfile::new()
                .with_id(&user_id)
                .with_provider("local")
                .with_name(Some(name))
                .with_username(Some(username))
                .with_email(Some(email))
                .with_email_verified(true)
                .with_additional_data(
                    "role".to_string(),
                    serde_json::Value::String(if username == "admin" {
                        "admin".to_string()
                    } else {
                        "user".to_string()
                    }),
                );

            // Create a basic auth token using the framework
            let mut token = self
                .auth
                .create_auth_token(&user_id, scopes, "jwt", None)
                .await?;

            // Add the user profile to the token
            token.user_profile = Some(user_profile);

            // Store the enhanced token
            self.storage.store_token(&token).await?;
        }

        println!("✅ Demo users created: admin, alice, bob (password: 'password' for all)");
        Ok(())
    }

    async fn login(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        print!("Username: ");
        io::stdout().flush()?;
        let mut username = String::new();
        io::stdin().read_line(&mut username)?;
        let username = username.trim();

        print!("Password: ");
        io::stdout().flush()?;
        let mut password = String::new();
        io::stdin().read_line(&mut password)?;
        let password = password.trim();

        // Simple authentication (in real app, hash/verify password)
        if !["admin", "alice", "bob"].contains(&username) || password != "password" {
            println!("❌ Invalid credentials");
            return Ok(());
        }

        // Use the authentication framework to create a proper token
        let user_id = format!("user_{}", username);
        let scopes = if username == "admin" {
            vec!["read".to_string(), "write".to_string(), "admin".to_string()]
        } else {
            vec!["read".to_string(), "write".to_string()]
        };

        // Create authentication token using the framework
        let mut token = self
            .auth
            .create_auth_token(&user_id, scopes, "jwt", None)
            .await?;

        // Add user profile information
        let display_name = match username {
            "admin" => "Admin User",
            "alice" => "Alice Smith",
            "bob" => "Bob Johnson",
            _ => username,
        };
        let email = format!("{}@example.com", username);

        let user_profile = UserProfile::new()
            .with_id(&user_id)
            .with_provider("local")
            .with_name(Some(display_name))
            .with_username(Some(username))
            .with_email(Some(&email))
            .with_email_verified(true)
            .with_additional_data(
                "role".to_string(),
                serde_json::Value::String(if username == "admin" {
                    "admin".to_string()
                } else {
                    "user".to_string()
                }),
            );

        // Add the user profile to the token
        token.user_profile = Some(user_profile);

        // Store token
        self.storage.store_token(&token).await?;
        self.current_user = Some(token.clone());

        println!("✅ Login successful! Token ID: {}", token.token_id);
        Ok(())
    }

    async fn show_profile(&self) -> Result<(), Box<dyn std::error::Error>> {
        match &self.current_user {
            Some(token) => {
                if let Some(ref profile) = token.user_profile {
                    println!("\n👤 User Profile:");
                    println!(
                        "   ID: {}",
                        profile.id.as_ref().unwrap_or(&"N/A".to_string())
                    );
                    println!(
                        "   Username: {}",
                        profile.username.as_ref().unwrap_or(&"N/A".to_string())
                    );
                    println!(
                        "   Name: {}",
                        profile.name.as_ref().unwrap_or(&"N/A".to_string())
                    );
                    println!(
                        "   Email: {}",
                        profile.email.as_ref().unwrap_or(&"N/A".to_string())
                    );
                    println!(
                        "   Email Verified: {}",
                        profile.email_verified.unwrap_or(false)
                    );
                    println!("   Scopes: {:?}", token.scopes);
                    println!("   Token Expires: {}", token.expires_at);

                    if !profile.additional_data.is_empty() {
                        println!("   Additional Data:");
                        for (key, value) in &profile.additional_data {
                            println!("     {}: {}", key, value);
                        }
                    }
                } else {
                    println!("❌ No user profile available");
                }
            }
            None => println!("❌ Not logged in"),
        }
        Ok(())
    }

    async fn list_tokens(&self) -> Result<(), Box<dyn std::error::Error>> {
        match &self.current_user {
            Some(current_token) => {
                let tokens = self
                    .storage
                    .list_user_tokens(&current_token.user_id)
                    .await?;

                println!("\n🎫 Your Active Tokens:");
                for (i, token) in tokens.iter().enumerate() {
                    let is_current = token.token_id == current_token.token_id;
                    let status = if token.expires_at < Utc::now() {
                        "EXPIRED"
                    } else if is_current {
                        "CURRENT"
                    } else {
                        "ACTIVE"
                    };

                    println!("   {}. {} [{}]", i + 1, token.token_id, status);
                    println!("      Issued: {}", token.issued_at);
                    println!("      Expires: {}", token.expires_at);
                    println!("      Scopes: {:?}", token.scopes);
                }

                if tokens.is_empty() {
                    println!("   No tokens found");
                }
            }
            None => println!("❌ Not logged in"),
        }
        Ok(())
    }

    async fn create_session(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match &self.current_user {
            Some(token) => {
                let session = SessionData {
                    session_id: Uuid::new_v4().to_string(),
                    user_id: token.user_id.clone(),
                    created_at: Utc::now(),
                    expires_at: Utc::now() + chrono::Duration::hours(2),
                    last_activity: Utc::now(),
                    ip_address: Some("127.0.0.1".to_string()),
                    user_agent: Some("AuthCLI/1.0".to_string()),
                    data: {
                        let mut data = HashMap::new();
                        data.insert("cli_session".to_string(), serde_json::Value::Bool(true));
                        data.insert(
                            "created_via".to_string(),
                            serde_json::Value::String("manual".to_string()),
                        );
                        data
                    },
                };

                self.storage
                    .store_session(&session.session_id, &session)
                    .await?;
                println!("✅ Session created: {}", session.session_id);
            }
            None => println!("❌ Not logged in"),
        }
        Ok(())
    }

    async fn list_sessions(&self) -> Result<(), Box<dyn std::error::Error>> {
        match &self.current_user {
            Some(token) => {
                let sessions = self.storage.list_user_sessions(&token.user_id).await?;

                println!("\n📱 Your Active Sessions:");
                for (i, session) in sessions.iter().enumerate() {
                    let status = if session.expires_at < Utc::now() {
                        "EXPIRED"
                    } else {
                        "ACTIVE"
                    };

                    println!("   {}. {} [{}]", i + 1, session.session_id, status);
                    println!("      Created: {}", session.created_at);
                    println!("      Last Activity: {}", session.last_activity);
                    println!("      Expires: {}", session.expires_at);

                    if !session.data.is_empty() {
                        println!("      Data: {:?}", session.data);
                    }
                }

                if sessions.is_empty() {
                    println!("   No sessions found");
                }
            }
            None => println!("❌ Not logged in"),
        }
        Ok(())
    }

    async fn logout(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match &self.current_user {
            Some(token) => {
                // Revoke current token
                self.storage.delete_token(&token.token_id).await?;
                self.current_user = None;
                println!("✅ Logged out successfully");
            }
            None => println!("❌ Already logged out"),
        }
        Ok(())
    }

    async fn admin_panel(&self) -> Result<(), Box<dyn std::error::Error>> {
        match &self.current_user {
            Some(token) => {
                // Check if user has admin scope
                if !token.scopes.contains(&"admin".to_string()) {
                    println!("❌ Access denied. Admin privileges required.");
                    return Ok(());
                }

                println!("\n👑 Admin Panel:");
                println!("1. List All Users");
                println!("2. List All Tokens");
                println!("3. List All Sessions");

                print!("Admin choice: ");
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;

                match input.trim() {
                    "1" => self.admin_list_users().await?,
                    "2" => self.admin_list_all_tokens().await?,
                    "3" => self.admin_list_all_sessions().await?,
                    _ => println!("❌ Invalid admin choice"),
                }
            }
            None => println!("❌ Not logged in"),
        }
        Ok(())
    }

    async fn admin_list_users(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n👥 All Users (based on active tokens):");

        // For this demo, just show the known users
        let known_users = ["user_admin", "user_alice", "user_bob"];

        for (i, user_id) in known_users.iter().enumerate() {
            let tokens = self.storage.list_user_tokens(user_id).await?;
            println!("   {}. {} ({} active tokens)", i + 1, user_id, tokens.len());
        }

        Ok(())
    }

    async fn admin_list_all_tokens(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n🎫 All Active Tokens:");

        let known_users = ["user_admin", "user_alice", "user_bob"];
        let mut total_tokens = 0;

        for user_id in &known_users {
            let tokens = self.storage.list_user_tokens(user_id).await?;
            for token in tokens {
                total_tokens += 1;
                let status = if token.expires_at < Utc::now() {
                    "EXPIRED"
                } else {
                    "ACTIVE"
                };
                println!(
                    "   {}. {} - {} [{}]",
                    total_tokens, token.user_id, token.token_id, status
                );
            }
        }

        if total_tokens == 0 {
            println!("   No tokens found");
        }

        Ok(())
    }

    async fn admin_list_all_sessions(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n📱 All Active Sessions:");

        let known_users = ["user_admin", "user_alice", "user_bob"];
        let mut total_sessions = 0;

        for user_id in &known_users {
            let sessions = self.storage.list_user_sessions(user_id).await?;
            for session in sessions {
                total_sessions += 1;
                let status = if session.expires_at < Utc::now() {
                    "EXPIRED"
                } else {
                    "ACTIVE"
                };
                println!(
                    "   {}. {} - {} [{}]",
                    total_sessions, session.user_id, session.session_id, status
                );
            }
        }

        if total_sessions == 0 {
            println!("   No sessions found");
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cli = AuthCli::new().await?;
    cli.run().await
}
