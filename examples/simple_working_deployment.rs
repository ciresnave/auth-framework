//! Simple Working Deployment Example for Auth Framework
//!
//! This example demonstrates basic authentication components
//! that are currently working in the Auth Framework.

use auth_framework::{
    AuthConfig, AuthFramework,
    methods::{AuthMethodEnum, JwtMethod},
    providers::OAuthProvider,
};
use std::time::Duration;

/// Simple working deployment example
pub async fn simple_working_deployment() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Setting up simple working deployment...");

    // Create auth configuration
    let config = AuthConfig::new()
        .secret("demo-secret-key".to_string())
        .issuer("https://localhost:8080".to_string())
        .audience("demo-app".to_string())
        .token_lifetime(Duration::from_secs(3600))
        .refresh_token_lifetime(Duration::from_secs(86400 * 7));

    // Create auth framework
    let mut auth_framework = AuthFramework::new(config);

    // Register JWT method
    let jwt_method = JwtMethod::new()
        .secret_key("demo-secret-key")
        .issuer("https://localhost:8080");

    auth_framework.register_method("jwt", AuthMethodEnum::Jwt(jwt_method));

    // Initialize framework
    auth_framework.initialize().await?;

    println!("✅ Auth framework initialized successfully!");

    // Create a sample token
    let token = auth_framework
        .create_auth_token(
            "demo_user",
            vec!["read".to_string(), "write".to_string()],
            "jwt",
            None,
        )
        .await?;

    println!("🔑 Created token: {}", token.access_token);

    // Validate the token
    if auth_framework.validate_token(&token).await? {
        println!("✅ Token validation successful!");

        // Check permission
        if auth_framework
            .check_permission(&token, "read", "documents")
            .await?
        {
            println!("✅ Permission check passed!");
        }
    }

    Ok(())
}

/// OAuth provider example
pub async fn oauth_provider_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Setting up OAuth provider example...");

    // Example with GitHub OAuth provider
    let github_provider = OAuthProvider::GitHub;

    println!("✅ OAuth provider configured: {:?}", github_provider);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Auth Framework - Simple Working Examples");
    println!("{}", "=".repeat(60));

    // Initialize logging
    tracing_subscriber::fmt::init();

    let example_type = std::env::var("EXAMPLE_TYPE").unwrap_or_else(|_| "simple".to_string());

    match example_type.as_str() {
        "oauth" => {
            println!("🔧 Running OAuth provider example...");
            oauth_provider_example().await?
        }
        _ => {
            println!("🛠️ Running simple working deployment...");
            simple_working_deployment().await?
        }
    }

    println!("\n✅ Example completed successfully!");

    Ok(())
}
