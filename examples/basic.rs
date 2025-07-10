//! Basic authentication example demonstrating the core functionality.

use auth_framework::{AuthFramework, AuthConfig};
use auth_framework::methods::JwtMethod;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    // Create configuration
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .refresh_token_lifetime(Duration::from_secs(86400));

    // Create auth framework (storage is handled internally)
    let mut auth = AuthFramework::new(config);

    // Set up JWT authentication method
    let jwt_method = JwtMethod::new()
        .secret_key("demo-secret-key-change-in-production")
        .issuer("basic-auth-demo")
        .audience("demo-users");

    auth.register_method("jwt", Box::new(jwt_method));

    // Initialize the framework
    auth.initialize().await?;

    println!("🔐 Auth Framework Demo Started");

    // Create a demo token
    let token = auth.create_auth_token(
        "demo_user",
        vec!["read".to_string(), "write".to_string()],
        "jwt",
        None,
    ).await?;

    println!("✅ Created token for user 'demo_user'");
    println!("   Token ID: {}", token.token_id);
    println!("   Access Token: {}...", &token.access_token[0..20]);

    // Validate the token
    if auth.validate_token(&token).await? {
        println!("✅ Token validation successful");

        // Get user info
        let user_info = auth.get_user_info(&token).await?;
        println!("👤 User Info: {} ({})", user_info.username, user_info.id);

        // Check permissions
        if auth.check_permission(&token, "read", "documents").await? {
            println!("✅ User has READ permission for documents");
        }

        if auth.check_permission(&token, "write", "documents").await? {
            println!("✅ User has WRITE permission for documents");
        }

        if !auth.check_permission(&token, "delete", "documents").await? {
            println!("❌ User does NOT have DELETE permission for documents");
        }
    } else {
        println!("❌ Token validation failed");
    }

    // Create API key
    let api_key = auth.create_api_key("demo_user", Some(Duration::from_secs(86400))).await?;
    println!("🔑 Created API key: {}...", &api_key[0..16]);

    // Refresh token
    let _refreshed_token = auth.refresh_token(&token).await?;
    println!("🔄 Token refreshed successfully");

    // Create session
    let session_id = auth.create_session(
        "demo_user",
        Duration::from_secs(3600),
        Some("127.0.0.1".to_string()),
        Some("demo-client".to_string()),
    ).await?;
    println!("🖥️  Created session: {}", session_id);

    // Get session info
    if let Some(session) = auth.get_session(&session_id).await? {
        println!("📋 Session Info: User {} from {}", 
                 session.user_id, 
                 session.ip_address.as_ref().unwrap_or(&"unknown".to_string()));
    }

    // Clean up - revoke token
    auth.revoke_token(&token).await?;
    println!("🗑️  Token revoked");

    // Delete session
    auth.delete_session(&session_id).await?;
    println!("🗑️  Session deleted");

    println!("🎉 Demo completed successfully!");

    Ok(())
}
