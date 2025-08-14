//! Basic usage example demonstrating core functionality of auth_framework
//!
//! This example shows how to:
//! - Set up the auth framework
//! - Create authentication tokens
//! - Validate tokens
//! - Manage sessions

use auth_framework::{
    AuthConfig, AuthFramework, AuthToken,
    methods::{AuthMethodEnum, JwtMethod},
    providers::UserProfile,
    storage::{AuthStorage, MemoryStorage, SessionData},
    tokens::TokenMetadata,
};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("🔐 Auth Framework - Basic Usage Example");
    println!("=====================================\n");

    // 1. Create configuration
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .refresh_token_lifetime(Duration::from_secs(86400 * 7));

    // 2. Create storage backend
    let storage = Arc::new(MemoryStorage::new());

    // 3. Initialize auth framework
    let mut auth = AuthFramework::new(config);

    // 4. Register JWT authentication method
    let jwt_method = JwtMethod::new()
        .secret_key("demo-secret-key")
        .issuer("auth-framework-demo");

    auth.register_method("jwt", AuthMethodEnum::Jwt(jwt_method));
    auth.initialize().await?;

    println!("✅ Auth framework initialized with JWT method");

    // 5. Create a test user profile
    let user_profile = UserProfile {
        id: Some("user123".to_string()),
        provider: Some("local".to_string()),
        username: Some("demo_user".to_string()),
        name: Some("Demo User".to_string()),
        email: Some("demo@example.com".to_string()),
        email_verified: Some(true),
        picture: None,
        locale: Some("en-US".to_string()),
        additional_data: HashMap::new(),
    };

    // 6. Create an authentication token
    let token = create_test_token(&user_profile)?;
    println!(
        "✅ Created authentication token for user: {}",
        user_profile.id.as_ref().unwrap()
    );

    // 7. Store the token using the trait
    storage.store_token(&token).await?;
    println!("✅ Stored token in storage backend");

    // 8. Validate the token
    match storage.get_token(&token.token_id).await? {
        Some(stored_token) => {
            println!("✅ Token validation successful");
            println!("   Token ID: {}", stored_token.token_id);
            println!("   User ID: {}", stored_token.user_id);
            println!("   Expires at: {}", stored_token.expires_at);
            println!("   Scopes: {:?}", stored_token.scopes);
        }
        None => {
            println!("❌ Token not found");
            return Err("Token validation failed".into());
        }
    }

    // 9. Create and store a session
    let session = create_test_session(&user_profile)?;
    storage.store_session(&session.session_id, &session).await?;
    println!("✅ Created session: {}", session.session_id);

    // 10. List user tokens
    let user_tokens = storage
        .list_user_tokens(user_profile.id.as_ref().unwrap())
        .await?;
    println!("✅ User has {} active tokens", user_tokens.len());

    // 11. Clean up - revoke token
    storage.delete_token(&token.token_id).await?;
    println!("✅ Token revoked and cleaned up");

    println!("\n🎉 Basic usage example completed successfully!");

    Ok(())
}

/// Create a test authentication token
fn create_test_token(user_profile: &UserProfile) -> Result<AuthToken, Box<dyn std::error::Error>> {
    let now = Utc::now();
    let user_id = user_profile.id.as_ref().unwrap().clone();

    Ok(AuthToken {
        token_id: uuid::Uuid::new_v4().to_string(),
        user_id: user_id.clone(),
        access_token: format!("demo_token_{}", uuid::Uuid::new_v4()),
        token_type: Some("Bearer".to_string()),
        subject: Some(user_id),
        issuer: Some("auth-framework-demo".to_string()),
        refresh_token: Some(format!("refresh_{}", uuid::Uuid::new_v4())),
        issued_at: now,
        expires_at: now + chrono::Duration::hours(1),
        scopes: vec!["read".to_string(), "write".to_string()],
        auth_method: "jwt".to_string(),
        client_id: Some("demo-client".to_string()),
        user_profile: Some(user_profile.clone()),
        metadata: TokenMetadata {
            issued_ip: Some("127.0.0.1".to_string()),
            user_agent: Some("Example Browser/1.0".to_string()),
            device_id: Some("demo-device".to_string()),
            session_id: None,
            revoked: false,
            revoked_at: None,
            revoked_reason: None,
            last_used: None,
            use_count: 0,
            custom: HashMap::new(),
        },
    })
}

/// Create a test session
fn create_test_session(
    user_profile: &UserProfile,
) -> Result<SessionData, Box<dyn std::error::Error>> {
    let now = Utc::now();
    let user_id = user_profile.id.as_ref().unwrap().clone();

    Ok(SessionData {
        session_id: uuid::Uuid::new_v4().to_string(),
        user_id,
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        last_activity: now,
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("Example Browser/1.0".to_string()),
        data: HashMap::new(),
    })
}
