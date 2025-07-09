//! OAuth authentication example
//! 
//! This example demonstrates OAuth integration with GitHub and other providers.

use auth_framework::{AuthFramework, AuthConfig, Credential, AuthResult};
use auth_framework::methods::OAuth2Method;
use auth_framework::providers::OAuthProvider;
use auth_framework::credentials::CredentialMetadata;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("🔐 Auth Framework - OAuth Example");
    println!("==================================");

    // 1. Configure the auth framework
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .refresh_token_lifetime(Duration::from_secs(86400 * 7))
        .enable_multi_factor(false);

    println!("✅ Configuration created");

    // 2. Create the auth framework
    let mut auth = AuthFramework::new(config);

    // 3. Set up OAuth methods for different providers
    setup_github_oauth(&mut auth).await?;
    setup_google_oauth(&mut auth).await?;
    setup_custom_oauth(&mut auth).await?;

    // 4. Initialize the framework
    auth.initialize().await?;
    println!("✅ Auth framework initialized");

    // 5. Demonstrate OAuth flow with GitHub
    println!("\n🐙 GitHub OAuth Flow:");
    demonstrate_github_oauth(&auth).await?;

    // 6. Demonstrate OAuth flow with Google
    println!("\n🌐 Google OAuth Flow:");
    demonstrate_google_oauth(&auth).await?;

    // 7. Demonstrate token refresh
    println!("\n🔄 Token Refresh:");
    demonstrate_token_refresh(&auth).await?;

    println!("\n🎉 OAuth example completed successfully!");
    
    Ok(())
}

async fn setup_github_oauth(auth: &mut AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    // In a real application, these would come from environment variables
    let github_method = OAuth2Method::new()
        .provider(OAuthProvider::GitHub)
        .client_id("your-github-client-id")
        .client_secret("your-github-client-secret")
        .redirect_uri("https://your-app.com/auth/github/callback")
        .scopes(vec!["user:email".to_string(), "read:user".to_string()]);

    auth.register_method("github", Box::new(github_method));
    println!("✅ GitHub OAuth method registered");
    
    Ok(())
}

async fn setup_google_oauth(auth: &mut AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    let google_method = OAuth2Method::new()
        .provider(OAuthProvider::Google)
        .client_id("your-google-client-id")
        .client_secret("your-google-client-secret")
        .redirect_uri("https://your-app.com/auth/google/callback")
        .scopes(vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ]);

    auth.register_method("google", Box::new(google_method));
    println!("✅ Google OAuth method registered");
    
    Ok(())
}

async fn setup_custom_oauth(auth: &mut AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    // Example of custom OAuth provider
    let custom_config = auth_framework::providers::OAuthProviderConfig {
        authorization_url: "https://auth.example.com/oauth/authorize".to_string(),
        token_url: "https://auth.example.com/oauth/token".to_string(),
        userinfo_url: Some("https://api.example.com/user".to_string()),
        revocation_url: Some("https://auth.example.com/oauth/revoke".to_string()),
        default_scopes: vec!["profile".to_string(), "email".to_string()],
        supports_pkce: true,
        supports_refresh: true,
        additional_params: std::collections::HashMap::new(),
    };

    let custom_provider = OAuthProvider::custom("custom-provider", custom_config);
    
    let custom_method = OAuth2Method::new()
        .provider(custom_provider)
        .client_id("your-custom-client-id")
        .client_secret("your-custom-client-secret")
        .redirect_uri("https://your-app.com/auth/custom/callback");

    auth.register_method("custom", Box::new(custom_method));
    println!("✅ Custom OAuth method registered");
    
    Ok(())
}

async fn demonstrate_github_oauth(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    // In a real application, this would be triggered by a user clicking "Login with GitHub"
    
    // 1. Generate authorization URL
    let github_method = OAuth2Method::new()
        .provider(OAuthProvider::GitHub)
        .client_id("your-github-client-id")
        .client_secret("your-github-client-secret")
        .redirect_uri("https://your-app.com/auth/github/callback");

    let (auth_url, state, pkce) = github_method.authorization_url()?;
    
    println!("📝 Generated authorization URL:");
    println!("   URL: {}", auth_url);
    println!("   State: {}", state);
    println!("   PKCE: {}", pkce.is_some());

    // 2. Simulate user authorization (in reality, user would visit the URL)
    println!("👤 User would visit the authorization URL and approve the app");
    
    // 3. Simulate receiving the authorization code callback
    let authorization_code = "simulated_authorization_code";
    
    // 4. Create credential with authorization code
    let credential = if let Some((code_verifier, _)) = pkce {
        Credential::oauth_code_with_pkce(authorization_code, code_verifier)
    } else {
        Credential::oauth_code(authorization_code)
    };

    // 5. Add metadata
    let metadata = CredentialMetadata::new()
        .client_ip("192.168.1.100")
        .user_agent("Mozilla/5.0 (Example Browser)")
        .client_id("your-github-client-id");

    println!("🔄 Attempting OAuth authentication...");
    
    // Note: This will fail in the example because we're using fake credentials
    // In a real application, you would have actual authorization codes
    match auth.authenticate_with_metadata("github", credential, metadata).await {
        Ok(AuthResult::Success(token)) => {
            println!("✅ GitHub OAuth successful!");
            println!("   User ID: {}", token.user_id);
            println!("   Token expires: {}", token.expires_at);
            println!("   Scopes: {:?}", token.scopes);
            
            // Get user info
            if let Ok(user_info) = auth.get_user_info(&token).await {
                println!("   User info:");
                println!("     Username: {}", user_info.username);
                println!("     Email: {:?}", user_info.email);
                println!("     Name: {:?}", user_info.name);
            }
        }
        Ok(AuthResult::Failure(reason)) => {
            println!("❌ GitHub OAuth failed: {}", reason);
            println!("   (This is expected in the example with fake credentials)");
        }
        Ok(AuthResult::MfaRequired(challenge)) => {
            println!("🔐 MFA required for GitHub OAuth: {}", challenge.id());
        }
        Err(e) => {
            println!("❌ OAuth error: {}", e);
            println!("   (This is expected in the example with fake credentials)");
        }
    }

    Ok(())
}

async fn demonstrate_google_oauth(_auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    // Similar to GitHub, but with Google-specific configuration
    
    let google_method = OAuth2Method::new()
        .provider(OAuthProvider::Google)
        .client_id("your-google-client-id")
        .client_secret("your-google-client-secret")
        .redirect_uri("https://your-app.com/auth/google/callback");

    let (auth_url, state, pkce) = google_method.authorization_url()?;
    
    println!("📝 Generated Google authorization URL:");
    println!("   URL: {}", auth_url);
    println!("   State: {}", state);
    println!("   PKCE: {}", pkce.is_some());

    // Google OAuth typically includes OpenID Connect
    println!("🔍 Google OAuth includes OpenID Connect for identity");
    println!("   - openid scope provides ID token");
    println!("   - profile scope provides user profile information");
    println!("   - email scope provides email address");

    Ok(())
}

async fn demonstrate_token_refresh(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    // Create a mock token with refresh capability
    let mut token = auth.create_auth_token(
        "oauth_user_123",
        vec!["profile".to_string(), "email".to_string()],
        "github",
        Some(Duration::from_secs(300)), // Short-lived for demo
    ).await?;
    
    // Add a refresh token (simulating OAuth flow)
    token = token.with_refresh_token("mock_refresh_token_12345");

    println!("📱 Created token with refresh capability:");
    println!("   Token ID: {}", token.token_id);
    println!("   Expires at: {}", token.expires_at);
    println!("   Has refresh token: {}", token.refresh_token.is_some());

    // Token is automatically stored by create_auth_token

    // Check if token is expiring soon
    if token.is_expiring(Duration::from_secs(600)) {
        println!("⏰ Token is expiring soon, refreshing...");
        
        match auth.refresh_token(&token).await {
            Ok(new_token) => {
                println!("✅ Token refreshed successfully!");
                println!("   New Token ID: {}", new_token.token_id);
                println!("   New Expires at: {}", new_token.expires_at);
                println!("   Time gained: {:?}", new_token.expires_at - token.expires_at);
            }
            Err(e) => {
                println!("❌ Token refresh failed: {}", e);
            }
        }
    }

    Ok(())
}

// Helper function to demonstrate OAuth provider configurations
#[allow(dead_code)]
fn show_provider_capabilities() {
    println!("\n🔍 OAuth Provider Capabilities:");
    
    let providers = vec![
        OAuthProvider::GitHub,
        OAuthProvider::Google,
        OAuthProvider::Microsoft,
        OAuthProvider::Discord,
        OAuthProvider::Twitter,
    ];

    for provider in providers {
        let config = provider.config();
        println!("\n📋 {}:", provider.name());
        println!("   Authorization URL: {}", config.authorization_url);
        println!("   Token URL: {}", config.token_url);
        println!("   Supports PKCE: {}", config.supports_pkce);
        println!("   Supports Refresh: {}", config.supports_refresh);
        println!("   Default Scopes: {:?}", config.default_scopes);
    }
}
