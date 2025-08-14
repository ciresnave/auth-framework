//! Simple OAuth 2.0 Server Configuration Example
//!
//! This example demonstrates basic OAuth 2.0 server configuration
//! using working components of the Auth Framework.

use auth_framework::oauth2_server::{GrantType, OAuth2Config, ResponseType};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 OAuth 2.0 Server Configuration Example");

    // Configure the OAuth 2.0 server
    let oauth2_config = OAuth2Config {
        issuer: "https://auth.mycompany.com".to_string(),
        authorization_code_lifetime: Duration::from_secs(600), // 10 minutes
        access_token_lifetime: Duration::from_secs(3600),      // 1 hour
        refresh_token_lifetime: Duration::from_secs(86400 * 7), // 7 days
        device_code_lifetime: Duration::from_secs(600),        // 10 minutes
        default_scope: Some("read write".to_string()),
        max_scope_lifetime: Duration::from_secs(86400 * 30), // 30 days
        require_pkce: true,
        enable_introspection: true,
        enable_revocation: true,
    };

    // Supported grant types example (for reference)
    let supported_grant_types = vec![
        GrantType::AuthorizationCode,
        GrantType::ClientCredentials,
        GrantType::RefreshToken,
        GrantType::DeviceCode,
    ];

    // Supported response types example (for reference)
    let supported_response_types = vec![
        ResponseType::Code,
        ResponseType::Token,
        ResponseType::IdToken,
    ];

    println!("✅ OAuth2 server configuration created successfully");
    println!("📋 Configuration details:");
    println!("   Issuer: {}", oauth2_config.issuer);
    println!(
        "   Authorization code lifetime: {:?}",
        oauth2_config.authorization_code_lifetime
    );
    println!(
        "   Access token lifetime: {:?}",
        oauth2_config.access_token_lifetime
    );
    println!("   PKCE required: {}", oauth2_config.require_pkce);
    println!("   Grant types: {:?}", supported_grant_types);
    println!("   Response types: {:?}", supported_response_types);

    println!("\n🎯 OAuth 2.0 Configuration Example Complete!");
    println!("📊 This example shows how to:");
    println!("   • Configure OAuth2Config with proper settings");
    println!("   • Set appropriate token lifetimes");
    println!("   • Enable security features (PKCE, introspection, revocation)");
    println!("   • Define supported grant and response types");

    Ok(())
}
