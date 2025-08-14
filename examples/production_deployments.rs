//! Production Deployment Configuration Examples
//!
//! This example demonstrates production-ready OAuth 2.0 server configurations
//! using working components of the Auth Framework.

use auth_framework::oauth2_server::OAuth2Config;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🏭 Production OAuth 2.0 Server Configuration Examples");

    // Example 1: High-security production configuration
    let production_config = create_production_config();
    
    // Example 2: Enterprise configuration
    let enterprise_config = create_enterprise_config();
    
    // Example 3: Financial services configuration (FAPI compliant)
    let fapi_config = create_fapi_config();

    println!("✅ All production configurations created successfully");
    
    demonstrate_configs(&production_config, &enterprise_config, &fapi_config);
    
    Ok(())
}

/// High-security production configuration
fn create_production_config() -> OAuth2Config {
    OAuth2Config {
        issuer: "https://auth.production.com".to_string(),
        authorization_code_lifetime: Duration::from_secs(300), // 5 minutes - short for security
        access_token_lifetime: Duration::from_secs(900), // 15 minutes - short for security  
        refresh_token_lifetime: Duration::from_secs(86400 * 7), // 7 days
        device_code_lifetime: Duration::from_secs(600), // 10 minutes
        default_scope: Some("read".to_string()), // Minimal default scope
        max_scope_lifetime: Duration::from_secs(86400), // 1 day max
        require_pkce: true, // Always required in production
        enable_introspection: true, // Required for microservices
        enable_revocation: true, // Required for security
    }
}

/// Enterprise configuration with balanced security and usability
fn create_enterprise_config() -> OAuth2Config {
    OAuth2Config {
        issuer: "https://auth.enterprise.com".to_string(),
        authorization_code_lifetime: Duration::from_secs(600), // 10 minutes
        access_token_lifetime: Duration::from_secs(3600), // 1 hour
        refresh_token_lifetime: Duration::from_secs(86400 * 30), // 30 days
        device_code_lifetime: Duration::from_secs(1800), // 30 minutes
        default_scope: Some("read write".to_string()),
        max_scope_lifetime: Duration::from_secs(86400 * 90), // 90 days
        require_pkce: true,
        enable_introspection: true,
        enable_revocation: true,
    }
}

/// FAPI (Financial-grade API) compliant configuration
fn create_fapi_config() -> OAuth2Config {
    OAuth2Config {
        issuer: "https://auth.bank.com".to_string(),
        authorization_code_lifetime: Duration::from_secs(60), // 1 minute - FAPI requirement
        access_token_lifetime: Duration::from_secs(300), // 5 minutes - very short
        refresh_token_lifetime: Duration::from_secs(3600), // 1 hour - short for banking
        device_code_lifetime: Duration::from_secs(300), // 5 minutes
        default_scope: Some("account_read".to_string()),
        max_scope_lifetime: Duration::from_secs(3600), // 1 hour max
        require_pkce: true, // FAPI requirement
        enable_introspection: true,
        enable_revocation: true,
    }
}

fn demonstrate_configs(prod: &OAuth2Config, ent: &OAuth2Config, fapi: &OAuth2Config) {
    println!("\n📊 Configuration Comparison:");
    
    println!("\n🔒 Production Configuration:");
    println!("   Issuer: {}", prod.issuer);
    println!("   Auth Code Lifetime: {:?}", prod.authorization_code_lifetime);
    println!("   Access Token Lifetime: {:?}", prod.access_token_lifetime);
    println!("   PKCE Required: {}", prod.require_pkce);
    
    println!("\n🏢 Enterprise Configuration:");
    println!("   Issuer: {}", ent.issuer);
    println!("   Auth Code Lifetime: {:?}", ent.authorization_code_lifetime);
    println!("   Access Token Lifetime: {:?}", ent.access_token_lifetime);
    println!("   PKCE Required: {}", ent.require_pkce);
    
    println!("\n🏦 FAPI (Banking) Configuration:");
    println!("   Issuer: {}", fapi.issuer);
    println!("   Auth Code Lifetime: {:?}", fapi.authorization_code_lifetime);
    println!("   Access Token Lifetime: {:?}", fapi.access_token_lifetime);
    println!("   PKCE Required: {}", fapi.require_pkce);
    
    println!("\n🎯 Production Deployment Examples Complete!");
    println!("📋 Key Production Considerations:");
    println!("   • Short token lifetimes for better security");
    println!("   • PKCE always required");
    println!("   • Introspection and revocation enabled");
    println!("   • FAPI compliance for financial services");
    println!("   • Configurable scopes and lifetimes");
}
