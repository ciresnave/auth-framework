//! Enhanced Device Flow Example using oauth-device-flows
//!
//! This example demonstrates the enhanced device flow implementation that leverages
//! the specialized oauth-device-flows crate for robust device authentication.
//! 
//! Features demonstrated:
//! - QR code generation for mobile authentication
//! - Robust polling with exponential backoff  
//! - Token management with automatic refresh
//! - Multiple OAuth provider support
//! - Proper error handling for all device flow scenarios

#[cfg(feature = "enhanced-device-flow")]
use auth_framework::{
    AuthFramework, AuthConfig, 
    methods::EnhancedDeviceFlowMethod,
};

#[cfg(feature = "enhanced-device-flow")]
use oauth_device_flows::Provider as DeviceFlowProvider;

#[cfg(feature = "enhanced-device-flow")]
use std::time::Duration;

#[cfg(feature = "enhanced-device-flow")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Enhanced Device Flow Authentication Example");
    println!("==============================================\n");

    // Initialize the auth framework
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .refresh_token_lifetime(Duration::from_secs(86400 * 7));

    let mut auth = AuthFramework::new(config);

    // Example 1: GitHub Device Flow with QR codes
    println!("🐙 Example 1: GitHub Device Flow");
    println!("--------------------------------");
    demonstrate_github_device_flow(&mut auth).await?;

    println!("\n");

    // Example 2: Microsoft Device Flow 
    println!("🔷 Example 2: Microsoft Device Flow");
    println!("-----------------------------------");
    demonstrate_microsoft_device_flow(&mut auth).await?;

    println!("\n");

    // Example 3: Google Device Flow with custom configuration
    println!("🌐 Example 3: Google Device Flow (Custom Config)");
    println!("------------------------------------------------");
    demonstrate_google_device_flow(&mut auth).await?;

    println!("\n🎉 Enhanced device flow examples completed!");
    Ok(())
}

#[cfg(feature = "enhanced-device-flow")]
async fn demonstrate_github_device_flow(auth: &mut AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    // Create enhanced device flow method for GitHub
    let github_device = EnhancedDeviceFlowMethod::new(
        DeviceFlowProvider::GitHub,
        "your-github-client-id".to_string(), // In real app: std::env::var("GITHUB_CLIENT_ID")?
    )
    .scopes(vec!["user:email".to_string(), "read:user".to_string()])
    .polling_config(Duration::from_secs(5), 60); // Poll every 5s for up to 5 minutes

    auth.register_method("github_enhanced", Box::new(github_device));
    auth.initialize().await?;

    println!("✅ Enhanced GitHub device flow configured");

    // In a real application, you would:
    println!("💡 Device Flow Process:");
    println!("   1. Call enhanced_method.start_device_flow() to get instructions");
    println!("   2. Display verification URL and user code to the user");
    println!("   3. Optionally display QR code for mobile devices");
    println!("   4. Call instructions.poll_for_token() to wait for user authorization");
    println!("   5. Handle the resulting AuthToken for API calls");

    println!("\n🔧 Features of the enhanced device flow:");
    println!("   • RFC 8628 compliant implementation");
    println!("   • QR code generation for mobile devices");  
    println!("   • Robust polling with exponential backoff");
    println!("   • Automatic token refresh management");
    println!("   • Strong error handling and validation");
    println!("   • Configurable polling intervals and timeouts");
    
    println!("\n📋 Example configuration:");
    println!("   • Client ID: your-github-client-id");
    println!("   • Scopes: user:email, read:user");
    println!("   • Poll interval: 5 seconds");  
    println!("   • Max attempts: 60 (5 minutes total)");

    // Note: We're not actually calling start_device_flow() to avoid OAuth errors
    // in this demonstration without real credentials
    println!("\n✅ GitHub device flow demonstration completed");

    Ok(())
}

#[cfg(feature = "enhanced-device-flow")]
async fn demonstrate_microsoft_device_flow(auth: &mut AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    // Microsoft device flow with custom scopes
    let microsoft_device = EnhancedDeviceFlowMethod::new(
        DeviceFlowProvider::Microsoft,
        "your-microsoft-client-id".to_string(), // In real app: std::env::var("AZURE_CLIENT_ID")?
    )
    .client_secret("your-microsoft-client-secret".to_string()) // Required for Microsoft
    .scopes(vec![
        "https://graph.microsoft.com/User.Read".to_string(),
        "https://graph.microsoft.com/Mail.Read".to_string(),
    ])
    .polling_config(Duration::from_secs(3), 100); // More frequent polling, longer timeout

    auth.register_method("microsoft_enhanced", Box::new(microsoft_device));

    println!("✅ Enhanced Microsoft device flow configured");
    println!("📋 Microsoft-specific features:");
    println!("   • Client secret support for enterprise apps");
    println!("   • Microsoft Graph API scopes");
    println!("   • Azure AD / Microsoft Entra integration");
    println!("   • Longer polling timeout for enterprise workflows");
    println!("   • Configurable polling interval (3 seconds)");

    Ok(())
}

#[cfg(feature = "enhanced-device-flow")]
async fn demonstrate_google_device_flow(auth: &mut AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    // Google device flow with comprehensive configuration
    let google_device = EnhancedDeviceFlowMethod::new(
        DeviceFlowProvider::Google,
        "your-google-client-id".to_string(), // In real app: std::env::var("GOOGLE_CLIENT_ID")?
    )
    .scopes(vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "https://www.googleapis.com/auth/drive.readonly".to_string(),
    ]);

    auth.register_method("google_enhanced", Box::new(google_device));

    println!("✅ Enhanced Google device flow configured");
    println!("🌟 Google-specific features:");
    println!("   • OpenID Connect support");
    println!("   • Google Drive API access");
    println!("   • Refresh token support");
    println!("   • Google Cloud Console integration");
    println!("   • Comprehensive scope management");

    Ok(())
}

#[cfg(feature = "enhanced-device-flow")]
async fn demonstrate_advanced_features() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Advanced Enhanced Device Flow Features");
    println!("=========================================");

    // Example of error handling patterns
    println!("🛠️  Error Handling:");
    demonstrate_error_handling().await?;
    
    // Example of token management
    println!("\n🎫 Token Management:");
    demonstrate_token_management().await?;

    // Example of provider comparison
    println!("\n📊 Provider Comparison:");
    demonstrate_provider_comparison();

    Ok(())
}

#[cfg(feature = "enhanced-device-flow")]
async fn demonstrate_error_handling() -> Result<(), Box<dyn std::error::Error>> {
    println!("   • authorization_pending → Continue polling");
    println!("   • slow_down → Increase polling interval");
    println!("   • access_denied → User denied authorization");
    println!("   • expired_token → Device code expired, restart flow");
    println!("   • invalid_client → Check client configuration");
    
    // The oauth-device-flows crate handles these automatically
    println!("   ✅ All handled automatically by oauth-device-flows");
    
    Ok(())
}

#[cfg(feature = "enhanced-device-flow")]
async fn demonstrate_token_management() -> Result<(), Box<dyn std::error::Error>> {
    println!("   • Automatic token refresh when expired");
    println!("   • Secure token storage using secrecy crate");
    println!("   • Token validation before API calls");
    println!("   • Easy integration with HTTP clients");
    println!("   ✅ Full lifecycle management included");
    
    Ok(())
}

#[cfg(feature = "enhanced-device-flow")]
fn demonstrate_provider_comparison() {
    println!("   GitHub:    Device flow ✅ | Refresh tokens ✅ | No client secret required");
    println!("   Google:    Device flow ✅ | Refresh tokens ✅ | OpenID Connect support");
    println!("   Microsoft: Device flow ✅ | Refresh tokens ✅ | Client secret required");
    println!("   GitLab:    Device flow ✅ | Refresh tokens ✅ | Self-hosted support");
}

// CLI integration example
#[cfg(feature = "enhanced-device-flow")]
mod cli_integration {
    use super::*;
    
    /// Example CLI tool using enhanced device flow
    pub async fn cli_auth_tool() -> Result<(), Box<dyn std::error::Error>> {
        println!("🖥️  CLI Authentication Tool");
        println!("===========================");
        
        // Parse command line arguments (would use clap in real implementation)
        let provider = "github"; // From CLI args
        let client_id = "your-client-id"; // From CLI args or env
        
        // Create device flow method
        let device_method = match provider {
            "github" => EnhancedDeviceFlowMethod::new(
                DeviceFlowProvider::GitHub,
                client_id.to_string(),
            ),
            "google" => EnhancedDeviceFlowMethod::new(
                DeviceFlowProvider::Google,
                client_id.to_string(),
            ),
            "microsoft" => EnhancedDeviceFlowMethod::new(
                DeviceFlowProvider::Microsoft,
                client_id.to_string(),
            )
            .client_secret(std::env::var("AZURE_CLIENT_SECRET").unwrap_or_default()),
            _ => return Err("Unsupported provider".into()),
        };
        
        // Start authentication flow
        let instructions = device_method.start_device_flow().await?;
        instructions.display_instructions();
        
        // Poll for completion
        println!("🔄 Waiting for authentication...");
        let token = instructions.poll_for_token().await?;
        
        println!("✅ Authentication successful!");
        println!("🎫 Token: {}...", &token.access_token[..10]);
        
        // Save token for future use
        // (Implementation would depend on your storage needs)
        
        Ok(())
    }
}

// Main function for when enhanced-device-flow feature is not enabled
#[cfg(not(feature = "enhanced-device-flow"))]
fn main() {
    println!("❌ Enhanced Device Flow Example");
    println!("===============================");
    println!("This example requires the 'enhanced-device-flow' feature.");
    println!("");
    println!("To run this example:");
    println!("cargo run --example enhanced_device_flow --features enhanced-device-flow");
    println!("");
    println!("Or add to your Cargo.toml:");
    println!("[dependencies]");
    println!("auth-framework = {{ version = \"0.2\", features = [\"enhanced-device-flow\"] }}");
}
