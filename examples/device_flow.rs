//! Device Flow Authentication Example
//!
//! This example demonstrates how to implement OAuth device flow authentication,
//! which is particularly useful for devices with limited input capabilities
//! or command-line applications.

use auth_framework::{
    AuthFramework, AuthConfig, Credential,
    methods::OAuth2Method,
    providers::{OAuthProvider, DeviceAuthorizationResponse},
    errors::AuthError,
};
use std::time::Duration;
use tokio::time::{sleep, timeout};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Device Flow Authentication Example");
    println!("=====================================\n");

    // Initialize the auth framework
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .refresh_token_lifetime(Duration::from_secs(86400 * 7));

    let mut auth = AuthFramework::new(config);

    // Configure OAuth method for device flow
    // In a real application, these would come from environment variables
    let oauth_method = OAuth2Method::new()
        .provider(OAuthProvider::GitHub) // GitHub supports device flow
        .client_id("your-github-client-id")
        .client_secret("your-github-client-secret");

    auth.register_method("github_device", Box::new(oauth_method));
    auth.initialize().await?;

    println!("🚀 Starting device flow authentication with GitHub...\n");

    // Step 1: Initiate device flow
    match initiate_device_flow(&auth).await {
        Ok(()) => println!("✅ Device flow completed successfully!"),
        Err(e) => {
            eprintln!("❌ Device flow failed: {}", e);
            
            // Demonstrate error handling for different scenarios
            handle_device_flow_errors(&e);
        }
    }

    Ok(())
}

async fn initiate_device_flow(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Get device authorization
    println!("📱 Step 1: Requesting device authorization...");
    
    let device_auth = request_device_authorization().await?;
    
    // Step 2: Display user instructions
    display_user_instructions(&device_auth);
    
    // Step 3: Poll for authorization
    let token = poll_for_authorization(auth, &device_auth).await?;
    
    // Step 4: Use the token
    println!("🎉 Authentication successful!");
    println!("Access Token: {}...", &token[..20.min(token.len())]);
    
    // Demonstrate token validation - for this example, we'll just show it's available
    println!("✅ Token is valid and ready to use");
    
    // In a real application, you would use the token to make API calls
    println!("� You can now use this token to make authenticated API requests");
    println!("   Example: curl -H 'Authorization: Bearer {}...' https://api.github.com/user", &token[..10]);
    
    Ok(())
}

async fn request_device_authorization() -> Result<DeviceAuthorizationResponse, Box<dyn std::error::Error>> {
    // In a real implementation, this would make an HTTP request to the device authorization endpoint
    // For this example, we'll simulate the response
    
    println!("   Making request to device authorization endpoint...");
    
    // Simulate API call delay
    sleep(Duration::from_millis(500)).await;
    
    // Simulated response from GitHub's device authorization endpoint
    Ok(DeviceAuthorizationResponse {
        device_code: "3584d83530557fdd1f46af8289938c8ef79f9dc5".to_string(),
        user_code: "WDJB-MJHT".to_string(),
        verification_uri: "https://github.com/login/device".to_string(),
        verification_uri_complete: Some(
            "https://github.com/login/device?user_code=WDJB-MJHT".to_string()
        ),
        interval: 5, // Poll every 5 seconds
        expires_in: 900, // Expires in 15 minutes
    })
}

fn display_user_instructions(device_auth: &DeviceAuthorizationResponse) {
    println!("\n📋 Step 2: User Authorization Required");
    println!("=====================================");
    println!("Please visit: {}", device_auth.verification_uri);
    println!("And enter code: {}", device_auth.user_code);
    
    if let Some(complete_uri) = &device_auth.verification_uri_complete {
        println!("Or visit directly: {}", complete_uri);
    }
    
    println!("\n⏰ Code expires in {} minutes", device_auth.expires_in / 60);
    println!("🔄 Polling for authorization every {} seconds...", device_auth.interval);
    println!("   (This will continue until you authorize or the code expires)\n");
}

async fn poll_for_authorization(
    auth: &AuthFramework,
    device_auth: &DeviceAuthorizationResponse,
) -> Result<String, Box<dyn std::error::Error>> {
    println!("🔄 Step 3: Polling for authorization...");
    
    let poll_interval = Duration::from_secs(device_auth.interval);
    let total_timeout = Duration::from_secs(device_auth.expires_in);
    
    // Create device code credential (simulated - in real implementation this would be properly supported)
    let credential = Credential::Custom {
        method: "device_code".to_string(),
        data: {
            let mut data = std::collections::HashMap::new();
            data.insert("device_code".to_string(), device_auth.device_code.clone());
            data.insert("client_id".to_string(), "your-github-client-id".to_string());
            data
        }
    };
    
    // Poll with timeout
    let result = timeout(total_timeout, async {
        let mut attempt = 1;
        
        loop {
            println!("   Polling attempt {} ...", attempt);
            
            match auth.authenticate("github_device", credential.clone()).await {
                Ok(auth_result) => {
                    match auth_result {
                        auth_framework::AuthResult::Success(token) => {
                            return Ok::<String, Box<dyn std::error::Error>>(token.access_token);
                        }
                        auth_framework::AuthResult::Failure(reason) => {
                            // Handle different failure reasons
                            if reason.contains("authorization_pending") {
                                println!("   ⏳ Authorization pending...");
                            } else if reason.contains("slow_down") {
                                println!("   🐌 Slowing down polling...");
                                sleep(poll_interval * 2).await; // Back off
                                continue;
                            } else if reason.contains("access_denied") {
                                return Err(Box::new(AuthError::auth_method("github_device", "Access denied by user")));
                            } else if reason.contains("expired_token") {
                                return Err(Box::new(AuthError::auth_method("github_device", "Device code expired")));
                            }
                        }
                        auth_framework::AuthResult::MfaRequired(_) => {
                            println!("   🔐 MFA required (unexpected for device flow)");
                        }
                    }
                }
                Err(e) => {
                    println!("   ❌ Polling error: {}", e);
                }
            }
            
            attempt += 1;
            sleep(poll_interval).await;
        }
    }).await??;
    
    Ok(result)
}

fn handle_device_flow_errors(error: &Box<dyn std::error::Error>) {
    println!("\n🛠️  Error Handling Examples:");
    println!("============================");
    
    // Try to downcast to specific error types for better handling
    let error_str = error.to_string();
    
    if error_str.contains("authorization_pending") {
        println!("💡 User hasn't completed authorization yet - continue polling");
    } else if error_str.contains("slow_down") {
        println!("💡 Polling too frequently - increase interval");
    } else if error_str.contains("access_denied") {
        println!("💡 User denied authorization - restart flow or handle gracefully");
    } else if error_str.contains("expired_token") {
        println!("💡 Device code expired - initiate new device flow");
    } else if error_str.contains("timeout") {
        println!("💡 Polling timeout - device code likely expired");
    } else {
        println!("💡 Unexpected error - check network connectivity and configuration");
    }
    
    println!("\n📚 Common Device Flow Patterns:");
    println!("- Implement exponential backoff for 'slow_down' errors");
    println!("- Provide clear user instructions and progress feedback");
    println!("- Handle timeouts gracefully with option to retry");
    println!("- Store device codes securely if persistence is needed");
    println!("- Implement proper error recovery strategies");
}

// Example of a more complete device flow implementation
async fn complete_device_flow_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔧 Complete Device Flow Implementation Example");
    println!("===============================================");
    
    // This shows how you might structure a complete device flow in a real application
    
    struct DeviceFlowConfig {
        client_id: String,
        device_auth_url: String,
        token_url: String,
        scopes: Vec<String>,
        poll_interval: Duration,
        timeout: Duration,
    }
    
    struct DeviceFlowManager {
        config: DeviceFlowConfig,
        auth: AuthFramework,
    }
    
    impl DeviceFlowManager {
        async fn authenticate_user(&self) -> Result<String, AuthError> {
            // 1. Request device authorization
            let device_auth = self.request_device_authorization().await?;
            
            // 2. Display instructions to user
            self.display_instructions(&device_auth);
            
            // 3. Poll for completion
            self.poll_for_token(&device_auth).await
        }
        
        async fn request_device_authorization(&self) -> Result<DeviceAuthorizationResponse, AuthError> {
            // Implementation details...
            todo!("Make HTTP request to device authorization endpoint")
        }
        
        fn display_instructions(&self, device_auth: &DeviceAuthorizationResponse) {
            // User-friendly display logic...
            println!("Visit {} and enter code {}", 
                device_auth.verification_uri, 
                device_auth.user_code);
        }
        
        async fn poll_for_token(&self, _device_auth: &DeviceAuthorizationResponse) -> Result<String, AuthError> {
            // Robust polling implementation with proper error handling...
            todo!("Implement polling with exponential backoff")
        }
    }
    
    println!("✨ This structure provides:");
    println!("- Clean separation of concerns");
    println!("- Configurable polling behavior");  
    println!("- Proper error handling");
    println!("- User-friendly feedback");
    println!("- Integration with auth-framework");
    
    Ok(())
}

// CLI integration helper example
// Note: This would require adding clap as a dependency and "cli" feature to Cargo.toml
/*
mod cli_integration {
    use super::*;
    use clap::{Arg, Command};
    
    /// Example of integrating device flow with clap CLI framework
    pub fn create_auth_command() -> Command {
        Command::new("auth")
            .about("Authenticate using device flow")
            .arg(
                Arg::new("provider")
                    .short('p')
                    .long("provider")
                    .value_name("PROVIDER")
                    .help("OAuth provider (github, google, microsoft)")
                    .default_value("github")
            )
            .arg(
                Arg::new("client-id")
                    .long("client-id")
                    .value_name("CLIENT_ID")
                    .help("OAuth client ID")
                    .env("OAUTH_CLIENT_ID")
                    .required(true)
            )
            .arg(
                Arg::new("timeout")
                    .long("timeout")
                    .value_name("SECONDS")
                    .help("Authentication timeout in seconds")
                    .default_value("900")
            )
    }
    
    pub async fn handle_auth_command(matches: &clap::ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
        let provider = matches.get_one::<String>("provider").unwrap();
        let client_id = matches.get_one::<String>("client-id").unwrap();
        let timeout = matches.get_one::<String>("timeout")
            .unwrap()
            .parse::<u64>()?;
        
        println!("🔐 Authenticating with {} (timeout: {}s)", provider, timeout);
        
        // Initialize auth framework with CLI-specific configuration
        let config = AuthConfig::new()
            .token_lifetime(Duration::from_secs(3600));
            // .timeout(Duration::from_secs(timeout)); // Not implemented yet
        
        // Continue with device flow...
        
        Ok(())
    }
}
*/
