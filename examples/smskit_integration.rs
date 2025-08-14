//! SMSKit Integration Example
//!
//! This example demonstrates how to use the new SMSKit integration for SMS-based MFA
//! instead of the deprecated SMS manager.

use auth_framework::{errors::Result, storage::MemoryStorage};

// Import SMSKit types directly from the modules
#[cfg(feature = "smskit")]
use auth_framework::auth_modular::mfa::SmsKitManager;

use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🚀 SMSKit Integration Example");
    println!("=============================");

    #[cfg(feature = "smskit")]
    {
        // Create storage backend
        let storage = Arc::new(MemoryStorage::new());

        // Example 1: Basic SMSKit manager (development mode)
        println!("\n📱 Example 1: Development Mode SMSKit");
        let basic_sms_kit = SmsKitManager::new(storage.clone());

        // Register a phone number
        let user_id = "user_123";
        let phone_number = "+1234567890";

        match basic_sms_kit
            .register_phone_number(user_id, phone_number)
            .await
        {
            Ok(_) => println!("✅ Phone number registered successfully"),
            Err(e) => println!("❌ Failed to register phone number: {}", e),
        }

        // Initiate SMS challenge
        let challenge_id = basic_sms_kit.initiate_challenge(user_id).await?;
        println!("📲 Challenge initiated: {}", challenge_id);

        // Generate and send code
        let code = basic_sms_kit.generate_code(&challenge_id).await?;
        println!("🔢 Generated code: {}", code);

        match basic_sms_kit.send_code(user_id, &code).await {
            Ok(_) => println!("✅ SMS sent successfully (development mode)"),
            Err(e) => println!("❌ Failed to send SMS: {}", e),
        }

        // Verify the code
        match basic_sms_kit.verify_code(&challenge_id, &code).await {
            Ok(true) => println!("✅ Code verified successfully"),
            Ok(false) => println!("❌ Invalid code"),
            Err(e) => println!("❌ Verification error: {}", e),
        }

        println!("\n📱 Example 2: Production Configuration Template");
        println!("// Use this template for production SMSKit configuration:");
        println!("//");
        println!("// let twilio_config = SmsKitConfig {{");
        println!("//     provider: SmsKitProvider::Twilio,");
        println!("//     config: SmsKitProviderConfig::Twilio {{");
        println!("//         account_sid: env!(\"TWILIO_ACCOUNT_SID\").to_string(),");
        println!("//         auth_token: env!(\"TWILIO_AUTH_TOKEN\").to_string(),");
        println!("//         from_number: \"+1234567890\".to_string(),");
        println!("//         webhook_url: Some(\"https://your-app.com/sms/webhook\".to_string()),");
        println!("//     }},");
        println!("//     fallback_provider: Some(SmsKitProvider::Plivo),");
        println!("//     fallback_config: Some(SmsKitProviderConfig::Plivo {{ ... }}),");
        println!("//     webhook_config: Some(WebhookConfig {{ ... }}),");
        println!("//     rate_limiting: RateLimitConfig::default(),");
        println!("// }};");
    }

    #[cfg(not(feature = "smskit"))]
    {
        println!("❌ SMSKit feature is not enabled!");
        println!("   Run with: cargo run --example smskit_integration --features smskit");
    }

    // Migration guidance
    println!("\n🔄 Migration from Legacy SMS Manager");
    println!("====================================");
    println!("1. Replace `SmsManager` with `SmsKitManager`");
    println!("2. Update configuration to use `SmsKitConfig`");
    println!("3. Enable 'smskit' feature flag in Cargo.toml");
    println!("4. Configure providers (Twilio, Plivo, AWS SNS)");
    println!("5. Set up webhooks for delivery status tracking");
    println!("6. Configure rate limiting for production use");

    println!("\n✨ SMSKit provides:");
    println!("   • Multi-provider support with automatic fallback");
    println!("   • Enhanced rate limiting and security");
    println!("   • Webhook support for delivery tracking");
    println!("   • Better error handling and logging");
    println!("   • Production-ready scalability");

    println!("\n🎉 SMSKit integration demonstration complete!");

    Ok(())
}
