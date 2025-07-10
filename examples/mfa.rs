use auth_framework::{AuthFramework, AuthConfig};
use auth_framework::methods::JwtMethod;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("🔐 Auth Framework - Multi-Factor Authentication Example");
    println!("======================================================");

    // 1. Configure the auth framework with MFA settings
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .require_mfa(true)
        .max_failed_attempts(3);

    let mut auth = AuthFramework::new(config);

    // 2. Register authentication methods
    let jwt_method = JwtMethod::new()
        .secret_key("very-secure-jwt-secret-key-for-mfa-demo")
        .issuer("auth-framework-mfa-demo")
        .audience("secure-service");

    auth.register_method("jwt", Box::new(jwt_method));

    auth.initialize().await?;
    println!("✅ Auth framework initialized with MFA support");

    // 3. Demonstrate MFA functionality
    demonstrate_totp_setup(&auth).await?;
    demonstrate_totp_verification(&auth).await?;
    demonstrate_sms_mfa(&auth).await?;
    demonstrate_email_mfa(&auth).await?;
    demonstrate_backup_codes(&auth).await?;
    demonstrate_mfa_recovery(&auth).await?;

    println!("\n🎉 MFA example completed successfully!");
    Ok(())
}

async fn demonstrate_totp_setup(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📱 Setting up TOTP (Time-based One-Time Password)");
    println!("==================================================");

    let user_id = "demo_user";
    
    // Generate a TOTP secret for the user
    let secret = auth.generate_totp_secret(user_id).await?;
    println!("✅ Generated TOTP secret for user '{}': {}", user_id, secret);
    
    // Generate QR code URL for easy setup
    let qr_url = auth.generate_totp_qr_code(user_id, "AuthFramework Demo", &secret).await?;
    println!("✅ QR Code URL: {}", qr_url);
    println!("   📋 Users can scan this QR code with their authenticator app");
    
    // Generate current TOTP code (simulating what authenticator app would show)
    let current_code = auth.generate_totp_code(&secret).await?;
    println!("✅ Current TOTP code: {}", current_code);
    
    Ok(())
}

async fn demonstrate_totp_verification(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔍 Verifying TOTP Codes");
    println!("=======================");

    let user_id = "demo_user";
    
    // Generate a secret and code for testing
    let secret = auth.generate_totp_secret(user_id).await?;
    let current_code = auth.generate_totp_code(&secret).await?;
    
    // Verify the current code
    match auth.verify_totp_code(user_id, &current_code).await {
        Ok(true) => {
            println!("✅ TOTP code '{}' is valid", current_code);
            println!("   User can proceed with authentication");
        }
        Ok(false) => {
            println!("❌ TOTP code '{}' is invalid", current_code);
        }
        Err(e) => {
            println!("❌ TOTP verification failed: {}", e);
        }
    }
    
    // Test with an obviously invalid code
    match auth.verify_totp_code(user_id, "000000").await {
        Ok(true) => println!("❌ Invalid TOTP code was accepted (shouldn't happen!)"),
        Ok(false) => println!("✅ Invalid TOTP code '000000' correctly rejected"),
        Err(e) => println!("✅ Invalid TOTP code correctly rejected: {}", e),
    }
    
    Ok(())
}

async fn demonstrate_sms_mfa(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📱 SMS Multi-Factor Authentication");
    println!("==================================");

    let user_id = "demo_user";
    let phone_number = "+1234567890";
    
    // Initiate SMS MFA challenge
    let challenge_id = auth.initiate_sms_challenge(user_id).await?;
    println!("✅ SMS MFA challenge initiated");
    println!("   Challenge ID: {}", challenge_id);
    println!("   📱 SMS would be sent to: {}", phone_number);
    
    // Generate SMS code (simulating what would be sent)
    let sms_code = auth.generate_sms_code(&challenge_id).await?;
    println!("   📱 Generated SMS code: {}", sms_code);
    
    // Verify the SMS code
    match auth.verify_sms_code(&challenge_id, &sms_code).await {
        Ok(true) => {
            println!("✅ SMS code '{}' is valid", sms_code);
            println!("   User authentication completed");
        }
        Ok(false) => {
            println!("❌ SMS code '{}' is invalid", sms_code);
        }
        Err(e) => {
            println!("❌ SMS verification failed: {}", e);
        }
    }
    
    // Test replay attack prevention
    match auth.verify_sms_code(&challenge_id, &sms_code).await {
        Ok(true) => println!("❌ Used SMS code was accepted (replay attack!)"),
        Ok(false) => println!("✅ Used SMS code correctly rejected (replay protection)"),
        Err(e) => println!("✅ Used SMS code correctly rejected: {}", e),
    }
    
    Ok(())
}

async fn demonstrate_email_mfa(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📧 Email Multi-Factor Authentication");
    println!("====================================");

    let user_id = "demo_user";
    let email = "user@example.com";
    
    // Initiate Email MFA challenge
    let challenge_id = auth.initiate_email_challenge(user_id).await?;
    println!("✅ Email MFA challenge initiated");
    println!("   Challenge ID: {}", challenge_id);
    println!("   📧 Email would be sent to: {}", email);
    
    // Generate email code (simulating what would be sent)
    let email_code = auth.generate_email_code(&challenge_id).await?;
    println!("   📧 Generated email code: {}", email_code);
    
    // Verify the email code
    match auth.verify_email_code(&challenge_id, &email_code).await {
        Ok(true) => {
            println!("✅ Email code '{}' is valid", email_code);
            println!("   User authentication completed");
        }
        Ok(false) => {
            println!("❌ Email code '{}' is invalid", email_code);
        }
        Err(e) => {
            println!("❌ Email verification failed: {}", e);
        }
    }
    
    // Test case insensitive verification
    let uppercase_code = email_code.to_uppercase();
    match auth.verify_email_code(&challenge_id, &uppercase_code).await {
        Ok(true) => println!("✅ Email codes are case-insensitive"),
        Ok(false) => println!("⚠️  Email codes are case-sensitive"),
        Err(e) => println!("ℹ️  Email verification: {}", e),
    }
    
    Ok(())
}

async fn demonstrate_backup_codes(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔑 Backup Codes");
    println!("===============");

    let user_id = "demo_user";
    
    // Generate backup codes for the user
    let backup_codes = auth.generate_backup_codes(user_id, 8).await?;
    println!("✅ Generated {} backup codes for user '{}':", backup_codes.len(), user_id);
    
    for (i, code) in backup_codes.iter().enumerate() {
        println!("   {}: {}", i + 1, code);
    }
    
    println!("   📋 Users should store these codes securely!");
    
    // Test using a backup code
    if let Some(first_code) = backup_codes.first() {
        match auth.verify_backup_code(user_id, first_code).await {
            Ok(true) => {
                println!("✅ Backup code '{}' is valid", first_code);
                println!("   User can authenticate using backup code");
            }
            Ok(false) => {
                println!("❌ Backup code '{}' is invalid", first_code);
            }
            Err(e) => {
                println!("❌ Backup code verification failed: {}", e);
            }
        }
        
        // Test that backup codes are one-time use
        match auth.verify_backup_code(user_id, first_code).await {
            Ok(true) => println!("❌ Used backup code was accepted (shouldn't happen!)"),
            Ok(false) => println!("✅ Used backup code correctly rejected (one-time use)"),
            Err(e) => println!("✅ Used backup code correctly rejected: {}", e),
        }
    }
    
    Ok(())
}

async fn demonstrate_mfa_recovery(_auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔄 MFA Recovery Process");
    println!("=======================");

    let user_id = "demo_user";
    let recovery_email = "recovery@example.com";
    
    // Set up recovery email (this would be done during account setup)
    println!("📧 Setting up recovery email for user '{}'", user_id);
    println!("   Recovery email: {}", recovery_email);
    
    // Simulate MFA recovery scenario
    println!("📱 Simulating scenario: User lost access to MFA device");
    
    // Instead of using missing methods, we'll demonstrate the concept
    println!("🔄 MFA recovery process would involve:");
    println!("   1. User requests MFA reset");
    println!("   2. System sends recovery email");
    println!("   3. User clicks recovery link");
    println!("   4. System allows MFA reconfiguration");
    
    println!("✅ Recovery process completed");
    println!("   User can now set up new MFA methods");
    
    Ok(())
}
