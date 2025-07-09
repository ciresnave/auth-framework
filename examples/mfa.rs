use auth_framework::{AuthFramework, AuthConfig, AuthResult};
use auth_framework::methods::{JwtMethod, MfaMethod};
use auth_framework::storage::MemoryStorage;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

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
        .mfa_validity_duration(Duration::from_secs(300)) // 5 minutes
        .max_failed_attempts(3);

    let storage = Arc::new(MemoryStorage::new());
    let mut auth = AuthFramework::new(config).with_storage(storage);

    // 2. Register authentication methods
    let jwt_method = JwtMethod::new()
        .secret_key("very-secure-jwt-secret-key-for-mfa-demo")
        .issuer("auth-framework-mfa-demo")
        .audience("secure-service");

    auth.register_method("jwt", Box::new(jwt_method));

    // Register MFA methods
    let totp_method = MfaMethod::new()
        .method_type("totp")
        .issuer("AuthFramework Demo")
        .key_length(32);

    let sms_method = MfaMethod::new()
        .method_type("sms")
        .code_length(6)
        .validity_duration(Duration::from_secs(300));

    let email_method = MfaMethod::new()
        .method_type("email")
        .code_length(8)
        .validity_duration(Duration::from_secs(600));

    auth.register_mfa_method("totp", Box::new(totp_method));
    auth.register_mfa_method("sms", Box::new(sms_method));
    auth.register_mfa_method("email", Box::new(email_method));

    auth.initialize().await?;
    println!("✅ Auth framework initialized with MFA support");

    // 3. Demonstrate MFA workflows
    demonstrate_totp_setup(&auth).await?;
    demonstrate_sms_authentication(&auth).await?;
    demonstrate_email_authentication(&auth).await?;
    demonstrate_backup_codes(&auth).await?;
    demonstrate_mfa_recovery(&auth).await?;
    demonstrate_adaptive_mfa(&auth).await?;

    println!("\n🎉 MFA example completed successfully!");
    println!("Next steps:");
    println!("- Try the permissions example: cargo run --example permissions");
    println!("- Try the middleware example: cargo run --example middleware");

    Ok(())
}

async fn demonstrate_totp_setup(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📱 TOTP (Time-based One-Time Password) Setup:");
    println!("=============================================");

    let user_id = "totp_user_123";
    
    // 1. Generate TOTP secret for user
    let totp_secret = auth.generate_totp_secret(user_id).await?;
    println!("🔑 TOTP Secret generated for user {}", user_id);
    println!("   Secret: {} (Keep this secure!)", totp_secret);

    // 2. Generate QR code data for authenticator apps
    let qr_code_url = auth.generate_totp_qr_code(user_id, "AuthFramework Demo", &totp_secret).await?;
    println!("📱 QR Code URL for authenticator app:");
    println!("   {}", qr_code_url);
    println!("   👆 Scan this with Google Authenticator, Authy, etc.");

    // 3. Verify TOTP setup (simulate user entering code)
    println!("\n🔍 Verifying TOTP setup:");
    
    // Generate a TOTP code (simulate what authenticator app would show)
    let current_code = auth.generate_totp_code(&totp_secret).await?;
    println!("📟 Current TOTP code: {} (valid for 30 seconds)", current_code);

    // Verify the code
    match auth.verify_totp_code(user_id, &current_code).await {
        Ok(()) => {
            println!("✅ TOTP verification successful!");
            println!("   User can now use TOTP for 2FA");
        }
        Err(e) => {
            println!("❌ TOTP verification failed: {}", e);
        }
    }

    // Test invalid code
    match auth.verify_totp_code(user_id, "000000").await {
        Ok(()) => println!("❌ Invalid TOTP code was accepted (shouldn't happen!)"),
        Err(_) => println!("✅ Invalid TOTP code properly rejected"),
    }

    Ok(())
}

async fn demonstrate_sms_authentication(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📨 SMS-based Authentication:");
    println!("===========================");

    let user_id = "sms_user_456";
    let phone_number = "+1-555-0123";

    // 1. Register phone number for user
    auth.register_phone_number(user_id, phone_number).await?;
    println!("📞 Phone number registered for user {}: {}", user_id, phone_number);

    // 2. Initiate SMS MFA challenge
    let challenge_id = auth.initiate_sms_challenge(user_id).await?;
    println!("📱 SMS challenge initiated. Challenge ID: {}", challenge_id);
    println!("   📨 SMS sent to {} (simulated)", phone_number);

    // 3. Generate verification code (simulate SMS code)
    let sms_code = auth.generate_sms_code(&challenge_id).await?;
    println!("💬 SMS Code: {} (expires in 5 minutes)", sms_code);

    // 4. Verify SMS code
    match auth.verify_sms_code(&challenge_id, &sms_code).await {
        Ok(()) => {
            println!("✅ SMS verification successful!");
            println!("   User authenticated via SMS");
        }
        Err(e) => {
            println!("❌ SMS verification failed: {}", e);
        }
    }

    // 5. Test expired code handling
    println!("\n⏰ Testing expired SMS codes:");
    tokio::time::sleep(Duration::from_millis(100)).await; // Simulate time passing
    
    // Try to use the same code again
    match auth.verify_sms_code(&challenge_id, &sms_code).await {
        Ok(()) => println!("❌ Used SMS code was accepted (replay attack!)"),
        Err(_) => println!("✅ Used SMS code properly rejected (prevents replay)"),
    }

    Ok(())
}

async fn demonstrate_email_authentication(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📧 Email-based Authentication:");
    println!("=============================");

    let user_id = "email_user_789";
    let email = "user@example.com";

    // 1. Register email for user
    auth.register_email(user_id, email).await?;
    println!("📧 Email registered for user {}: {}", user_id, email);

    // 2. Initiate email MFA challenge
    let challenge_id = auth.initiate_email_challenge(user_id).await?;
    println!("📬 Email challenge initiated. Challenge ID: {}", challenge_id);
    println!("   📧 Verification email sent to {} (simulated)", email);

    // 3. Generate verification code (simulate email code)
    let email_code = auth.generate_email_code(&challenge_id).await?;
    println!("🔢 Email Code: {} (expires in 10 minutes)", email_code);

    // 4. Verify email code
    match auth.verify_email_code(&challenge_id, &email_code).await {
        Ok(()) => {
            println!("✅ Email verification successful!");
            println!("   User authenticated via email");
        }
        Err(e) => {
            println!("❌ Email verification failed: {}", e);
        }
    }

    // 5. Test case sensitivity
    let uppercase_code = email_code.to_uppercase();
    match auth.verify_email_code(&challenge_id, &uppercase_code).await {
        Ok(()) => println!("✅ Email codes are case-insensitive"),
        Err(_) => println!("ℹ️  Email codes are case-sensitive"),
    }

    Ok(())
}

async fn demonstrate_backup_codes(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔒 Backup Codes:");
    println!("===============");

    let user_id = "backup_user_321";

    // 1. Generate backup codes
    let backup_codes = auth.generate_backup_codes(user_id, 10).await?;
    println!("🎫 Generated {} backup codes for user {}:", backup_codes.len(), user_id);
    
    for (i, code) in backup_codes.iter().enumerate() {
        println!("   {}. {}", i + 1, code);
    }
    println!("   💾 Store these codes securely - they can only be used once each");

    // 2. Use a backup code
    let first_code = &backup_codes[0];
    println!("\n🔑 Testing backup code: {}", first_code);

    match auth.verify_backup_code(user_id, first_code).await {
        Ok(()) => {
            println!("✅ Backup code verification successful!");
            println!("   This code is now marked as used");
        }
        Err(e) => {
            println!("❌ Backup code verification failed: {}", e);
        }
    }

    // 3. Try to reuse the same backup code
    match auth.verify_backup_code(user_id, first_code).await {
        Ok(()) => println!("❌ Used backup code was accepted (shouldn't happen!)"),
        Err(_) => println!("✅ Used backup code properly rejected"),
    }

    // 4. Check remaining backup codes
    let remaining_codes = auth.get_remaining_backup_codes(user_id).await?;
    println!("📊 Backup codes status:");
    println!("   Remaining codes: {}", remaining_codes);
    println!("   Used codes: {}", backup_codes.len() - remaining_codes);

    Ok(())
}

async fn demonstrate_mfa_recovery(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🆘 MFA Recovery Process:");
    println!("=======================");

    let user_id = "recovery_user_654";
    let recovery_email = "recovery@example.com";

    // 1. Set up recovery email
    auth.set_recovery_email(user_id, recovery_email).await?;
    println!("🔐 Recovery email set for user {}: {}", user_id, recovery_email);

    // 2. Simulate user losing access to MFA device
    println!("\n📱 Simulating lost MFA device scenario...");
    println!("   User has lost their phone with authenticator app");
    println!("   User needs to recover account access");

    // 3. Initiate recovery process
    let recovery_token = auth.initiate_mfa_recovery(user_id).await?;
    println!("🔑 MFA recovery initiated. Recovery token: {}", recovery_token);
    println!("   📧 Recovery instructions sent to {}", recovery_email);

    // 4. Verify recovery token
    match auth.verify_recovery_token(user_id, &recovery_token).await {
        Ok(()) => {
            println!("✅ Recovery token verified!");
            println!("   User can now reset their MFA settings");
        }
        Err(e) => {
            println!("❌ Recovery token verification failed: {}", e);
        }
    }

    // 5. Reset MFA settings
    auth.reset_mfa_settings(user_id).await?;
    println!("🔄 MFA settings reset for user");
    println!("   User can now set up new MFA methods");

    // 6. Generate new backup codes
    let new_backup_codes = auth.generate_backup_codes(user_id, 10).await?;
    println!("🎫 New backup codes generated: {} codes", new_backup_codes.len());

    Ok(())
}

async fn demonstrate_adaptive_mfa(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🧠 Adaptive MFA (Risk-based Authentication):");
    println!("============================================");

    let user_id = "adaptive_user_987";

    // 1. Simulate different risk scenarios
    let scenarios = vec![
        ("low", "Same device, same location, normal hours"),
        ("medium", "New device, same location, normal hours"),
        ("high", "New device, new location, unusual hours"),
        ("critical", "Multiple failed attempts, suspicious IP"),
    ];

    for (risk_level, description) in scenarios {
        println!("\n🎯 Risk Level: {} - {}", risk_level.to_uppercase(), description);

        // Get MFA requirements based on risk
        let mfa_requirements = auth.get_adaptive_mfa_requirements(user_id, risk_level).await?;
        
        println!("   Required MFA methods: {:?}", mfa_requirements.required_methods);
        println!("   Allow backup codes: {}", mfa_requirements.allow_backup_codes);
        println!("   Session duration: {:?}", mfa_requirements.session_duration);

        // Simulate MFA based on risk level
        match risk_level {
            "low" => {
                println!("   ✅ Low risk: No additional MFA required");
            }
            "medium" => {
                println!("   📱 Medium risk: TOTP required");
                // Would initiate TOTP challenge
            }
            "high" => {
                println!("   🔐 High risk: TOTP + SMS required");
                // Would initiate multiple MFA challenges
            }
            "critical" => {
                println!("   🚨 Critical risk: Full MFA + manual review");
                // Would require manual admin approval
            }
            _ => {}
        }
    }

    // 2. Demonstrate continuous authentication
    println!("\n🔄 Continuous Authentication:");
    println!("   Monitoring user behavior during session...");
    
    let behavior_changes = vec![
        "Typing pattern changed",
        "Mouse movement unusual",
        "Access from new IP",
        "Unusual API usage pattern",
    ];

    for change in behavior_changes {
        println!("   🔍 Detected: {}", change);
        
        // Check if re-authentication is needed
        let needs_reauth = auth.evaluate_continuous_auth(user_id, change).await?;
        if needs_reauth {
            println!("     ⚠️  Re-authentication required");
        } else {
            println!("     ✅ Behavior within normal parameters");
        }
    }

    Ok(())
}
