use auth_framework::{AuthFramework, AuthConfig};
use auth_framework::methods::{JwtMethod, ApiKeyMethod};
use auth_framework::credentials::Credential;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("🔒 Auth Framework - Security Audit Example");
    println!("==========================================");

    // Set up the auth framework with security settings
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .enable_rbac(true)
        .max_failed_attempts(3);

    let mut auth = AuthFramework::new(config);

    // Register secure authentication methods
    let jwt_method = JwtMethod::new()
        .secret_key("very-secure-secret-key-for-security-audit-demo")
        .issuer("security-audit-demo")
        .audience("secure-service");

    let api_key_method = ApiKeyMethod::new()
        .key_prefix("sec_")
        .key_length(32);

    auth.register_method("jwt", Box::new(jwt_method));
    auth.register_method("api_key", Box::new(api_key_method));

    auth.initialize().await?;
    println!("✅ Auth framework initialized with security features");

    // Run security audit tests
    audit_authentication_security(&auth).await?;
    audit_token_security(&auth).await?;
    audit_permission_security(&auth).await?;
    audit_rate_limiting(&auth).await?;
    audit_api_key_security(&auth).await?;

    println!("\n🎯 Security Audit Complete!");
    println!("   Review findings and implement recommendations for production use.");

    Ok(())
}

async fn audit_authentication_security(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔐 Authentication Security Audit");
    println!("================================");

    // Test weak password attempts
    let weak_passwords = vec![
        "123456",
        "password",
        "qwerty",
        "abc123",
        "admin",
    ];

    let test_user = "security_test_user";
    let mut failed_attempts = 0;

    for weak_password in &weak_passwords {
        let credential = Credential::Password {
            username: test_user.to_string(),
            password: weak_password.to_string(),
        };

        match auth.authenticate("jwt", credential).await {
            Ok(_) => {
                println!("   ⚠️  WEAK PASSWORD ACCEPTED: '{}'", weak_password);
            }
            Err(_) => {
                failed_attempts += 1;
                println!("   ✅ Weak password rejected: '{}'", weak_password);
            }
        }
    }

    println!("   📊 Weak password test results:");
    println!("      - Total attempts: {}", weak_passwords.len());
    println!("      - Rejected: {}", failed_attempts);
    println!("      - Security score: {:.1}%", 
             (failed_attempts as f64 / weak_passwords.len() as f64) * 100.0);

    // Test brute force protection
    println!("\n🛡️  Brute Force Protection Test:");
    let brute_force_attempts = 10;
    let mut blocked_attempts = 0;

    for i in 1..=brute_force_attempts {
        let credential = Credential::Password {
            username: format!("brute_force_user_{}", i),
            password: "wrong_password".to_string(),
        };

        match auth.authenticate("jwt", credential).await {
            Ok(_) => {
                println!("   ⚠️  Attempt {}: Authentication succeeded (unexpected)", i);
            }
            Err(err) => {
                if err.to_string().contains("rate limit") || err.to_string().contains("locked") {
                    blocked_attempts += 1;
                    println!("   ✅ Attempt {}: Blocked by protection", i);
                } else {
                    println!("   ❌ Attempt {}: Failed normally", i);
                }
            }
        }
    }

    println!("   📊 Brute force protection results:");
    println!("      - Total attempts: {}", brute_force_attempts);
    println!("      - Blocked by protection: {}", blocked_attempts);

    Ok(())
}

async fn audit_token_security(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🎫 Token Security Audit");
    println!("=======================");

    // Create a test token
    let credential = Credential::Password {
        username: "token_test_user".to_string(),
        password: "SecurePassword123!".to_string(),
    };

    let auth_result = auth.authenticate("jwt", credential).await?;
    let token = match auth_result {
        auth_framework::AuthResult::Success(token) => *token,
        _ => return Err("Failed to create test token".into()),
    };

    println!("   ✅ Test token created successfully");

    // Test token validation
    let is_valid = auth.validate_token(&token).await?;
    if is_valid {
        println!("   ✅ Token validation working correctly");
    } else {
        println!("   ❌ Token validation failed unexpectedly");
    }

    // Test token expiration (simulated)
    println!("   📅 Token expiration check:");
    println!("      - Token expires at: {}", token.expires_at);
    println!("      - Current time: {}", chrono::Utc::now());
    
    let time_until_expiry = token.expires_at - chrono::Utc::now();
    if time_until_expiry.num_seconds() > 0 {
        println!("      - Time until expiry: {} seconds", time_until_expiry.num_seconds());
        println!("      - Status: ✅ Token not expired");
    } else {
        println!("      - Status: ⚠️  Token expired");
    }

    // Test token revocation
    println!("\n🔒 Token Revocation Test:");
    auth.revoke_token(&token).await?;
    println!("   ✅ Token revoked successfully");

    // Verify token is invalid after revocation
    match auth.validate_token(&token).await {
        Ok(false) => println!("   ✅ Revoked token correctly invalidated"),
        Ok(true) => println!("   ❌ Revoked token still valid (security issue!)"),
        Err(e) => println!("   ✅ Revoked token validation failed as expected: {}", e),
    }

    Ok(())
}

async fn audit_permission_security(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔐 Permission Security Audit");
    println!("============================");

    // Create a test token
    let credential = Credential::Password {
        username: "permission_test_user".to_string(),
        password: "SecurePassword123!".to_string(),
    };

    let auth_result = auth.authenticate("jwt", credential).await?;
    let token = match auth_result {
        auth_framework::AuthResult::Success(token) => *token,
        _ => return Err("Failed to create test token".into()),
    };

    // Test various permission levels
    let permission_tests = vec![
        ("read", "public_content", "Should be allowed for most users"),
        ("write", "user_profile", "Should be allowed for authenticated users"),
        ("delete", "user_data", "Should require special permissions"),
        ("admin", "system_settings", "Should be restricted to administrators"),
        ("execute", "dangerous_operation", "Should be highly restricted"),
    ];

    println!("   🧪 Permission Tests:");
    for (action, resource, description) in permission_tests {
        match auth.check_permission(&token, action, resource).await {
            Ok(true) => {
                println!("   ✅ GRANTED: {}:{} - {}", action, resource, description);
            }
            Ok(false) => {
                println!("   ❌ DENIED:  {}:{} - {}", action, resource, description);
            }
            Err(e) => {
                println!("   ⚠️  ERROR:   {}:{} - Error: {}", action, resource, e);
            }
        }
    }

    // Test privilege escalation attempts
    println!("\n🚨 Privilege Escalation Tests:");
    let escalation_attempts = vec![
        ("../admin", "system"),
        ("root", "all_resources"),
        ("*", "wildcard_resource"),
        ("sudo", "elevation"),
    ];

    for (malicious_action, target_resource) in escalation_attempts {
        match auth.check_permission(&token, malicious_action, target_resource).await {
            Ok(true) => {
                println!("   🚨 SECURITY ISSUE: Escalation succeeded for {}:{}", 
                        malicious_action, target_resource);
            }
            Ok(false) => {
                println!("   ✅ Escalation blocked: {}:{}", malicious_action, target_resource);
            }
            Err(_) => {
                println!("   ✅ Escalation failed: {}:{}", malicious_action, target_resource);
            }
        }
    }

    Ok(())
}

async fn audit_rate_limiting(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⚡ Rate Limiting Audit");
    println!("=====================");

    let user_id = "rate_limit_test_user";
    let test_attempts = 20;
    let mut successful_attempts = 0;
    let mut rate_limited_attempts = 0;

    println!("   🧪 Testing {} rapid authentication attempts...", test_attempts);

    for i in 1..=test_attempts {
        let credential = Credential::Password {
            username: user_id.to_string(),
            password: format!("attempt_{}", i),
        };

        match auth.authenticate("jwt", credential).await {
            Ok(_) => {
                successful_attempts += 1;
            }
            Err(err) => {
                if err.to_string().contains("rate limit") || err.to_string().contains("too many") {
                    rate_limited_attempts += 1;
                    if i <= 5 {
                        println!("   ⚡ Attempt {}: Rate limited", i);
                    }
                }
            }
        }

        // Small delay to simulate rapid attempts
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    println!("   📊 Rate Limiting Results:");
    println!("      - Total attempts: {}", test_attempts);
    println!("      - Successful: {}", successful_attempts);
    println!("      - Rate limited: {}", rate_limited_attempts);
    println!("      - Other failures: {}", test_attempts - successful_attempts - rate_limited_attempts);

    if rate_limited_attempts > 0 {
        println!("   ✅ Rate limiting is working");
    } else {
        println!("   ⚠️  No rate limiting detected - consider implementing");
    }

    Ok(())
}

async fn audit_api_key_security(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔐 API Key Security Audit");
    println!("=========================");

    // Create a test API key
    let api_key = auth.create_api_key("api_security_test_user", None).await?;
    println!("   ✅ Test API key created: {}", &api_key[..20]);

    // Test API key authentication
    let credential = Credential::ApiKey {
        key: api_key.clone(),
    };

    match auth.authenticate("api_key", credential).await {
        Ok(_) => {
            println!("   ✅ API key authentication successful");
        }
        Err(e) => {
            println!("   ❌ API key authentication failed: {}", e);
        }
    }

    // Test invalid API key
    let invalid_credential = Credential::ApiKey {
        key: "invalid_api_key_12345".to_string(),
    };

    match auth.authenticate("api_key", invalid_credential).await {
        Ok(_) => {
            println!("   🚨 SECURITY ISSUE: Invalid API key accepted!");
        }
        Err(_) => {
            println!("   ✅ Invalid API key correctly rejected");
        }
    }

    // Test API key prefix validation
    println!("   🧪 API Key Format Tests:");
    if api_key.starts_with("sec_") {
        println!("      - Prefix: ✅ Correct prefix 'sec_'");
    } else {
        println!("      - Prefix: ❌ Unexpected prefix");
    }

    if api_key.len() >= 32 {
        println!("      - Length: ✅ Adequate length ({} chars)", api_key.len());
    } else {
        println!("      - Length: ⚠️  Short length ({} chars)", api_key.len());
    }

    // Test API key entropy (basic check)
    let unique_chars: std::collections::HashSet<char> = api_key.chars().collect();
    let entropy_score = unique_chars.len() as f64 / api_key.len() as f64;
    
    if entropy_score > 0.5 {
        println!("      - Entropy: ✅ Good character diversity ({:.1}%)", entropy_score * 100.0);
    } else {
        println!("      - Entropy: ⚠️  Low character diversity ({:.1}%)", entropy_score * 100.0);
    }

    Ok(())
}
