use auth_framework::{AuthFramework, AuthConfig};
use auth_framework::methods::{ApiKeyMethod, JwtMethod};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("🔑 Auth Framework - API Keys Example");
    println!("====================================");

    // 1. Configure the auth framework
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(7200)) // 2 hours
        .max_failed_attempts(5);

    let mut auth = AuthFramework::new(config);

    // 2. Register API key authentication method
    let api_key_method = ApiKeyMethod::new()
        .key_prefix("ak_")
        .key_length(32);

    auth.register_method("api_key", Box::new(api_key_method));

    // Also register JWT for comparison
    let jwt_method = JwtMethod::new()
        .secret_key("very-secure-jwt-secret-key-for-comparison")
        .issuer("auth-framework-demo")
        .audience("api-service");

    auth.register_method("jwt", Box::new(jwt_method));

    auth.initialize().await?;
    println!("✅ Auth framework initialized");

    // 3. Demonstrate API key creation and management
    demonstrate_api_key_creation(&auth).await?;
    demonstrate_api_key_validation(&auth).await?;
    demonstrate_api_key_rotation(&auth).await?;
    demonstrate_rate_limiting(&auth).await?;

    println!("\n🎉 API Keys example completed successfully!");
    Ok(())
}

async fn demonstrate_api_key_creation(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📝 Creating API Keys");
    println!("===================");

    // Create various API keys with different expiration times
    let services = vec![
        ("service1", Duration::from_secs(3600)),     // 1 hour
        ("service2", Duration::from_secs(86400)),    // 24 hours
        ("service3", Duration::from_secs(604800)),   // 1 week
    ];

    for (service_name, duration) in services {
        let user_id = &format!("user_{}", service_name);
        let api_key = auth.create_api_key(user_id, Some(duration)).await?;
        println!("✅ Created API key for {}: {}", service_name, api_key);
    }

    // Create a long-lived API key
    let long_lived_key = auth.create_api_key(
        "long_lived_service",
        Some(Duration::from_secs(365 * 24 * 3600)), // 1 year
    ).await?;
    println!("✅ Created long-lived API key: {}", long_lived_key);

    Ok(())
}

async fn demonstrate_api_key_validation(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔍 Validating API Keys");
    println!("======================");

    // Create a test API key
    let test_key = auth.create_api_key(
        "test_validation_user",
        Some(Duration::from_secs(3600)),
    ).await?;
    println!("✅ Created test API key: {}", test_key);

    // Validate the API key
    match auth.validate_api_key(&test_key).await {
        Ok(user_info) => {
            println!("✅ API key validation successful:");
            println!("   - User ID: {}", user_info.id);
            println!("   - Username: {}", user_info.username);
            println!("   - Active: {}", user_info.active);
            println!("   - Roles: {:?}", user_info.roles);
        }
        Err(e) => {
            println!("❌ API key validation failed: {}", e);
        }
    }

    // Test with an invalid API key
    let invalid_key = "ak_invalid_key_for_testing";
    match auth.validate_api_key(invalid_key).await {
        Ok(_) => println!("❌ Invalid API key was accepted (shouldn't happen!)"),
        Err(e) => println!("✅ Invalid API key correctly rejected: {}", e),
    }

    Ok(())
}

async fn demonstrate_api_key_rotation(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔄 API Key Rotation");
    println!("==================");

    // Create an original API key
    let original_key = auth.create_api_key(
        "rotation_test_service",
        Some(Duration::from_secs(3600)),
    ).await?;
    println!("✅ Created original API key: {}", original_key);

    // Validate the original key
    match auth.validate_api_key(&original_key).await {
        Ok(_) => println!("✅ Original API key is valid"),
        Err(e) => println!("❌ Original API key validation failed: {}", e),
    }

    // Revoke the original key
    auth.revoke_api_key(&original_key).await?;
    println!("✅ Original API key revoked");

    // Try to validate the revoked key (should fail)
    match auth.validate_api_key(&original_key).await {
        Ok(_) => println!("❌ Revoked API key was accepted (shouldn't happen!)"),
        Err(e) => println!("✅ Revoked API key correctly rejected: {}", e),
    }

    // Create a new API key as replacement
    let new_key = auth.create_api_key(
        "rotation_test_service",
        Some(Duration::from_secs(3600)),
    ).await?;
    println!("✅ Created new API key: {}", new_key);

    // Validate the new key
    match auth.validate_api_key(&new_key).await {
        Ok(_) => println!("✅ New API key is valid"),
        Err(e) => println!("❌ New API key validation failed: {}", e),
    }

    Ok(())
}

async fn demonstrate_rate_limiting(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⚡ Rate Limiting Test");
    println!("====================");

    // Create a test API key
    let test_key = auth.create_api_key(
        "rate_limit_test",
        Some(Duration::from_secs(3600)),
    ).await?;
    println!("✅ Created test API key for rate limiting: {}", test_key);

    // Simulate multiple API calls
    let mut successful_calls = 0;
    let mut rate_limited_calls = 0;

    for i in 1..=20 {
        match auth.validate_api_key(&test_key).await {
            Ok(_) => {
                successful_calls += 1;
                println!("✅ API call {} successful", i);
            }
            Err(e) => {
                rate_limited_calls += 1;
                println!("⚠️  API call {} rate limited: {}", i, e);
            }
        }
        
        // Small delay between calls
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    println!("\n📊 Rate Limiting Results:");
    println!("   - Successful calls: {}", successful_calls);
    println!("   - Rate limited calls: {}", rate_limited_calls);
    println!("   - Total calls: {}", successful_calls + rate_limited_calls);

    Ok(())
}
