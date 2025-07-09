use auth_framework::{AuthFramework, AuthConfig, AuthResult};
use auth_framework::methods::{ApiKeyMethod, JwtMethod};
use auth_framework::storage::MemoryStorage;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("🔑 Auth Framework - API Keys Example");
    println!("====================================");

    // 1. Configure the auth framework
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(7200)) // 2 hours
        .max_failed_attempts(5)
        .lockout_duration(Duration::from_secs(300)); // 5 minutes

    let storage = Arc::new(MemoryStorage::new());
    let mut auth = AuthFramework::new(config).with_storage(storage);

    // 2. Register API key authentication method
    let api_key_method = ApiKeyMethod::new()
        .key_prefix("ak_")
        .key_length(32)
        .require_scopes(vec!["api:read".to_string(), "api:write".to_string()]);

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
    await demonstrate_api_key_creation(&auth).await?;
    await demonstrate_api_key_validation(&auth).await?;
    await demonstrate_api_key_scopes(&auth).await?;
    await demonstrate_api_key_rotation(&auth).await?;
    await demonstrate_rate_limiting(&auth).await?;

    println!("\n🎉 API Keys example completed successfully!");
    println!("Next steps:");
    println!("- Try the MFA example: cargo run --example mfa");
    println!("- Try the permissions example: cargo run --example permissions");
    println!("- Try the middleware example: cargo run --example middleware");

    Ok(())
}

async fn demonstrate_api_key_creation(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔨 Creating API Keys:");
    println!("===================");

    // Create API keys for different services
    let services = vec![
        ("web-service", vec!["api:read".to_string(), "api:write".to_string()]),
        ("mobile-app", vec!["api:read".to_string(), "user:profile".to_string()]),
        ("analytics", vec!["api:read".to_string(), "analytics:view".to_string()]),
        ("admin-tool", vec!["api:read".to_string(), "api:write".to_string(), "admin:manage".to_string()]),
    ];

    for (service_name, scopes) in services {
        let api_key = auth.create_api_key(
            &format!("service_{}", service_name),
            scopes.clone(),
            Some(Duration::from_secs(86400)), // 24 hours
        ).await?;

        println!("📱 Created API key for {}:", service_name);
        println!("   Key: {}", api_key);
        println!("   Scopes: {:?}", scopes);
        println!("   Expires: 24 hours from now");
    }

    // Create a long-lived API key
    let long_lived_key = auth.create_api_key(
        "long_lived_service",
        vec!["api:read".to_string()],
        Some(Duration::from_secs(365 * 24 * 3600)), // 1 year
    ).await?;

    println!("🗓️  Long-lived API key: {}", long_lived_key);

    Ok(())
}

async fn demonstrate_api_key_validation(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔍 Validating API Keys:");
    println!("======================");

    // Create a test API key
    let test_key = auth.create_api_key(
        "test_validation_user",
        vec!["api:read".to_string(), "api:write".to_string()],
        Some(Duration::from_secs(3600)),
    ).await?;

    println!("🧪 Test API key created: {}", test_key);

    // Validate the API key
    match auth.validate_api_key(&test_key).await {
        Ok(user_info) => {
            println!("✅ API key validation successful:");
            println!("   User ID: {}", user_info.id);
            println!("   Username: {}", user_info.username);
            println!("   Active: {}", user_info.active);
        }
        Err(e) => {
            println!("❌ API key validation failed: {}", e);
        }
    }

    // Test with invalid key
    let invalid_key = "ak_invalid_key_123456789";
    match auth.validate_api_key(invalid_key).await {
        Ok(_) => println!("❌ Invalid key was accepted (this shouldn't happen!)"),
        Err(e) => println!("✅ Invalid key properly rejected: {}", e),
    }

    // Test with malformed key
    let malformed_key = "not_an_api_key";
    match auth.validate_api_key(malformed_key).await {
        Ok(_) => println!("❌ Malformed key was accepted (this shouldn't happen!)"),
        Err(e) => println!("✅ Malformed key properly rejected: {}", e),
    }

    Ok(())
}

async fn demonstrate_api_key_scopes(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🎯 Testing API Key Scopes:");
    println!("=========================");

    // Create API keys with different scopes
    let read_only_key = auth.create_api_key(
        "read_only_service",
        vec!["api:read".to_string()],
        Some(Duration::from_secs(3600)),
    ).await?;

    let full_access_key = auth.create_api_key(
        "full_access_service",
        vec!["api:read".to_string(), "api:write".to_string(), "admin:manage".to_string()],
        Some(Duration::from_secs(3600)),
    ).await?;

    println!("🔑 Read-only key: {}", read_only_key);
    println!("🔑 Full access key: {}", full_access_key);

    // Test scope validation
    let test_operations = vec![
        ("api:read", "Reading API data"),
        ("api:write", "Writing API data"),
        ("admin:manage", "Managing admin settings"),
        ("user:delete", "Deleting users"),
    ];

    for (scope, description) in test_operations {
        println!("\n📋 Testing operation: {} ({})", scope, description);
        
        // Test read-only key
        if let Ok(user_info) = auth.validate_api_key(&read_only_key).await {
            let has_permission = auth.check_permission(&user_info.id, scope, "system").await?;
            println!("   Read-only key: {}", if has_permission { "✅ Allowed" } else { "❌ Denied" });
        }

        // Test full access key
        if let Ok(user_info) = auth.validate_api_key(&full_access_key).await {
            let has_permission = auth.check_permission(&user_info.id, scope, "system").await?;
            println!("   Full access key: {}", if has_permission { "✅ Allowed" } else { "❌ Denied" });
        }
    }

    Ok(())
}

async fn demonstrate_api_key_rotation(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔄 API Key Rotation:");
    println!("===================");

    // Create an API key
    let original_key = auth.create_api_key(
        "rotation_test_service",
        vec!["api:read".to_string(), "api:write".to_string()],
        Some(Duration::from_secs(3600)),
    ).await?;

    println!("🔑 Original API key: {}", original_key);

    // Validate it works
    match auth.validate_api_key(&original_key).await {
        Ok(_) => println!("✅ Original key is valid"),
        Err(e) => println!("❌ Original key validation failed: {}", e),
    }

    // Revoke the original key
    auth.revoke_api_key(&original_key).await?;
    println!("🚫 Original key revoked");

    // Test that revoked key no longer works
    match auth.validate_api_key(&original_key).await {
        Ok(_) => println!("❌ Revoked key still works (this shouldn't happen!)"),
        Err(_) => println!("✅ Revoked key properly rejected"),
    }

    // Create a new key for the same service
    let new_key = auth.create_api_key(
        "rotation_test_service",
        vec!["api:read".to_string(), "api:write".to_string()],
        Some(Duration::from_secs(3600)),
    ).await?;

    println!("🔑 New API key: {}", new_key);

    // Validate new key works
    match auth.validate_api_key(&new_key).await {
        Ok(_) => println!("✅ New key is valid and working"),
        Err(e) => println!("❌ New key validation failed: {}", e),
    }

    Ok(())
}

async fn demonstrate_rate_limiting(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⏱️  Rate Limiting:");
    println!("=================");

    // Create an API key for testing
    let test_key = auth.create_api_key(
        "rate_limit_test",
        vec!["api:read".to_string()],
        Some(Duration::from_secs(3600)),
    ).await?;

    println!("🔑 Testing rate limits with key: {}", test_key);

    // Simulate multiple API calls
    let mut successful_calls = 0;
    let mut rate_limited_calls = 0;

    for i in 1..=20 {
        match auth.validate_api_key(&test_key).await {
            Ok(_) => {
                successful_calls += 1;
                println!("   Call {}: ✅ Success", i);
            }
            Err(e) => {
                rate_limited_calls += 1;
                println!("   Call {}: ⏸️  Rate limited - {}", i, e);
            }
        }

        // Small delay between calls
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    println!("\n📊 Rate limiting results:");
    println!("   Successful calls: {}", successful_calls);
    println!("   Rate limited calls: {}", rate_limited_calls);

    if rate_limited_calls > 0 {
        println!("✅ Rate limiting is working correctly");
    } else {
        println!("ℹ️  No rate limiting triggered (limits may be high for demo)");
    }

    Ok(())
}
