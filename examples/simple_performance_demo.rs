//! Simple Performance Demo
//!
//! This example demonstrates the key optimizations working together.

use auth_framework::{
    AuthConfig, AuthFramework, Result,
    methods::{AuthMethodEnum, JwtMethod},
};

#[cfg(feature = "performance-optimization")]
use auth_framework::storage::unified::UnifiedStorage;

#[cfg(feature = "enhanced-observability")]
use auth_framework::observability::ObservabilityManager;

use std::time::Duration;
use tokio::time::Instant;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 AuthFramework Performance Demo");
    println!("==================================");

    // Test unified storage performance
    #[cfg(feature = "performance-optimization")]
    {
        println!("\n📊 Testing Unified Storage Performance...");
        test_unified_storage().await?;
    }

    // Test observability features
    #[cfg(feature = "enhanced-observability")]
    {
        println!("\n📈 Testing Enhanced Observability...");
        test_observability().await?;
    }

    // Test basic AuthFramework performance
    println!("\n⚡ Testing Core Framework Performance...");
    test_core_performance().await?;

    println!("\n✅ All performance tests completed successfully!");
    Ok(())
}

#[cfg(feature = "performance-optimization")]
async fn test_unified_storage() -> Result<()> {
    use auth_framework::storage::AuthStorage;

    let storage = UnifiedStorage::new();

    println!("  🔄 Creating test tokens...");
    let start = Instant::now();

    // Create some test tokens
    for i in 0..100 {
        let token = auth_framework::tokens::AuthToken {
            token_id: format!("test-token-{}", i),
            user_id: format!("user-{}", i),
            access_token: format!("access-{}", i),
            token_type: Some("Bearer".to_string()),
            subject: Some(format!("user-{}", i)),
            issuer: Some("test-issuer".to_string()),
            refresh_token: None,
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            scopes: vec!["read".to_string(), "write".to_string()],
            auth_method: "jwt".to_string(),
            client_id: Some("test-client".to_string()),
            user_profile: None,
            permissions: vec!["read".to_string(), "write".to_string()],
            roles: vec!["user".to_string()],
            metadata: auth_framework::tokens::TokenMetadata {
                issued_ip: Some("127.0.0.1".to_string()),
                user_agent: Some("test-agent".to_string()),
                device_id: None,
                session_id: Some(format!("session-{}", i)),
                revoked: false,
                revoked_at: None,
                revoked_reason: None,
                last_used: None,
                use_count: 0,
                custom: std::collections::HashMap::new(),
            },
        };

        storage.store_token(&token).await?;

        // Test retrieval
        let retrieved = storage.get_token(&token.token_id).await?;
        assert!(retrieved.is_some());
    }

    let duration = start.elapsed();
    println!("  ✅ Stored and retrieved 100 tokens in {:?}", duration);

    // Test memory usage
    let storage_stats = storage.get_stats();
    println!("  📊 Storage stats:");
    println!("      - Total entries: {}", storage_stats.total_entries);
    println!("      - Memory usage: {} bytes", storage_stats.memory_usage);
    println!("      - Hit rate: {:.2}%", storage_stats.hit_rate * 100.0);

    Ok(())
}

#[cfg(feature = "enhanced-observability")]
async fn test_observability() -> Result<()> {
    let observability = ObservabilityManager::new()?;

    println!("  📊 Recording test authentication attempts...");

    // Simulate authentication attempts
    for i in 0..50 {
        let success = i % 4 != 0; // 75% success rate
        let duration = Duration::from_millis(10 + (i % 100) as u64);

        observability
            .record_auth_attempt(success, duration, "jwt")
            .await;

        if i % 10 == 0 {
            observability
                .record_token_operation("issue", &format!("token-{}", i))
                .await;
        }
    }

    // Get performance metrics
    let metrics = observability.get_performance_metrics().await;
    println!(
        "  ✅ Average response time: {:?}",
        metrics.average_response_time
    );
    println!("  ✅ Error rate: {:.2}%", metrics.error_rate * 100.0);

    // Export Prometheus metrics
    #[cfg(feature = "prometheus")]
    {
        let prometheus_metrics = observability.export_prometheus_metrics()?;
        println!(
            "  📈 Exported {} bytes of Prometheus metrics",
            prometheus_metrics.len()
        );
    }

    Ok(())
}

async fn test_core_performance() -> Result<()> {
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .refresh_token_lifetime(Duration::from_secs(86400 * 7))
        .secret("test_secret_key_for_demo_purposes_that_is_long_enough_to_be_secure_and_valid");

    let mut framework = AuthFramework::new(config);

    // Register JWT method
    let jwt_method = JwtMethod::new();
    framework.register_method("jwt", AuthMethodEnum::Jwt(jwt_method));

    // Initialize the framework
    framework.initialize().await?;

    println!("  🔄 Performing authentication tests...");
    let start = Instant::now();

    // Test basic framework operations
    for i in 0..10 {
        let user_id = format!("user-{}", i);

        // Create a basic credential for testing
        use auth_framework::authentication::credentials::Credential;
        let credential = Credential::password(&user_id, "test-password");

        // Attempt authentication
        let auth_result = framework.authenticate("jwt", credential).await;

        if let Ok(auth_framework::auth::AuthResult::Success(token)) = auth_result {
            // Test token validation
            let _is_valid = framework.validate_token(&token).await.unwrap_or(false);
        }
    }

    let duration = start.elapsed();
    println!("  ✅ Completed 10 auth cycles in {:?}", duration);
    println!("  ⚡ Average: {:?} per authentication", duration / 10);

    // Get framework stats
    let stats = framework.get_stats().await?;
    println!("  📊 Framework stats:");
    println!("      - Registered methods: {:?}", stats.registered_methods);
    println!("      - Active sessions: {}", stats.active_sessions);
    println!("      - Auth attempts: {}", stats.auth_attempts);
    println!("      - Tokens issued: {}", stats.tokens_issued);

    Ok(())
}
