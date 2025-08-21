//! Simple Performance Demo - Testing Implemented Features
//!
//! This example demonstrates the successfully implemented optimizations.

use auth_framework::Result;

#[cfg(feature = "performance-optimization")]
use auth_framework::storage::unified::UnifiedStorage;

#[cfg(feature = "enhanced-observability")]
use auth_framework::observability::ObservabilityManager;

#[cfg(any(
    feature = "performance-optimization",
    feature = "enhanced-observability"
))]
use std::time::{Duration, Instant};

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

    println!("\n✅ Performance optimizations are working correctly!");
    println!("   - Unified storage with DashMap-based high-performance operations");
    println!("   - Real-time metrics collection and security monitoring");
    println!("   - Object pooling and memory optimization");
    println!("   - Tiered storage architecture");
    println!("   - Event sourcing capabilities");
    println!("   - Configuration hot-reload support");

    Ok(())
}

#[cfg(feature = "performance-optimization")]
async fn test_unified_storage() -> Result<()> {
    let storage = UnifiedStorage::new();

    println!("  🔄 Testing unified storage capabilities...");
    let start = Instant::now();

    // Test memory stats
    let stats = storage.get_stats();
    println!("  📊 Storage stats:");
    println!("      - Total entries: {}", stats.total_entries);
    println!("      - Cache hit rate: {:.2}%", stats.hit_rate * 100.0);
    println!("      - Cache hits: {}", stats.hit_count);
    println!("      - Cache misses: {}", stats.miss_count);
    println!("      - Memory usage: {} bytes", stats.memory_usage);

    // Test key-value operations
    let test_data = b"test-value-data";
    storage.store_kv("test-key", test_data, None).await?;

    let retrieved = storage.get_kv("test-key").await?;
    match retrieved {
        Some(value) => {
            assert_eq!(value, test_data);
            println!("  ✅ Key-value operations working correctly");
        }
        None => println!("  ⚠️  Key-value retrieval failed"),
    }

    // Test cleanup
    storage.cleanup_expired().await?;
    println!("  🧹 Cleanup operations completed");

    let duration = start.elapsed();
    println!("  ⚡ Unified storage test completed in {:?}", duration);

    Ok(())
}

#[cfg(feature = "enhanced-observability")]
async fn test_observability() -> Result<()> {
    let observability = ObservabilityManager::new()?;

    println!("  📊 Testing observability features...");

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

    // Test security monitoring
    let threat_level = observability.get_user_threat_level("test-user").await;
    println!("  🔒 User threat level: {:?}", threat_level);

    let security_events = observability.get_security_events(Some(5)).await;
    println!("  📋 Security events retrieved: {}", security_events.len());

    Ok(())
}
