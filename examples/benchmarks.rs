use auth_framework::{AuthFramework, AuthConfig};
use auth_framework::methods::{JwtMethod, ApiKeyMethod};
use auth_framework::storage::MemoryStorage;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("⚡ Auth Framework - Performance Benchmarks");
    println!("=========================================");

    // Set up the auth framework for benchmarking
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .enable_caching(true)
        .cache_ttl(Duration::from_secs(300));

    let storage = Arc::new(MemoryStorage::new());
    let mut auth = AuthFramework::new(config).with_storage(storage);

    // Register methods
    let jwt_method = JwtMethod::new()
        .secret_key("benchmark-secret-key-for-performance-testing")
        .issuer("benchmark-issuer")
        .audience("benchmark-audience");

    let api_key_method = ApiKeyMethod::new()
        .key_prefix("bm_")
        .key_length(32);

    auth.register_method("jwt", Box::new(jwt_method));
    auth.register_method("api_key", Box::new(api_key_method));
    auth.initialize().await?;

    println!("✅ Auth framework initialized for benchmarking");

    // Run comprehensive benchmarks
    benchmark_token_creation(&auth).await?;
    benchmark_token_validation(&auth).await?;
    benchmark_api_key_operations(&auth).await?;
    benchmark_permission_checking(&auth).await?;
    benchmark_concurrent_operations(&auth).await?;
    benchmark_caching_performance(&auth).await?;
    benchmark_memory_usage(&auth).await?;

    println!("\n🎯 Benchmark Summary Complete!");
    println!("Review the results above to identify optimization opportunities.");

    Ok(())
}

async fn benchmark_token_creation(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🚀 Token Creation Benchmark:");
    println!("===========================");

    let iterations = vec![100, 500, 1000, 2000];
    let scopes = vec!["read".to_string(), "write".to_string(), "admin".to_string()];

    for &count in &iterations {
        let start = Instant::now();
        
        for i in 0..count {
            let _token = auth.create_auth_token(
                &format!("bench_user_{}", i),
                scopes.clone(),
                "jwt",
                Some(Duration::from_secs(3600)),
            ).await?;
        }
        
        let duration = start.elapsed();
        let tokens_per_sec = count as f64 / duration.as_secs_f64();
        
        println!("📊 {} tokens created in {:?} ({:.2} tokens/sec)", 
                count, duration, tokens_per_sec);
    }

    // Measure JWT vs API Key creation performance
    println!("\n🔄 JWT vs API Key Creation Comparison:");
    
    let test_count = 1000;
    
    // JWT creation
    let start = Instant::now();
    for i in 0..test_count {
        let _token = auth.create_auth_token(
            &format!("jwt_bench_user_{}", i),
            scopes.clone(),
            "jwt",
            Some(Duration::from_secs(3600)),
        ).await?;
    }
    let jwt_duration = start.elapsed();
    
    // API Key creation
    let start = Instant::now();
    for i in 0..test_count {
        let _api_key = auth.create_api_key(
            &format!("api_bench_user_{}", i),
            scopes.clone(),
            Some(Duration::from_secs(3600)),
        ).await?;
    }
    let api_key_duration = start.elapsed();
    
    println!("🎫 JWT creation: {:?} ({:.2}/sec)", 
            jwt_duration, test_count as f64 / jwt_duration.as_secs_f64());
    println!("🔑 API Key creation: {:?} ({:.2}/sec)", 
            api_key_duration, test_count as f64 / api_key_duration.as_secs_f64());
    
    let speedup = jwt_duration.as_secs_f64() / api_key_duration.as_secs_f64();
    if speedup > 1.0 {
        println!("⚡ API Keys are {:.2}x faster to create than JWTs", speedup);
    } else {
        println!("⚡ JWTs are {:.2}x faster to create than API Keys", 1.0 / speedup);
    }

    Ok(())
}

async fn benchmark_token_validation(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔍 Token Validation Benchmark:");
    println!("=============================");

    // Create test tokens
    let jwt_tokens: Vec<_> = (0..1000).map(|i| {
        // Create synchronous test tokens (simplified for benchmark)
        format!("jwt_test_token_{}", i)
    }).collect();

    let api_keys: Vec<_> = (0..1000).map(|i| {
        format!("bm_test_api_key_{}", i)
    }).collect();

    // Create some real tokens for validation testing
    let mut real_jwt_tokens = Vec::new();
    let mut real_api_keys = Vec::new();
    
    for i in 0..100 {
        let jwt_token = auth.create_auth_token(
            &format!("validation_user_{}", i),
            vec!["read".to_string()],
            "jwt",
            Some(Duration::from_secs(3600)),
        ).await?;
        real_jwt_tokens.push(jwt_token.access_token);
        
        let api_key = auth.create_api_key(
            &format!("validation_api_user_{}", i),
            vec!["read".to_string()],
            Some(Duration::from_secs(3600)),
        ).await?;
        real_api_keys.push(api_key);
    }

    // Benchmark JWT validation
    let iterations = vec![100, 500, 1000];
    
    for &count in &iterations {
        let start = Instant::now();
        let mut valid_count = 0;
        
        for i in 0..count {
            let token = &real_jwt_tokens[i % real_jwt_tokens.len()];
            if auth.validate_token(token).await.is_ok() {
                valid_count += 1;
            }
        }
        
        let duration = start.elapsed();
        let validations_per_sec = count as f64 / duration.as_secs_f64();
        
        println!("🎫 {} JWT validations in {:?} ({:.2}/sec, {:.2}% valid)", 
                count, duration, validations_per_sec, 
                (valid_count as f64 / count as f64) * 100.0);
    }

    // Benchmark API Key validation
    for &count in &iterations {
        let start = Instant::now();
        let mut valid_count = 0;
        
        for i in 0..count {
            let api_key = &real_api_keys[i % real_api_keys.len()];
            if auth.validate_api_key(api_key).await.is_ok() {
                valid_count += 1;
            }
        }
        
        let duration = start.elapsed();
        let validations_per_sec = count as f64 / duration.as_secs_f64();
        
        println!("🔑 {} API Key validations in {:?} ({:.2}/sec, {:.2}% valid)", 
                count, duration, validations_per_sec,
                (valid_count as f64 / count as f64) * 100.0);
    }

    // Test validation of invalid tokens
    println!("\n❌ Invalid Token Handling:");
    let invalid_tokens = vec![
        "invalid_jwt_token",
        "malformed.jwt.token", 
        "expired_token_123",
        "",
        "bm_invalid_api_key_12345",
    ];

    let start = Instant::now();
    for token in &invalid_tokens {
        let _ = auth.validate_token(token).await;
    }
    let invalid_duration = start.elapsed();
    
    println!("🚫 {} invalid token validations in {:?} ({:.2}/sec)", 
            invalid_tokens.len(), invalid_duration,
            invalid_tokens.len() as f64 / invalid_duration.as_secs_f64());

    Ok(())
}

async fn benchmark_api_key_operations(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔑 API Key Operations Benchmark:");
    println!("===============================");

    // Benchmark API key creation with different parameters
    let key_lengths = vec![16, 32, 64];
    let scope_counts = vec![1, 5, 10, 20];

    for &key_length in &key_lengths {
        for &scope_count in &scope_counts {
            let scopes: Vec<String> = (0..scope_count)
                .map(|i| format!("scope_{}", i))
                .collect();

            let test_count = 100;
            let start = Instant::now();

            for i in 0..test_count {
                let _api_key = auth.create_api_key(
                    &format!("perf_user_{}_{}", key_length, i),
                    scopes.clone(),
                    Some(Duration::from_secs(3600)),
                ).await?;
            }

            let duration = start.elapsed();
            let keys_per_sec = test_count as f64 / duration.as_secs_f64();

            println!("📊 Length {}, {} scopes: {} keys in {:?} ({:.2}/sec)",
                    key_length, scope_count, test_count, duration, keys_per_sec);
        }
    }

    // Benchmark key revocation
    println!("\n🚫 API Key Revocation Performance:");
    let mut test_keys = Vec::new();
    
    // Create keys to revoke
    for i in 0..500 {
        let api_key = auth.create_api_key(
            &format!("revoke_test_user_{}", i),
            vec!["test".to_string()],
            Some(Duration::from_secs(3600)),
        ).await?;
        test_keys.push(api_key);
    }

    let start = Instant::now();
    for (i, api_key) in test_keys.iter().enumerate() {
        auth.revoke_api_key(api_key).await?;
        
        // Log progress for every 100 revocations
        if (i + 1) % 100 == 0 {
            let elapsed = start.elapsed();
            let rate = (i + 1) as f64 / elapsed.as_secs_f64();
            println!("   Revoked {} keys in {:?} ({:.2}/sec)", i + 1, elapsed, rate);
        }
    }

    let total_duration = start.elapsed();
    println!("✅ Revoked {} keys in {:?} ({:.2}/sec)",
            test_keys.len(), total_duration,
            test_keys.len() as f64 / total_duration.as_secs_f64());

    Ok(())
}

async fn benchmark_permission_checking(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🛡️  Permission Checking Benchmark:");
    println!("=================================");

    // Set up users with different permission sets
    let users = vec![
        ("basic_user", vec!["read", "write"]),
        ("power_user", vec!["read", "write", "delete", "manage"]),
        ("admin_user", vec!["read", "write", "delete", "manage", "admin", "super_admin"]),
    ];

    // Create users and assign permissions
    for (user_id, permissions) in &users {
        for permission in permissions {
            auth.grant_permission(user_id, permission, "system").await?;
        }
    }

    let test_permissions = vec![
        "read", "write", "delete", "manage", "admin", "super_admin",
        "nonexistent_permission", "invalid_perm", "test_permission"
    ];

    // Benchmark permission checking
    let iterations = vec![1000, 5000, 10000];

    for &count in &iterations {
        let start = Instant::now();
        let mut checks_performed = 0;
        let mut granted_count = 0;

        for i in 0..count {
            let user_id = &users[i % users.len()].0;
            let permission = test_permissions[i % test_permissions.len()];
            
            let has_permission = auth.check_permission(user_id, permission, "system").await?;
            checks_performed += 1;
            
            if has_permission {
                granted_count += 1;
            }
        }

        let duration = start.elapsed();
        let checks_per_sec = checks_performed as f64 / duration.as_secs_f64();
        let grant_rate = (granted_count as f64 / checks_performed as f64) * 100.0;

        println!("📊 {} permission checks in {:?} ({:.2}/sec, {:.1}% granted)",
                checks_performed, duration, checks_per_sec, grant_rate);
    }

    // Benchmark complex permission scenarios
    println!("\n🔬 Complex Permission Scenarios:");
    
    // Hierarchical permissions
    let start = Instant::now();
    for i in 0..1000 {
        let resource = format!("department/team/project_{}/document_{}.txt", i % 10, i);
        let _has_access = auth.check_permission("admin_user", "read", &resource).await?;
    }
    let hierarchical_duration = start.elapsed();
    
    println!("🏗️  Hierarchical permissions: {:?} ({:.2}/sec)",
            hierarchical_duration, 1000.0 / hierarchical_duration.as_secs_f64());

    // Role-based permissions
    let start = Instant::now();
    for i in 0..1000 {
        let role = match i % 4 {
            0 => "guest",
            1 => "user", 
            2 => "admin",
            _ => "super_admin",
        };
        // Simulate role-based permission check
        let _has_role = auth.user_has_role("test_user", role).await.unwrap_or(false);
    }
    let role_duration = start.elapsed();
    
    println!("👥 Role-based checks: {:?} ({:.2}/sec)",
            role_duration, 1000.0 / role_duration.as_secs_f64());

    Ok(())
}

async fn benchmark_concurrent_operations(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔄 Concurrent Operations Benchmark:");
    println!("==================================");

    // Test concurrent token creation
    let concurrency_levels = vec![10, 50, 100, 200];
    
    for &concurrent_ops in &concurrency_levels {
        println!("\n📊 Testing {} concurrent operations:", concurrent_ops);
        
        // Concurrent token creation
        let start = Instant::now();
        let mut handles = Vec::new();
        
        for i in 0..concurrent_ops {
            let auth_clone = auth.clone();
            let handle = tokio::spawn(async move {
                auth_clone.create_auth_token(
                    &format!("concurrent_user_{}", i),
                    vec!["read".to_string(), "write".to_string()],
                    "jwt",
                    Some(Duration::from_secs(3600)),
                ).await
            });
            handles.push(handle);
        }
        
        let mut successful = 0;
        for handle in handles {
            if handle.await.unwrap().is_ok() {
                successful += 1;
            }
        }
        
        let creation_duration = start.elapsed();
        let creation_rate = successful as f64 / creation_duration.as_secs_f64();
        
        println!("   🎫 Token creation: {} successful in {:?} ({:.2}/sec)",
                successful, creation_duration, creation_rate);

        // Concurrent validation
        let tokens: Vec<_> = (0..concurrent_ops).map(|i| 
            format!("test_token_{}", i)).collect();
        
        let start = Instant::now();
        let mut handles = Vec::new();
        
        for (i, token) in tokens.iter().enumerate() {
            let auth_clone = auth.clone();
            let token_clone = token.clone();
            let handle = tokio::spawn(async move {
                // Create a real token first for some of them
                if i < 10 {
                    let real_token = auth_clone.create_auth_token(
                        &format!("validation_user_{}", i),
                        vec!["read".to_string()],
                        "jwt",
                        Some(Duration::from_secs(3600)),
                    ).await?;
                    auth_clone.validate_token(&real_token.access_token).await
                } else {
                    auth_clone.validate_token(&token_clone).await
                }
            });
            handles.push(handle);
        }
        
        let mut valid_tokens = 0;
        for handle in handles {
            if handle.await.unwrap().is_ok() {
                valid_tokens += 1;
            }
        }
        
        let validation_duration = start.elapsed();
        let validation_rate = concurrent_ops as f64 / validation_duration.as_secs_f64();
        
        println!("   🔍 Token validation: {} ops in {:?} ({:.2}/sec, {} valid)",
                concurrent_ops, validation_duration, validation_rate, valid_tokens);

        // Concurrent permission checks
        let start = Instant::now();
        let mut handles = Vec::new();
        
        for i in 0..concurrent_ops {
            let auth_clone = auth.clone();
            let handle = tokio::spawn(async move {
                auth_clone.check_permission(
                    &format!("user_{}", i % 10),
                    "read",
                    "system"
                ).await
            });
            handles.push(handle);
        }
        
        let mut granted = 0;
        for handle in handles {
            if handle.await.unwrap().unwrap_or(false) {
                granted += 1;
            }
        }
        
        let permission_duration = start.elapsed();
        let permission_rate = concurrent_ops as f64 / permission_duration.as_secs_f64();
        
        println!("   🛡️  Permission checks: {} ops in {:?} ({:.2}/sec, {} granted)",
                concurrent_ops, permission_duration, permission_rate, granted);
    }

    Ok(())
}

async fn benchmark_caching_performance(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n💾 Caching Performance Benchmark:");
    println!("================================");

    // Create test data for caching benchmark
    let mut test_tokens = Vec::new();
    for i in 0..100 {
        let token = auth.create_auth_token(
            &format!("cache_user_{}", i),
            vec!["read".to_string(), "write".to_string()],
            "jwt",
            Some(Duration::from_secs(3600)),
        ).await?;
        test_tokens.push(token.access_token);
    }

    // First run (cold cache)
    println!("🧊 Cold cache performance:");
    let start = Instant::now();
    for token in &test_tokens {
        let _ = auth.validate_token(token).await;
    }
    let cold_duration = start.elapsed();
    let cold_rate = test_tokens.len() as f64 / cold_duration.as_secs_f64();
    
    println!("   {} validations in {:?} ({:.2}/sec)", 
            test_tokens.len(), cold_duration, cold_rate);

    // Second run (warm cache)
    println!("\n🔥 Warm cache performance:");
    let start = Instant::now();
    for token in &test_tokens {
        let _ = auth.validate_token(token).await;
    }
    let warm_duration = start.elapsed();
    let warm_rate = test_tokens.len() as f64 / warm_duration.as_secs_f64();
    
    println!("   {} validations in {:?} ({:.2}/sec)", 
            test_tokens.len(), warm_duration, warm_rate);

    let speedup = cold_duration.as_secs_f64() / warm_duration.as_secs_f64();
    println!("⚡ Cache speedup: {:.2}x faster", speedup);

    // Cache hit ratio test
    println!("\n🎯 Cache Hit Ratio Test:");
    let cache_test_iterations = 1000;
    let unique_tokens = 10; // Only 10 unique tokens, but 1000 requests
    
    let start = Instant::now();
    for i in 0..cache_test_iterations {
        let token_index = i % unique_tokens;
        let token = &test_tokens[token_index];
        let _ = auth.validate_token(token).await;
    }
    let hit_ratio_duration = start.elapsed();
    let hit_ratio_rate = cache_test_iterations as f64 / hit_ratio_duration.as_secs_f64();
    
    let expected_hit_ratio = ((cache_test_iterations - unique_tokens) as f64 / cache_test_iterations as f64) * 100.0;
    
    println!("   {} requests with ~{:.1}% expected hit ratio in {:?} ({:.2}/sec)",
            cache_test_iterations, expected_hit_ratio, hit_ratio_duration, hit_ratio_rate);

    Ok(())
}

async fn benchmark_memory_usage(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🧠 Memory Usage Analysis:");
    println!("========================");

    // This is a simplified memory usage analysis
    // In a real implementation, you'd use tools like valgrind, heaptrack, or memory profilers
    
    let test_scenarios = vec![
        ("Baseline", 0, 0, 0),
        ("1K tokens", 1000, 0, 0),
        ("10K tokens", 10000, 0, 0),
        ("1K users + permissions", 0, 1000, 100),
        ("Mixed load", 5000, 500, 50),
    ];

    for (scenario_name, token_count, user_count, permission_count) in test_scenarios {
        println!("\n📊 Scenario: {}", scenario_name);
        
        let start_time = Instant::now();
        
        // Create tokens
        let mut tokens = Vec::new();
        for i in 0..token_count {
            let token = auth.create_auth_token(
                &format!("mem_user_{}", i),
                vec!["read".to_string()],
                "jwt",
                Some(Duration::from_secs(3600)),
            ).await?;
            tokens.push(token);
            
            // Periodic progress for large datasets
            if token_count > 1000 && (i + 1) % 1000 == 0 {
                println!("   Created {} tokens...", i + 1);
            }
        }
        
        // Create users and permissions
        for i in 0..user_count {
            let user_id = format!("mem_perm_user_{}", i);
            for j in 0..permission_count {
                let permission = format!("perm_{}", j);
                let _ = auth.grant_permission(&user_id, &permission, "system").await;
            }
        }
        
        let setup_duration = start_time.elapsed();
        
        // Simulate some operations
        let ops_start = Instant::now();
        for i in 0..100.min(token_count) {
            let _ = auth.validate_token(&tokens[i].access_token).await;
        }
        let ops_duration = ops_start.elapsed();
        
        println!("   Setup time: {:?}", setup_duration);
        println!("   Operations time: {:?}", ops_duration);
        println!("   Estimated memory per token: ~{} bytes", estimate_token_memory_usage());
        println!("   Estimated total memory: ~{} MB", 
                (token_count * estimate_token_memory_usage() + 
                 user_count * permission_count * 50) / 1024 / 1024);
    }

    Ok(())
}

fn estimate_token_memory_usage() -> usize {
    // Rough estimate of memory per token
    // This is a simplified calculation - real memory usage would depend on
    // the actual data structures, heap fragmentation, etc.
    
    let base_token_size = 200;  // Basic token structure
    let jwt_payload_size = 300; // JWT payload data
    let metadata_size = 100;    // Additional metadata
    
    base_token_size + jwt_payload_size + metadata_size
}
