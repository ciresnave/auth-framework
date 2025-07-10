use auth_framework::{AuthFramework, AuthConfig};
use auth_framework::methods::{JwtMethod, ApiKeyMethod};
use auth_framework::credentials::Credential;
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("⚡ Auth Framework - Performance Benchmarks");
    println!("=========================================");

    // Set up the auth framework for benchmarking
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .enable_caching(true);

    let mut auth = AuthFramework::new(config);

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
    benchmark_memory_usage(&auth).await?;
    
    // Run concurrent operations last since it consumes the auth
    let auth_arc = Arc::new(auth);
    benchmark_concurrent_operations(auth_arc).await?;

    println!("\n🎯 Benchmark Summary Complete!");
    println!("   For production use, consider:");
    println!("   - Database storage for persistence");
    println!("   - Redis caching for high-throughput");
    println!("   - Connection pooling for database operations");
    println!("   - Rate limiting for API protection");

    Ok(())
}

async fn benchmark_token_creation(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔄 Token Creation Benchmark");
    println!("==========================");

    let iterations = 1000;
    let credential = Credential::Password {
        username: "benchmark_user".to_string(),
        password: "benchmark_password".to_string(),
    };

    // JWT Token Creation
    let start = Instant::now();
    for _i in 0..iterations {
        let _result = auth.authenticate("jwt", credential.clone()).await?;
    }
    let jwt_duration = start.elapsed();
    let jwt_per_sec = iterations as f64 / jwt_duration.as_secs_f64();

    println!("🗝️  JWT Token Creation:");
    println!("   {} tokens in {:?}", iterations, jwt_duration);
    println!("   {:.2} tokens/sec", jwt_per_sec);
    println!("   {:.2} μs per token", jwt_duration.as_micros() as f64 / iterations as f64);

    Ok(())
}

async fn benchmark_token_validation(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n✅ Token Validation Benchmark");
    println!("=============================");

    let iterations = 1000;
    
    // Create a test token first
    let credential = Credential::Password {
        username: "validation_user".to_string(),
        password: "validation_password".to_string(),
    };
    
    let auth_result = auth.authenticate("jwt", credential).await?;
    let token = match auth_result {
        auth_framework::AuthResult::Success(token) => *token,
        _ => return Err("Failed to create test token".into()),
    };

    // JWT Token Validation
    let start = Instant::now();
    for _i in 0..iterations {
        let _is_valid = auth.validate_token(&token).await?;
    }
    let validation_duration = start.elapsed();
    let validations_per_sec = iterations as f64 / validation_duration.as_secs_f64();

    println!("🔍 JWT Token Validation:");
    println!("   {} validations in {:?}", iterations, validation_duration);
    println!("   {:.2} validations/sec", validations_per_sec);
    println!("   {:.2} μs per validation", validation_duration.as_micros() as f64 / iterations as f64);

    Ok(())
}

async fn benchmark_api_key_operations(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔑 API Key Operations Benchmark");
    println!("===============================");

    let iterations = 100; // Fewer iterations for API key creation as it's more expensive

    // API Key Creation
    let start = Instant::now();
    let mut api_keys = Vec::new();
    for i in 0..iterations {
        let api_key = auth.create_api_key(
            &format!("api_bench_user_{}", i),
            None,
        ).await?;
        api_keys.push(api_key);
    }
    let creation_duration = start.elapsed();
    let creation_per_sec = iterations as f64 / creation_duration.as_secs_f64();

    println!("🔨 API Key Creation:");
    println!("   {} keys in {:?}", iterations, creation_duration);
    println!("   {:.2} keys/sec", creation_per_sec);
    println!("   {:.2} ms per key", creation_duration.as_millis() as f64 / iterations as f64);

    // API Key Validation
    let start = Instant::now();
    let validation_iterations = 500;
    for i in 0..validation_iterations {
        let key_index = i % api_keys.len();
        let api_key = &api_keys[key_index];
        let credential = Credential::ApiKey {
            key: api_key.clone(),
        };
        let _result = auth.authenticate("api_key", credential).await?;
    }
    let validation_duration = start.elapsed();
    let validation_per_sec = validation_iterations as f64 / validation_duration.as_secs_f64();

    println!("🔍 API Key Validation:");
    println!("   {} validations in {:?}", validation_iterations, validation_duration);
    println!("   {:.2} validations/sec", validation_per_sec);
    println!("   {:.2} μs per validation", validation_duration.as_micros() as f64 / validation_iterations as f64);

    Ok(())
}

async fn benchmark_permission_checking(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔒 Permission Checking Benchmark");
    println!("================================");

    let iterations = 1000;
    
    // Create a test token
    let credential = Credential::Password {
        username: "permission_user".to_string(),
        password: "permission_password".to_string(),
    };
    
    let auth_result = auth.authenticate("jwt", credential).await?;
    let token = match auth_result {
        auth_framework::AuthResult::Success(token) => *token,
        _ => return Err("Failed to create test token".into()),
    };

    let permissions = vec!["read", "write", "delete", "admin"];
    let resources = vec!["users", "posts", "comments", "settings"];

    // Permission Checking
    let start = Instant::now();
    for i in 0..iterations {
        let permission = permissions[i % permissions.len()];
        let resource = resources[i % resources.len()];
        let _has_permission = auth.check_permission(&token, permission, resource).await?;
    }
    let check_duration = start.elapsed();
    let checks_per_sec = iterations as f64 / check_duration.as_secs_f64();

    println!("🔍 Permission Checks:");
    println!("   {} checks in {:?}", iterations, check_duration);
    println!("   {:.2} checks/sec", checks_per_sec);
    println!("   {:.2} μs per check", check_duration.as_micros() as f64 / iterations as f64);

    Ok(())
}

async fn benchmark_concurrent_operations(auth: Arc<AuthFramework>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🚀 Concurrent Operations Benchmark");
    println!("==================================");

    let concurrent_tasks = 50;
    let operations_per_task = 20;
    let total_operations = concurrent_tasks * operations_per_task;

    // Create auth for concurrent use
    let start = Instant::now();
    
    let mut tasks = JoinSet::new();
    
    for task_id in 0..concurrent_tasks {
        let auth_clone = Arc::clone(&auth);
        tasks.spawn(async move {
            let mut results = Vec::new();
            for i in 0..operations_per_task {
                let credential = Credential::Password {
                    username: format!("concurrent_user_{}_{}", task_id, i),
                    password: "concurrent_password".to_string(),
                };
                let result = auth_clone.authenticate("jwt", credential).await;
                results.push(result);
            }
            results
        });
    }

    let mut all_results: Vec<auth_framework::Result<auth_framework::AuthResult>> = Vec::new();
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(task_results) => all_results.extend(task_results),
            Err(e) => eprintln!("Task error: {}", e),
        }
    }

    let concurrent_duration = start.elapsed();
    let concurrent_per_sec = total_operations as f64 / concurrent_duration.as_secs_f64();

    println!("⚡ Concurrent Authentication:");
    println!("   {} tasks, {} ops/task = {} total ops", concurrent_tasks, operations_per_task, total_operations);
    println!("   Completed in {:?}", concurrent_duration);
    println!("   {:.2} ops/sec", concurrent_per_sec);
    println!("   {:.2} ms per op", concurrent_duration.as_millis() as f64 / total_operations as f64);

    // Calculate success rate
    let successful = all_results.iter().filter(|r| r.is_ok()).count();
    let success_rate = successful as f64 / total_operations as f64 * 100.0;
    println!("   Success rate: {:.1}% ({}/{})", success_rate, successful, total_operations);

    Ok(())
}

async fn benchmark_memory_usage(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n💾 Memory Usage Benchmark");
    println!("=========================");

    let iterations = 1000;
    
    // Create many tokens and measure memory impact
    let mut tokens = Vec::new();
    let start = Instant::now();
    
    for i in 0..iterations {
        let credential = Credential::Password {
            username: format!("memory_user_{}", i),
            password: "memory_password".to_string(),
        };
        
        if let Ok(auth_result) = auth.authenticate("jwt", credential).await {
            if let auth_framework::AuthResult::Success(token) = auth_result {
                tokens.push(*token);
            }
        }
    }
    
    let memory_duration = start.elapsed();
    
    println!("🧠 Memory Impact Test:");
    println!("   Created {} tokens in {:?}", tokens.len(), memory_duration);
    println!("   {:.2} tokens/sec", tokens.len() as f64 / memory_duration.as_secs_f64());
    
    // Test token validation performance with many tokens
    let validation_start = Instant::now();
    let mut validation_count = 0;
    
    for token in &tokens {
        if validation_count >= 100 { break; } // Limit to 100 validations
        if let Ok(_valid) = auth.validate_token(token).await {
            validation_count += 1;
        }
    }
    
    let validation_duration = validation_start.elapsed();
    
    println!("   Validated {} tokens in {:?}", validation_count, validation_duration);
    if validation_count > 0 {
        println!("   {:.2} validations/sec", validation_count as f64 / validation_duration.as_secs_f64());
    }

    // Clear tokens to free memory
    tokens.clear();
    
    println!("   Memory cleanup: {} tokens cleared", iterations);

    Ok(())
}
