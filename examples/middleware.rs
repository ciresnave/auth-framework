use auth_framework::{AuthFramework, AuthConfig, AuthError};
use auth_framework::methods::{JwtMethod, ApiKeyMethod};
use auth_framework::tokens::AuthToken;
use std::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// Simulated middleware types for demonstration
#[derive(Debug)]
pub struct AuthRequest {
    pub headers: HashMap<String, String>,
    pub method: String,
    pub path: String,
}

#[derive(Debug)]
pub struct AuthResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

#[derive(Debug)]
pub struct UserInfo {
    pub id: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

/// Middleware function that extracts and validates authentication tokens
pub async fn auth_middleware(
    auth: &AuthFramework,
    request: &AuthRequest,
) -> Result<UserInfo, AuthError> {
    // Check for JWT token in Authorization header
    if let Some(auth_header) = request.headers.get("Authorization") {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            // Parse token - in real implementation, you'd parse the JWT
            // For demo purposes, we'll simulate token validation
            if let Ok(token_obj) = parse_token(token) {
                if auth.validate_token(&token_obj).await? {
                    // Extract user info from token
                    let user_info = extract_user_info(&token_obj);
                    return Ok(user_info);
                }
            }
        }
    }
    
    // Check for API key in X-API-Key header
    if let Some(api_key) = request.headers.get("X-API-Key") {
        // In a real implementation, you'd validate the API key
        // For demo purposes, we'll simulate validation
        if let Ok(user_id) = validate_api_key(api_key) {
            return Ok(UserInfo {
                id: user_id,
                roles: vec!["api_client".to_string()],
                permissions: vec!["api:read".to_string()],
            });
        }
    }
    
    Err(AuthError::access_denied("No valid authentication found"))
}

/// Permission checking middleware
pub async fn permission_middleware(
    auth: &AuthFramework,
    _user_info: &UserInfo,
    required_permission: &str,
) -> Result<bool, AuthError> {
    // Create a mock token for permission checking
    // In real implementation, you'd use the actual token
    let mock_token = AuthToken::new(
        "mock_user".to_string(),
        "mock_token".to_string(),
        Duration::from_secs(3600),
        "jwt".to_string(),
    );
    
    // Check if user has required permission
    auth.check_permission(&mock_token, required_permission, "api").await
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    user_id: &str,
    rate_limiter: &Arc<RwLock<HashMap<String, (u64, std::time::Instant)>>>,
    max_requests: u64,
    window_seconds: u64,
) -> Result<(), AuthError> {
    let mut limiter = rate_limiter.write().await;
    let now = std::time::Instant::now();
    
    let (count, last_reset) = limiter.get(user_id).cloned().unwrap_or((0, now));
    
    // Reset counter if window has passed
    if now.duration_since(last_reset).as_secs() >= window_seconds {
        limiter.insert(user_id.to_string(), (1, now));
        return Ok(());
    }
    
    // Check if limit exceeded
    if count >= max_requests {
        return Err(AuthError::rate_limit("Rate limit exceeded"));
    }
    
    // Increment counter
    limiter.insert(user_id.to_string(), (count + 1, last_reset));
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("🔧 Auth Framework - Middleware Integration Example");
    println!("=================================================");

    // Set up the auth framework
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .enable_rbac(true);

    let mut auth = AuthFramework::new(config);

    // Register authentication methods
    let jwt_method = JwtMethod::new()
        .secret_key("middleware-demo-secret-key")
        .issuer("middleware-demo")
        .audience("api-service");

    auth.register_method("jwt", Box::new(jwt_method));

    let api_key_method = ApiKeyMethod::new()
        .key_prefix("mw_")
        .key_length(32);

    auth.register_method("api_key", Box::new(api_key_method));

    auth.initialize().await?;
    println!("✅ Auth framework initialized");

    // Create test API key
    let api_key = auth.create_api_key("warp_service_client", None).await?;
    println!("✅ Created API key: {}", api_key);

    // Set up rate limiter
    let rate_limiter = Arc::new(RwLock::new(HashMap::new()));

    // Demonstrate middleware usage
    demonstrate_auth_middleware(&auth).await?;
    demonstrate_permission_middleware(&auth).await?;
    demonstrate_rate_limiting(&rate_limiter).await?;
    demonstrate_middleware_pipeline(&auth, &rate_limiter).await?;

    println!("\n🎉 Middleware integration example completed successfully!");
    Ok(())
}

async fn demonstrate_auth_middleware(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔐 Authentication Middleware Demo");
    println!("=================================");

    // Simulate requests with different authentication methods
    let test_requests = vec![
        AuthRequest {
            headers: {
                let mut headers = HashMap::new();
                headers.insert("Authorization".to_string(), "Bearer valid_jwt_token".to_string());
                headers
            },
            method: "GET".to_string(),
            path: "/api/users".to_string(),
        },
        AuthRequest {
            headers: {
                let mut headers = HashMap::new();
                headers.insert("X-API-Key".to_string(), "mw_valid_api_key".to_string());
                headers
            },
            method: "POST".to_string(),
            path: "/api/webhooks".to_string(),
        },
        AuthRequest {
            headers: HashMap::new(),
            method: "GET".to_string(),
            path: "/api/protected".to_string(),
        },
    ];

    for (i, request) in test_requests.iter().enumerate() {
        println!("\n📨 Request {}: {} {}", i + 1, request.method, request.path);
        
        match auth_middleware(auth, request).await {
            Ok(user_info) => {
                println!("   ✅ Authentication successful");
                println!("   👤 User: {}", user_info.id);
                println!("   🏷️  Roles: {:?}", user_info.roles);
                println!("   🔑 Permissions: {:?}", user_info.permissions);
            }
            Err(e) => {
                println!("   ❌ Authentication failed: {}", e);
            }
        }
    }

    Ok(())
}

async fn demonstrate_permission_middleware(_auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔒 Permission Middleware Demo");
    println!("=============================");

    let test_users = vec![
        UserInfo {
            id: "admin_user".to_string(),
            roles: vec!["admin".to_string()],
            permissions: vec!["read".to_string(), "write".to_string(), "delete".to_string()],
        },
        UserInfo {
            id: "api_client".to_string(),
            roles: vec!["client".to_string()],
            permissions: vec!["read".to_string()],
        },
        UserInfo {
            id: "guest_user".to_string(),
            roles: vec!["guest".to_string()],
            permissions: vec![],
        },
    ];

    let required_permissions = vec!["read", "write", "delete"];

    for user in &test_users {
        println!("\n👤 User: {}", user.id);
        
        for perm in &required_permissions {
            // For demonstration, we'll just check if user has the permission in their list
            let has_permission = user.permissions.contains(&perm.to_string());
            let status = if has_permission { "✅ Allowed" } else { "❌ Denied" };
            println!("   {} permission: {}", perm, status);
        }
    }

    Ok(())
}

async fn demonstrate_rate_limiting(rate_limiter: &Arc<RwLock<HashMap<String, (u64, std::time::Instant)>>>) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⚡ Rate Limiting Middleware Demo");
    println!("===============================");

    let user_id = "test_user";
    let max_requests = 5;
    let window_seconds = 60;

    println!("📊 Rate limit: {} requests per {} seconds", max_requests, window_seconds);
    println!("🧪 Testing with user: {}", user_id);

    // Simulate multiple requests
    for i in 1..=7 {
        match rate_limit_middleware(user_id, rate_limiter, max_requests, window_seconds).await {
            Ok(()) => {
                println!("   Request {}: ✅ Allowed", i);
            }
            Err(e) => {
                println!("   Request {}: ❌ Denied - {}", i, e);
            }
        }
    }

    Ok(())
}

async fn demonstrate_middleware_pipeline(
    auth: &AuthFramework,
    rate_limiter: &Arc<RwLock<HashMap<String, (u64, std::time::Instant)>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔄 Complete Middleware Pipeline Demo");
    println!("===================================");

    let request = AuthRequest {
        headers: {
            let mut headers = HashMap::new();
            headers.insert("Authorization".to_string(), "Bearer valid_jwt_token".to_string());
            headers
        },
        method: "POST".to_string(),
        path: "/api/sensitive-operation".to_string(),
    };

    println!("📨 Processing request: {} {}", request.method, request.path);

    // Step 1: Authentication
    println!("\n1️⃣ Authentication middleware...");
    let user_info = match auth_middleware(auth, &request).await {
        Ok(user) => {
            println!("   ✅ Authentication successful for user: {}", user.id);
            user
        }
        Err(e) => {
            println!("   ❌ Authentication failed: {}", e);
            return Ok(());
        }
    };

    // Step 2: Rate limiting
    println!("\n2️⃣ Rate limiting middleware...");
    match rate_limit_middleware(&user_info.id, rate_limiter, 10, 60).await {
        Ok(()) => {
            println!("   ✅ Rate limit check passed");
        }
        Err(e) => {
            println!("   ❌ Rate limit exceeded: {}", e);
            return Ok(());
        }
    }

    // Step 3: Permission checking
    println!("\n3️⃣ Permission middleware...");
    let has_permission = user_info.permissions.contains(&"write".to_string());
    if has_permission {
        println!("   ✅ Permission check passed");
    } else {
        println!("   ❌ Insufficient permissions");
        return Ok(());
    }

    // Step 4: Process request
    println!("\n4️⃣ Processing request...");
    println!("   ✅ Request processed successfully");
    println!("   📝 Result: Sensitive operation completed");

    Ok(())
}

// Helper functions for demonstration
fn parse_token(token: &str) -> Result<AuthToken, AuthError> {
    // In real implementation, you'd parse and validate the JWT
    // For demo purposes, we'll just create a mock token
    if token == "valid_jwt_token" {
        Ok(AuthToken::new(
            "user_123".to_string(),
            "token_123".to_string(),
            Duration::from_secs(3600),
            "jwt".to_string(),
        ))
    } else {
        Err(AuthError::token("Invalid token"))
    }
}

fn extract_user_info(_token: &AuthToken) -> UserInfo {
    // In real implementation, you'd extract user info from the token
    // For demo purposes, we'll return mock data
    UserInfo {
        id: "user_123".to_string(),
        roles: vec!["user".to_string()],
        permissions: vec!["read".to_string(), "write".to_string()],
    }
}

fn validate_api_key(api_key: &str) -> Result<String, AuthError> {
    // In real implementation, you'd validate the API key against your database
    // For demo purposes, we'll just check a mock key
    if api_key == "mw_valid_api_key" {
        Ok("api_client_123".to_string())
    } else {
        Err(AuthError::token("Invalid API key"))
    }
}
