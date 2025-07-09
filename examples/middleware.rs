use auth_framework::{AuthFramework, AuthConfig, AuthResult, AuthError};
use auth_framework::methods::JwtMethod;
use auth_framework::storage::MemoryStorage;
use auth_framework::middleware::{AuthMiddleware, AuthContext};
use std::sync::Arc;
use std::time::Duration;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("🔧 Auth Framework - Middleware Integration Example");
    println!("=================================================");

    // Set up the auth framework
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .enable_middleware(true);

    let storage = Arc::new(MemoryStorage::new());
    let mut auth = AuthFramework::new(config).with_storage(storage);

    let jwt_method = JwtMethod::new()
        .secret_key("middleware-demo-secret-key")
        .issuer("middleware-demo")
        .audience("api-service");

    auth.register_method("jwt", Box::new(jwt_method));
    auth.initialize().await?;
    println!("✅ Auth framework initialized");

    // Demonstrate different middleware integrations
    demonstrate_axum_integration(&auth).await?;
    demonstrate_warp_integration(&auth).await?;
    demonstrate_actix_integration(&auth).await?;
    demonstrate_custom_middleware(&auth).await?;
    demonstrate_middleware_chain(&auth).await?;
    demonstrate_conditional_auth(&auth).await?;

    println!("\n🎉 Middleware example completed successfully!");
    println!("Integration examples shown for:");
    println!("- Axum web framework");
    println!("- Warp web framework"); 
    println!("- Actix-web framework");
    println!("- Custom middleware patterns");

    Ok(())
}

async fn demonstrate_axum_integration(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🚀 Axum Integration:");
    println!("===================");

    // Create a test token for demonstration
    let test_token = auth.create_auth_token(
        "axum_user_123",
        vec!["api:read".to_string(), "api:write".to_string()],
        "jwt",
        Some(Duration::from_secs(3600)),
    ).await?;

    println!("🔑 Created test token: {}", test_token.access_token);

    // Simulate Axum middleware usage
    println!("\n📡 Simulating Axum HTTP requests:");

    // Example 1: Public endpoint (no auth required)
    simulate_request(
        "GET /api/health",
        None,
        &["public"],
        "Health check endpoint - no auth required"
    ).await;

    // Example 2: Protected endpoint with valid token
    simulate_request(
        "GET /api/users",
        Some(&test_token.access_token),
        &["api:read"],
        "Protected endpoint with valid token"
    ).await;

    // Example 3: Protected endpoint with invalid token
    simulate_request(
        "POST /api/users",
        Some("invalid_token_12345"),
        &["api:write"],
        "Protected endpoint with invalid token"
    ).await;

    // Example 4: Admin endpoint requiring higher privileges
    simulate_request(
        "DELETE /api/users/123",
        Some(&test_token.access_token),
        &["admin:delete"],
        "Admin endpoint requiring higher privileges"
    ).await;

    // Show Axum middleware code example
    print_axum_middleware_example();

    Ok(())
}

async fn demonstrate_warp_integration(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🌊 Warp Integration:");
    println!("===================");

    // Create API key for Warp example
    let api_key = auth.create_api_key(
        "warp_service_client",
        vec!["api:read".to_string(), "webhooks:receive".to_string()],
        Some(Duration::from_secs(7200)),
    ).await?;

    println!("🔑 Created API key for Warp demo: {}", api_key);

    // Simulate Warp filter usage
    println!("\n📡 Simulating Warp filter chain:");

    let routes = vec![
        ("GET /api/status", None, vec![], "Public status endpoint"),
        ("GET /api/data", Some(&api_key), vec!["api:read"], "API key protected data"),
        ("POST /webhooks/github", Some(&api_key), vec!["webhooks:receive"], "Webhook endpoint"),
        ("GET /admin/metrics", Some(&api_key), vec!["admin:view"], "Admin metrics (insufficient permissions)"),
    ];

    for (route, auth_header, required_perms, description) in routes {
        println!("\n🔗 Route: {} - {}", route, description);
        
        if let Some(key) = auth_header {
            match auth.validate_api_key(key).await {
                Ok(user_info) => {
                    println!("   ✅ API key valid for user: {}", user_info.id);
                    
                    if required_perms.is_empty() {
                        println!("   ✅ No permissions required");
                    } else {
                        for perm in required_perms {
                            let has_perm = auth.check_permission(&user_info.id, &perm, "api").await?;
                            if has_perm {
                                println!("   ✅ Permission '{}' granted", perm);
                            } else {
                                println!("   ❌ Permission '{}' denied", perm);
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("   ❌ API key validation failed: {}", e);
                }
            }
        } else {
            println!("   ℹ️  Public endpoint - no authentication required");
        }
    }

    print_warp_middleware_example();

    Ok(())
}

async fn demonstrate_actix_integration(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🎭 Actix-web Integration:");
    println!("========================");

    // Create JWT token for Actix example
    let jwt_token = auth.create_auth_token(
        "actix_user_789",
        vec!["profile:read".to_string(), "profile:write".to_string()],
        "jwt",
        Some(Duration::from_secs(1800)), // 30 minutes
    ).await?;

    println!("🎫 Created JWT token: {}", jwt_token.access_token);

    // Simulate Actix middleware processing
    println!("\n📡 Simulating Actix-web middleware:");

    let requests = vec![
        Request {
            method: "GET",
            path: "/api/profile",
            headers: vec![("Authorization", &format!("Bearer {}", jwt_token.access_token))],
            body: None,
        },
        Request {
            method: "PUT", 
            path: "/api/profile",
            headers: vec![("Authorization", &format!("Bearer {}", jwt_token.access_token))],
            body: Some("Profile update data"),
        },
        Request {
            method: "DELETE",
            path: "/api/profile",
            headers: vec![("Authorization", "Bearer invalid_jwt_token")],
            body: None,
        },
        Request {
            method: "GET",
            path: "/api/admin/users",
            headers: vec![("Authorization", &format!("Bearer {}", jwt_token.access_token))],
            body: None,
        },
    ];

    for request in requests {
        println!("\n🌐 {} {} - Processing request", request.method, request.path);
        
        // Extract and validate authorization header
        if let Some(auth_header) = request.headers.iter()
            .find(|(name, _)| name.to_lowercase() == "authorization")
            .map(|(_, value)| value) {
            
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                match auth.validate_token(token).await {
                    Ok(user_info) => {
                        println!("   ✅ JWT token valid for user: {}", user_info.id);
                        
                        // Check route-specific permissions
                        let required_permission = match (request.method, request.path) {
                            ("GET", "/api/profile") => Some("profile:read"),
                            ("PUT", "/api/profile") => Some("profile:write"),
                            ("DELETE", "/api/profile") => Some("profile:delete"),
                            ("GET", "/api/admin/users") => Some("admin:users:view"),
                            _ => None,
                        };

                        if let Some(perm) = required_permission {
                            let has_perm = auth.check_permission(&user_info.id, perm, "api").await?;
                            if has_perm {
                                println!("   ✅ Permission '{}' granted - request allowed", perm);
                            } else {
                                println!("   ❌ Permission '{}' denied - request blocked", perm);
                            }
                        } else {
                            println!("   ✅ No specific permissions required");
                        }
                    }
                    Err(e) => {
                        println!("   ❌ JWT validation failed: {} - request blocked", e);
                    }
                }
            } else {
                println!("   ❌ Invalid authorization header format");
            }
        } else {
            println!("   ❌ No authorization header found - request blocked");
        }
    }

    print_actix_middleware_example();

    Ok(())
}

async fn demonstrate_custom_middleware(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🛠️  Custom Middleware Pattern:");
    println!("=============================");

    // Create a custom middleware that implements specific business logic
    let custom_middleware = CustomAuthMiddleware::new(auth.clone());

    // Test different scenarios
    let scenarios = vec![
        Scenario {
            name: "API rate limiting",
            user_id: "rate_test_user",
            endpoint: "/api/data",
            rate_limit_key: Some("api_calls"),
            expected_calls: 5,
        },
        Scenario {
            name: "IP allowlist check",
            user_id: "ip_test_user", 
            endpoint: "/admin/sensitive",
            rate_limit_key: None,
            expected_calls: 1,
        },
        Scenario {
            name: "Time-based access",
            user_id: "time_test_user",
            endpoint: "/api/reports",
            rate_limit_key: None,
            expected_calls: 1,
        },
    ];

    for scenario in scenarios {
        println!("\n🧪 Testing scenario: {}", scenario.name);
        
        for call_num in 1..=scenario.expected_calls + 2 {
            let context = AuthContext {
                user_id: scenario.user_id.to_string(),
                endpoint: scenario.endpoint.to_string(),
                ip_address: "192.168.1.100".to_string(),
                user_agent: "test-client/1.0".to_string(),
                timestamp: chrono::Utc::now(),
                headers: HashMap::new(),
            };

            let result = custom_middleware.process_request(&context).await;
            
            match result {
                Ok(()) => {
                    println!("   Call {}: ✅ Request allowed", call_num);
                }
                Err(e) => {
                    println!("   Call {}: ❌ Request blocked - {}", call_num, e);
                }
            }

            // Small delay between calls for rate limiting demo
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    print_custom_middleware_example();

    Ok(())
}

async fn demonstrate_middleware_chain(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔗 Middleware Chain Processing:");
    println!("==============================");

    // Simulate a chain of middleware components
    let middleware_chain = vec![
        "CORS Handler",
        "Rate Limiter", 
        "Authentication",
        "Authorization",
        "Audit Logger",
        "Request Handler",
    ];

    let test_request = AuthContext {
        user_id: "chain_test_user".to_string(),
        endpoint: "/api/secure-data".to_string(),
        ip_address: "203.0.113.45".to_string(),
        user_agent: "MyApp/2.1".to_string(),
        timestamp: chrono::Utc::now(),
        headers: {
            let mut headers = HashMap::new();
            headers.insert("Authorization".to_string(), "Bearer valid_jwt_token".to_string());
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers
        },
    };

    println!("🌐 Processing request: {} {}", "GET", test_request.endpoint);
    println!("👤 User: {} from IP: {}", test_request.user_id, test_request.ip_address);

    let mut should_continue = true;

    for (step, middleware_name) in middleware_chain.iter().enumerate() {
        if !should_continue {
            println!("   {}. {} - ⏭️  SKIPPED (previous middleware blocked)", 
                    step + 1, middleware_name);
            continue;
        }

        println!("   {}. {} - 🔄 Processing...", step + 1, middleware_name);
        
        let success = match middleware_name {
            &"CORS Handler" => {
                // CORS check always passes in this demo
                println!("      ✅ CORS headers validated");
                true
            }
            &"Rate Limiter" => {
                // Simple rate limit check
                let within_limits = true; // Simulate rate limit check
                if within_limits {
                    println!("      ✅ Request within rate limits");
                    true
                } else {
                    println!("      ❌ Rate limit exceeded");
                    false
                }
            }
            &"Authentication" => {
                // Token validation
                if test_request.headers.contains_key("Authorization") {
                    println!("      ✅ Valid authentication token");
                    true
                } else {
                    println!("      ❌ Missing or invalid authentication");
                    false
                }
            }
            &"Authorization" => {
                // Permission check
                let has_permission = true; // Simulate permission check
                if has_permission {
                    println!("      ✅ User authorized for this resource");
                    true
                } else {
                    println!("      ❌ Insufficient permissions");
                    false
                }
            }
            &"Audit Logger" => {
                // Audit logging always succeeds
                println!("      📝 Request logged for audit");
                true
            }
            &"Request Handler" => {
                // Final request processing
                println!("      🎯 Request processed successfully");
                true
            }
            _ => true,
        };

        if !success {
            should_continue = false;
            println!("      🛑 Middleware chain stopped");
        }
    }

    if should_continue {
        println!("\n🎉 Request completed successfully through entire middleware chain");
    } else {
        println!("\n🚫 Request blocked by middleware chain");
    }

    Ok(())
}

async fn demonstrate_conditional_auth(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔀 Conditional Authentication:");
    println!("=============================");

    // Different endpoints with different auth requirements
    let endpoints = vec![
        EndpointConfig {
            path: "/api/public/status",
            auth_required: false,
            permissions: vec![],
            description: "Public health check",
        },
        EndpointConfig {
            path: "/api/user/profile", 
            auth_required: true,
            permissions: vec!["profile:read".to_string()],
            description: "User profile (requires auth)",
        },
        EndpointConfig {
            path: "/api/admin/users",
            auth_required: true,
            permissions: vec!["admin:users:view".to_string()],
            description: "Admin endpoint (requires auth + admin role)",
        },
        EndpointConfig {
            path: "/api/debug/logs",
            auth_required: true,
            permissions: vec!["debug:view".to_string(), "logs:read".to_string()],
            description: "Debug endpoint (requires multiple permissions)",
        },
    ];

    // Test different user types
    let test_users = vec![
        ("anonymous", None),
        ("regular_user", Some("regular_user_token")),
        ("admin_user", Some("admin_user_token")),
    ];

    for (user_type, token) in test_users {
        println!("\n👤 Testing as: {}", user_type);
        
        for endpoint in &endpoints {
            print!("   {} {} - ", "GET", endpoint.path);
            
            if !endpoint.auth_required {
                println!("✅ ALLOWED (public endpoint)");
                continue;
            }

            if token.is_none() {
                println!("❌ DENIED (authentication required)");
                continue;
            }

            // Simulate token validation
            let is_admin = user_type == "admin_user";
            let user_permissions = if is_admin {
                vec!["profile:read", "admin:users:view", "debug:view", "logs:read"]
            } else {
                vec!["profile:read"]
            };

            let has_all_permissions = endpoint.permissions.iter()
                .all(|perm| user_permissions.iter()
                    .any(|user_perm| user_perm == perm));

            if has_all_permissions {
                println!("✅ ALLOWED ({})", endpoint.description);
            } else {
                println!("❌ DENIED (insufficient permissions)");
            }
        }
    }

    Ok(())
}

// Helper structures
#[derive(Debug)]
struct Request<'a> {
    method: &'a str,
    path: &'a str,
    headers: Vec<(&'a str, &'a str)>,
    body: Option<&'a str>,
}

#[derive(Debug)]
struct Scenario<'a> {
    name: &'a str,
    user_id: &'a str,
    endpoint: &'a str,
    rate_limit_key: Option<&'a str>,
    expected_calls: usize,
}

#[derive(Debug)]
struct EndpointConfig {
    path: &'static str,
    auth_required: bool,
    permissions: Vec<String>,
    description: &'static str,
}

// Custom middleware implementation
#[derive(Clone)]
struct CustomAuthMiddleware {
    auth: AuthFramework,
}

impl CustomAuthMiddleware {
    fn new(auth: AuthFramework) -> Self {
        Self { auth }
    }

    async fn process_request(&self, context: &AuthContext) -> Result<(), AuthError> {
        // IP allowlist check for admin endpoints
        if context.endpoint.starts_with("/admin/") {
            let allowed_ips = vec!["192.168.1.0/24", "10.0.0.0/8"];
            let is_allowed_ip = allowed_ips.iter()
                .any(|range| context.ip_address.starts_with("192.168.1.") || 
                           context.ip_address.starts_with("10."));
            
            if !is_allowed_ip {
                return Err(AuthError::access_denied("IP not in allowlist for admin endpoints"));
            }
        }

        // Time-based access for reports
        if context.endpoint.contains("/reports") {
            let current_hour = context.timestamp.hour();
            if current_hour < 6 || current_hour > 22 {
                return Err(AuthError::access_denied("Reports only available 6 AM - 10 PM"));
            }
        }

        Ok(())
    }
}

async fn simulate_request(route: &str, auth_header: Option<&str>, required_permissions: &[&str], description: &str) {
    println!("\n🌐 {} - {}", route, description);
    
    if let Some(token) = auth_header {
        println!("   🔑 Authorization: Bearer {}", token);
        if token.starts_with("invalid") {
            println!("   ❌ Invalid token format - request blocked");
        } else {
            println!("   ✅ Valid token found");
            for perm in required_permissions {
                println!("   🔍 Checking permission: {}", perm);
                // Simulate permission check
                if perm.starts_with("admin") {
                    println!("   ❌ Admin permission required but not granted");
                } else {
                    println!("   ✅ Permission granted");
                }
            }
        }
    } else {
        if required_permissions.is_empty() {
            println!("   ✅ Public endpoint - no auth required");
        } else {
            println!("   ❌ Auth required but no token provided");
        }
    }
}

fn print_axum_middleware_example() {
    println!("\n📝 Axum Middleware Code Example:");
    println!(r#"
```rust
use axum::{{
    extract::State,
    http::{{Request, StatusCode}},
    middleware::Next,
    response::Response,
}};

async fn auth_middleware<B>(
    State(auth): State<AuthFramework>,
    mut req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {{
    let auth_header = req.headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok());
    
    if let Some(token) = auth_header.and_then(|h| h.strip_prefix("Bearer ")) {{
        match auth.validate_token(token).await {{
            Ok(user_info) => {{
                req.extensions_mut().insert(user_info);
                Ok(next.run(req).await)
            }}
            Err(_) => Err(StatusCode::UNAUTHORIZED),
        }}
    }} else {{
        Err(StatusCode::UNAUTHORIZED)
    }}
}}
```"#);
}

fn print_warp_middleware_example() {
    println!("\n📝 Warp Filter Code Example:");
    println!(r#"
```rust
use warp::Filter;

fn with_auth(auth: AuthFramework) -> impl Filter<Extract = (UserInfo,), Error = warp::Rejection> + Clone {{
    warp::header::<String>("authorization")
        .and_then(move |auth_header: String| {{
            let auth = auth.clone();
            async move {{
                if let Some(token) = auth_header.strip_prefix("Bearer ") {{
                    auth.validate_token(token).await
                        .map_err(|_| warp::reject::custom(AuthError))
                }} else {{
                    Err(warp::reject::custom(AuthError))
                }}
            }}
        }})
}}

let protected_route = warp::path("api")
    .and(warp::path("users"))
    .and(with_auth(auth_framework))
    .and_then(|user_info: UserInfo| async move {{
        // Handle authenticated request
        Ok::<_, warp::Rejection>(warp::reply::json(&user_info))
    }});
```"#);
}

fn print_actix_middleware_example() {
    println!("\n📝 Actix-web Middleware Code Example:");
    println!(r#"
```rust
use actix_web::{{
    dev::{{ServiceRequest, ServiceResponse}},
    Error, HttpMessage,
}};

pub struct AuthMiddleware {{
    auth: AuthFramework,
}}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{{
    fn new_transform(&self, service: S) -> Self::Future {{
        let auth = self.auth.clone();
        ready(Ok(AuthMiddlewareService {{ service, auth }}))
    }}
}}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{{
    async fn call(&self, req: ServiceRequest) -> Result<Self::Response, Self::Error> {{
        if let Some(auth_header) = req.headers().get("Authorization") {{
            if let Ok(auth_str) = auth_header.to_str() {{
                if let Some(token) = auth_str.strip_prefix("Bearer ") {{
                    match self.auth.validate_token(token).await {{
                        Ok(user_info) => {{
                            req.extensions_mut().insert(user_info);
                            return self.service.call(req).await;
                        }}
                        Err(_) => return Ok(req.error_response(StatusCode::UNAUTHORIZED)),
                    }}
                }}
            }}
        }}
        Ok(req.error_response(StatusCode::UNAUTHORIZED))
    }}
}}
```"#);
}

fn print_custom_middleware_example() {
    println!("\n📝 Custom Middleware Pattern:");
    println!(r#"
```rust
#[async_trait]
pub trait AuthMiddleware: Send + Sync {{
    async fn process_request(&self, context: &AuthContext) -> Result<(), AuthError>;
}}

pub struct AuthContext {{
    pub user_id: String,
    pub endpoint: String,
    pub ip_address: String,
    pub user_agent: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub headers: HashMap<String, String>,
}}

// Usage in your web framework:
async fn middleware_handler(req: Request) -> Result<Response, Error> {{
    let context = AuthContext::from_request(&req);
    
    for middleware in &middleware_chain {{
        middleware.process_request(&context).await?;
    }}
    
    // Continue to next handler
    next_handler(req).await
}}
```"#);
}
