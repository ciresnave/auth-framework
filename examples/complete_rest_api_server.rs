//! Complete REST API Server Example
//!
//! This example demonstrates how to set up and run the comprehensive REST API server
//! that exposes all AuthFramework functionality through HTTP endpoints.

use auth_framework::{
    AuthFramework,
    api::{ApiServer, server::ApiServerConfig},
    config::AuthConfig,
    storage::memory::InMemoryStorage,
};
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    info!("🚀 Starting AuthFramework REST API Server Example");

    // Create storage backend (currently unused but available for future expansion)
    let _storage = Arc::new(InMemoryStorage::new());

    // Create auth configuration
    let auth_config = AuthConfig::new()
        .secret("your-super-secret-jwt-key-change-this-in-production".to_string())
        .token_lifetime(chrono::Duration::hours(1).to_std().unwrap())
        .refresh_token_lifetime(chrono::Duration::days(7).to_std().unwrap());

    // Initialize AuthFramework
    let auth_framework = Arc::new(AuthFramework::new(auth_config));

    info!("✅ AuthFramework initialized successfully");

    // Create API server configuration
    let api_config = ApiServerConfig {
        host: "127.0.0.1".to_string(),
        port: 8080,
        enable_cors: true,
        max_body_size: 1024 * 1024, // 1MB
        enable_tracing: true,
    };

    // Create and configure the API server
    let api_server = ApiServer::with_config(auth_framework, api_config);

    info!("📊 API Server Configuration:");
    info!("   Host: {}", api_server.config().host);
    info!("   Port: {}", api_server.config().port);
    info!("   CORS: {}", api_server.config().enable_cors);
    info!(
        "   Max Body Size: {} bytes",
        api_server.config().max_body_size
    );

    info!("🌐 Available Endpoints:");
    info!("   Health Check:     GET  http://127.0.0.1:8080/health");
    info!("   Detailed Health:  GET  http://127.0.0.1:8080/health/detailed");
    info!("   Metrics:          GET  http://127.0.0.1:8080/metrics");
    info!("   Login:            POST http://127.0.0.1:8080/auth/login");
    info!("   Refresh Token:    POST http://127.0.0.1:8080/auth/refresh");
    info!("   User Profile:     GET  http://127.0.0.1:8080/users/profile");
    info!("   OAuth Authorize:  GET  http://127.0.0.1:8080/oauth/authorize");
    info!("   OAuth Token:      POST http://127.0.0.1:8080/oauth/token");
    info!("   Admin Users:      GET  http://127.0.0.1:8080/admin/users");
    info!("   MFA Setup:        POST http://127.0.0.1:8080/mfa/setup");

    info!("📖 Example API calls:");
    info!("   # Health check");
    info!("   curl http://127.0.0.1:8080/health");
    info!("");
    info!("   # Login");
    info!("   curl -X POST http://127.0.0.1:8080/auth/login \\");
    info!("     -H \"Content-Type: application/json\" \\");
    info!("     -d '{{\"username\":\"user@example.com\",\"password\":\"password\"}}'");
    info!("");
    info!("   # Get profile (with token)");
    info!("   curl -H \"Authorization: Bearer <your-token>\" \\");
    info!("     http://127.0.0.1:8080/users/profile");

    // Start the server
    info!("🎯 Starting API server...");
    api_server.start().await?;

    Ok(())
}
