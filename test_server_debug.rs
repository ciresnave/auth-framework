use auth_framework::{
    AuthFramework,
    api::{ApiServer, server::ApiServerConfig},
    config::AuthConfig,
    storage::memory::InMemoryStorage,
};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    println!("Starting server debug test...");

    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("Creating storage...");
    let _storage = Arc::new(InMemoryStorage::new());

    println!("Creating auth config...");
    let auth_config = match AuthConfig::new()
        .secret("your-super-secret-jwt-key-change-this-in-production".to_string())
        .token_lifetime(chrono::Duration::hours(1).to_std().unwrap())
        .refresh_token_lifetime(chrono::Duration::days(7).to_std().unwrap())
    {
        config => config,
    };

    println!("Creating AuthFramework...");
    let auth_framework = Arc::new(AuthFramework::new(auth_config));

    println!("Creating API config...");
    let api_config = ApiServerConfig {
        host: "127.0.0.1".to_string(),
        port: 8080,
        enable_cors: true,
        max_body_size: 1024 * 1024,
        enable_tracing: true,
    };

    println!("Creating API server...");
    let api_server = ApiServer::with_config(auth_framework, api_config);

    println!("Building router...");
    match api_server.build_router().await {
        Ok(_router) => {
            println!("✅ Router built successfully!");
        }
        Err(e) => {
            println!("❌ Router build failed: {}", e);
            return;
        }
    }

    println!("Starting server...");
    match api_server.start().await {
        Ok(_) => println!("Server completed"),
        Err(e) => println!("Server error: {}", e),
    }
}
