//! Debug REST API Server
//! Simple test to identify startup issues

use auth_framework::{
    AuthFramework,
    api::{ApiServer, server::ApiServerConfig},
    config::AuthConfig,
    storage::memory::InMemoryStorage,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Starting server debug test...");

    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("📦 Creating storage...");
    let _storage = Arc::new(InMemoryStorage::new());

    println!("⚙️  Creating auth config...");
    // The signing secret comes from the environment; there is no built-in default.
    // For example: AUTH_FRAMEWORK_DEBUG_SECRET="$(openssl rand -hex 32)" cargo run --example debug_server
    let dev_secret = std::env::var("AUTH_FRAMEWORK_DEBUG_SECRET")
        .map_err(|_| "AUTH_FRAMEWORK_DEBUG_SECRET must be set (at least 32 characters)")?;
    let auth_config = AuthConfig::new()
        .secret(dev_secret)
        .token_lifetime(chrono::Duration::hours(1).to_std().unwrap())
        .refresh_token_lifetime(chrono::Duration::days(7).to_std().unwrap());

    println!("🔐 Creating AuthFramework...");
    let mut auth_framework_mut = AuthFramework::new(auth_config);

    println!("⚡ Initializing AuthFramework...");
    auth_framework_mut.initialize().await?;

    let auth_framework = Arc::new(auth_framework_mut);

    println!("🌐 Creating API config...");
    let api_config = ApiServerConfig {
        host: "127.0.0.1".to_string(),
        port: 8088,
        cors: auth_framework::CorsConfig {
            enabled: true,
            allowed_origins: vec!["http://localhost:3000".to_string()],
            ..auth_framework::CorsConfig::default()
        },
        max_body_size: 1024 * 1024,
        enable_tracing: true,
    };

    println!("🚀 Creating API server...");
    let api_server = ApiServer::with_config(auth_framework, api_config);

    println!("🎯 Starting server (this should not return immediately)...");
    api_server.start().await?;
    println!("⚠️  Server method returned (this should not happen)");
    Ok(())
}
