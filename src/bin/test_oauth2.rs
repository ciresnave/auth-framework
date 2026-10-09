//! Test OAuth2 Authorization Server Implementation
//!
//! This binary tests the complete OAuth2 authorization server flow

use auth_framework::{
    AuthConfig, AuthFramework,
    api::{ApiServer, server::ApiServerConfig},
};
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    info!("Starting OAuth2 Authorization Server Test");

    // Create auth framework configuration
    let config = AuthConfig::new()
        .secret("test_oauth2_secret_key_that_is_long_enough_for_secure_operation".to_string());

    // Create and initialize auth framework
    let mut auth_framework = AuthFramework::new(config);
    auth_framework.initialize().await?;

    let auth_framework = Arc::new(auth_framework);

    // Create API server
    let api_config = ApiServerConfig {
        host: "127.0.0.1".to_string(),
        port: 8080,
        cors: auth_framework::CorsConfig {
            enabled: true,
            allowed_origins: vec!["http://localhost:3000".to_string()],
            ..auth_framework::CorsConfig::default()
        },
        max_body_size: 1024 * 1024, // 1MB
        enable_tracing: true,
    };

    let api_server = ApiServer::with_config(auth_framework.clone(), api_config);

    info!("Building OAuth2 server router...");
    let app = api_server.build_router().await?;

    info!("Starting OAuth2 Authorization Server on http://127.0.0.1:8080");
    info!("Available OAuth2 endpoints:");
    info!("  - GET  /api/v1/oauth/authorize - Authorization endpoint");
    info!("  - POST /api/v1/oauth/token     - Token exchange endpoint");
    info!("  - POST /api/v1/oauth/revoke    - Token revocation endpoint");
    info!("  - GET  /api/v1/oauth/userinfo  - User info endpoint");
    info!("");
    info!("Test the server with curl commands like:");
    info!(
        "curl \"http://127.0.0.1:8080/api/v1/oauth/authorize?response_type=code&client_id=test_client&redirect_uri=http://localhost:3000/callback&state=xyz&code_challenge=abc&code_challenge_method=S256\""
    );

    // Start the server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
