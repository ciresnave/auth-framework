//! Test OAuth2 Authorization Server Implementation
//!
//! This binary tests the complete OAuth2 authorization server flow

use auth_framework::{
    AuthConfig, AuthFramework,
    api::{ApiServer, server::ApiServerConfig},
};
use std::sync::Arc;
use tracing::info;

const USAGE: &str = "Usage: test_oauth2 serve\n       test_oauth2 --help | --version\n\n\
Starts an OAuth2 authorization server with CORS for http://localhost:3000, for testing the authorization flow.\n\
It binds http://127.0.0.1:8080 with a fixed, publicly known test secret: use it on a development\n\
machine only. Nothing starts unless you give the `serve` subcommand.\n";

/// What the command line asked for.
enum Command {
    Serve,
    Help,
    Version,
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut args = args.into_iter();
    let command = match args.next().as_deref() {
        None | Some("-h" | "--help") => Command::Help,
        Some("-V" | "--version") => Command::Version,
        Some("serve") => Command::Serve,
        Some(other) => return Err(format!("unknown argument '{other}'")),
    };
    match args.next() {
        Some(extra) => Err(format!("unexpected argument '{extra}'")),
        None => Ok(command),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match parse_args(std::env::args().skip(1)) {
        Ok(Command::Serve) => {}
        Ok(Command::Help) => {
            print!("{USAGE}");
            return Ok(());
        }
        Ok(Command::Version) => {
            println!("test_oauth2 {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            std::process::exit(2);
        }
    }

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
