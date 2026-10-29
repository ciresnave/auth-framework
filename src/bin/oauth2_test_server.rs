//! OAuth2 Authorization Server Test Binary
//!
//! This binary demonstrates and tests the complete OAuth2 authorization server functionality
//! including authorization code flow, PKCE support, and token exchange.

use auth_framework::{AuthConfig, AuthFramework, api::ApiServer};
use std::sync::Arc;
use tracing::info;

const USAGE: &str = "Usage: oauth2_test_server serve\n       oauth2_test_server --help | --version\n\n\
Starts an OAuth2 authorization server for trying out the authorization code flow, PKCE and token exchange.\n\
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
            println!("oauth2_test_server {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            std::process::exit(2);
        }
    }

    // Initialize tracing
    tracing_subscriber::fmt::init();

    info!("🚀 Starting OAuth2 Authorization Server Test");

    // Create AuthFramework instance
    // Create auth framework configuration
    let config = AuthConfig::new()
        .secret("test_oauth2_secret_key_that_is_long_enough_for_secure_operation".to_string());

    // Create and initialize auth framework
    let mut auth_framework = AuthFramework::new(config);
    auth_framework.initialize().await?;

    let auth_framework = Arc::new(auth_framework);

    // Create API server
    let server = ApiServer::new(auth_framework.clone());

    info!("📖 OAuth2 Endpoints Available:");
    info!("  Authorization: GET  http://127.0.0.1:8080/api/v1/oauth/authorize");
    info!("  Token:         POST http://127.0.0.1:8080/api/v1/oauth/token");
    info!("  Revoke:        POST http://127.0.0.1:8080/api/v1/oauth/revoke");
    info!("  UserInfo:      GET  http://127.0.0.1:8080/api/v1/oauth/userinfo");
    info!("");
    info!("🔍 Testing OAuth2 Authorization Code Flow:");
    info!(
        "1. GET /api/v1/oauth/authorize?response_type=code&client_id=test_client&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&state=xyz"
    );
    info!("2. Use returned authorization_url to get code");
    info!("3. POST /api/v1/oauth/token with authorization_code grant");
    info!("4. Use access_token for authenticated requests");
    info!("");
    info!("🔐 PKCE Support:");
    info!("  Add code_challenge and code_challenge_method=S256 to authorization request");
    info!("  Include code_verifier in token request");
    info!("");

    // Start the server
    info!("🌐 Starting server on http://127.0.0.1:8080");
    server.start().await?;

    Ok(())
}
