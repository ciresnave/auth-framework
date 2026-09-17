use anyhow::{Context, Result, anyhow, bail};
use auth_framework::{
    ApiKeyMethod, ApiServer, ApiServerSettings, AuthConfig, AuthFramework, AuthFrameworkSettings,
    JwtMethod, LayeredConfigBuilder, OAuth2Method, PasswordMethod,
};
use std::{env, path::PathBuf, sync::Arc};
use tracing::info;
use tracing_subscriber::EnvFilter;

use auth_framework::api::server::ApiServerConfig;
use auth_framework::config::StorageConfig;
use auth_framework::methods::AuthMethodEnum;

const DEFAULT_ENV_PREFIX: &str = "AUTH_FRAMEWORK";
const HELP_TEXT: &str = "auth-framework standalone server\n\nUsage:\n  auth-framework [--config <path>] [--env-prefix <prefix>] [--host <host>] [--port <port>]\n\nOptions:\n  -c, --config <path>        Load an explicit configuration file\n      --env-prefix <prefix>  Environment prefix for layered config (default: AUTH_FRAMEWORK)\n      --host <host>          Override the bind host\n  -p, --port <port>          Override the bind port\n  -h, --help                 Show this help text\n\nEnvironment:\n  JWT_SECRET, DATABASE_URL, REDIS_URL, AUTH_ISSUER, AUTH_AUDIENCE\n  AUTH_FRAMEWORK_API_SERVER__HOST\n  AUTH_FRAMEWORK_API_SERVER__PORT\n  AUTH_FRAMEWORK_API_SERVER__MAX_BODY_SIZE\n  AUTH_FRAMEWORK_API_SERVER__ENABLE_TRACING\n";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServerCliArgs {
    config: Option<PathBuf>,
    env_prefix: String,
    host: Option<String>,
    port: Option<u16>,
}

impl Default for ServerCliArgs {
    fn default() -> Self {
        Self {
            config: None,
            env_prefix: DEFAULT_ENV_PREFIX.to_string(),
            host: None,
            port: None,
        }
    }
}

enum ServerCommand {
    Run(ServerCliArgs),
    Help,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    match parse_cli_args(env::args())? {
        ServerCommand::Help => {
            print!("{HELP_TEXT}");
            Ok(())
        }
        ServerCommand::Run(args) => run_server(args).await,
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

async fn run_server(args: ServerCliArgs) -> Result<()> {
    let settings = load_settings(&args)?;
    let auth_config = settings.auth.clone();
    let runtime_settings = apply_cli_overrides(settings.api_server.unwrap_or_default(), &args);

    let mut framework = AuthFramework::new(auth_config.clone());
    register_default_methods(&mut framework);
    framework.initialize().await?;

    let api_config = build_api_server_config(&auth_config, &runtime_settings);
    info!(
        host = %runtime_settings.host,
        port = runtime_settings.port,
        "Starting auth-framework API server"
    );

    let server = ApiServer::with_config(Arc::new(framework), api_config);
    server
        .start()
        .await
        .map_err(|error| anyhow!("API server exited with an error: {error}"))
}

fn parse_cli_args<I, S>(args: I) -> Result<ServerCommand>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let _program = args.next();
    let mut parsed = ServerCliArgs::default();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(ServerCommand::Help),
            "-c" | "--config" => {
                parsed.config = Some(PathBuf::from(next_value(&mut args, "--config")?));
            }
            "--env-prefix" => {
                parsed.env_prefix = next_value(&mut args, "--env-prefix")?;
            }
            "--host" => {
                parsed.host = Some(next_value(&mut args, "--host")?);
            }
            "-p" | "--port" => {
                parsed.port = Some(parse_port(&next_value(&mut args, "--port")?)?);
            }
            _ if arg.starts_with("--config=") => {
                parsed.config = Some(PathBuf::from(value_after_equals(&arg, "--config")?));
            }
            _ if arg.starts_with("--env-prefix=") => {
                parsed.env_prefix = value_after_equals(&arg, "--env-prefix")?;
            }
            _ if arg.starts_with("--host=") => {
                parsed.host = Some(value_after_equals(&arg, "--host")?);
            }
            _ if arg.starts_with("--port=") => {
                parsed.port = Some(parse_port(&value_after_equals(&arg, "--port")?)?);
            }
            _ => bail!("Unknown argument: {arg}\n\n{HELP_TEXT}"),
        }
    }

    Ok(ServerCommand::Run(parsed))
}

fn next_value<I>(args: &mut I, flag: &str) -> Result<String>
where
    I: Iterator<Item = String>,
{
    args.next()
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("{flag} requires a value"))
}

fn value_after_equals(arg: &str, flag: &str) -> Result<String> {
    let value = arg
        .split_once('=')
        .map(|(_, value)| value)
        .unwrap_or_default()
        .trim();

    if value.is_empty() {
        bail!("{flag} requires a value");
    }

    Ok(value.to_string())
}

fn parse_port(value: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .with_context(|| format!("Invalid port '{value}'"))
}

fn load_settings(args: &ServerCliArgs) -> Result<AuthFrameworkSettings> {
    let mut builder = LayeredConfigBuilder::new().with_env_prefix(&args.env_prefix);
    if let Some(config_path) = &args.config {
        builder = builder.add_file(config_path, true);
    }

    let manager = builder.build()?;

    let mut settings = manager.get_auth_settings()?;

    if let Ok(api_server) = manager.get_section::<ApiServerSettings>("api_server") {
        settings.api_server = Some(api_server);
    }

    apply_common_env_overrides(&mut settings.auth);
    Ok(settings)
}

fn apply_common_env_overrides(config: &mut AuthConfig) {
    if let Ok(secret) = env::var("JWT_SECRET") {
        config.secret = Some(secret.clone());
        config.security.secret_key = Some(secret);
    }

    if let Ok(issuer) = env::var("AUTH_ISSUER") {
        config.issuer = issuer;
    }

    if let Ok(audience) = env::var("AUTH_AUDIENCE") {
        config.audience = audience;
    }

    #[cfg(feature = "postgres-storage")]
    if let Ok(connection_string) = env::var("DATABASE_URL") {
        config.storage = StorageConfig::Postgres {
            connection_string,
            table_prefix: "auth_".to_string(),
        };
    }

    #[cfg(feature = "redis-storage")]
    if matches!(config.storage, StorageConfig::Memory) {
        if let Ok(url) = env::var("REDIS_URL") {
            config.storage = StorageConfig::Redis {
                url,
                key_prefix: "auth:".to_string(),
            };
        }
    }
}

fn apply_cli_overrides(
    mut runtime_settings: ApiServerSettings,
    args: &ServerCliArgs,
) -> ApiServerSettings {
    if let Some(host) = &args.host {
        runtime_settings.host = host.clone();
    }

    if let Some(port) = args.port {
        runtime_settings.port = port;
    }

    runtime_settings
}

fn build_api_server_config(
    auth_config: &AuthConfig,
    runtime_settings: &ApiServerSettings,
) -> ApiServerConfig {
    ApiServerConfig {
        host: runtime_settings.host.clone(),
        port: runtime_settings.port,
        cors: auth_config.cors.clone(),
        max_body_size: runtime_settings.max_body_size,
        enable_tracing: runtime_settings.enable_tracing,
    }
}

fn register_default_methods(framework: &mut AuthFramework) {
    framework.register_method("password", AuthMethodEnum::Password(PasswordMethod::new()));
    framework.register_method("jwt", AuthMethodEnum::Jwt(JwtMethod::new()));
    framework.register_method("api_key", AuthMethodEnum::ApiKey(ApiKeyMethod::new()));
    framework.register_method("oauth2", AuthMethodEnum::OAuth2(OAuth2Method::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_help_flag() {
        let command = parse_cli_args(["auth-framework", "--help"]).expect("help should parse");
        assert!(matches!(command, ServerCommand::Help));
    }

    #[test]
    fn parse_cli_overrides() {
        let command = parse_cli_args([
            "auth-framework",
            "--config",
            "config/auth-framework.toml",
            "--env-prefix",
            "AUTH_FRAMEWORK_STAGING",
            "--host=127.0.0.1",
            "--port",
            "9090",
        ])
        .expect("cli args should parse");

        let ServerCommand::Run(args) = command else {
            panic!("expected run command");
        };

        assert_eq!(
            args.config,
            Some(PathBuf::from("config/auth-framework.toml"))
        );
        assert_eq!(args.env_prefix, "AUTH_FRAMEWORK_STAGING");
        assert_eq!(args.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(args.port, Some(9090));
    }

    #[test]
    fn build_api_server_config_uses_runtime_and_auth_settings() {
        let mut auth_config = AuthConfig::default();
        auth_config.cors.enabled = true;
        auth_config.cors.allowed_origins = vec!["https://app.example.com".to_string()];

        let runtime_settings = ApiServerSettings {
            host: "127.0.0.1".to_string(),
            port: 9090,
            max_body_size: 4096,
            enable_tracing: false,
        };

        let config = build_api_server_config(&auth_config, &runtime_settings);

        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 9090);
        assert_eq!(config.max_body_size, 4096);
        assert!(!config.enable_tracing);
        assert_eq!(config.cors.allowed_origins, vec!["https://app.example.com"]);
    }
}
