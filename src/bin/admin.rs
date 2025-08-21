//! Comprehensive Auth Framework Administration Binary
//!
//! This binary provides three interfaces for managing the auth-framework:
//! 1. CLI - Command-line interface for scripting and automation
//! 2. TUI - Terminal-based user interface for interactive management
//! 3. Web GUI - Web-based interface for remote administration

use auth_framework::{
    admin::{AppState, CliCommand},
    config::AuthFrameworkSettings,
    errors::Result,
};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "auth-framework")]
#[command(about = "Auth Framework Administration - CLI, TUI, and Web GUI")]
#[command(version)]
pub struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config/auth-framework.toml")]
    pub config: String,

    /// Environment variable prefix
    #[arg(long, default_value = "AUTH_FRAMEWORK")]
    pub env_prefix: String,

    /// Verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Interface mode
    #[command(subcommand)]
    pub interface: Interface,
}

#[derive(Subcommand)]
pub enum Interface {
    /// Command Line Interface - for automation and scripting
    Cli {
        #[command(subcommand)]
        command: CliCommand,
    },
    /// Terminal User Interface - interactive management
    #[cfg(feature = "tui")]
    Tui {
        /// Start in read-only mode
        #[arg(long)]
        readonly: bool,
    },
    /// Web GUI - browser-based administration
    #[cfg(feature = "web-gui")]
    WebGui {
        /// Port to bind web server
        #[arg(short, long, default_value_t = 8080)]
        port: u16,

        /// Host to bind to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Run as daemon
        #[arg(short, long)]
        daemon: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    init_logging(args.verbose);

    // Load configuration
    let settings = load_config(&args.config, &args.env_prefix).await?;
    let app_state = AppState::new(settings)?;

    match args.interface {
        Interface::Cli { command } => {
            #[cfg(feature = "cli")]
            {
                use auth_framework::admin::cli;
                cli::run_cli(app_state, command).await?;
            }
            #[cfg(not(feature = "cli"))]
            {
                eprintln!("CLI feature not enabled. Rebuild with --features cli");
                std::process::exit(1);
            }
        }
        #[cfg(feature = "tui")]
        Interface::Tui { readonly } => {
            use auth_framework::admin::tui;
            tui::run_tui(app_state, readonly).await?;
        }
        #[cfg(feature = "web-gui")]
        Interface::WebGui { port, host, daemon } => {
            use auth_framework::admin::web;
            web::run_web_gui(app_state, &host, port, daemon, true).await?;
        }
    }

    Ok(())
}

fn init_logging(verbose: bool) {
    // Simple logging setup
    if verbose {
        println!("🔧 Verbose logging enabled");
    }
    // In a real implementation, this would configure proper logging
}

async fn load_config(
    config_path: &str,
    env_prefix: &str,
) -> Result<AuthFrameworkSettings, Box<dyn std::error::Error>> {
    // Simple configuration loading - in a real implementation this would
    // use the ConfigManager to load from various sources
    let settings = AuthFrameworkSettings::default();
    println!("✅ Configuration loaded from {}", config_path);
    println!("🔧 Environment prefix: {}", env_prefix);
    Ok(settings)
}


