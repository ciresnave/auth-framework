//! CLI integration helpers for enhanced device flow
//!
//! This module provides utilities for integrating enhanced device flow authentication
//! into command-line applications, including progress indicators, user interaction,
//! and token persistence.

#[cfg(feature = "enhanced-device-flow")]
use crate::{
    methods::enhanced_device::{EnhancedDeviceFlowMethod, DeviceFlowInstructions},
    errors::Result,
    tokens::AuthToken,
};

#[cfg(feature = "enhanced-device-flow")]
use oauth_device_flows::Provider as DeviceFlowProvider;
use std::time::Duration;

/// CLI-specific configuration for enhanced device flow
#[cfg(feature = "enhanced-device-flow")]
pub struct CliDeviceFlowConfig {
    /// Whether to show progress indicators
    pub show_progress: bool,
    /// Whether to attempt to open browser automatically
    pub auto_open_browser: bool,
    /// Custom timeout for device flow
    pub timeout: Option<Duration>,
    /// Whether to display QR codes in terminal
    pub show_qr_code: bool,
    /// Whether to use colored output
    pub use_colors: bool,
}

#[cfg(feature = "enhanced-device-flow")]
impl Default for CliDeviceFlowConfig {
    fn default() -> Self {
        Self {
            show_progress: true,
            auto_open_browser: false, // Don't auto-open by default for security
            timeout: Some(Duration::from_secs(300)), // 5 minutes default
            show_qr_code: true,
            use_colors: true,
        }
    }
}

/// CLI helper for enhanced device flow authentication
#[cfg(feature = "enhanced-device-flow")]
pub struct CliDeviceFlowHelper {
    method: EnhancedDeviceFlowMethod,
    config: CliDeviceFlowConfig,
}

#[cfg(feature = "enhanced-device-flow")]
impl CliDeviceFlowHelper {
    /// Create a new CLI device flow helper
    pub fn new(
        provider: DeviceFlowProvider,
        client_id: String,
        config: CliDeviceFlowConfig,
    ) -> Self {
        let method = EnhancedDeviceFlowMethod::new(provider, client_id);
        Self { method, config }
    }

    /// Create helper with client secret
    pub fn with_client_secret(mut self, client_secret: String) -> Self {
        self.method = self.method.client_secret(client_secret);
        self
    }

    /// Set custom scopes
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.method = self.method.scopes(scopes);
        self
    }

    /// Set polling configuration
    pub fn with_polling_config(mut self, interval: Duration, max_attempts: u32) -> Self {
        self.method = self.method.polling_config(interval, max_attempts);
        self
    }

    /// Perform device flow authentication with CLI interaction
    pub async fn authenticate(&self) -> Result<AuthToken> {
        // Start device flow
        let instructions = self.method.start_device_flow().await?;

        // Display instructions to user
        self.display_cli_instructions(&instructions);

        // Optionally auto-open browser
        if self.config.auto_open_browser {
            self.attempt_browser_open(&instructions.verification_uri);
        }

        // Poll for token with progress indication
        if self.config.show_progress {
            self.poll_with_progress(instructions).await
        } else {
            match self.config.timeout {
                Some(timeout) => instructions.poll_for_token_with_timeout(Some(timeout)).await,
                None => instructions.poll_for_token().await,
            }
        }
    }

    /// Display user-friendly CLI instructions
    fn display_cli_instructions(&self, instructions: &DeviceFlowInstructions) {
        if self.config.use_colors {
            self.display_colored_instructions(instructions);
        } else {
            self.display_plain_instructions(instructions);
        }
    }

    /// Display colored instructions (when colors are enabled)
    fn display_colored_instructions(&self, instructions: &DeviceFlowInstructions) {
        println!("\n🔐 \x1b[1;34mDevice Authentication Required\x1b[0m");
        println!("\x1b[1;37m{}\x1b[0m", "=".repeat(35));
        println!("\n\x1b[1;32m1.\x1b[0m Open your web browser and visit:");
        println!("   \x1b[1;36m{}\x1b[0m", instructions.verification_uri);
        println!("\n\x1b[1;32m2.\x1b[0m Enter this code when prompted:");
        println!("   \x1b[1;33m{}\x1b[0m", instructions.user_code);

        if let Some(complete_uri) = &instructions.verification_uri_complete {
            println!("\n\x1b[1;32mAlternatively:\x1b[0m Visit this direct link:");
            println!("   \x1b[1;36m{}\x1b[0m", complete_uri);
        }

        if self.config.show_qr_code {
            if let Some(qr_code) = &instructions.qr_code {
                println!("\n\x1b[1;32mOr scan this QR code:\x1b[0m");
                println!("{}", qr_code);
            }
        }

        println!("\n⏰ Code expires in \x1b[1;31m{}\x1b[0m minutes", instructions.expires_in / 60);
        println!("🔄 \x1b[1;90mWaiting for authorization...\x1b[0m\n");
    }

    /// Display plain instructions (when colors are disabled)
    fn display_plain_instructions(&self, instructions: &DeviceFlowInstructions) {
        println!("\nDevice Authentication Required");
        println!("{}", "=".repeat(35));
        println!("\n1. Open your web browser and visit:");
        println!("   {}", instructions.verification_uri);
        println!("\n2. Enter this code when prompted:");
        println!("   {}", instructions.user_code);

        if let Some(complete_uri) = &instructions.verification_uri_complete {
            println!("\nAlternatively: Visit this direct link:");
            println!("   {}", complete_uri);
        }

        if self.config.show_qr_code {
            if let Some(qr_code) = &instructions.qr_code {
                println!("\nOr scan this QR code:");
                println!("{}", qr_code);
            }
        }

        println!("\nCode expires in {} minutes", instructions.expires_in / 60);
        println!("Waiting for authorization...\n");
    }

    /// Attempt to open browser (best effort)
    fn attempt_browser_open(&self, url: &str) {
        #[cfg(target_os = "windows")]
        {
            let _ = std::process::Command::new("cmd")
                .args(&["/c", "start", url])
                .spawn();
        }

        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("open")
                .arg(url)
                .spawn();
        }

        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("xdg-open")
                .arg(url)
                .spawn();
        }
    }

    /// Poll with progress indication
    async fn poll_with_progress(&self, instructions: DeviceFlowInstructions) -> Result<AuthToken> {
        let timeout = self.config.timeout.unwrap_or(Duration::from_secs(300));

        // Simple progress indication (in a real implementation, you might use a progress bar library)
        let progress_task = tokio::spawn(async move {
            let mut dots = 0;
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                dots = (dots + 1) % 4;
                let dot_str = ".".repeat(dots);
                print!("\r🔄 Waiting for authorization{:<3}", dot_str);
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
        });

        // Poll for token
        let result = instructions.poll_for_token_with_timeout(Some(timeout)).await;

        // Stop progress indication
        progress_task.abort();
        
        match &result {
            Ok(_) => {
                if self.config.use_colors {
                    println!("\r✅ \x1b[1;32mAuthentication successful!\x1b[0m           ");
                } else {
                    println!("\rAuthentication successful!           ");
                }
            }
            Err(e) => {
                if self.config.use_colors {
                    println!("\r❌ \x1b[1;31mAuthentication failed:\x1b[0m {}          ", e);
                } else {
                    println!("\rAuthentication failed: {}          ", e);
                }
            }
        }

        result
    }
}

/// Utility functions for CLI integration
#[cfg(feature = "enhanced-device-flow")]
pub mod cli_utils {
    use super::*;

    /// Check if running in a terminal that supports colors
    pub fn supports_colors() -> bool {
        std::env::var("NO_COLOR").is_err() && 
        std::env::var("TERM").map(|t| t != "dumb").unwrap_or(false)
    }

    /// Create a CLI config with smart defaults based on environment
    pub fn smart_cli_config() -> CliDeviceFlowConfig {
        CliDeviceFlowConfig {
            show_progress: true,
            auto_open_browser: false, // Security consideration
            timeout: Some(Duration::from_secs(300)),
            show_qr_code: true,
            use_colors: supports_colors(),
        }
    }

    /// Format duration for human-readable display
    pub fn format_duration(duration: Duration) -> String {
        let secs = duration.as_secs();
        if secs >= 60 {
            format!("{} minute(s) {} second(s)", secs / 60, secs % 60)
        } else {
            format!("{} second(s)", secs)
        }
    }
}

#[cfg(test)]
#[cfg(feature = "enhanced-device-flow")]
mod tests {
    use super::*;
    use crate::methods::AuthMethod;

    #[test]
    fn test_cli_config_defaults() {
        let config = CliDeviceFlowConfig::default();
        assert!(config.show_progress);
        assert!(!config.auto_open_browser); // Should be false for security
        assert!(config.timeout.is_some());
        assert!(config.show_qr_code);
        assert!(config.use_colors);
    }

    #[test]
    fn test_smart_cli_config() {
        let config = cli_utils::smart_cli_config();
        // Should have reasonable defaults
        assert!(config.timeout.is_some());
        assert!(config.timeout.unwrap() >= Duration::from_secs(60));
    }

    #[test]
    fn test_duration_formatting() {
        assert_eq!(cli_utils::format_duration(Duration::from_secs(30)), "30 second(s)");
        assert_eq!(cli_utils::format_duration(Duration::from_secs(90)), "1 minute(s) 30 second(s)");
        assert_eq!(cli_utils::format_duration(Duration::from_secs(120)), "2 minute(s) 0 second(s)");
    }

    #[test]
    fn test_cli_helper_creation() {
        let config = CliDeviceFlowConfig::default();
        let helper = CliDeviceFlowHelper::new(
            DeviceFlowProvider::GitHub,
            "test-client-id".to_string(),
            config,
        );

        // Should be able to chain configuration
        let helper = helper
            .with_scopes(vec!["user:email".to_string()])
            .with_polling_config(Duration::from_secs(5), 60);

        // Verify the helper was created - access the name field directly since it's private
        assert_eq!(helper.method.name, "enhanced-device-flow");
    }
}
