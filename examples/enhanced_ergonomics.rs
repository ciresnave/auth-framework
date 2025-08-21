//! Enhanced Ergonomics Example - Demonstrating New Developer Experience Features
//!
//! This example showcases the new ergonomic improvements to the Auth Framework:
//! - Prelude module for easy imports
//! - Quick start builders for common setups
//! - Security presets with validation
//! - Enhanced error messages with actionable guidance
//! - Fluent API design patterns
//!
//! Run this example with:
//! ```bash
//! JWT_SECRET="your-super-secret-jwt-key-at-least-32-characters-long" cargo run --example enhanced_ergonomics --features "enhanced-rbac postgres-storage"
//! ```

use auth_framework::prelude::*;
use std::env;

#[tokio::main]
async fn main() -> AuthFrameworkResult<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("auth_framework=debug,enhanced_ergonomics=info")
        .init();

    println!("🚀 Auth Framework - Enhanced Ergonomics Demo");
    println!("=============================================\n");

    // Demonstrate enhanced error handling
    demonstrate_enhanced_errors().await;

    // Demonstrate quick start builder
    demonstrate_quick_start().await?;

    // Demonstrate security presets
    demonstrate_security_presets().await?;

    // Demonstrate fluent API design
    demonstrate_fluent_api().await?;

    println!("\n🎉 Enhanced ergonomics demo completed successfully!");
    println!("💡 Check out the code to see how much simpler the API has become!");

    Ok(())
}

/// Demonstrate enhanced error messages with actionable guidance
async fn demonstrate_enhanced_errors() {
    println!("📋 1. Enhanced Error Messages");
    println!("=============================");

    // Simulate configuration errors with helpful messages
    let weak_secret = "weak123";

    if let Err(error) = validate_jwt_secret(weak_secret) {
        println!("❌ Configuration Error Detected:");
        println!("   {}", error);

        // In the enhanced error type, we'd have:
        // if let Some(help) = error.help { println!("💡 Help: {}", help); }
        // if let Some(fix) = error.suggested_fix { println!("🔧 Fix: {}", fix); }
        // if let Some(docs) = error.docs_url { println!("📖 Docs: {}", docs); }

        println!("💡 Help: Use a cryptographically secure random string of at least 32 characters");
        println!("🔧 Fix: Generate a secure secret: `openssl rand -hex 32`");
        println!("📖 Docs: https://docs.rs/auth-framework/latest/auth_framework/config/");
    }

    println!();
}

/// Demonstrate the quick start builder for common setups
async fn demonstrate_quick_start() -> AuthFrameworkResult<()> {
    println!("⚡ 2. Quick Start Builder");
    println!("========================");

    // Check if JWT_SECRET is set
    match env::var("JWT_SECRET") {
        Ok(secret) if secret.len() >= 32 => {
            println!("✅ JWT_SECRET found and valid");

            // Quick start - one-liner setup for common case
            println!("🔧 Creating auth framework with quick start...");

            let _auth = AuthFramework::quick_start()
                .jwt_auth_from_env()
                .with_memory_storage() // Use memory for demo
                .security_level(SecurityPreset::Development)
                .build()
                .await?;

            println!("✅ Auth framework created successfully!");
            println!("   - JWT authentication configured from environment");
            println!("   - Memory storage (development only)");
            println!("   - Development security preset applied");
        }
        Ok(secret) => {
            println!(
                "⚠️  JWT_SECRET found but too short ({} chars, need 32+)",
                secret.len()
            );
            println!("💡 Tip: Run with a longer JWT_SECRET:");
            println!(
                "   JWT_SECRET=\"$(openssl rand -hex 32)\" cargo run --example enhanced_ergonomics"
            );
        }
        Err(_) => {
            println!("⚠️  JWT_SECRET not found");
            println!("💡 Tip: Set JWT_SECRET environment variable:");
            println!("   JWT_SECRET=\"your-super-secret-jwt-key-at-least-32-characters-long\" \\");
            println!("   cargo run --example enhanced_ergonomics");

            // Demo with inline secret (development only!)
            println!("\n🔧 Creating demo with inline secret (development only)...");
            let _auth = AuthFramework::quick_start()
                .jwt_auth("demo-secret-for-development-only-not-production-safe")
                .with_memory_storage()
                .security_level(SecurityPreset::Development)
                .build()
                .await?;

            println!("✅ Demo auth framework created!");
        }
    }

    println!();
    Ok(())
}

/// Demonstrate security presets with validation
async fn demonstrate_security_presets() -> AuthFrameworkResult<()> {
    println!("🔒 3. Security Presets & Validation");
    println!("===================================");

    // Demonstrate different security levels
    let presets = [
        (
            SecurityPreset::Development,
            "Development (convenient but insecure)",
        ),
        (SecurityPreset::Balanced, "Balanced (good for most apps)"),
        (
            SecurityPreset::HighSecurity,
            "High Security (sensitive data)",
        ),
        (SecurityPreset::Paranoid, "Paranoid (maximum security)"),
    ];

    for (preset, description) in &presets {
        println!("🛡️  {}: {}", preset.clone() as u8, description);

        // Show security configuration
        let security_config = preset.to_config();
        println!(
            "   - Min password length: {} chars",
            security_config.min_password_length
        );
        println!("   - JWT algorithm: {:?}", security_config.jwt_algorithm);
        println!(
            "   - Session timeout: {:?}",
            security_config.session_timeout
        );

        // Show rate limiting
        let rate_config = preset.to_rate_limit_config();
        if rate_config.enabled {
            println!(
                "   - Rate limit: {} requests per {:?}",
                rate_config.max_requests, rate_config.window
            );
        } else {
            println!("   - Rate limiting: disabled");
        }

        println!();
    }

    // Demonstrate security audit
    println!("🔍 Running Security Audit for Development preset...");
    let audit_report = SecurityPreset::Development.security_audit().await?;

    println!("📊 Audit Results:");
    println!("   Status: {:?}", audit_report.status);
    println!(
        "   Issues: {} critical, {} errors, {} warnings",
        audit_report.critical_count, audit_report.error_count, audit_report.warning_count
    );

    if !audit_report.issues.is_empty() {
        println!("\n🚨 Security Issues Found:");
        for issue in audit_report.issues.iter().take(3) {
            // Show first 3
            println!(
                "   {} {}: {}",
                match issue.severity {
                    SecuritySeverity::Critical => "🚨",
                    SecuritySeverity::Error => "❌",
                    SecuritySeverity::Warning => "⚠️ ",
                    SecuritySeverity::Info => "ℹ️ ",
                },
                issue.component,
                issue.description
            );
            println!("     💡 {}", issue.suggestion);
        }

        if audit_report.issues.len() > 3 {
            println!("   ... and {} more issues", audit_report.issues.len() - 3);
        }
    }

    println!();
    Ok(())
}

/// Demonstrate fluent API design patterns
async fn demonstrate_fluent_api() -> AuthFrameworkResult<()> {
    println!("🔗 4. Fluent API Design");
    println!("=======================");

    println!("🔧 Building auth framework with fluent API...");

    // Demonstrate the fluent builder pattern
    let _auth = AuthFramework::builder()
        .security_preset(SecurityPreset::Balanced)
        .with_jwt()
        .secret("demo-secret-for-development-only-not-production-safe")
        .issuer("enhanced-ergonomics-demo")
        .audience("demo-users")
        .token_lifetime(hours(2))
        .done()
        .with_storage()
        .memory()
        .done()
        .with_rate_limiting()
        .per_ip(requests(100).per_minute())
        .done()
        .with_security()
        .min_password_length(8)
        .require_password_complexity(true)
        .secure_cookies(true)
        .done()
        .with_audit()
        .enabled(true)
        .log_failures(true)
        .done()
        .build()
        .await?;

    println!("✅ Fluent API auth framework created!");
    println!("   - JWT configured with custom settings");
    println!("   - Memory storage configured");
    println!("   - Rate limiting: 100 requests per minute");
    println!("   - Security: 8+ char passwords required");
    println!("   - Audit: failure logging enabled");

    println!("\n💡 Compare this fluent API to the old verbose configuration!");
    println!("   Old way: Multiple separate config objects, unclear relationships");
    println!("   New way: Single fluent chain, clear relationships, IDE completion");

    // Demonstrate time helpers
    println!("\n⏰ Time Duration Helpers:");
    println!("   - hours(2) = {:?}", hours(2));
    println!("   - minutes(30) = {:?}", minutes(30));
    println!("   - days(7) = {:?}", days(7));
    println!("   - weeks(2) = {:?}", weeks(2));

    // Demonstrate rate limiting helpers
    println!("\n🚦 Rate Limiting Helpers:");
    let (count, window) = requests(100).per_minute();
    println!(
        "   - requests(100).per_minute() = {} requests per {:?}",
        count, window
    );
    let (count, window) = requests(50).per_hour();
    println!(
        "   - requests(50).per_hour() = {} requests per {:?}",
        count, window
    );

    println!();
    Ok(())
}

/// Helper function to validate JWT secret (demonstrates enhanced error handling)
fn validate_jwt_secret(secret: &str) -> AuthFrameworkResult<()> {
    if secret.len() < 32 {
        return Err(AuthError::jwt_secret_too_short(secret.len()));
    }

    if secret.contains("password") || secret.contains("secret") || secret.contains("123") {
        return Err(AuthError::config_with_help(
            "JWT secret contains weak patterns or common words".to_string(),
            "Use a cryptographically secure random string without common words".to_string(),
            Some("Generate a secure secret: `openssl rand -base64 64`".to_string()),
        ));
    }

    Ok(())
}

/// Demo showing different ways to configure auth for different use cases
#[allow(dead_code)]
async fn demonstrate_use_case_presets() -> AuthFrameworkResult<()> {
    println!("🎯 Use Case Presets");
    println!("===================");

    // Web application
    println!("🌐 Web Application Configuration:");
    let _web_auth = AuthFramework::for_use_case(UseCasePreset::WebApp)
        // Note: Customize would need setter methods, using direct builder for now
        .build()
        .await?;
    println!("   ✅ Configured for web app with sessions and CSRF protection");

    // API Service
    println!("\n🔌 API Service Configuration:");
    let _api_auth = AuthFramework::for_use_case(UseCasePreset::ApiService)
        // Note: Customize would need setter methods, using direct builder for now
        .build()
        .await?;
    println!("   ✅ Configured for API with JWT tokens and rate limiting");

    // Enterprise
    println!("\n🏢 Enterprise Configuration:");
    let _enterprise_auth = AuthFramework::for_use_case(UseCasePreset::Enterprise)
        .security_preset(SecurityPreset::HighSecurity)
        .build()
        .await?;
    println!("   ✅ Configured for enterprise with MFA and comprehensive auditing");

    Ok(())
}
