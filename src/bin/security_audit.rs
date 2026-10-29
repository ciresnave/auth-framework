//! Security Audit Tool for AuthFramework
//!
//! This script analyzes the AuthFramework codebase for security configurations,
//! potential vulnerabilities, and compliance with security best practices.

use std::process::Command;

const USAGE: &str = "Usage: security_audit [--help] [--version]\n\n\
Greps the AuthFramework source tree under ./src for security-relevant patterns and prints a report.\n\
Run it from the repository root; it takes no other arguments.\n";

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => {}
        Some("-h" | "--help") => {
            print!("{USAGE}");
            return;
        }
        Some("-V" | "--version") => {
            println!("security_audit {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some(other) => {
            eprintln!("error: unknown argument '{other}'\n\n{USAGE}");
            std::process::exit(2);
        }
    }
    if let Some(extra) = args.next() {
        eprintln!("error: unexpected argument '{extra}'\n\n{USAGE}");
        std::process::exit(2);
    }

    println!(
        "🔒 AuthFramework v{} Security Audit",
        env!("CARGO_PKG_VERSION")
    );
    println!("=====================================\n");

    // 1. Check for hardcoded secrets
    check_hardcoded_secrets();

    // 2. Validate security configurations
    check_security_configs();

    // 3. Analyze authentication flows
    check_auth_flows();

    // 4. Validate encryption standards
    check_encryption_standards();

    // 5. Check for SQL injection protections
    check_sql_injection_protection();

    // 6. Validate input sanitization
    check_input_sanitization();

    println!("\n✅ Security Audit Complete");
}

fn check_hardcoded_secrets() {
    println!("🔍 Checking for hardcoded secrets...");

    // Check for common secret patterns
    let patterns = vec![
        "secret.*=.*\"[a-zA-Z0-9]+\"",
        "password.*=.*\"[a-zA-Z0-9]+\"",
        "key.*=.*\"[a-zA-Z0-9]+\"",
        "token.*=.*\"[a-zA-Z0-9]+\"",
    ];

    for pattern in patterns {
        let output = Command::new("grep")
            .args(["-r", "-i", "--include=*.rs", pattern, "src/"])
            .output();

        match output {
            Ok(result) => {
                if !result.stdout.is_empty() {
                    println!("⚠️  Potential hardcoded secret found: {}", pattern);
                    println!("{}", String::from_utf8_lossy(&result.stdout));
                }
            }
            Err(_) => println!("   Could not check pattern: {}", pattern),
        }
    }

    println!("✅ Hardcoded secrets check complete\n");
}

fn check_security_configs() {
    println!("🛡️  Checking security configurations...");

    // Check SecurityConfig usage
    let output = Command::new("grep")
        .args(["-r", "--include=*.rs", "SecurityConfig", "src/"])
        .output();

    match output {
        Ok(result) => {
            if !result.stdout.is_empty() {
                println!("✅ SecurityConfig found in codebase");
                let lines = String::from_utf8_lossy(&result.stdout);
                let count = lines.lines().count();
                println!("   {} security configuration references found", count);
            }
        }
        Err(_) => println!("⚠️  Could not analyze SecurityConfig usage"),
    }

    println!("✅ Security configuration check complete\n");
}

fn check_auth_flows() {
    println!("🔐 Checking authentication flows...");

    let auth_patterns = vec![
        "authenticate",
        "authorize",
        "validate_token",
        "verify_password",
        "hash_password",
    ];

    for pattern in auth_patterns {
        let output = Command::new("grep")
            .args(["-r", "--include=*.rs", "-c", pattern, "src/"])
            .output();

        match output {
            Ok(result) => {
                if !result.stdout.is_empty() {
                    let count: i32 = String::from_utf8_lossy(&result.stdout)
                        .lines()
                        .filter_map(|line| line.split(':').nth(1)?.parse::<i32>().ok())
                        .sum();
                    if count > 0 {
                        println!(
                            "✅ {} authentication functions found: {} occurrences",
                            pattern, count
                        );
                    }
                }
            }
            Err(_) => println!("⚠️  Could not check: {}", pattern),
        }
    }

    println!("✅ Authentication flow check complete\n");
}

fn check_encryption_standards() {
    println!("🔐 Checking encryption standards...");

    let crypto_patterns = vec![
        "AES", "ChaCha20", "Argon2", "bcrypt", "scrypt", "HMAC", "RSA", "Ed25519",
    ];

    for pattern in crypto_patterns {
        let output = Command::new("grep")
            .args(["-r", "--include=*.rs", "-i", pattern, "src/"])
            .output();

        if let Ok(result) = output
            && !result.stdout.is_empty()
        {
            println!("✅ {} encryption found in codebase", pattern);
        }
    }

    println!("✅ Encryption standards check complete\n");
}

fn check_sql_injection_protection() {
    println!("🛡️  Checking SQL injection protection...");

    // Check for parameterized queries
    let output = Command::new("grep")
        .args(["-r", "--include=*.rs", "prepare\\|bind\\|?", "src/"])
        .output();

    match output {
        Ok(result) => {
            if !result.stdout.is_empty() {
                println!("✅ Parameterized query patterns found");
            } else {
                println!("⚠️  No parameterized query patterns detected");
            }
        }
        Err(_) => println!("⚠️  Could not check SQL injection protection"),
    }

    println!("✅ SQL injection protection check complete\n");
}

fn check_input_sanitization() {
    println!("🧹 Checking input sanitization...");

    let sanitization_patterns = vec!["validate", "sanitize", "escape", "filter"];

    for pattern in sanitization_patterns {
        let output = Command::new("grep")
            .args(["-r", "--include=*.rs", "-c", pattern, "src/"])
            .output();

        if let Ok(result) = output
            && !result.stdout.is_empty()
        {
            let count: i32 = String::from_utf8_lossy(&result.stdout)
                .lines()
                .filter_map(|line| line.split(':').nth(1)?.parse::<i32>().ok())
                .sum();
            if count > 0 {
                println!(
                    "✅ {} input sanitization functions: {} occurrences",
                    pattern, count
                );
            }
        }
    }

    println!("✅ Input sanitization check complete\n");
}
