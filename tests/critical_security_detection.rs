//! Critical security vulnerability detection
//!
//! This test exposes the hardcoded user ID and missing client secret validation
//! that previous audits failed to catch.

#[test]
fn test_detect_hardcoded_user123_vulnerability() {
    // This test looks for the CRITICAL hardcoded user ID at oauth2.rs:660
    let oauth2_source =
        std::fs::read_to_string("src/server/oauth/oauth2.rs").expect("Could not read oauth2.rs");

    // Search for the hardcoded user ID
    if oauth2_source.contains("user123") {
        panic!(
            "CRITICAL SECURITY VULNERABILITY DETECTED: Hardcoded user ID 'user123' found in oauth2.rs!\n\
               This means ALL authorization codes are assigned to the same user.\n\
               Location: src/server/oauth/oauth2.rs around line 660\n\
               Impact: Complete user identity bypass - any user can access any other user's resources!"
        );
    }

    println!("✓ No hardcoded 'user123' found (good)");
}

#[test]
fn test_detect_missing_client_secret_validation() {
    // This test looks for the TODO comment that shows missing client secret validation
    let oauth2_source =
        std::fs::read_to_string("src/server/oauth/oauth2.rs").expect("Could not read oauth2.rs");

    // Search for the TODO comment about client secret validation
    if oauth2_source.contains("TODO: Validate client secret") {
        panic!(
            "CRITICAL SECURITY VULNERABILITY DETECTED: Client secret validation is missing!\n\
               Location: src/server/oauth/oauth2.rs around line 807\n\
               Impact: Any client can impersonate any other client - complete authentication bypass!"
        );
    }

    println!("✓ Client secret validation appears to be implemented (good)");
}

#[test]
fn test_detect_missing_refresh_token_validation() {
    // This test looks for the TODO comment about refresh token validation
    let oauth2_source =
        std::fs::read_to_string("src/server/oauth/oauth2.rs").expect("Could not read oauth2.rs");

    // Search for the TODO comment about refresh token validation
    if oauth2_source.contains("TODO: Validate refresh token from storage") {
        panic!(
            "CRITICAL SECURITY VULNERABILITY DETECTED: Refresh token validation is missing!\n\
               Location: src/server/oauth/oauth2.rs around line 771\n\
               Impact: Invalid/expired refresh tokens can be used to generate new access tokens!"
        );
    }

    println!("✓ Refresh token validation appears to be implemented (good)");
}

#[test]
fn test_detect_hardcoded_scopes() {
    // This test looks for hardcoded scopes that bypass authorization
    let oauth2_source =
        std::fs::read_to_string("src/server/oauth/oauth2.rs").expect("Could not read oauth2.rs");

    // Search for hardcoded scopes in refresh token flow
    if oauth2_source.contains("vec![\"read\".to_string(), \"write\".to_string()]") {
        panic!(
            "CRITICAL SECURITY VULNERABILITY DETECTED: Hardcoded scopes found!\n\
               Location: src/server/oauth/oauth2.rs around line 774\n\
               Impact: All refresh tokens get 'read' and 'write' scopes regardless of original grant!"
        );
    }

    println!("✓ No hardcoded scopes found (good)");
}

#[test]
fn test_comprehensive_todo_audit() {
    let critical_files = vec![
        "src/server/oauth/oauth2.rs",
        "src/server/oidc.rs",
        "src/server/client_registry.rs",
    ];

    let mut total_todos = 0;
    let mut critical_issues = Vec::new();

    for file in critical_files {
        if let Ok(content) = std::fs::read_to_string(file) {
            let file_todos = content.matches("TODO").count();
            total_todos += file_todos;

            if file_todos > 0 {
                critical_issues.push(format!("{}: {} TODO comments", file, file_todos));

                // Look for specific critical patterns
                if content.contains("TODO: Validate client secret") {
                    critical_issues.push(format!(
                        "{}: CRITICAL - Missing client secret validation",
                        file
                    ));
                }
                if content.contains("TODO: Validate refresh token") {
                    critical_issues.push(format!(
                        "{}: CRITICAL - Missing refresh token validation",
                        file
                    ));
                }
                if content.contains("user123") {
                    critical_issues.push(format!("{}: CRITICAL - Hardcoded user ID", file));
                }
            }
        }
    }

    if total_todos > 0 {
        let mut error_msg = format!(
            "CRITICAL SECURITY AUDIT FAILURE: Found {} TODO comments in security-critical files!\n\n",
            total_todos
        );

        for issue in critical_issues {
            error_msg.push_str(&format!("- {}\n", issue));
        }

        error_msg.push_str("\nThese TODO comments represent incomplete security implementations that make the framework unsuitable for production use!");

        panic!("{}", error_msg);
    }

    println!("✓ No TODO comments found in critical security files (good)");
}

#[test]
fn test_oauth2_implementation_completeness() {
    // Read the oauth2.rs file and check for implementation completeness
    let oauth2_source =
        std::fs::read_to_string("src/server/oauth/oauth2.rs").expect("Could not read oauth2.rs");

    let critical_checks = vec![
        ("TODO: Validate client secret", "Client secret validation"),
        ("TODO: Validate refresh token", "Refresh token validation"),
        ("TODO: Get user_id from", "User ID extraction"),
        ("user123", "Hardcoded user credentials"),
        (
            "vec![\"read\".to_string(), \"write\".to_string()]",
            "Hardcoded authorization scopes",
        ),
    ];

    let mut failures = Vec::new();

    for (pattern, description) in critical_checks {
        if oauth2_source.contains(pattern) {
            failures.push(format!("❌ {}: Found '{}'", description, pattern));
        } else {
            println!("✓ {}: Implementation appears complete", description);
        }
    }

    if !failures.is_empty() {
        let mut error_msg = String::from("OAUTH2 IMPLEMENTATION IS CRITICALLY INCOMPLETE:\n\n");
        for failure in failures {
            error_msg.push_str(&format!("{}\n", failure));
        }
        error_msg.push_str(
            "\nThese issues represent fundamental authentication bypass vulnerabilities!",
        );

        panic!("{}", error_msg);
    }
}

#[test]
fn test_security_audit_effectiveness() {
    // This meta-test verifies that security audits can catch these issues
    // If this test passes, it means the previous audit should have caught these vulnerabilities

    println!("Running comprehensive security audit check...");

    // Count all TODO comments in the codebase
    let mut total_todos = 0;
    let mut security_todos = 0;

    // Read only source files (not test files, as test files may legitimately contain TODO comments for test infrastructure)
    let source_dirs = vec!["src/"];

    for dir in source_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "rs")
                    && let Ok(content) = std::fs::read_to_string(&path)
                {
                    // Count actual TODO comments (not TODO in string literals or comments about TODOs)
                    for line in content.lines() {
                        let trimmed = line.trim();
                        // Look for actual TODO comments (starting with // TODO or /* TODO)
                        if (trimmed.starts_with("// TODO") || trimmed.starts_with("/* TODO"))
                            && !trimmed.contains("This test looks for the TODO")
                            && !trimmed.contains("Search for the TODO")
                        {
                            total_todos += 1;

                            // Check for security-related TODOs
                            if trimmed.contains("TODO: Validate")
                                || trimmed.contains("TODO: Implement")
                                || trimmed.contains("TODO: Get")
                            {
                                security_todos += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    if total_todos > 0 {
        println!("AUDIT FAILURE DETECTED:");
        println!("- Total TODO comments found: {}", total_todos);
        println!("- Security-related TODOs: {}", security_todos);
        println!();
        println!("A comprehensive security audit should have identified all TODO comments");
        println!("as potential security vulnerabilities requiring immediate attention.");
        println!();
        println!("The fact that these TODOs exist means previous audits were INADEQUATE.");

        // This is the critical failure - audits missed these issues
        panic!(
            "SECURITY AUDIT METHODOLOGY FAILURE: {} TODO comments were not identified as security risks in previous audits",
            total_todos
        );
    }
}
