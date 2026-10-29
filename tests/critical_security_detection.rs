//! Critical security vulnerability detection
//!
//! These tests look for the marks of the flaws earlier audits missed: a hardcoded user id,
//! unfinished client-secret and refresh-token validation, hardcoded scopes. They search the files
//! that now hold the OAuth2 flow, and they fail when one of those files is missing: a detector
//! that cannot read its subject has not found "no problem".

use std::path::{Path, PathBuf};

/// Where the OAuth2 flow lives. `src/server/oauth/oauth2.rs` is only a thin wrapper around
/// `oauth2_server.rs`; the HTTP handlers (client authentication, the refresh grant, revocation,
/// introspection) are in `src/api`.
const OAUTH2_FILES: &[&str] = &[
    "src/server/oauth/oauth2.rs",
    "src/server/oauth/oauth2_server.rs",
    "src/api/oauth2.rs",
    "src/api/oauth_advanced.rs",
];

/// Read a file the detectors depend on. A missing or unreadable file is a failure, never a
/// clean result.
fn read_subject(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "the audit subject {path} cannot be read ({e}); the file moved or was removed, so \
             this detector would report nothing about it. Repoint the detector."
        )
    })
}

/// The subject files with their text.
fn oauth2_sources() -> Vec<(&'static str, String)> {
    let sources: Vec<_> = OAUTH2_FILES
        .iter()
        .map(|path| (*path, read_subject(path)))
        .collect();
    // The subject is the OAuth2 flow, not four files that happen to exist: the client secret
    // check must be somewhere in them, or the detectors below are looking at the wrong files.
    assert!(
        sources
            .iter()
            .any(|(_, text)| text.contains("client_secret")),
        "none of {OAUTH2_FILES:?} mentions client_secret: these are not the OAuth2 flow any more"
    );
    sources
}

/// The files in `sources` that contain `pattern`.
fn files_containing(sources: &[(&'static str, String)], pattern: &str) -> Vec<&'static str> {
    sources
        .iter()
        .filter(|(_, text)| text.contains(pattern))
        .map(|(path, _)| *path)
        .collect()
}

#[test]
fn test_detect_hardcoded_user123_vulnerability() {
    let sources = oauth2_sources();
    let found = files_containing(&sources, "user123");
    if !found.is_empty() {
        panic!(
            "CRITICAL SECURITY VULNERABILITY DETECTED: hardcoded user ID 'user123' found in {found:?}.\n\
             This means ALL authorization codes are assigned to the same user.\n\
             Impact: Complete user identity bypass - any user can access any other user's resources!"
        );
    }

    println!("✓ No hardcoded 'user123' in {OAUTH2_FILES:?}");
}

#[test]
fn test_detect_missing_client_secret_validation() {
    let sources = oauth2_sources();
    let found = files_containing(&sources, "TODO: Validate client secret");
    if !found.is_empty() {
        panic!(
            "CRITICAL SECURITY VULNERABILITY DETECTED: client secret validation is missing ({found:?} still carry the TODO)!\n\
             Impact: Any client can impersonate any other client - complete authentication bypass!"
        );
    }

    // What this search can and cannot show: no TODO about it is left in these files. Whether the
    // validation is correct is the job of the behavioural tests, not of this one.
    println!("✓ No 'TODO: Validate client secret' left in {OAUTH2_FILES:?}");
}

#[test]
fn test_detect_missing_refresh_token_validation() {
    let sources = oauth2_sources();
    let found = files_containing(&sources, "TODO: Validate refresh token from storage");
    if !found.is_empty() {
        panic!(
            "CRITICAL SECURITY VULNERABILITY DETECTED: refresh token validation is missing ({found:?} still carry the TODO)!\n\
             Impact: Invalid/expired refresh tokens can be used to generate new access tokens!"
        );
    }

    println!("✓ No 'TODO: Validate refresh token from storage' left in {OAUTH2_FILES:?}");
}

#[test]
fn test_detect_hardcoded_scopes() {
    let sources = oauth2_sources();
    let found = files_containing(
        &sources,
        "vec![\"read\".to_string(), \"write\".to_string()]",
    );
    if !found.is_empty() {
        panic!(
            "CRITICAL SECURITY VULNERABILITY DETECTED: hardcoded scopes found in {found:?}!\n\
             Impact: All refresh tokens get 'read' and 'write' scopes regardless of original grant!"
        );
    }

    println!("✓ No hardcoded read/write scope list in {OAUTH2_FILES:?}");
}

#[test]
fn test_comprehensive_todo_audit() {
    // The OAuth2 flow plus the OpenID Connect core and the client registry.
    let mut critical_files: Vec<&str> = OAUTH2_FILES.to_vec();
    critical_files.extend([
        "src/server/oidc/core.rs",
        "src/server/core/client_registry.rs",
    ]);

    let mut total_todos = 0;
    let mut critical_issues = Vec::new();

    for file in &critical_files {
        let content = read_subject(file);
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

    println!(
        "✓ No TODO comments in the {} critical security files read",
        critical_files.len()
    );
}

#[test]
fn test_oauth2_implementation_completeness() {
    let sources = oauth2_sources();

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
        let found = files_containing(&sources, pattern);
        if found.is_empty() {
            println!("✓ {}: '{}' not present", description, pattern);
        } else {
            failures.push(format!(
                "❌ {}: Found '{}' in {:?}",
                description, pattern, found
            ));
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

/// Every `.rs` file under `dir`, found by walking the directory. An unreadable directory is a
/// failure.
fn rust_files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read the directory {}: {e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("cannot read an entry of {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            files.extend(rust_files_under(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    files
}

#[test]
fn test_security_audit_effectiveness() {
    // This meta-test verifies that security audits can catch these issues
    // If this test passes, it means the previous audit should have caught these vulnerabilities

    println!("Running comprehensive security audit check...");

    // Count all TODO comments in the source tree (not the tests, which may legitimately mention TODO)
    let mut total_todos = 0;
    let mut security_todos = 0;

    let files = rust_files_under(Path::new("src"));
    // Not vacuous: this must have read the source tree, not an empty or moved directory.
    assert!(
        files.len() > 100,
        "only {} .rs files found under src/; the audit would be reading the wrong tree",
        files.len()
    );

    for path in &files {
        let content = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
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

    println!(
        "✓ No TODO comments in the {} .rs files under src/",
        files.len()
    );
}

/// The detectors above must be able to fail: each pattern they look for is found when it is
/// present, and a missing subject panics.
#[test]
fn test_detectors_can_fail() {
    let planted = vec![(
        "planted.rs",
        "let id = \"user123\"; // TODO: Validate client secret".to_string(),
    )];
    assert_eq!(files_containing(&planted, "user123"), vec!["planted.rs"]);
    assert_eq!(
        files_containing(&planted, "TODO: Validate client secret"),
        vec!["planted.rs"]
    );
    assert!(files_containing(&planted, "TODO: Validate refresh token").is_empty());

    let missing = std::panic::catch_unwind(|| read_subject("src/server/oidc.rs"));
    assert!(
        missing.is_err(),
        "a moved file must fail, not read as clean"
    );
}
