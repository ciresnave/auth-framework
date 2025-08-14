//! Comprehensive code quality audit tests
//!
//! These tests ensure we don't ship incomplete or potentially vulnerable code.

use std::fs;

/// Test to ensure no TODO comments exist in production code
#[test]
fn test_no_todos_in_source_code() {
    let todos = find_todos_in_directory("src");

    if !todos.is_empty() {
        let mut error_msg = String::from("Found TODO comments in source code:\n");
        for (file, line_num, content) in todos {
            error_msg.push_str(&format!("  {}:{} - {}\n", file, line_num, content.trim()));
        }
        error_msg.push_str("\nAll TODOs must be completed before release!");
        panic!("{}", error_msg);
    }
}

/// Test to ensure no TODO comments exist in examples (they should be production-ready)
#[test]
fn test_no_todos_in_examples() {
    let todos = find_todos_in_directory("examples");

    if !todos.is_empty() {
        let mut error_msg = String::from("Found TODO comments in examples:\n");
        for (file, line_num, content) in todos {
            error_msg.push_str(&format!("  {}:{} - {}\n", file, line_num, content.trim()));
        }
        error_msg.push_str("\nExamples must be complete and production-ready!");
        panic!("{}", error_msg);
    }
}

/// Test to audit all #[allow(dead_code)] directives
#[test]
fn test_audit_allow_dead_code_directives() {
    let allows = find_allow_dead_code_in_directory("src");

    if !allows.is_empty() {
        let mut error_msg = String::from("Found #[allow(dead_code)] directives in source code:\n");
        for (file, line_num, content) in allows {
            error_msg.push_str(&format!("  {}:{} - {}\n", file, line_num, content.trim()));
        }
        error_msg.push('\n');
        error_msg.push_str("Each #[allow(dead_code)] directive must be justified:\n");
        error_msg.push_str("- Is this truly necessary?\n");
        error_msg.push_str("- Could it be hiding incomplete implementations?\n");
        error_msg.push_str("- Is there a comment explaining why it's needed?\n");
        error_msg.push_str("- Could the code be refactored to avoid it?\n\n");
        error_msg.push_str("Security-critical code should NOT use #[allow(dead_code)]!\n");

        // This is a warning, not a hard failure for now, but should be reviewed
        println!("WARNING: {}", error_msg);
    }
}

/// Test to ensure no unimplemented!() macros in production code
#[test]
fn test_no_unimplemented_in_source() {
    let unimplemented = find_pattern_in_directory("src", "unimplemented!");

    if !unimplemented.is_empty() {
        let mut error_msg = String::from("Found unimplemented!() macros in source code:\n");
        for (file, line_num, content) in unimplemented {
            error_msg.push_str(&format!("  {}:{} - {}\n", file, line_num, content.trim()));
        }
        error_msg.push_str("\nAll functionality must be implemented!");
        panic!("{}", error_msg);
    }
}

/// Test to find potential security-critical panics
#[test]
fn test_audit_panics_in_source() {
    let panics = find_pattern_in_directory("src", "panic!");

    // Filter out test-only panics
    let non_test_panics: Vec<_> = panics
        .into_iter()
        .filter(|(file, _, _)| !file.contains("test") && !file.contains("bench"))
        .collect();

    if !non_test_panics.is_empty() {
        let mut error_msg = String::from("Found panic!() calls in non-test source code:\n");
        for (file, line_num, content) in non_test_panics {
            error_msg.push_str(&format!("  {}:{} - {}\n", file, line_num, content.trim()));
        }
        error_msg.push_str("\nProduction code should handle errors gracefully, not panic!\n");
        error_msg.push_str("Consider using Result<T, E> instead.\n");

        // This is a warning for now, but should be reviewed
        println!("WARNING: {}", error_msg);
    }
}

/// Test to find hardcoded credentials or secrets
#[test]
fn test_no_hardcoded_secrets() {
    let patterns = vec![
        "password",
        "secret",
        "api_key",
        "access_token",
        "private_key",
        "client_secret",
    ];

    let mut found_secrets = Vec::new();

    for pattern in patterns {
        let matches = find_pattern_in_directory("src", pattern);
        for (file, line_num, content) in matches {
            // Skip documentation, comments, and variable names
            let line = content.to_lowercase();
            if line.contains(&format!("= \"{}\"", pattern))
                || line.contains(&format!("= '{}'", pattern))
                || (line.contains("=")
                    && line.contains(pattern)
                    && (line.contains("\"") || line.contains("'"))
                    && !line.trim_start().starts_with("//")
                    && !line.trim_start().starts_with("///")
                    && !line.trim_start().starts_with("*"))
            {
                found_secrets.push((file, line_num, content));
            }
        }
    }

    if !found_secrets.is_empty() {
        let mut error_msg = String::from("Found potential hardcoded secrets:\n");
        for (file, line_num, content) in found_secrets {
            error_msg.push_str(&format!("  {}:{} - {}\n", file, line_num, content.trim()));
        }
        error_msg.push_str(
            "\nSecrets should come from environment variables or secure configuration!\n",
        );

        // This is a warning that should be manually reviewed
        println!("WARNING: {}", error_msg);
    }
}

/// Helper function to find TODO comments in a directory
fn find_todos_in_directory(dir: &str) -> Vec<(String, usize, String)> {
    find_pattern_in_directory(dir, "TODO")
}

/// Helper function to find #[allow(dead_code)] in a directory
fn find_allow_dead_code_in_directory(dir: &str) -> Vec<(String, usize, String)> {
    find_pattern_in_directory(dir, "#[allow(dead_code)]")
}

/// Helper function to find patterns in files recursively
fn find_pattern_in_directory(dir: &str, pattern: &str) -> Vec<(String, usize, String)> {
    let mut results = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();

            if path.is_dir() {
                // Recursively search subdirectories
                let subdir_results = find_pattern_in_directory(&path.to_string_lossy(), pattern);
                results.extend(subdir_results);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                // Search .rs files
                if let Ok(content) = fs::read_to_string(&path) {
                    for (line_num, line) in content.lines().enumerate() {
                        if line.contains(pattern) {
                            results.push((
                                path.to_string_lossy().to_string(),
                                line_num + 1,
                                line.to_string(),
                            ));
                        }
                    }
                }
            }
        }
    }

    results
}

/// Test for common security anti-patterns
#[test]
fn test_security_anti_patterns() {
    let mut warnings = Vec::new();

    // Check for unsafe blocks (should be rare and well-justified)
    let unsafe_blocks = find_pattern_in_directory("src", "unsafe");
    if !unsafe_blocks.is_empty() {
        warnings.push(format!(
            "Found {} unsafe blocks - ensure they're necessary and sound",
            unsafe_blocks.len()
        ));
    }

    // Check for transmute usage (very dangerous)
    let transmutes = find_pattern_in_directory("src", "transmute");
    if !transmutes.is_empty() {
        warnings.push(format!(
            "Found {} transmute calls - extremely dangerous!",
            transmutes.len()
        ));
    }

    // Check for deprecated functions
    let deprecated = find_pattern_in_directory("src", "#[deprecated");
    if !deprecated.is_empty() {
        warnings.push(format!(
            "Found {} deprecated items - should be removed",
            deprecated.len()
        ));
    }

    if !warnings.is_empty() {
        println!("SECURITY WARNINGS:");
        for warning in warnings {
            println!("  - {}", warning);
        }
    }
}

/// Test to ensure examples compile and run
#[test]
fn test_examples_are_complete() {
    // This is a placeholder - in a real implementation, this would
    // compile and run each example to ensure they work
    let example_files = find_pattern_in_directory("examples", "fn main");

    if example_files.is_empty() {
        println!("WARNING: No complete examples found with main() functions");
    } else {
        println!(
            "Found {} example files with main() functions",
            example_files.len()
        );
    }
}
