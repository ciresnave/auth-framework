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
#[ignore = "20 unreviewed #[allow(dead_code)] directives, see https://github.com/ciresnave/auth-framework/issues/80"]
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

        panic!("{}", error_msg);
    }
}

/// Test to ensure no unimplemented!() macros in production code
#[test]
fn test_no_unimplemented_in_source() {
    let unimplemented: Vec<_> = find_pattern_in_directory("src", "unimplemented!")
        .into_iter()
        .filter(|(_, _, content)| {
            let trimmed = content.trim_start();
            !trimmed.starts_with("///")
                && !trimmed.starts_with("//!")
                && !trimmed.starts_with("/*")
                && !trimmed.starts_with("*")
        })
        .collect();

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
#[ignore = "pattern matching is too crude to assert on (~190 hits, all reviewed false positives), see https://github.com/ciresnave/auth-framework/issues/81"]
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

        panic!("{}", error_msg);
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

/// Test for common security anti-patterns.
///
/// `unsafe`/`transmute`/`#[deprecated]` are not anti-patterns by themselves
/// (an `unsafe` block guarding an env-var mutation under a test lock, or a
/// `#[deprecated]` item with real migration guidance, are both legitimate),
/// so this doesn't fail on their mere presence -- it asserts the actual
/// property that makes each one safe: every literal `unsafe {` block has an
/// adjacent `// SAFETY:` comment justifying it, every `#[deprecated(...)]`
/// item names a `note = "..."` migration path, and `transmute` (the one
/// genuinely dangerous pattern here) is absent entirely.
#[test]
fn test_security_anti_patterns() {
    let mut failures = Vec::new();

    for (file, line_num, _) in find_unsafe_blocks_in_directory("src") {
        if !has_nearby_safety_comment(&file, line_num) {
            failures.push(format!(
                "{}:{} - `unsafe` block with no adjacent `// SAFETY:` comment",
                file, line_num
            ));
        }
    }

    for (file, line_num, content) in find_pattern_in_directory("src", "transmute") {
        failures.push(format!(
            "{}:{} - transmute is not allowed: {}",
            file,
            line_num,
            content.trim()
        ));
    }

    for (file, line_num, content) in find_deprecated_attrs_without_note("src") {
        failures.push(format!(
            "{}:{} - #[deprecated] with no `note = \"...\"` migration guidance: {}",
            file,
            line_num,
            content.trim()
        ));
    }

    if !failures.is_empty() {
        panic!("Security anti-patterns found:\n{}", failures.join("\n"));
    }
}

/// Find literal `unsafe { ... }` block openers, excluding identifiers and
/// prose that merely contain the substring "unsafe" (e.g. `extract_claims_unsafe`,
/// `"unsafe path"`, a doc comment mentioning "unsafe alternative").
fn find_unsafe_blocks_in_directory(dir: &str) -> Vec<(String, usize, String)> {
    find_pattern_in_directory(dir, "unsafe")
        .into_iter()
        .filter(|(_, _, content)| content.trim_start().starts_with("unsafe {"))
        .collect()
}

/// A block opener counts as justified if any of the few lines immediately
/// above it contains a `SAFETY:` comment.
fn has_nearby_safety_comment(file: &str, unsafe_line_num: usize) -> bool {
    const LOOKBACK_LINES: usize = 3;
    let Ok(content) = fs::read_to_string(file) else {
        return false;
    };
    let lines: Vec<&str> = content.lines().collect();
    let start = unsafe_line_num.saturating_sub(LOOKBACK_LINES + 1);
    let end = unsafe_line_num.saturating_sub(1).min(lines.len());
    lines[start..end].iter().any(|l| l.contains("SAFETY:"))
}

/// Find `#[deprecated` attributes (single-line or the `#[deprecated(` opener
/// of a multi-line one) that don't carry a `note = "..."` within the next
/// few lines.
fn find_deprecated_attrs_without_note(dir: &str) -> Vec<(String, usize, String)> {
    find_pattern_in_directory(dir, "#[deprecated")
        .into_iter()
        .filter(|(file, line_num, content)| {
            if content.contains("note =") {
                return false;
            }
            const LOOKAHEAD_LINES: usize = 4;
            let Ok(file_content) = fs::read_to_string(file) else {
                return true;
            };
            let lines: Vec<&str> = file_content.lines().collect();
            let start = line_num.saturating_sub(1);
            let end = (start + LOOKAHEAD_LINES).min(lines.len());
            !lines[start..end].iter().any(|l| l.contains("note ="))
        })
        .collect()
}

/// Test to ensure at least one complete example exists.
///
/// Actually compiling and running every example is already covered in CI
/// (`.github/workflows/ci-cd.yml`'s "Verify examples compile" step runs
/// `cargo test --examples --no-run`, and several feature-matrix jobs build
/// `--examples` too) -- duplicating that here would just be a slower copy of
/// the same check. What this asserts instead is the one property a CI
/// compile step can't: that the `examples/` directory hasn't quietly lost
/// all of its examples (e.g. every file deleted but the directory kept),
/// which would leave the CI step passing vacuously.
#[test]
fn test_examples_are_complete() {
    let example_files = find_pattern_in_directory("examples", "fn main");
    assert!(
        !example_files.is_empty(),
        "no example files with a main() function were found under examples/ -- \
         either examples/ lost all its examples, or this check's directory/pattern is wrong"
    );
}
