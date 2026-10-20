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

/// Every `allow(dead_code)` in production code must say why: `#[allow(dead_code, reason = "...")]`.
///
/// `dead_code` is a signal that something is unused, unfinished or unreachable; an allow without a
/// reason silences it for good. Covers `#[allow(..)]`, `#![allow(..)]` and `cfg_attr(.., allow(..))`.
#[test]
fn test_audit_allow_dead_code_directives() {
    let mut unexplained = Vec::new();
    for (file, line_num, content) in find_production_pattern_in_directory("src", "allow(dead_code")
    {
        // The attribute may be wrapped over a few lines, so look at the line and the three after it.
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        let window: String = text
            .lines()
            .skip(line_num - 1)
            .take(4)
            .collect::<Vec<_>>()
            .join("\n");
        if !window.contains("reason =") {
            unexplained.push(format!("  {}:{} - {}", file, line_num, content.trim()));
        }
    }

    assert!(
        unexplained.is_empty(),
        "allow(dead_code) without a reason. Remove the dead item, or write \
         #[allow(dead_code, reason = \"why this is not dead\")]:\n{}",
        unexplained.join("\n")
    );
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
///
/// Scans production code only: items under `#[cfg(test)]` (or `#[cfg(all(test, ..))]`) and
/// `#[test]` functions are skipped by [`production_lines`], however the file is named.
#[test]
fn test_audit_panics_in_source() {
    let panics = find_production_pattern_in_directory("src", "panic!");

    if !panics.is_empty() {
        let mut error_msg = String::from("Found panic!() calls in non-test source code:\n");
        for (file, line_num, content) in panics {
            error_msg.push_str(&format!("  {}:{} - {}\n", file, line_num, content.trim()));
        }
        error_msg.push_str("\nProduction code should handle errors gracefully, not panic!\n");
        error_msg.push_str("Consider using Result<T, E> instead.\n");

        panic!("{}", error_msg);
    }
}

/// Shapes of a default key, secret, password, salt or token spelled out in production source.
///
/// Each pattern is a way a fixed credential has actually appeared in this crate: a secret-named
/// variable or field set to a string literal, a key constructor handed a literal, a template or
/// "change me" marker inside a string, or a named byte-string constant. A hit is either a real
/// defect (fix it: generate a random per-instance value, or require the caller to supply one) or it
/// is listed in [`SECRET_LITERAL_ALLOWLIST`] with the reason it is harmless.
const SECRET_LITERAL_PATTERNS: [&str; 5] = [
    // secret-named identifier = "literal"
    r#"(?i)\b\w*(password|passwd|secret|api_?key|private_key|signing_key|salt|pepper)\w*\s*(:\s*[^=]{1,40})?[=:]\s*b?"[^"{}$]{8,}""#,
    // key/secret constructors given a literal
    r#"(?i)\b(from_secret|new_hmac|from_base64_secret|SecureJwtValidator::new)\(\s*&?b?""#,
    // builder calls handed a literal secret
    r#"(?i)\.(secret|jwt_secret|with_jwt_secret|secret_key|password)\(\s*&?""#,
    // template / placeholder / development-key markers inside a string literal
    r#"(?i)"[^"]*(change_this|changeme|change-me|change-in-production|change_in_production|development-only|dev-only|test_key|your-secret|replace-with)[^"]*""#,
    // named byte-string constants that look like keys
    r#"(?i)\b(const|static|let)\s+\w*(key|secret|salt|nonce)\w*\s*(:[^=]+)?=\s*b"[^"]{8,}""#,
];

/// Known harmless hits: `(file suffix, text that must appear on the line, reason)`. An entry that
/// no longer matches anything fails the test, so the list cannot go stale.
const SECRET_LITERAL_ALLOWLIST: [(&str, &str, &str); 17] = [
    (
        "src/auth_modular/user_manager.rs",
        "DEFAULT_API_KEY_ROLE: &str",
        "the role name a key gets when none is chosen (a role, not a credential)",
    ),
    (
        "src/config/mod.rs",
        "\"change-in-production\",",
        "refusal list in PLACEHOLDER_SECRET_MARKERS: a string production validation rejects, never used as a secret",
    ),
    (
        "src/config/mod.rs",
        "\"change_in_production\",",
        "refusal list in PLACEHOLDER_SECRET_MARKERS: a string production validation rejects, never used as a secret",
    ),
    (
        "src/config/mod.rs",
        "\"change-me\",",
        "refusal list in PLACEHOLDER_SECRET_MARKERS: a string production validation rejects, never used as a secret",
    ),
    (
        "src/config/mod.rs",
        "\"changeme\",",
        "refusal list in PLACEHOLDER_SECRET_MARKERS: a string production validation rejects, never used as a secret",
    ),
    (
        "src/config/mod.rs",
        "\"your-secret\",",
        "refusal list in PLACEHOLDER_SECRET_MARKERS: a string production validation rejects, never used as a secret",
    ),
    (
        "src/config/mod.rs",
        "\"development-only\",",
        "refusal list in PLACEHOLDER_SECRET_MARKERS: a string production validation rejects, never used as a secret",
    ),
    (
        "src/config/mod.rs",
        "\"replace-with\",",
        "refusal list in PLACEHOLDER_SECRET_MARKERS: a string production validation rejects, never used as a secret",
    ),
    (
        "src/bin/oauth2_test_server.rs",
        "test_oauth2_secret_key_that_is_long_enough",
        "development test server binary, not library surface; run by hand against localhost",
    ),
    (
        "src/bin/test_oauth2.rs",
        "test_oauth2_secret_key_that_is_long_enough",
        "development test binary, not library surface; run by hand against localhost",
    ),
    (
        "src/sdks/python.rs",
        "api_key=\"your-api-key\"",
        "template text for generated Python SDK sample code, not used as a credential",
    ),
    (
        "src/testing/test_infrastructure.rs",
        "test-jwt-secret-for-container-tests",
        "test helper that sets an environment variable for the container-backed integration tests",
    ),
    (
        "src/auth.rs",
        "export JWT_SECRET=",
        "operator-facing error message showing how to set the variable; not a value the code uses",
    ),
    (
        "src/auth.rs",
        "using development-only default",
        "log message text; the token manager it refers to is built from a random per-process secret",
    ),
    (
        "src/lib.rs",
        "replace-with-a-32-char-random-secret",
        "crate-level documentation example; production validation refuses this placeholder",
    ),
    (
        "src/server/token_exchange/advanced_token_exchange.rs",
        "BEGIN RSA PRIVATE KEY",
        "default config holds a truncated PEM that from_rsa_pem rejects, so no usable key exists",
    ),
    (
        "src/server/token_exchange/token_exchange_factory.rs",
        "SecureJwtValidator::new(\"your-secret-key\"",
        "inside a raw string of example code returned to the reader, never executed",
    ),
];

/// Hits of [`SECRET_LITERAL_PATTERNS`] on the production lines of `content`: `(line number, line)`.
fn secret_literal_hits<'a>(file: &str, content: &'a str) -> Vec<(usize, &'a str)> {
    let patterns: Vec<regex::Regex> = SECRET_LITERAL_PATTERNS
        .iter()
        .map(|p| regex::Regex::new(p).expect("pattern compiles"))
        .collect();
    production_lines(file, content)
        .into_iter()
        .filter(|(_, line)| {
            let t = line.trim_start();
            !(t.starts_with("//") || t.starts_with('*') || t.starts_with("/*"))
        })
        .filter(|(_, line)| patterns.iter().any(|p| p.is_match(line)))
        .collect()
}

fn rust_files_under(dir: &str, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files_under(&path.to_string_lossy(), out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// No production source line may spell out a default key, secret, password or salt unless it is
/// listed (with a reason) as harmless. Older releases shipped fixed signing secrets in several
/// places; this is the guard against another one appearing.
#[test]
fn test_no_hardcoded_secrets() {
    let mut files = Vec::new();
    rust_files_under("src", &mut files);
    files.sort();

    let mut unexplained = Vec::new();
    let mut used = [false; SECRET_LITERAL_ALLOWLIST.len()];
    for file in &files {
        let Ok(content) = fs::read_to_string(file) else {
            continue;
        };
        for (line_num, line) in secret_literal_hits(file, &content) {
            let listed = SECRET_LITERAL_ALLOWLIST
                .iter()
                .enumerate()
                .find(|(_, (suffix, text, _))| file.ends_with(suffix) && line.contains(text));
            match listed {
                Some((i, _)) => used[i] = true,
                None => unexplained.push(format!("  {file}:{line_num} - {}", line.trim())),
            }
        }
    }

    let stale: Vec<String> = SECRET_LITERAL_ALLOWLIST
        .iter()
        .zip(used)
        .filter(|(_, used)| !used)
        .map(|((suffix, text, _), _)| format!("  {suffix}: {text}"))
        .collect();

    assert!(
        unexplained.is_empty() && stale.is_empty(),
        "hard-coded secret audit failed.\nUnexplained hits (fix them, or list them with a reason in \
         SECRET_LITERAL_ALLOWLIST):\n{}\nStale allowlist entries (remove them):\n{}",
        unexplained.join("\n"),
        stale.join("\n")
    );
}

#[cfg(test)]
mod secret_scanner_tests {
    use super::secret_literal_hits;

    fn hits(src: &str) -> usize {
        secret_literal_hits("fixture.rs", src).len()
    }

    #[test]
    fn finds_each_shape_a_fixed_credential_has_taken() {
        assert_eq!(hits("let jwt_secret = \"correct-horse-battery\";\n"), 1);
        assert_eq!(
            hits("cfg.signing_key: \"-----BEGIN RSA PRIVATE KEY-----\".to_string(),\n"),
            1
        );
        assert_eq!(
            hits("let k = EncodingKey::from_secret(b\"anything\");\n"),
            1
        );
        assert_eq!(
            hits("TokenManager::new_hmac(b\"x\", \"iss\", \"aud\");\n"),
            1
        );
        assert_eq!(hits("let msg = \"please change-in-production soon\";\n"), 1);
        assert_eq!(
            hits("const SIGNING_KEY: &[u8] = b\"0123456789abcdef\";\n"),
            1
        );
    }

    #[test]
    fn ignores_ordinary_code_comments_and_test_items() {
        assert_eq!(hits("token_type: \"Bearer\".to_string(),\n"), 0);
        assert_eq!(hits("let key = format!(\"user:{}\", id);\n"), 0);
        assert_eq!(hits("// let password = \"hunter2hunter2\";\n"), 0);
        assert_eq!(hits("/// jwt_secret = \"documented-example\"\n"), 0);
        assert_eq!(
            hits("#[test]\nfn t() {\n    let password = \"hunter2hunter2\";\n}\n"),
            0
        );
        assert_eq!(hits("let secret = random_secret();\n"), 0);
    }
}

/// Whether `line` is an attribute that makes the item after it test-only.
fn is_test_attribute(line: &str) -> bool {
    let line = line.trim();
    line == "#[test]"
        || line.starts_with("#[tokio::test")
        || line == "#[cfg(test)]"
        || line.starts_with("#[cfg(all(test,")
        || line.starts_with("#[cfg(all(test)")
}

/// The index of the line on which the item that starts at `lines[start]` ends: where its braces
/// balance, or at a `;` that ends a body-less item. Comments, string and raw-string literals, and
/// character literals are skipped, so a `"{"` or `r#"{"#` inside one does not count as a brace.
/// `None` if the item never ends.
fn item_end(lines: &[&str], start: usize) -> Option<usize> {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let text: Vec<char> = lines[start..].join("\n").chars().collect();
    let mut i = 0;
    let mut line = start;
    let mut braces: i64 = 0;
    let mut nesting: i64 = 0; // parentheses and brackets
    let mut opened = false;
    while i < text.len() {
        let c = text[i];
        let prev = if i > 0 { Some(text[i - 1]) } else { None };
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            '/' if text.get(i + 1) == Some(&'/') => {
                while i < text.len() && text[i] != '\n' {
                    i += 1;
                }
            }
            '/' if text.get(i + 1) == Some(&'*') => {
                let mut depth = 1;
                i += 2;
                while i < text.len() && depth > 0 {
                    if text[i] == '/' && text.get(i + 1) == Some(&'*') {
                        depth += 1;
                        i += 2;
                    } else if text[i] == '*' && text.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        if text[i] == '\n' {
                            line += 1;
                        }
                        i += 1;
                    }
                }
            }
            'r' if !prev.is_some_and(is_ident)
                || (prev == Some('b') && i >= 2 && !is_ident(text[i - 2])) =>
            {
                // Possibly a raw string: r"..." or r#"..."# (any number of #).
                let mut j = i + 1;
                let mut hashes = 0;
                while text.get(j) == Some(&'#') {
                    hashes += 1;
                    j += 1;
                }
                if text.get(j) != Some(&'"') {
                    i += 1;
                    continue;
                }
                j += 1;
                loop {
                    match text.get(j) {
                        None => return None,
                        Some('\n') => {
                            line += 1;
                            j += 1;
                        }
                        Some('"') if (0..hashes).all(|k| text.get(j + 1 + k) == Some(&'#')) => {
                            j += 1 + hashes;
                            break;
                        }
                        Some(_) => j += 1,
                    }
                }
                i = j;
            }
            '"' => {
                i += 1;
                while i < text.len() {
                    match text[i] {
                        '\\' => {
                            if text.get(i + 1) == Some(&'\n') {
                                line += 1;
                            }
                            i += 2;
                        }
                        '"' => {
                            i += 1;
                            break;
                        }
                        '\n' => {
                            line += 1;
                            i += 1;
                        }
                        _ => i += 1,
                    }
                }
            }
            '\'' => {
                if text.get(i + 1) == Some(&'\\') {
                    // escaped character literal: '\n', '\'', '\u{..}'
                    let mut j = i + 2;
                    while j < text.len() && text[j] != '\'' {
                        j += 1;
                    }
                    i = j + 1;
                } else if text.get(i + 2) == Some(&'\'') {
                    i += 3; // 'x'
                } else {
                    i += 1; // a lifetime
                }
            }
            '(' | '[' => {
                nesting += 1;
                i += 1;
            }
            ')' | ']' => {
                nesting -= 1;
                i += 1;
            }
            '{' => {
                braces += 1;
                opened = true;
                i += 1;
            }
            '}' => {
                braces -= 1;
                if opened && braces <= 0 {
                    return Some(line);
                }
                i += 1;
            }
            ';' if !opened && nesting <= 0 => return Some(line),
            _ => i += 1,
        }
    }
    None
}

/// The lines of `content` that are production code: everything except the items (module,
/// function, impl, ...) that carry a test-only attribute (see [`is_test_attribute`]).
///
/// An item is skipped from its first non-attribute line to where it ends ([`item_end`]). If a
/// skipped item never ends before the end of the file this panics, naming the file, rather than
/// silently dropping the rest of it from the audit.
fn production_lines<'a>(file: &str, content: &'a str) -> Vec<(usize, &'a str)> {
    let lines: Vec<&str> = content.lines().collect();
    let mut kept = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if !is_test_attribute(lines[i]) {
            kept.push((i + 1, lines[i]));
            i += 1;
            continue;
        }
        // Skip further attributes, doc comments and blanks up to the item itself.
        let mut j = i + 1;
        while j < lines.len() {
            let t = lines[j].trim_start();
            if t.starts_with("#[") || t.starts_with("//") || t.is_empty() {
                j += 1;
            } else {
                break;
            }
        }
        let end = item_end(&lines, j.min(lines.len().saturating_sub(1)));
        let Some(end) = end else {
            panic!(
                "audit scanner lost track of a test-only item starting near {file}:{}: \
                 it never ended before the end of the file",
                i + 1
            );
        };
        i = end + 1;
    }
    kept
}

/// Find `pattern` in production code (see [`production_lines`]) under `dir`, ignoring comment lines.
fn find_production_pattern_in_directory(dir: &str, pattern: &str) -> Vec<(String, usize, String)> {
    let mut results = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return results;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            results.extend(find_production_pattern_in_directory(
                &path.to_string_lossy(),
                pattern,
            ));
        } else if path.extension().is_some_and(|ext| ext == "rs")
            && let Ok(content) = fs::read_to_string(&path)
        {
            let file = path.to_string_lossy().to_string();
            for (line_num, line) in production_lines(&file, &content) {
                let trimmed = line.trim_start();
                let is_comment = trimmed.starts_with("//")
                    || trimmed.starts_with('*')
                    || trimmed.starts_with("/*");
                if line.contains(pattern) && !is_comment {
                    results.push((file.clone(), line_num, line.to_string()));
                }
            }
        }
    }
    results
}

#[cfg(test)]
mod scanner_tests {
    use super::production_lines;

    fn kept(src: &str) -> Vec<usize> {
        production_lines("fixture.rs", src)
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    }

    #[test]
    fn skips_a_cfg_test_module_and_keeps_the_rest() {
        let src =
            "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() { panic!(\"x\"); }\n}\nfn b() {}\n";
        assert_eq!(kept(src), [1, 6]);
    }

    #[test]
    fn skips_a_test_function_outside_a_test_module() {
        let src = "fn a() {}\n#[test]\nfn t() {\n    if true { panic!(\"x\"); }\n}\nfn b() {}\n";
        assert_eq!(kept(src), [1, 6]);
    }

    #[test]
    fn skips_cfg_all_test_and_stacked_attributes() {
        let src = "#[cfg(all(test, feature = \"web-gui\"))]\n#[allow(dead_code)]\n/// doc\nmod tests {\n    fn t() {}\n}\nfn prod() {}\n";
        assert_eq!(kept(src), [7]);
    }

    #[test]
    fn does_not_skip_other_cfg_attributes() {
        let src =
            "#[cfg(feature = \"x\")]\nfn a() { panic!(\"real\"); }\n#[cfg(not(test))]\nfn b() {}\n";
        assert_eq!(kept(src), [1, 2, 3, 4]);
    }

    #[test]
    fn skips_a_test_only_item_that_ends_in_a_semicolon() {
        let src = "#[cfg(test)]\nuse foo::bar;\nfn a() {}\n";
        assert_eq!(kept(src), [3]);
    }

    #[test]
    #[should_panic(expected = "lost track")]
    fn fails_loudly_when_the_item_never_ends() {
        production_lines("fixture.rs", "#[cfg(test)]\nmod tests {\n    fn f() {\n");
    }

    #[test]
    fn braces_inside_literals_and_comments_do_not_count() {
        let src = concat!(
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    const A: &str = r#\"{\"#;\n",
            "    const B: &str = \"}\";\n",
            "    const C: char = '{';\n",
            "    // }\n",
            "    /* { */\n",
            "    fn f<'a>(x: &'a str) -> &'a str { x }\n",
            "}\n",
            "fn prod() {}\n",
        );
        assert_eq!(kept(src), [10]);
    }

    #[test]
    fn a_semicolon_inside_brackets_does_not_end_a_fn_early() {
        let src = "#[cfg(test)]\nfn f(a: [u8; 4]) {\n    panic!(\"x\");\n}\nfn prod() {}\n";
        assert_eq!(kept(src), [5]);
    }
}

/// Helper function to find TODO comments in a directory
fn find_todos_in_directory(dir: &str) -> Vec<(String, usize, String)> {
    find_pattern_in_directory(dir, "TODO")
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

/// Types allowed to derive `Debug` although a field looks like a secret: `(file suffix, type, why)`.
const DERIVED_DEBUG_SECRET_ALLOWLIST: [(&str, &str, &str); 4] = [
    (
        "src/admin/mod.rs",
        "UserAction",
        "clap subcommand arguments parsed from the operator's own command line; never stored or sent",
    ),
    (
        "src/protocols/acme.rs",
        "AcmeChallenge",
        "the ACME challenge token is published at /.well-known/acme-challenge/<token> by design",
    ),
    (
        "src/methods/enhanced_device/mod.rs",
        "DeviceFlowInstructions",
        "the QR code encodes the public verification URI and the user code, which the flow shows on screen by design",
    ),
    (
        "src/protocols/oauth1.rs",
        "OAuthToken",
        "`token` is the public OAuth 1.0a token identifier; the secret half is a Zeroizing field",
    ),
];

/// `(type name, line number, field)` for each type in `content` that derives `Debug` and has a
/// plain `String` / `Vec<u8>` (or `Option` of one) field named like a secret. Such a field is
/// printed by `{:?}`, so any log line or panic message that formats the value leaks it; the type
/// needs a hand-written `Debug` that redacts the field (see `src/utils/redact.rs`).
fn derived_debug_secret_fields(file: &str, content: &str) -> Vec<(String, usize, String)> {
    let item = regex::Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum)\s+(\w+)").unwrap();
    let field = regex::Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*(.+?),?\s*(?://.*)?$")
        .unwrap();
    let secret_name = regex::Regex::new(
        r"(?i)(secret|password|passwd|api_key|private_key|signing_key|encryption_key|master_key|jwt_key|shared_key|access_key|passphrase|_pem|totp_code|(?:^|_)auth_token|bearer_token|(?:^|_)(?:access|refresh|id|session|api)_token$|^token$|device_code|authorization_code|backup_codes?|recovery_codes?|(?:^|_)seed|mnemonic|(?:^|_)pin$|(?:^|_)otp$|_codes$|^codes$|qr_code|otpauth|provisioning_uri)",
    )
    .unwrap();
    let not_secret = regex::Regex::new(
        r"(?i)(hash|policy|min_|require|length|expir|_at$|_id$|disallow|allowed|banned|strength|type$|public)",
    )
    .unwrap();
    let plain = regex::Regex::new(r"^(?:Option<)?(?:String|Vec<u8>|Vec<String>)>?$").unwrap();

    let lines = production_lines(file, content);
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let Some(m) = item.captures(lines[i].1) else {
            i += 1;
            continue;
        };
        let name = m[1].to_string();
        // Attributes directly above the item.
        let mut derives_debug = false;
        let mut j = i;
        while j > 0 {
            let above = lines[j - 1].1.trim();
            if above.starts_with("#[") || above.starts_with("///") {
                if above.starts_with("#[derive(") && above.contains("Debug") {
                    derives_debug = true;
                }
                j -= 1;
            } else {
                break;
            }
        }
        // Body: until the braces opened on the item line (or after it) balance again.
        let (mut depth, mut opened) = (0i32, false);
        let mut k = i;
        while k < lines.len() {
            let l = lines[k].1;
            depth += l.matches('{').count() as i32 - l.matches('}').count() as i32;
            opened |= l.contains('{');
            if k > i
                && derives_debug
                && let Some(f) = field.captures(l)
            {
                let (fname, ftype) = (&f[1], f[2].trim());
                if secret_name.is_match(fname)
                    && !not_secret.is_match(fname)
                    && plain.is_match(ftype)
                {
                    out.push((name.clone(), lines[k].0, fname.to_string()));
                }
            }
            if (opened && depth <= 0) || (!opened && l.trim_end().ends_with(';')) {
                break;
            }
            k += 1;
        }
        i = k + 1;
    }
    out
}

/// A type with a plain-text secret field must not derive `Debug` (it would print the secret). The
/// positive control is the scanner's own fixtures below, which flag a derived type and pass a
/// hand-written one.
#[test]
fn test_secret_fields_are_not_derived_debug() {
    let mut files = Vec::new();
    rust_files_under("src", &mut files);
    files.sort();

    let mut unexplained = Vec::new();
    let mut used = [false; DERIVED_DEBUG_SECRET_ALLOWLIST.len()];
    for file in &files {
        let Ok(content) = fs::read_to_string(file) else {
            continue;
        };
        for (ty, line, field) in derived_debug_secret_fields(file, &content) {
            match DERIVED_DEBUG_SECRET_ALLOWLIST
                .iter()
                .position(|(suffix, t, _)| file.ends_with(suffix) && *t == ty)
            {
                Some(i) => used[i] = true,
                None => unexplained.push(format!("  {file}:{line} - {ty}.{field}")),
            }
        }
    }
    let stale: Vec<String> = DERIVED_DEBUG_SECRET_ALLOWLIST
        .iter()
        .zip(used)
        .filter(|(_, used)| !used)
        .map(|((suffix, ty, _), _)| format!("  {suffix}: {ty}"))
        .collect();
    assert!(
        unexplained.is_empty() && stale.is_empty(),
        "types deriving Debug with a plain secret field (give them a redacting Debug, or list \
         them with a reason in DERIVED_DEBUG_SECRET_ALLOWLIST):\n{}\nStale allowlist entries:\n{}",
        unexplained.join("\n"),
        stale.join("\n")
    );
}

#[cfg(test)]
mod derived_debug_scanner_tests {
    use super::derived_debug_secret_fields;

    #[test]
    fn flags_a_derived_type_and_passes_a_hand_written_one() {
        let derived = "#[derive(Debug, Clone)]\npub struct A {\n    pub id: u32,\n    pub client_secret: Option<String>,\n}\n";
        let hits = derived_debug_secret_fields("fixture.rs", derived);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(
            (hits[0].0.as_str(), hits[0].2.as_str()),
            ("A", "client_secret")
        );

        let by_hand = "#[derive(Clone)]\npub struct A {\n    pub client_secret: Option<String>,\n}\nimpl std::fmt::Debug for A {}\n";
        assert!(derived_debug_secret_fields("fixture.rs", by_hand).is_empty());
    }

    #[test]
    fn flags_a_list_of_codes_and_a_qr_payload() {
        let src = "#[derive(Debug)]
pub struct C {
    pub backup_codes: Vec<String>,
    pub qr_code_url: String,
    pub label: String,
}
";
        let hits = derived_debug_secret_fields("fixture.rs", src);
        let fields: Vec<&str> = hits.iter().map(|(_, _, f)| f.as_str()).collect();
        assert_eq!(fields, ["backup_codes", "qr_code_url"], "{hits:?}");
    }

    #[test]
    fn ignores_non_secret_names_and_zeroizing_fields() {
        let src = "#[derive(Debug)]\npub struct B {\n    pub password_hash: String,\n    pub min_password_length: usize,\n    pub secret_key: Zeroizing<String>,\n    pub client_id: String,\n}\n";
        assert!(derived_debug_secret_fields("fixture.rs", src).is_empty());
    }

    #[test]
    fn flags_enum_variant_fields() {
        let src = "#[derive(Debug)]\npub enum C {\n    Create {\n        password: Option<String>,\n    },\n}\n";
        assert_eq!(derived_debug_secret_fields("fixture.rs", src).len(), 1);
    }
}
