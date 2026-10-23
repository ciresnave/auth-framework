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

/// What the scanner found in one file: every struct / enum that derives `Debug`, and the plain-text
/// fields (`String`, `Vec<u8>`, `Vec<String>`, `Option` of those, `Box<str>`, `Arc<str>`) of those types
/// that `{:?}` would print verbatim.
struct DebugScan {
    /// Types that derive `Debug`, with or without plain-text fields.
    derived_types: usize,
    /// `(type, line, field, container)`; a tuple struct / tuple variant payload is reported as the
    /// field `<tuple>`. `container` is true for a map, set or JSON value (see [`is_container`]).
    plain_fields: Vec<(String, usize, String, bool)>,
}

/// Splits a tuple payload such as `String, HashMap<String, String>` on the commas that are not
/// inside angle brackets.
fn split_top_level(list: &str) -> Vec<&str> {
    let (mut parts, mut depth, mut start) = (Vec::new(), 0i32, 0);
    for (i, c) in list.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&list[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&list[start..]);
    parts
}

/// `Option<`, `Arc<`, locks and the like around the type that matters.
fn strip_wrappers(mut ty: &str) -> &str {
    const WRAPPERS: &[&str] = &[
        "Option<",
        "Arc<",
        "std::sync::Arc<",
        "Box<",
        "Rc<",
        "RwLock<",
        "Mutex<",
        "tokio::sync::RwLock<",
        "tokio::sync::Mutex<",
        "std::sync::RwLock<",
        "std::sync::Mutex<",
        "parking_lot::RwLock<",
        "parking_lot::Mutex<",
    ];
    'again: loop {
        ty = ty.trim();
        for w in WRAPPERS {
            if let Some(inner) = ty.strip_prefix(w).and_then(|r| r.strip_suffix('>')) {
                ty = inner;
                continue 'again;
            }
        }
        return ty;
    }
}

/// A map, set or JSON value whose keys or contents are free text: `DashMap<String, _>`,
/// `HashMap<_, String>`, `HashSet<String>`, `serde_json::Value`, each possibly wrapped in `Option`,
/// `Arc` or a lock. Its `Debug` prints every entry, so a map keyed by a token or session id prints it.
fn is_container(ty: &str, plain: &regex::Regex) -> bool {
    let s = strip_wrappers(ty);
    if s == "Value" || s == "serde_json::Value" {
        return true;
    }
    let Some((head, rest)) = s.split_once('<') else {
        return false;
    };
    let head = head.rsplit("::").next().unwrap_or(head);
    if !matches!(
        head,
        "DashMap" | "HashMap" | "BTreeMap" | "HashSet" | "BTreeSet" | "DashSet"
    ) {
        return false;
    }
    let Some(args) = rest.strip_suffix('>') else {
        return false;
    };
    split_top_level(args).iter().any(|a| {
        let a = a.trim();
        plain.is_match(a) || a == "Value" || a == "serde_json::Value"
    })
}

/// Joins an attribute that spans several lines (a multi-line `#[derive(..)]`) into one entry, so the
/// derive scan sees `Debug` in it. The entry keeps the line number of the attribute's first line.
fn join_multiline_attributes(lines: Vec<(usize, &str)>) -> Vec<(usize, String)> {
    let mut out = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let (no, line) = lines[i];
        let open = line.matches('[').count() as i32 - line.matches(']').count() as i32;
        if line.trim_start().starts_with("#[") && open > 0 {
            let mut joined = line.to_string();
            let mut depth = open;
            while depth > 0 && i + 1 < lines.len() {
                i += 1;
                let next = lines[i].1;
                depth += next.matches('[').count() as i32 - next.matches(']').count() as i32;
                joined.push(' ');
                joined.push_str(next.trim());
            }
            out.push((no, joined));
        } else {
            out.push((no, line.to_string()));
        }
        i += 1;
    }
    out
}

/// The `name: type` pairs written between the braces of a single line, for a struct declared on one
/// line (`struct A { a: String }`, `from_item`) or an enum variant on one line
/// (`Variant { a: String, b: u32 },`, `variant`). Empty when the line has no complete brace pair or is
/// not one of those shapes.
fn inline_fields(code: &str, from_item: bool, variant: bool) -> Vec<(String, String)> {
    if !from_item && !variant {
        return Vec::new();
    }
    let (Some(open), Some(close)) = (code.find('{'), code.rfind('}')) else {
        return Vec::new();
    };
    if open >= close {
        return Vec::new();
    }
    split_top_level(&code[open + 1..close])
        .iter()
        .filter_map(|part| {
            let (name, ty) = part.split_once(':')?;
            let name = name.trim().trim_start_matches("pub").trim();
            let name = name.trim_start_matches(|c: char| c == '(' || c == ')' || c.is_whitespace());
            let name = name.rsplit(' ').next().unwrap_or(name);
            (!name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
                .then(|| (name.to_string(), ty.trim().to_string()))
        })
        .collect()
}

fn scan_derived_debug(file: &str, content: &str) -> DebugScan {
    let item = regex::Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(struct|enum)\s+(\w+)").unwrap();
    let field = regex::Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*(.+?),?\s*(?://.*)?$")
        .unwrap();
    let tuple = regex::Regex::new(r"(?:^|[^\w])(\w*)\(([^()]*)\)").unwrap();
    let plain = regex::Regex::new(
        r"^(?:pub(?:\([^)]*\))?\s+)?(?:Option<)?(?:String|Vec<u8>|Vec<String>|Vec<Vec<u8>>|Box<str>|Box<\[u8\]>|Arc<str>|Cow<'\w+, ?str>|Bytes|\[u8; ?\w+\])>?$",
    )
    .unwrap();

    let lines = join_multiline_attributes(production_lines(file, content));
    let mut scan = DebugScan {
        derived_types: 0,
        plain_fields: Vec::new(),
    };
    let mut i = 0;
    while i < lines.len() {
        let Some(m) = item.captures(lines[i].1.as_str()) else {
            i += 1;
            continue;
        };
        let (kind, name) = (m[1].to_string(), m[2].to_string());
        // Attributes directly above the item.
        let mut derives_debug = false;
        let mut j = i;
        while j > 0 {
            let above = lines[j - 1].1.trim();
            if above.starts_with("#[") || above.starts_with("///") {
                if (above.starts_with("#[derive(") || above.starts_with("#[cfg_attr("))
                    && above.contains("derive(")
                    && above.contains("Debug")
                {
                    derives_debug = true;
                }
                j -= 1;
            } else {
                break;
            }
        }
        if derives_debug {
            scan.derived_types += 1;
        }
        // Body: until the braces opened on the item line (or after it) balance again.
        let (mut depth, mut opened) = (0i32, false);
        let mut k = i;
        while k < lines.len() {
            let l = lines[k].1.as_str();
            depth += l.matches('{').count() as i32 - l.matches('}').count() as i32;
            opened |= l.contains('{');
            if derives_debug {
                let code = l.split("//").next().unwrap_or(l);
                let trimmed = code.trim_start();
                let inline = inline_fields(code, k == i && kind == "struct", k > i);
                if !inline.is_empty() {
                    // `Variant { a: String, b: String },` or `struct A { a: String }` on one line.
                    for (fname, fty) in inline {
                        if plain.is_match(fty.trim()) {
                            scan.plain_fields
                                .push((name.clone(), lines[k].0, fname, false));
                        } else if is_container(fty.trim(), &plain) {
                            scan.plain_fields
                                .push((name.clone(), lines[k].0, fname, true));
                        }
                    }
                } else if k > i
                    && let Some(f) = field.captures(l)
                {
                    if plain.is_match(f[2].trim()) {
                        scan.plain_fields
                            .push((name.clone(), lines[k].0, f[1].to_string(), false));
                    } else if is_container(f[2].trim(), &plain) {
                        scan.plain_fields
                            .push((name.clone(), lines[k].0, f[1].to_string(), true));
                    }
                } else if (k > i && !trimmed.starts_with('#') && !trimmed.starts_with('}'))
                    || (kind == "struct" && k == i)
                {
                    // Tuple struct (`struct A(pub String);`) or tuple variant (`Variant(String),`).
                    let probe = if k == i {
                        code.split_once(&name).map_or("", |(_, rest)| rest)
                    } else {
                        code
                    };
                    for t in tuple.captures_iter(probe) {
                        if split_top_level(&t[2])
                            .iter()
                            .any(|ty| plain.is_match(ty.trim()))
                        {
                            scan.plain_fields.push((
                                name.clone(),
                                lines[k].0,
                                "<tuple>".to_string(),
                                false,
                            ));
                            break;
                        }
                    }
                }
            }
            if (opened && depth <= 0) || (!opened && l.trim_end().ends_with(';')) {
                break;
            }
            k += 1;
        }
        i = k + 1;
    }
    scan
}

/// The reviewed field-name lists (`tests/debug_field_review.txt`).
struct DebugFieldReview {
    public: std::collections::HashSet<String>,
    secret_capable: std::collections::HashSet<String>,
    ambiguous: std::collections::HashSet<String>,
    /// Field names whose maps, sets or JSON values hold no credential and are keyed by no credential.
    container_ok: std::collections::HashSet<String>,
    /// `(file suffix, type, field, reason)`.
    allow: Vec<(String, String, String, String)>,
}

fn parse_debug_field_review(text: &str) -> DebugFieldReview {
    let mut r = DebugFieldReview {
        public: Default::default(),
        secret_capable: Default::default(),
        ambiguous: Default::default(),
        container_ok: Default::default(),
        allow: Vec::new(),
    };
    let mut section = "";
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = match name {
                "public" => "public",
                "secret_capable" => "secret_capable",
                "ambiguous" => "ambiguous",
                "container_ok" => "container_ok",
                "allow" => "allow",
                other => panic!(
                    "debug_field_review.txt:{}: unknown section [{other}]",
                    n + 1
                ),
            };
            continue;
        }
        match section {
            "public" => drop(r.public.insert(line.to_string())),
            "secret_capable" => drop(r.secret_capable.insert(line.to_string())),
            "ambiguous" => drop(r.ambiguous.insert(line.to_string())),
            "container_ok" => drop(r.container_ok.insert(line.to_string())),
            "allow" => {
                let (spec, reason) = line.split_once(" | ").unwrap_or_else(|| {
                    panic!(
                        "debug_field_review.txt:{}: [allow] needs ' | reason'",
                        n + 1
                    )
                });
                let mut parts = spec.splitn(3, ':');
                let (Some(file), Some(ty), Some(field)) =
                    (parts.next(), parts.next(), parts.next())
                else {
                    panic!(
                        "debug_field_review.txt:{}: [allow] is path:Type:field | reason",
                        n + 1
                    );
                };
                assert!(
                    !reason.trim().is_empty(),
                    "debug_field_review.txt:{}: empty reason",
                    n + 1
                );
                r.allow.push((
                    file.to_string(),
                    ty.to_string(),
                    field.to_string(),
                    reason.trim().to_string(),
                ));
            }
            _ => panic!(
                "debug_field_review.txt:{}: entry before any [section]",
                n + 1
            ),
        }
    }
    r
}

/// Why a derived-`Debug` plain field is not acceptable, or `None`. `used` records which `[allow]`
/// entries were consulted so stale ones can be reported.
fn review_debug_field(
    review: &DebugFieldReview,
    used: &mut [bool],
    file: &str,
    ty: &str,
    field: &str,
    container: bool,
) -> Option<&'static str> {
    if let Some(i) = review
        .allow
        .iter()
        .position(|(f, t, fld, _)| file.ends_with(f.as_str()) && t == ty && fld == field)
    {
        used[i] = true;
        return None;
    }
    if container {
        if review.container_ok.contains(field) {
            None
        } else {
            Some(
                "a map, set or JSON value keyed by or holding free text: redact it (hand-written Debug), list the name under [container_ok], or [allow] it with a reason",
            )
        }
    } else if field == "<tuple>" {
        Some("a tuple payload holds a plain string: redact it or [allow] it with a reason")
    } else if review.public.contains(field) {
        None
    } else if review.secret_capable.contains(field) {
        Some(
            "a secret-capable field name: redact it (hand-written Debug) or [allow] it with a reason",
        )
    } else if review.ambiguous.contains(field) {
        Some("an ambiguous field name: redact it or record a per-type decision in [allow]")
    } else {
        Some("a field name nobody has reviewed: add it to a list in tests/debug_field_review.txt")
    }
}

/// `(derive(Debug) types, of which with a plain field, problems, stale [allow] entries)`.
/// The label of a field of unknown type that a hand-written impl prints as it is: only names the review
/// file calls secret-capable or ambiguous are a problem, since without the type nothing else is known.
fn review_unknown_field(
    review: &DebugFieldReview,
    used: &mut [bool],
    file: &str,
    ty: &str,
    label: &str,
) -> Option<&'static str> {
    if let Some(i) = review
        .allow
        .iter()
        .position(|(f, t, fld, _)| file.ends_with(f.as_str()) && t == ty && fld == label)
    {
        used[i] = true;
        return None;
    }
    if review.secret_capable.contains(label) {
        Some(
            "printed as it is by a hand-written Debug although the name is secret-capable: redact it or [allow] it with a reason",
        )
    } else if review.ambiguous.contains(label) {
        Some(
            "printed as it is by a hand-written Debug although the name is ambiguous: redact it or [allow] it with a reason",
        )
    } else {
        None
    }
}

/// A field of a type defined elsewhere that a hand-written impl prints as it is: acceptable when that
/// type's `Debug` is audited here (derive or hand-written impl in `src/`), or when an `[allow]` says why.
/// A type from another crate is in neither case, so it needs the `[allow]`.
fn review_custom_field(
    review: &DebugFieldReview,
    used: &mut [bool],
    audited: &std::collections::HashSet<String>,
    file: &str,
    ty: &str,
    label: &str,
    field_type: &str,
) -> Option<String> {
    if audited.contains(field_type) {
        return None;
    }
    if let Some(i) = review
        .allow
        .iter()
        .position(|(f, t, fld, _)| file.ends_with(f.as_str()) && t == ty && fld == label)
    {
        used[i] = true;
        return None;
    }
    Some(format!(
        "printed as it is by a hand-written Debug, and `{field_type}` has no Debug audited here: redact it, give the type a redacting Debug, or [allow] it with a reason"
    ))
}

fn debug_review_problems(
    review: &DebugFieldReview,
    files: &[(String, String)],
) -> (usize, usize, Vec<String>, Vec<String>) {
    let mut used = vec![false; review.allow.len()];
    let audited = audited_debug_types(files);
    let (mut derived, mut with_plain) = (0, 0);
    let mut problems = Vec::new();
    for (file, content) in files {
        let scan = scan_derived_debug(file, content);
        derived += scan.derived_types;
        let mut types: Vec<&str> = scan
            .plain_fields
            .iter()
            .map(|(t, _, _, _)| t.as_str())
            .collect();
        types.sort_unstable();
        types.dedup();
        with_plain += types.len();
        for (ty, line, field, container) in &scan.plain_fields {
            if let Some(why) = review_debug_field(review, &mut used, file, ty, field, *container) {
                problems.push(format!("  {file}:{line} - {ty}.{field}: {why}"));
            }
        }
        for (ty, label, kind) in handwritten_debug_fields(content).0 {
            let why = match kind {
                HandKind::Plain => review_debug_field(review, &mut used, file, &ty, &label, false)
                    .map(String::from),
                HandKind::Container => {
                    review_debug_field(review, &mut used, file, &ty, &label, true).map(String::from)
                }
                HandKind::Unknown => {
                    review_unknown_field(review, &mut used, file, &ty, &label).map(String::from)
                }
                HandKind::Custom(name) => {
                    review_custom_field(review, &mut used, &audited, file, &ty, &label, &name)
                }
            };
            if let Some(why) = why {
                problems.push(format!(
                    "  {file} - {ty}.{label} (hand-written Debug): {why}"
                ));
            }
        }
    }
    let stale = review
        .allow
        .iter()
        .zip(used)
        .filter(|(_, used)| !used)
        .map(|((f, t, fld, _), _)| format!("  {f}:{t}:{fld}"))
        .collect();
    (derived, with_plain, problems, stale)
}

/// Floors for the scanner's population, set below the measured counts so ordinary change does not trip
/// them but a broken scanner does.
const DERIVED_DEBUG_TYPES_FLOOR: usize = 900;
const PLAIN_FIELD_TYPES_FLOOR: usize = 400;

/// Every `derive(Debug)` struct / enum in `src/` with a plain-text field must either have that field's
/// NAME on the reviewed public list, or be redacted by a hand-written `Debug`, or carry an explicit
/// `[allow]` decision with a reason. A name nobody has reviewed fails, so each new field name needs
/// a human decision; this replaces the earlier blacklist of secret-sounding names, which missed
/// fields called `value`, `code` and `token_id`.
#[test]
fn test_derived_debug_plain_fields_are_reviewed() {
    let mut paths = Vec::new();
    rust_files_under("src", &mut paths);
    paths.sort();
    let files: Vec<(String, String)> = paths
        .into_iter()
        .filter_map(|p| fs::read_to_string(&p).ok().map(|c| (p, c)))
        .collect();
    let review = parse_debug_field_review(include_str!("debug_field_review.txt"));

    let (derived, with_plain, problems, stale) = debug_review_problems(&review, &files);
    // Vacuity controls: a scanner that silently found nothing would pass everything.
    assert!(
        derived >= DERIVED_DEBUG_TYPES_FLOOR,
        "scanner found only {derived} derive(Debug) types (floor {DERIVED_DEBUG_TYPES_FLOOR}): it is broken or src/ moved"
    );
    assert!(
        with_plain >= PLAIN_FIELD_TYPES_FLOOR,
        "scanner found only {with_plain} types with a plain-text field (floor {PLAIN_FIELD_TYPES_FLOOR})"
    );
    let both: Vec<&String> = review
        .public
        .iter()
        .filter(|n| review.secret_capable.contains(*n) || review.ambiguous.contains(*n))
        .collect();
    assert!(
        both.is_empty(),
        "field names on the public list and another list: {both:?}"
    );
    assert!(
        problems.is_empty() && stale.is_empty(),
        "derive(Debug) types with unreviewed plain-text fields:\n{}\nStale [allow] entries:\n{}",
        problems.join("\n"),
        stale.join("\n")
    );
}

/// The text between the braces that open at or after `from` in `content`, braces balanced.
fn braced_block(content: &str, from: usize) -> Option<&str> {
    let open = from + content[from..].find('{')?;
    let mut depth = 0i32;
    for (i, c) in content[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&content[open + 1..open + i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// How a field is printed by a hand-written `impl Debug`, when it is printed as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HandKind {
    /// A plain-text field (`String`, `Vec<u8>`, ...) of the struct itself.
    Plain,
    /// A map, set or JSON value of the struct itself.
    Container,
    /// Anything else: an enum payload, a nested expression. Only the field's label is known.
    Unknown,
    /// A field of a type defined elsewhere, printed as it is.
    Custom(String),
}

/// The text of the call whose `(` is just before `start`, up to its matching `)`.
fn call_args(body: &str, start: usize) -> Option<&str> {
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for (i, c) in body[start..].char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth < 0 {
                    return Some(&body[start..start + i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// `("label", value)` from the arguments of a `.field(..)` call; the label is `<tuple>` for the
/// one-argument form used by `debug_tuple`.
fn split_field_args(args: &str) -> (String, &str) {
    let args = args.trim();
    if let Some(rest) = args.strip_prefix('"')
        && let Some(end) = rest.find('"')
    {
        let label = &rest[..end];
        let value = rest[end + 1..].trim_start().trim_start_matches(',').trim();
        return (label.to_string(), value);
    }
    ("<tuple>".to_string(), args)
}

/// Whether a value passed to `.field(..)` cannot print a secret: it goes through `redacted(..)`, is a
/// literal, or is only a count or presence flag.
fn field_value_is_safe(value: &str) -> bool {
    let v = value.trim();
    v.contains("redacted(")
        || v.starts_with("&\"")
        || v.starts_with("&format_args!(\"")
        || v.contains(".len()")
        || v.contains(".is_some()")
        || v.contains(".is_none()")
        || v.contains(".is_empty()")
}

/// The first type in a field's declared type that is neither a primitive, a std container or time type,
/// nor a single-letter generic: the type whose own `Debug` decides what the field prints.
fn custom_type(ty: &str) -> Option<String> {
    const KNOWN: &[&str] = &[
        "Option",
        "Arc",
        "Box",
        "Rc",
        "Vec",
        "VecDeque",
        "RwLock",
        "Mutex",
        "Cell",
        "RefCell",
        "HashMap",
        "BTreeMap",
        "HashSet",
        "BTreeSet",
        "DashMap",
        "DashSet",
        "Duration",
        "Instant",
        "SystemTime",
        "DateTime",
        "Utc",
        "Local",
        "Uuid",
        "IpAddr",
        "Ipv4Addr",
        "Ipv6Addr",
        "SocketAddr",
        "PathBuf",
        "Path",
        "Self",
        "Result",
        "String",
        "Value",
        "Cow",
        "PhantomData",
    ];
    let ident = regex::Regex::new(r"\b[A-Z][A-Za-z0-9_]*\b").unwrap();
    ident
        .find_iter(ty)
        .map(|m| m.as_str())
        .find(|i| i.len() > 1 && !KNOWN.contains(i) && !i.starts_with("Atomic"))
        .map(str::to_string)
}

/// Names of the types in `files` whose `Debug` the audit looks at: those with `derive(Debug)`
/// (plain fields reviewed by the derive scan) and those with a hand-written impl (scanned here).
fn audited_debug_types(files: &[(String, String)]) -> std::collections::HashSet<String> {
    let derive = regex::Regex::new(
        r"(?s)#\[derive\([^\]]*\bDebug\b[^\]]*\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum)\s+(\w+)",
    )
    .unwrap();
    let manual =
        regex::Regex::new(r"impl(?:<[^>]*>)?\s+(?:std::fmt::|fmt::)?Debug\s+for\s+(\w+)").unwrap();
    let mut out = std::collections::HashSet::new();
    for (_, content) in files {
        for re in [&derive, &manual] {
            out.extend(re.captures_iter(content).map(|c| c[1].to_string()));
        }
    }
    out
}

/// Every field a hand-written `impl Debug for T` prints without redacting it, as `(type, label, kind)`,
/// and the number of hand-written impls looked at (the control that the scan reached any).
///
/// `kind` says what is known about the field: for a struct whose field the impl prints as
/// `&self.member`, its declared type (plain text or container; other types cannot hold a secret and are
/// not reported); otherwise only the label.
fn handwritten_debug_fields(content: &str) -> (Vec<(String, String, HandKind)>, usize) {
    let impl_re =
        regex::Regex::new(r"impl(?:<[^>]*>)?\s+(?:std::fmt::|fmt::)?Debug\s+for\s+(\w+)").unwrap();
    let field_re =
        regex::Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*(.+?),?\s*(?://.*)?$")
            .unwrap();
    let member_re =
        regex::Regex::new(r"^&?self\.(\w+)(?:\.as_str\(\)|\.as_deref\(\)|\.clone\(\))?$").unwrap();
    let plain = regex::Regex::new(
        r"^(?:pub(?:\([^)]*\))?\s+)?(?:Option<)?(?:String|Vec<u8>|Vec<String>|Vec<Vec<u8>>|Box<str>|Box<\[u8\]>|Arc<str>|Cow<'\w+, ?str>|Bytes|\[u8; ?\w+\])>?$",
    )
    .unwrap();
    let (mut found, mut impls) = (Vec::new(), 0);
    for m in impl_re.captures_iter(content) {
        let ty = &m[1];
        let Some(body) = braced_block(content, m.get(0).unwrap().end()) else {
            continue;
        };
        impls += 1;
        // Declared field types, when the type is a struct declared in this file.
        let mut types = std::collections::HashMap::new();
        let item = regex::Regex::new(&format!(
            r"(?:pub(?:\([^)]*\))?\s+)?struct\s+{ty}\b[^;{{]*\{{"
        ))
        .unwrap();
        if let Some(item_m) = item.find(content)
            && let Some(fields) = braced_block(content, item_m.start())
        {
            let mut depth = 0i32;
            for line in fields.lines() {
                if depth == 0
                    && let Some(f) = field_re.captures(line)
                {
                    types.insert(f[1].to_string(), f[2].trim().to_string());
                }
                depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
            }
        }
        let mut at = 0;
        while let Some(i) = body[at..].find(".field(") {
            let start = at + i + ".field(".len();
            at = start;
            let Some(args) = call_args(body, start) else {
                continue;
            };
            let (label, value) = split_field_args(args);
            if field_value_is_safe(value) {
                continue;
            }
            let kind = match member_re
                .captures(value)
                .and_then(|c| types.get(&c[1]).cloned())
            {
                Some(ft) if plain.is_match(ft.trim()) => HandKind::Plain,
                Some(ft) if is_container(&ft, &plain) => HandKind::Container,
                Some(ft) => match custom_type(&ft) {
                    Some(name) => HandKind::Custom(name),
                    None => continue,
                },
                None => HandKind::Unknown,
            };
            found.push((ty.to_string(), label, kind));
        }
    }
    (found, impls)
}

/// The hand-written side of the audit reaches many impls (control: an empty result is not vacuous).
#[test]
fn test_handwritten_debug_scan_reaches_the_impls() {
    let mut paths = Vec::new();
    rust_files_under("src", &mut paths);
    let impls: usize = paths
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok())
        .map(|c| handwritten_debug_fields(&c).1)
        .sum();
    assert!(
        impls >= 150,
        "only {impls} hand-written Debug impls scanned"
    );
}

/// How a value passed to a log macro has to be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogSecret {
    /// A high-entropy identifier (session id, token): log `redact::fingerprint(..)`.
    HighEntropy,
    /// A low-entropy secret (one-time code, password, challenge): do not log it at all.
    LowEntropy,
}

/// Whether a bare identifier names a value that must not be logged as it is.
fn log_secret_kind(ident: &str) -> Option<LogSecret> {
    let ident = ident
        .strip_suffix("_string")
        .or_else(|| ident.strip_suffix("_str"))
        .unwrap_or(ident);
    const LOW: &[&str] = &[
        "otp",
        "otp_code",
        "password",
        "passwd",
        "secret",
        "secrets",
        "api_key",
        "apikey",
        "verification_code",
        "mfa_code",
        "totp_code",
        "backup_code",
        "user_code",
        "device_code",
        "auth_code",
        "authorization_code",
        "assertion",
        "private_key",
        "passphrase",
        "credential",
        "credentials",
        "challenge",
        "stored_challenge",
        "code",
        "sms_code",
        "email_code",
    ];
    const HIGH: &[&str] = &[
        "session_id",
        "sid",
        "session_token",
        "token",
        "jwt",
        "bearer",
        "id_token",
        "event_jwt",
        "auth_req_id",
        "session_ids",
        "sids",
    ];
    if LOW.contains(&ident)
        || ident.ends_with("_secret")
        || ident.ends_with("_password")
        || ident.ends_with("_challenge")
        || ident.ends_with("_api_key")
    {
        Some(LogSecret::LowEntropy)
    } else if HIGH.contains(&ident)
        || ident.ends_with("_session_id")
        || ident.ends_with("_token")
        || ident.ends_with("_jwt")
    {
        Some(LogSecret::HighEntropy)
    } else {
        None
    }
}

/// Splits the arguments of a macro call on the commas that are not nested or inside a string.
fn split_macro_args(args: &str) -> Vec<&str> {
    let (mut parts, mut depth, mut start) = (Vec::new(), 0i32, 0);
    let mut in_str = false;
    let mut escaped = false;
    for (i, c) in args.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&args[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if !args[start..].trim().is_empty() {
        parts.push(&args[start..]);
    }
    parts
}

/// The index just past the `)` that closes a call whose arguments start at `from` (string literals
/// are skipped); the end of `code` if it never closes.
fn call_end(code: &str, from: usize) -> usize {
    let (mut depth, mut in_str, mut escaped) = (1i32, false, false);
    for (i, c) in code[from..].char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return from + i;
                }
            }
            _ => {}
        }
    }
    code.len()
}

/// Reports what the arguments `args` of a log macro, or of a `format!`/`json!`/`serde_json::to_string`
/// call nested in one, write as they are.
fn log_arg_secrets(args: &str, line: usize, found: &mut Vec<(usize, String, LogSecret)>) {
    let bare = regex::Regex::new(
        r"^(?:%|\?)?\s*(?:&|\*)*\s*((?:[a-z_][a-z_0-9]*\.)*[a-z_][a-z_0-9]*)(?:\.(?:clone|as_str|to_string|as_ref|as_deref)\(\))*$",
    )
    .unwrap();
    let named = regex::Regex::new(r"^[a-z_][a-z_0-9]*\s*=\s*(?s:(.*))$").unwrap();
    let json_key = regex::Regex::new(r#"^"[^"]*"\s*:\s*(?s:(.*))$"#).unwrap();
    let inline = regex::Regex::new(r"\{([a-z_][a-z_0-9]*)(?::[^}]*)?\}").unwrap();
    let nested =
        regex::Regex::new(r"\b(?:format!|json!|serde_json::to_string(?:_pretty)?)\s*\(").unwrap();
    for part in split_macro_args(args) {
        let part = part.trim();
        if part.starts_with('"') && !json_key.is_match(part) {
            for c in inline.captures_iter(part) {
                if let Some(kind) = log_secret_kind(&c[1]) {
                    found.push((line, c[1].to_string(), kind));
                }
            }
            continue;
        }
        let part = json_key
            .captures(part)
            .map_or(part, |c| c.get(1).unwrap().as_str().trim());
        let expr = named
            .captures(part)
            .map_or(part, |c| c.get(1).unwrap().as_str().trim());
        if let Some(b) = bare.captures(expr) {
            let mut path = b[1].rsplit('.');
            let ident = path.next().unwrap_or(&b[1]);
            // `session.id` names a session id by its owner, not by itself.
            let kind = if ident == "id" && path.next() == Some("session") {
                Some(LogSecret::HighEntropy)
            } else {
                log_secret_kind(ident)
            };
            if let Some(kind) = kind {
                found.push((line, ident.to_string(), kind));
            }
            continue;
        }
        // A `json!({ .. })` object: look at each of its members.
        if let Some(inner) = expr.strip_prefix('{').and_then(|e| e.strip_suffix('}')) {
            log_arg_secrets(inner, line, found);
        }
        for m in nested.find_iter(expr) {
            let end = call_end(expr, m.end());
            log_arg_secrets(&expr[m.end()..end], line, found);
        }
    }
}

/// The secrets a `trace!`/`debug!`/`info!`/`warn!`/`error!` call in `content` logs as they are: a bare
/// identifier or field access (optionally `&x`, `x.clone()`, `x.as_str()`, ...) passed as an argument or
/// written inline in the format string (`"{session_id}"`), also inside a `format!`, `json!` or
/// `serde_json::to_string` that is one of its arguments. A value that goes through a function
/// (`redact::fingerprint(&session_id)`) or is a literal is not reported. Only test-only items (see
/// [`production_lines`]) and commented-out lines are skipped. Returns `(line, ident, kind)`.
fn logged_secrets(content: &str) -> Vec<(usize, String, LogSecret)> {
    let mac =
        regex::Regex::new(r"\b(?:tracing::|log::)?(?:trace|debug|info|warn|error)!\s*\(").unwrap();
    // Test-only lines are blanked, not removed, so line numbers stay those of the file.
    let kept: std::collections::HashSet<usize> = production_lines("log scan", content)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    let code: String = content
        .lines()
        .enumerate()
        .map(|(i, l)| if kept.contains(&(i + 1)) { l } else { "" })
        .collect::<Vec<_>>()
        .join("\n");
    let mut found = Vec::new();
    for m in mac.find_iter(&code) {
        let line_start = code[..m.start()].rfind('\n').map_or(0, |i| i + 1);
        if code[line_start..m.start()].trim_start().starts_with("//") {
            continue;
        }
        let end = call_end(&code, m.end());
        let line = code[..m.start()].matches('\n').count() + 1;
        log_arg_secrets(&code[m.end()..end], line, &mut found);
    }
    found
}

/// CWE-532: a log macro must not write a session id, token, one-time code or password as it is. High
/// entropy identifiers are logged as `crate::utils::redact::fingerprint(&id)`, low entropy secrets are
/// left out.
#[test]
fn test_log_macros_do_not_log_secrets() {
    let mut paths = Vec::new();
    rust_files_under("src", &mut paths);
    paths.sort();
    let (mut calls, mut problems) = (0usize, Vec::new());
    let mac =
        regex::Regex::new(r"\b(?:tracing::|log::)?(?:trace|debug|info|warn|error)!\s*\(").unwrap();
    for path in &paths {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        calls += mac.find_iter(&content).count();
        for (line, ident, kind) in logged_secrets(&content) {
            let fix = match kind {
                LogSecret::HighEntropy => "log redact::fingerprint(..) of it",
                LogSecret::LowEntropy => "do not log it",
            };
            problems.push(format!(
                "  {path}:{line} - `{ident}` is logged as it is: {fix}"
            ));
        }
    }
    // Control: the scan reached the log macros, so an empty result is not vacuous.
    assert!(
        calls >= 500,
        "only {calls} log macro calls found under src/"
    );
    assert!(
        problems.is_empty(),
        "secrets written to the log:\n{}",
        problems.join("\n")
    );
}

/// Lines inside `macro_rules!` bodies that define a type or derive anything. A type generated by a
/// macro is invisible to the derived-`Debug` scan, so none may exist until the scan learns them.
fn macro_defined_types(file: &str, content: &str) -> Vec<String> {
    let mut found = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        if !lines[i].contains("macro_rules!") {
            i += 1;
            continue;
        }
        let (mut depth, mut opened) = (0i32, false);
        let mut k = i;
        while k < lines.len() {
            let l = lines[k];
            depth += l.matches('{').count() as i32 - l.matches('}').count() as i32;
            opened |= l.contains('{');
            let code = l.trim_start();
            if !code.starts_with("//")
                && (code.contains("#[derive(")
                    || code.starts_with("struct ")
                    || code.starts_with("pub struct ")
                    || code.starts_with("enum ")
                    || code.starts_with("pub enum "))
            {
                found.push(format!("{file}:{} - {}", k + 1, code));
            }
            if opened && depth <= 0 {
                break;
            }
            k += 1;
        }
        i = k + 1;
    }
    found
}

/// No macro in `src/` defines a type (see [`macro_defined_types`]).
#[test]
fn test_no_types_are_defined_inside_macros() {
    let mut paths = Vec::new();
    rust_files_under("src", &mut paths);
    paths.sort();
    let macros_seen = paths
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok())
        .filter(|c| c.contains("macro_rules!"))
        .count();
    // Control: the walk reaches files that do contain macros.
    assert!(
        macros_seen > 0,
        "no macro_rules! found under src/: the walk is broken"
    );
    let found: Vec<String> = paths
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok().map(|c| (p, c)))
        .flat_map(|(p, c)| macro_defined_types(p, &c))
        .collect();
    assert!(
        found.is_empty(),
        "types defined inside macros:
{}",
        found.join(
            "
"
        )
    );
}

#[cfg(test)]
mod debug_review_tests {
    use super::*;

    fn review() -> DebugFieldReview {
        parse_debug_field_review(
            "[public]\nclient_id\nname\npassword_type\n[secret_capable]\nvalue\ncode\n[ambiguous]\nbody\n[container_ok]\nlabels\n[allow]\nfixture.rs:Allowed:value | the fixture says this value is public\n",
        )
    }

    fn problems(src: &str) -> Vec<String> {
        debug_review_problems(&review(), &[("fixture.rs".to_string(), src.to_string())]).2
    }

    /// Seeded copies of the two leaks that the old name-based audit missed.
    #[test]
    fn the_leaks_the_old_audit_missed_are_flagged() {
        let ws = "#[derive(Debug, Clone)]\npub struct UsernamePassword {\n    pub value: String,\n    pub password_type: PasswordType,\n}\n";
        let code = "#[derive(Debug, Clone)]\npub struct EnhancedAuthorizationCode {\n    pub code: String,\n    pub client_id: String,\n}\n";
        let got = problems(ws);
        assert!(
            got.iter().any(|p| p.contains("UsernamePassword.value")),
            "{got:?}"
        );
        let got = problems(code);
        assert!(
            got.iter()
                .any(|p| p.contains("EnhancedAuthorizationCode.code")),
            "{got:?}"
        );
        // Control: the same types hand-written (no derive) are not flagged.
        assert!(problems(&ws.replace("#[derive(Debug, Clone)]", "#[derive(Clone)]")).is_empty());
    }

    #[test]
    fn public_names_pass_and_unreviewed_names_fail() {
        let src = "#[derive(Debug)]\npub struct A {\n    pub client_id: String,\n    pub name: Option<String>,\n    pub shiny_new_field: String,\n}\n";
        let got = problems(src);
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].contains("shiny_new_field") && got[0].contains("nobody has reviewed"));
    }

    #[test]
    fn ambiguous_names_and_tuple_payloads_need_a_decision() {
        let src = "#[derive(Debug)]\npub struct A {\n    pub body: String,\n}\n#[derive(Debug)]\npub struct B(pub String);\n#[derive(Debug)]\npub enum E {\n    Failed(String),\n    Unit,\n}\n";
        let got = problems(src);
        assert!(got.iter().any(|p| p.contains("A.body")), "{got:?}");
        assert!(got.iter().any(|p| p.contains("B.<tuple>")), "{got:?}");
        assert!(got.iter().any(|p| p.contains("E.<tuple>")), "{got:?}");
        assert_eq!(got.len(), 3, "{got:?}");
    }

    #[test]
    fn non_string_fields_and_zeroizing_are_not_scanned() {
        let src = "#[derive(Debug)]\npub struct A {\n    pub value: u32,\n    pub code: Zeroizing<String>,\n    pub secret: SecretBox,\n}\n";
        assert!(problems(src).is_empty());
    }

    #[test]
    fn an_allow_entry_clears_one_type_and_a_stale_one_is_reported() {
        let ok = "#[derive(Debug)]\npub struct Allowed {\n    pub value: String,\n}\n";
        let other = "#[derive(Debug)]\npub struct Other {\n    pub value: String,\n}\n";
        assert!(problems(ok).is_empty());
        assert_eq!(problems(other).len(), 1);
        let (_, _, _, stale) =
            debug_review_problems(&review(), &[("fixture.rs".to_string(), other.to_string())]);
        assert_eq!(stale.len(), 1, "{stale:?}");
    }

    #[test]
    fn enum_variant_fields_are_seen() {
        let src = "#[derive(Debug)]\npub enum C {\n    Create {\n        value: Option<String>,\n    },\n}\n";
        assert_eq!(problems(src).len(), 1);
    }

    #[test]
    fn one_line_struct_variants_and_structs_are_seen() {
        let variant = "#[derive(Debug)]
pub enum E {
    Ext { name: String, value: String },
    Unit,
}
";
        let got = problems(variant);
        assert!(got.iter().any(|p| p.contains("E.value")), "{got:?}");
        let inline_struct = "#[derive(Debug)]
pub struct A { pub value: String }
";
        let got = problems(inline_struct);
        assert!(got.iter().any(|p| p.contains("A.value")), "{got:?}");
        // Controls: a one-line variant with only public names, and a hand-written one, are fine.
        assert!(
            problems(
                "#[derive(Debug)]
pub enum E {
    Ext { name: String, client_id: String },
}
"
            )
            .is_empty()
        );
        assert!(problems(&variant.replace("#[derive(Debug)]", "#[derive(Clone)]")).is_empty());
    }

    #[test]
    fn a_derive_inside_cfg_attr_counts() {
        let src = "#[cfg_attr(feature = \"x\", derive(Debug))]
pub struct A {
    pub value: String,
}
";
        let got = problems(src);
        assert!(got.iter().any(|p| p.contains("A.value")), "{got:?}");
        // Control: a cfg_attr that derives something else is not a Debug derive.
        assert!(problems(&src.replace("derive(Debug)", "derive(Clone)")).is_empty());
    }

    #[test]
    fn generic_cfg_gated_and_multiline_derive_items_are_scanned() {
        let generic = "#[cfg(feature = \"x\")]
#[derive(Debug)]
pub struct W<T>(pub String, T);
";
        let got = problems(generic);
        assert!(got.iter().any(|p| p.contains("W.<tuple>")), "{got:?}");
        let multi = "#[derive(
    Debug,
    Clone,
)]
pub struct M {
    pub value: String,
}
";
        let got = problems(multi);
        assert!(got.iter().any(|p| p.contains("M.value")), "{got:?}");
        // Control: the same multi-line attribute without `Debug` derives nothing to check.
        assert!(
            problems(&multi.replace(
                "    Debug,
",
                ""
            ))
            .is_empty()
        );
    }

    #[test]
    fn other_byte_and_string_shapes_count_as_plain_text() {
        for ty in [
            "Vec<Vec<u8>>",
            "Box<[u8]>",
            "Cow<'static, str>",
            "Bytes",
            "[u8; 32]",
            "Option<Bytes>",
        ] {
            let src = format!(
                "#[derive(Debug)]
pub struct A {{
    pub value: {ty},
}}
"
            );
            assert_eq!(problems(&src).len(), 1, "{ty}: {:?}", problems(&src));
        }
        // Control: a non-text shape is not scanned.
        assert!(
            problems(
                "#[derive(Debug)]
pub struct A {
    pub value: u64,
}
"
            )
            .is_empty()
        );
    }

    #[test]
    fn macro_bodies_that_define_types_are_found() {
        let defining = "macro_rules! make {
    ($n:ident) => {
        #[derive(Debug)]
        pub struct $n {
            pub value: String,
        }
    };
}
";
        assert!(!macro_defined_types("fixture.rs", defining).is_empty());
        // Control: a macro that only expands to expressions is fine.
        let plain = "macro_rules! twice {
    ($e:expr) => {
        $e + $e
    };
}
";
        assert!(macro_defined_types("fixture.rs", plain).is_empty());
    }

    #[test]
    fn maps_sets_and_json_values_need_a_decision() {
        // Keyed by a token: the map's Debug prints every key.
        let keyed =
            "#[derive(Debug)]\npub struct S {\n    tokens: DashMap<String, AuthToken>,\n}\n";
        let got = problems(keyed);
        assert!(got.iter().any(|p| p.contains("S.tokens")), "{got:?}");
        // Wrappers are looked through.
        let wrapped = "#[derive(Debug)]\npub struct S {\n    sessions: Arc<RwLock<HashMap<String, Session>>>,\n}\n";
        assert!(problems(wrapped).iter().any(|p| p.contains("S.sessions")));
        // JSON values and sets of strings.
        let value = "#[derive(Debug)]\npub struct S {\n    pub challenge_data: Option<serde_json::Value>,\n    seen: HashSet<String>,\n}\n";
        assert_eq!(problems(value).len(), 2, "{:?}", problems(value));
        // Controls: a name listed under [container_ok], a map with no free-text key or value, and a
        // hand-written Debug are not flagged.
        assert!(
            problems("#[derive(Debug)]\npub struct S {\n    labels: HashMap<String, String>,\n}\n")
                .is_empty()
        );
        assert!(
            problems("#[derive(Debug)]\npub struct S {\n    counts: HashMap<u64, u64>,\n}\n")
                .is_empty()
        );
        assert!(problems(&keyed.replace("#[derive(Debug)]", "#[derive(Clone)]")).is_empty());
    }

    #[test]
    fn handwritten_debug_printing_a_field_as_it_is_is_found() {
        let leaky = "pub struct M {\n    pub name: String,\n    pub token: String,\n    sessions: HashMap<String, Session>,\n    count: u32,\n}\nimpl std::fmt::Debug for M {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        f.debug_struct(\"M\")\n            .field(\"name\", &self.name)\n            .field(\"token\", &self.token)\n            .field(\"sessions\", &self.sessions)\n            .field(\"count\", &self.count)\n            .finish()\n    }\n}\n";
        let (found, impls) = handwritten_debug_fields(leaky);
        assert_eq!(impls, 1);
        assert_eq!(
            found,
            vec![
                ("M".to_string(), "name".to_string(), HandKind::Plain),
                ("M".to_string(), "token".to_string(), HandKind::Plain),
                ("M".to_string(), "sessions".to_string(), HandKind::Container),
            ]
        );
        // The review turns those into problems: `token` is secret-capable in the fixture, `name` is
        // public and `sessions` is not a [container_ok] name.
        let got =
            debug_review_problems(&review(), &[("fixture.rs".to_string(), leaky.to_string())]).2;
        assert!(got.iter().any(|p| p.contains("M.token")), "{got:?}");
        assert!(got.iter().any(|p| p.contains("M.sessions")), "{got:?}");
        assert!(!got.iter().any(|p| p.contains("M.name")), "{got:?}");
        // Controls: the same fields behind `redacted(..)`, as a literal, or as a count are not
        // reported, and a map with no free-text key or value is not reported.
        let hidden = leaky
            .replace("&self.token", "&redacted(&self.token)")
            .replace("&self.sessions", "&self.sessions.len()");
        assert_eq!(
            handwritten_debug_fields(&hidden).0.len(),
            1,
            "{:?}",
            handwritten_debug_fields(&hidden).0
        );
        let numeric = leaky.replace("HashMap<String, Session>", "HashMap<u64, u64>");
        assert!(
            !handwritten_debug_fields(&numeric)
                .0
                .iter()
                .any(|f| f.1 == "sessions")
        );
    }

    #[test]
    fn a_custom_typed_field_printed_as_it_is_needs_an_audited_type() {
        // `client` is a newtype whose Debug nobody here has audited; `count` and `at` cannot hold a secret.
        let src = "pub struct Holder {\n    pub client: ApiToken,\n    pub count: u32,\n    pub at: Option<Duration>,\n}\nimpl std::fmt::Debug for Holder {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        f.debug_struct(\"Holder\")\n            .field(\"client\", &self.client)\n            .field(\"count\", &self.count)\n            .field(\"at\", &self.at)\n            .finish()\n    }\n}\n";
        let file = |content: &str| vec![("fixture.rs".to_string(), content.to_string())];
        let (found, _) = handwritten_debug_fields(src);
        assert_eq!(
            found,
            vec![(
                "Holder".to_string(),
                "client".to_string(),
                HandKind::Custom("ApiToken".to_string())
            )]
        );
        let got = debug_review_problems(&review(), &file(src)).2;
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].contains("Holder.client"), "{got:?}");
        // Controls: the same field is fine once its type is audited (derive(Debug), whose plain
        // fields the derive scan reviews, or a hand-written impl), is redacted, or is allowed.
        let derived =
            format!("{src}#[derive(Debug)]\npub struct ApiToken {{\n    pub id: u64,\n}}\n");
        assert!(
            debug_review_problems(&review(), &file(&derived))
                .2
                .is_empty()
        );
        let manual = format!(
            "{src}impl std::fmt::Debug for ApiToken {{\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{\n        f.debug_struct(\"ApiToken\").field(\"id\", &\"<redacted>\").finish()\n    }}\n}}\n"
        );
        assert!(
            debug_review_problems(&review(), &file(&manual))
                .2
                .is_empty()
        );
        let hidden = src.replace("&self.client", "&redacted(&self.client)");
        assert!(
            debug_review_problems(&review(), &file(&hidden))
                .2
                .is_empty()
        );
        let allowed = parse_debug_field_review(
            "[allow]\nfixture.rs:Holder:client | the token type prints only a public id\n",
        );
        assert!(debug_review_problems(&allowed, &file(src)).2.is_empty());
        // A type audited in another scanned file counts.
        let two_files = vec![
            ("a.rs".to_string(), src.to_string()),
            (
                "b.rs".to_string(),
                "#[derive(Debug)]\npub struct ApiToken {\n    pub id: u64,\n}\n".to_string(),
            ),
        ];
        assert!(debug_review_problems(&review(), &two_files).2.is_empty());
    }

    #[test]
    fn handwritten_enum_arms_are_checked_by_label() {
        let src = "pub enum E {\n    A { value: String, name: String },\n}\nimpl std::fmt::Debug for E {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        match self {\n            Self::A { value, name } => f.debug_struct(\"A\").field(\"value\", value).field(\"name\", name).finish(),\n        }\n    }\n}\n";
        let got =
            debug_review_problems(&review(), &[("fixture.rs".to_string(), src.to_string())]).2;
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].contains("E.value"), "{got:?}");
        let fixed = src.replace(
            "field(\"value\", value)",
            "field(\"value\", &\"<redacted>\")",
        );
        assert!(
            debug_review_problems(&review(), &[("fixture.rs".to_string(), fixed)])
                .2
                .is_empty()
        );
    }

    #[test]
    fn a_test_only_item_does_not_hide_the_code_after_it() {
        let src =
            "#[cfg(test)]\nfn helper() {}\nfn prod() {\n    info!(\"x {}\", session_id);\n}\n";
        let got = logged_secrets(src);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, 4, "line numbers stay those of the file");
    }

    #[test]
    fn logged_secrets_are_found_and_wrapped_ones_are_not() {
        let leaky = "fn f() {\n    info!(\"revoked {}\", session_id);\n    debug!(\"code {code}\");\n    tracing::warn!(\"x {}\", &token.clone());\n    info!(\n        \"two {} {}\",\n        user_id,\n        otp\n    );\n}\n";
        let got = logged_secrets(leaky);
        let idents: Vec<&str> = got.iter().map(|g| g.1.as_str()).collect();
        assert_eq!(
            idents,
            vec!["session_id", "code", "token", "otp"],
            "{got:?}"
        );
        // Round 2 shapes: field access, `*_str` names, ids of a session or request, nested
        // `format!`/`json!`/`to_string`, and a list of ids.
        let shapes = [
            "info!(\"a {}\", request.session_id);",
            "info!(\"a {}\", logout_request.session_id);",
            "info!(\"a {}\", session.id);",
            "info!(\"a {}\", session_id_str);",
            "info!(\"a {}\", auth_req_id);",
            "info!(\"a {}\", format!(\"x {}\", session_id));",
            "info!(\"a {}\", json!({ \"session_id\": session_id }));",
            "info!(\"a {}\", serde_json::to_string(&token).unwrap());",
            "info!(\"a {:?}\", session_ids);",
        ];
        for shape in shapes {
            assert_eq!(logged_secrets(shape).len(), 1, "not reported: {shape}");
        }
        assert_eq!(got[0].2, LogSecret::HighEntropy);
        assert_eq!(got[1].2, LogSecret::LowEntropy);
        // Controls: wrapped, field access, literal, comment and test code are not reported.
        let fine = "fn f() {\n    info!(\"a {}\", crate::utils::redact::fingerprint(&session_id));\n    debug!(\"b {}\", crate::utils::redact::fingerprint(&request.session_id));\n    debug!(\"b2 {}\", session.created_at);\n    warn!(\"c {}\", \"<redacted>\");\n    // info!(\"d {}\", token);\n    info!(\"e {}\", user_id);\n}\n#[cfg(test)]\nmod tests {\n    fn t() { info!(\"{}\", token); }\n}\n";
        assert!(
            logged_secrets(fine).is_empty(),
            "{:?}",
            logged_secrets(fine)
        );
    }
}
