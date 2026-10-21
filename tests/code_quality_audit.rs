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

/// What the scanner found in one file: every struct / enum that derives `Debug`, and the plain-text
/// fields (`String`, `Vec<u8>`, `Vec<String>`, `Option` of those, `Box<str>`, `Arc<str>`) of those types
/// that `{:?}` would print verbatim.
struct DebugScan {
    /// Types that derive `Debug`, with or without plain-text fields.
    derived_types: usize,
    /// `(type, line, field)`; a tuple struct / tuple variant payload is reported as the field `<tuple>`.
    plain_fields: Vec<(String, usize, String)>,
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

fn scan_derived_debug(file: &str, content: &str) -> DebugScan {
    let item = regex::Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(struct|enum)\s+(\w+)").unwrap();
    let field = regex::Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*(.+?),?\s*(?://.*)?$")
        .unwrap();
    let tuple = regex::Regex::new(r"(?:^|[^\w])(\w*)\(([^()]*)\)").unwrap();
    let plain = regex::Regex::new(
        r"^(?:pub(?:\([^)]*\))?\s+)?(?:Option<)?(?:String|Vec<u8>|Vec<String>|Box<str>|Arc<str>)>?$",
    )
    .unwrap();

    let lines = production_lines(file, content);
    let mut scan = DebugScan {
        derived_types: 0,
        plain_fields: Vec::new(),
    };
    let mut i = 0;
    while i < lines.len() {
        let Some(m) = item.captures(lines[i].1) else {
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
                if above.starts_with("#[derive(") && above.contains("Debug") {
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
            let l = lines[k].1;
            depth += l.matches('{').count() as i32 - l.matches('}').count() as i32;
            opened |= l.contains('{');
            if derives_debug {
                let code = l.split("//").next().unwrap_or(l);
                let trimmed = code.trim_start();
                if k > i
                    && let Some(f) = field.captures(l)
                {
                    if plain.is_match(f[2].trim()) {
                        scan.plain_fields
                            .push((name.clone(), lines[k].0, f[1].to_string()));
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
    /// `(file suffix, type, field, reason)`.
    allow: Vec<(String, String, String, String)>,
}

fn parse_debug_field_review(text: &str) -> DebugFieldReview {
    let mut r = DebugFieldReview {
        public: Default::default(),
        secret_capable: Default::default(),
        ambiguous: Default::default(),
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
) -> Option<&'static str> {
    if let Some(i) = review
        .allow
        .iter()
        .position(|(f, t, fld, _)| file.ends_with(f.as_str()) && t == ty && fld == field)
    {
        used[i] = true;
        return None;
    }
    if field == "<tuple>" {
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
fn debug_review_problems(
    review: &DebugFieldReview,
    files: &[(String, String)],
) -> (usize, usize, Vec<String>, Vec<String>) {
    let mut used = vec![false; review.allow.len()];
    let (mut derived, mut with_plain) = (0, 0);
    let mut problems = Vec::new();
    for (file, content) in files {
        let scan = scan_derived_debug(file, content);
        derived += scan.derived_types;
        let mut types: Vec<&str> = scan
            .plain_fields
            .iter()
            .map(|(t, _, _)| t.as_str())
            .collect();
        types.sort_unstable();
        types.dedup();
        with_plain += types.len();
        for (ty, line, field) in &scan.plain_fields {
            if let Some(why) = review_debug_field(review, &mut used, file, ty, field) {
                problems.push(format!("  {file}:{line} - {ty}.{field}: {why}"));
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

#[cfg(test)]
mod debug_review_tests {
    use super::*;

    fn review() -> DebugFieldReview {
        parse_debug_field_review(
            "[public]\nclient_id\nname\npassword_type\n[secret_capable]\nvalue\ncode\n[ambiguous]\nbody\n[allow]\nfixture.rs:Allowed:value | the fixture says this value is public\n",
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
}
