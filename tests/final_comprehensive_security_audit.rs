//! Source-pattern audit of the OAuth2 server and the other security-critical files.
//!
//! Every file this audit names must exist: a path that has moved fails the
//! test instead of counting as "nothing found".

use std::path::Path;

/// The OAuth2 flow: the public wrapper and the server that holds the logic.
const OAUTH2_FILES: &[&str] = &[
    "src/server/oauth/oauth2.rs",
    "src/server/oauth/oauth2_server.rs",
];

/// Files whose TODO comments mark unfinished security work.
const SECURITY_FILES: &[&str] = &[
    "src/server/oauth/oauth2.rs",
    "src/server/oauth/oauth2_server.rs",
    "src/server/oidc/mod.rs",
    "src/server/oidc/core.rs",
    "src/server/core/client_registry.rs",
    "src/auth.rs",
    "src/session/mod.rs",
    "src/session/manager.rs",
];

/// Read `path`, panicking when it is missing, unreadable or empty.
fn read_required(path: &str) -> String {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("audit subject {path} cannot be read: {e}"));
    assert!(!content.trim().is_empty(), "audit subject {path} is empty");
    content
}

/// Concatenate the required files so one pattern query covers all of them.
fn read_all(paths: &[&str]) -> String {
    paths
        .iter()
        .map(|p| read_required(p))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn test_required_audit_subjects_exist() {
    for path in SECURITY_FILES {
        assert!(Path::new(path).is_file(), "audit subject {path} is missing");
    }
}

#[test]
#[should_panic(expected = "cannot be read")]
fn test_missing_audit_subject_fails_loudly() {
    // Control: the reader must not turn a moved file into a clean result.
    read_required("src/server/this_file_does_not_exist.rs");
}

#[test]
fn test_oauth2_flow_has_no_known_vulnerability_markers() {
    let oauth2_source = read_all(OAUTH2_FILES);

    let markers = [
        ("hardcoded user identity", "user123"),
        (
            "client secret validation TODO",
            "TODO: Validate client secret",
        ),
        (
            "refresh token validation TODO",
            "TODO: Validate refresh token from storage",
        ),
        (
            "hardcoded authorization scopes",
            "vec![\"read\".to_string(), \"write\".to_string()]",
        ),
    ];

    let found: Vec<&str> = markers
        .iter()
        .filter(|(_, pattern)| oauth2_source.contains(pattern))
        .map(|(name, _)| *name)
        .collect();

    assert!(
        found.is_empty(),
        "marker(s) present in {OAUTH2_FILES:?}: {found:?}"
    );
}

#[test]
fn test_no_todo_comments_in_security_critical_files() {
    let mut todos = Vec::new();
    for file in SECURITY_FILES {
        let count = read_required(file).matches("TODO").count();
        if count > 0 {
            todos.push(format!("{file}: {count}"));
        }
    }
    assert!(
        todos.is_empty(),
        "TODO comments in security-critical files: {todos:?}"
    );
}
