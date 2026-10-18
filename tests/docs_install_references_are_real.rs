//! Installation references in the documentation must point at something that can be installed.
//!
//! Measured before this test existed: `docs/web-frameworks.md` told readers to depend on
//! `auth-framework = { version = "0.1.0", ... }` (a version yanked from crates.io, whose features
//! `actix-web`, `warp` and `rocket` are not the crate's integration features) and
//! `docs/guides/administrator-setup.md` told them to run `authframework/auth-framework:0.4.0`
//! (a registry namespace this project does not publish to, at a yanked version).
//!
//! What is checked, over every Markdown file under `docs/` and the root `README.md`:
//!
//! 1. no dependency line pins `auth-framework` at 0.1, 0.2 or 0.3, none of which is installable;
//! 2. no container image reference uses a name other than `ghcr.io/ciresnave/auth-framework`;
//! 3. no dependency line enables an `auth-framework` feature the crate does not define.

use std::fs;

fn markdown_files(dir: &str, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            markdown_files(&path.to_string_lossy(), out);
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path.to_string_lossy().replace('\\', "/"));
        }
    }
}

fn docs() -> Vec<(String, String)> {
    let mut files = vec!["README.md".to_string()];
    markdown_files("docs", &mut files);
    files.sort();
    files
        .into_iter()
        .filter_map(|f| fs::read_to_string(&f).ok().map(|t| (f, t)))
        .collect()
}

/// The `[features]` names of this crate's manifest.
fn manifest_features() -> Vec<String> {
    let manifest = include_str!("../Cargo.toml");
    let mut in_features = false;
    let mut names = Vec::new();
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_features = t == "[features]";
            continue;
        }
        if in_features
            && !t.starts_with('#')
            && let Some((name, _)) = t.split_once('=')
        {
            names.push(name.trim().trim_matches('"').to_string());
        }
    }
    names
}

#[test]
fn no_doc_pins_auth_framework_at_a_version_that_cannot_be_installed() {
    let mut bad = Vec::new();
    for (file, text) in docs() {
        for (i, line) in text.lines().enumerate() {
            let compact = line.replace(' ', "");
            for pin in [
                "auth-framework=\"0.1.",
                "auth-framework=\"0.2.",
                "auth-framework=\"0.3.",
                "auth-framework={version=\"0.1.",
                "auth-framework={version=\"0.2.",
                "auth-framework={version=\"0.3.",
            ] {
                if compact.contains(pin) {
                    bad.push(format!("{file}:{}: {}", i + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "documented pins that cannot be installed:\n{}",
        bad.join("\n")
    );
}

#[test]
fn no_doc_names_an_image_this_project_does_not_publish() {
    let mut bad = Vec::new();
    for (file, text) in docs() {
        for (i, line) in text.lines().enumerate() {
            if line.contains("auth-framework:")
                && line.contains("image:")
                && !line.contains("ghcr.io/ciresnave/auth-framework:")
            {
                bad.push(format!("{file}:{}: {}", i + 1, line.trim()));
            }
            if line.contains("docker run")
                && line.contains("auth-framework:")
                && !line.contains("ghcr.io/ciresnave/auth-framework:")
            {
                bad.push(format!("{file}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "documented images that are not published:\n{}",
        bad.join("\n")
    );
}

#[test]
fn documented_dependency_features_exist() {
    let features = manifest_features();
    assert!(
        features.len() > 10,
        "control: parsed only {features:?} from Cargo.toml"
    );
    let mut bad = Vec::new();
    for (file, text) in docs() {
        for (i, line) in text.lines().enumerate() {
            let Some(rest) = line.split("auth-framework = {").nth(1) else {
                continue;
            };
            let Some(list) = rest
                .split("features = [")
                .nth(1)
                .and_then(|r| r.split(']').next())
            else {
                continue;
            };
            for feature in list
                .split(',')
                .map(|f| f.trim().trim_matches('"'))
                .filter(|f| !f.is_empty() && *f != "...")
            {
                if !features.iter().any(|f| f == feature) {
                    bad.push(format!(
                        "{file}:{}: feature {feature:?} is not defined",
                        i + 1
                    ));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "documented features that do not exist:\n{}",
        bad.join("\n")
    );
}
