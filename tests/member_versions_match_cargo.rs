//! **One version number per project:** the member crate and the SDKs carry the root crate's version.
//!
//! They sat at 0.6.0-rc64 and 0.6.0-rc108 while the crate moved on, because no release bump touched them.

use std::fs;

fn read(path: &str) -> String {
    fs::read_to_string(format!("{}/{path}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The string value of the first `key = "v"` (TOML, Python) or `"key": "v"` (JSON) line.
fn value_of(text: &str, key: &str) -> String {
    for line in text.lines() {
        let l = line.trim().trim_end_matches(',');
        let Some((k, v)) = l.split_once(['=', ':']) else {
            continue;
        };
        if k.trim().trim_matches('"') == key {
            return v.trim().trim_matches('"').to_string();
        }
    }
    panic!("no `{key}` in file");
}

#[test]
fn member_crate_and_sdks_carry_the_cargo_version() {
    let cargo = env!("CARGO_PKG_VERSION");
    // PEP 440 spells the pre-release `0.6.0rc152`.
    let pep440 = cargo.replace("-rc", "rc");

    assert_eq!(
        value_of(&read("auth-storage-sqlite/Cargo.toml"), "version"),
        cargo
    );
    assert_eq!(
        value_of(&read("sdks/javascript/package.json"), "version"),
        cargo
    );
    assert_eq!(
        value_of(&read("sdks/python/pyproject.toml"), "version"),
        pep440
    );
    assert_eq!(
        value_of(
            &read("sdks/python/src/authframework/__init__.py"),
            "__version__"
        ),
        pep440
    );
}

#[test]
fn the_helper_reads_a_known_value() {
    // Positive control: the same reader finds the root manifest's own version.
    assert_eq!(
        value_of(&read("Cargo.toml"), "version"),
        env!("CARGO_PKG_VERSION")
    );
}
