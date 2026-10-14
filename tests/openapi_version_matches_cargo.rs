//! **A version the API documents about itself must be the version it is.**
//!
//! Measured at `54bfa1c2` (0.6.0-rc52): `generate_openapi_spec()` served
//! `info.version = "0.5.0-rc24"` -- a literal that no release bump touched -- and the three
//! checked-in OpenAPI documents plus `schemas/health.yaml` (x2) carried the same string.
//! Twenty-eight releases of a consumer reading the spec to learn which API it was talking to.
//!
//! # What is checked
//!
//! 1. The served spec's `info.version` equals `CARGO_PKG_VERSION`. (It is derived, so this
//!    pins the derivation: a literal put back fails here.)
//! 2. Every checked-in OpenAPI document's `info.version`, and every `version:` example in
//!    `schemas/health.yaml`, equals the Cargo version. These are static files and cannot be
//!    derived, so a release bump must touch them; this fails the bump that forgets.
//!
//! # What this does NOT cover
//!
//! - Other docs that name a version (guides, footers).
//! - Whether the yaml files describe the same routes as the served spec.

const CARGO_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `version: X` / `version: "X"` as the first `version:` key under `info:`.
fn info_version(yaml: &str) -> Option<String> {
    let mut in_info = false;
    for l in yaml.lines() {
        if l.starts_with("info:") {
            in_info = true;
            continue;
        }
        if in_info {
            if !l.starts_with(' ') && !l.trim().is_empty() {
                return None; // left the info block
            }
            if let Some(v) = l.trim().strip_prefix("version:") {
                return Some(v.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

/// The `example:` value on the line after each `version:` key.
fn version_examples(yaml: &str) -> Vec<String> {
    let lines: Vec<&str> = yaml.lines().collect();
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if l.trim() == "version:" {
            for next in lines.iter().skip(i + 1).take(3) {
                if let Some(v) = next.trim().strip_prefix("example:") {
                    out.push(v.trim().trim_matches('"').to_string());
                    break;
                }
            }
        }
    }
    out
}

#[test]
fn checked_in_openapi_documents_carry_the_cargo_version() {
    for (name, text) in [
        ("openapi.yaml", include_str!("../docs/api/openapi.yaml")),
        (
            "openapi-modular.yaml",
            include_str!("../docs/api/openapi-modular.yaml"),
        ),
        (
            "openapi-bundled.yaml",
            include_str!("../docs/api/openapi-bundled.yaml"),
        ),
    ] {
        // Control: the parser must find a version, or a pass means "found nothing".
        let found = info_version(text)
            .unwrap_or_else(|| panic!("control: no info.version parsed from {name}"));
        assert_eq!(
            found, CARGO_VERSION,
            "docs/api/{name} says info.version {found}, but Cargo.toml is {CARGO_VERSION}: \
             a release bump must update the checked-in OpenAPI documents"
        );
    }
}

#[test]
fn health_schema_version_examples_carry_the_cargo_version() {
    let text = include_str!("../docs/api/schemas/health.yaml");
    let examples = version_examples(text);
    assert_eq!(
        examples.len(),
        2,
        "control: expected 2 `version` examples in health.yaml, parsed {examples:?}"
    );
    for e in &examples {
        assert_eq!(
            e, CARGO_VERSION,
            "docs/api/schemas/health.yaml has a version example {e}, Cargo.toml is {CARGO_VERSION}"
        );
    }
}

#[cfg(feature = "api-server")]
#[test]
fn served_openapi_spec_reports_the_cargo_version() {
    let spec = auth_framework::api::openapi::generate_openapi_spec();
    assert_eq!(
        spec["info"]["version"].as_str(),
        Some(CARGO_VERSION),
        "the served OpenAPI spec must report the crate version it is served by"
    );
}
