//! **A README claim must be true of the artifact a reader installs, not just of the tree.**
//!
//! Measured at `9bf3d893` (0.6.0-rc50), before this test existed:
//!
//! - README told readers to depend on `auth-framework = "0.5.0-rc24"` (three places) and to
//!   `docker run ...:0.5.0-rc24`. That version is inside the affected range of published
//!   advisories (e.g. GHSA-cw9x-gg6m-9cqr, rc18..rc26), and the 0.6.0 line had been current
//!   for twenty-six releases.
//! - README said "CVE-Free: Clean security record" while the repository had 14 published
//!   advisories.
//! - Both storage guides named "0.4.3, the newest stable version", when stable is 0.4.7.
//!   A hardcoded "newest" is a claim about the registry that the registry changes under it.
//!
//! # What is checked
//!
//! 1. Every `auth-framework` install pin in README is on the same `0.N` line as `Cargo.toml`.
//!    It is deliberately a *line* check, not an exact-version check: an exact check would
//!    fail every release PR that does not touch README, which is a cost the claim is not
//!    worth. The README says the pin is "at time of writing".
//! 2. README contains none of a short list of unfalsifiable security claims.
//! 3. The storage guides do not hardcode a "newest stable" patch version.
//!
//! # What this does NOT cover
//!
//! - The phrase list is a **floor**, not a census; a rephrased claim passes.
//! - Only `README.md` and the two storage guides. Other docs are not checked.
//! - It cannot tell whether the line it accepts still receives fixes.

const README: &str = include_str!("../README.md");
const CUSTOM_GUIDE: &str = include_str!("../docs/guides/custom-storage-implementation.md");
const THIRD_PARTY_GUIDE: &str = include_str!("../docs/guides/third-party-storage-usage.md");
const MANIFEST: &str = include_str!("../Cargo.toml");
const DEV_INTEGRATION: &str = include_str!("../docs/guides/developer-integration.md");

/// `0.6` from `0.6.0-rc50`.
fn line_of(version: &str) -> String {
    let mut parts = version.split('.');
    format!(
        "{}.{}",
        parts.next().unwrap_or(""),
        parts.next().unwrap_or("")
    )
}

fn manifest_version() -> String {
    let mut in_package = false;
    for l in MANIFEST.lines() {
        let l = l.trim();
        if l.starts_with('[') {
            in_package = l == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(rest) = l.strip_prefix("version")
            && let Some(q) = rest.split('"').nth(1)
        {
            return q.to_string();
        }
    }
    panic!("control: no version line in Cargo.toml");
}

/// Versions that follow `auth-framework = "`, `auth-framework = { version = "`, `cargo add
/// auth-framework@` and the `ghcr.io/ciresnave/auth-framework:` image reference.
fn install_pins(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for l in text.lines() {
        for lead in [
            "auth-framework = \"",
            "auth-framework = { version = \"",
            "cargo add auth-framework@",
            "ghcr.io/ciresnave/auth-framework:",
        ] {
            if let Some(i) = l.find(lead) {
                let rest = &l[i + lead.len()..];
                let v: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
                    .collect();
                if v.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    out.push(v);
                }
            }
        }
    }
    out
}

const UNFALSIFIABLE: &[&str] = &[
    "cve-free",
    "clean security record",
    "no critical vulnerabilities",
    "military-grade",
    // A pass count nobody re-derives: the package holds more test functions than this, but
    // not all run in one feature configuration, and CI is the only source of "passing".
    "1,900+ passing",
];

fn unfalsifiable_hits(text: &str) -> Vec<&'static str> {
    let lower = text.to_ascii_lowercase();
    UNFALSIFIABLE
        .iter()
        .copied()
        .filter(|p| lower.contains(p))
        .collect()
}

#[test]
fn readme_install_pins_are_on_the_current_line() {
    let line = line_of(&manifest_version());
    let pins = install_pins(README);
    assert!(
        pins.len() >= 3,
        "only {} install pins parsed from README.md ({pins:?}) -- the parser is broken, \
         not the README",
        pins.len()
    );
    let stale: Vec<_> = pins.iter().filter(|p| line_of(p) != line).collect();
    assert!(
        stale.is_empty(),
        "README tells readers to install {stale:?}, but this tree is on the {line} line. \
         An older line is a version the reader cannot get this tree's fixes from."
    );
}

#[test]
fn readme_makes_no_unfalsifiable_security_claims() {
    // Control: the matcher must fire on a string that has the phrase, or a
    // pass below means "the matcher is broken".
    assert_eq!(
        unfalsifiable_hits("**CVE-Free**: Clean security record"),
        vec!["cve-free", "clean security record"]
    );
    assert!(
        README.to_ascii_lowercase().contains("security"),
        "control: README.md must be non-empty and readable"
    );
    let hits = unfalsifiable_hits(README);
    assert!(
        hits.is_empty(),
        "README makes claims nothing can falsify: {hits:?}. This repository publishes \
         security advisories, and a pass count nobody re-derives rots the same way a \
         clean record does."
    );
}

#[test]
fn storage_guides_do_not_hardcode_a_newest_stable_version() {
    for (name, guide) in [
        ("custom-storage-implementation.md", CUSTOM_GUIDE),
        ("third-party-storage-usage.md", THIRD_PARTY_GUIDE),
    ] {
        assert!(
            guide.contains("new_with_storage"),
            "control: {name} is expected to discuss new_with_storage"
        );
        let lower = guide.to_ascii_lowercase();
        for phrase in [
            "the newest stable version",
            "unreleased 0.5+ line",
            "wait for a stable 0.5.0",
        ] {
            assert!(
                !lower.contains(phrase),
                "{name} still says {phrase:?}: a hardcoded \"newest\" is a claim about the \
                 registry that the registry changes. Name the line (0.4.x) and what it lacks."
            );
        }
    }
}

#[test]
fn developer_integration_guide_pins_are_on_the_current_line() {
    let line = line_of(&manifest_version());
    let pins = install_pins(DEV_INTEGRATION);
    assert!(
        pins.len() >= 2,
        "only {} install pins parsed from developer-integration.md ({pins:?}) -- the parser is broken, not the guide",
        pins.len()
    );
    let stale: Vec<_> = pins.iter().filter(|p| line_of(p) != line).collect();
    assert!(
        stale.is_empty(),
        "developer-integration.md tells readers to install {stale:?}, but this tree is on the {line} line"
    );
}

/// The first release, on the 0.6 line, that is outside every published advisory
/// (GHSA-9r7g-3hh2-8x65 and GHSA-jr9j-g3xj-q9x8, both fixed in `0.6.0-rc85`). Raise it when a
/// later advisory is published.
const FIRST_UNAFFECTED_RC_ON_0_6: u32 = 85;

/// `73` from `0.6.0-rc73`, `None` for a pin that is not a 0.6 release candidate.
fn rc_number_on_0_6(version: &str) -> Option<u32> {
    version.strip_prefix("0.6.0-rc")?.parse().ok()
}

#[test]
fn install_pins_are_not_inside_a_published_advisory_range() {
    let mut stale = Vec::new();
    for (name, text) in [
        ("README.md", README),
        ("docs/guides/developer-integration.md", DEV_INTEGRATION),
        ("docs/guides/custom-storage-implementation.md", CUSTOM_GUIDE),
        (
            "docs/guides/third-party-storage-usage.md",
            THIRD_PARTY_GUIDE,
        ),
    ] {
        for pin in install_pins(text) {
            if rc_number_on_0_6(&pin).is_some_and(|rc| rc < FIRST_UNAFFECTED_RC_ON_0_6) {
                stale.push(format!("{name}: {pin}"));
            }
        }
    }
    assert!(
        stale.is_empty(),
        "docs tell readers to install a version older than 0.6.0-rc{FIRST_UNAFFECTED_RC_ON_0_6},          which falls inside a published security advisory (see SECURITY.md): {stale:?}"
    );
}

#[test]
fn the_rc_floor_check_can_tell_a_vulnerable_pin() {
    // Control for the test above: it must flag an old pin and accept a new one.
    assert_eq!(rc_number_on_0_6("0.6.0-rc50"), Some(50));
    assert!(rc_number_on_0_6("0.6.0-rc50").is_some_and(|rc| rc < FIRST_UNAFFECTED_RC_ON_0_6));
    assert!(rc_number_on_0_6("0.6.0-rc73").is_some_and(|rc| rc < FIRST_UNAFFECTED_RC_ON_0_6));
    assert!(!rc_number_on_0_6("0.6.0-rc85").is_some_and(|rc| rc < FIRST_UNAFFECTED_RC_ON_0_6));
    assert_eq!(rc_number_on_0_6("0.4.28"), None);
    assert_eq!(rc_number_on_0_6("<tag>"), None);
}

#[test]
fn security_md_lists_every_active_line_as_supported() {
    const SECURITY: &str = include_str!("../SECURITY.md");
    for line in ["0.6.x", "0.5.x", "0.4.x"] {
        let row = SECURITY
            .lines()
            .find(|l| l.starts_with('|') && l.contains(line))
            .unwrap_or_else(|| panic!("SECURITY.md has no supported-versions row for {line}"));
        assert!(
            row.contains(":white_check_mark:"),
            "SECURITY.md does not mark {line} as supported: {row}"
        );
    }
}
