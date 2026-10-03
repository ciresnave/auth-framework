//! **A README badge must not hardcode a verdict it cannot lose.**
//!
//! Measured at `881c696`, before this test existed:
//!
//! ```text
//! [![Security Audit](.../badge/security-audited-green.svg)](SECURITY.md)
//! [![Tests](.../badge/tests-CI%20verified-brightgreen.svg)](docs/.../TESTING_RESULTS.md)
//! ```
//!
//! **Every CI run on `main` was `failure`, back five months** (control: the same
//! query returns 11 successes elsewhere in the repo, so it can see non-failure).
//! And `SECURITY.md` — the file the *green* security badge linked to — opens with
//! *"Important Security Notice: RUSTSEC-2023-0071 … Current Vulnerability Status"*,
//! an advisory with no fix available.
//!
//! ⚠️ **The badge did not merely outrank CI. It contradicted its own link target, in
//! that target's first heading.** A reader who clicks learns the truth; a reader who
//! scans the badges is told the opposite — and badges exist to be scanned.
//!
//! # The rule, and why it is about the COLOUR and not the topic
//!
//! `img.shields.io/badge/...` is the *hardcoded-text* endpoint: whatever it says, it
//! says forever. That is fine for a fact that cannot rot (`license-MIT`, `OAuth-2.1`)
//! and fine for a pointer (`security-policy-blue`). **It is not fine for a VERDICT.**
//!
//! **A hardcoded GREEN badge is a verdict that can never go red.** That is the whole
//! defect: it is not that the claim was wrong, it is that nothing could ever make it
//! wrong. A claim in an authority position is either re-derived on every read, or it
//! should not be there — so the CI badge is now the live workflow-status endpoint,
//! which shows `failing` today because that is true.
//!
//! # What this does NOT cover
//!
//! - **Only `README.md`.** Other docs make status claims and are not checked here.
//! - **Only badges.** Prose claiming "no critical vulnerabilities" passes this test.
//!   Two such bullets were corrected by hand in the same change and nothing guards
//!   them; that is a real gap, stated rather than implied.
//! - The verdict vocabulary is a **floor**, not a census.

/// Hardcoded-text badge endpoint: whatever it renders, it renders forever.
const STATIC_BADGE: &str = "img.shields.io/badge/";

/// Tokens that make a badge a VERDICT rather than a label. Green in any shade is a
/// verdict on its own — it is the colour that means "good".
const VERDICTS: &[&str] = &[
    "green", "audited", "passing", "verified", "success", "secure", "clean",
];

fn badge_urls(readme: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in readme.lines() {
        let l = line.trim();
        if !l.starts_with("[![") {
            continue;
        }
        // [![alt](url)](target) -- take alt and the first parenthesised url
        let Some(alt_end) = l.find("](") else {
            continue;
        };
        let alt = l[3..alt_end].to_string();
        let rest = &l[alt_end + 2..];
        let Some(url_end) = rest.find(')') else {
            continue;
        };
        out.push((alt, rest[..url_end].to_string()));
    }
    out
}

#[test]
fn no_readme_badge_hardcodes_a_verdict() {
    let readme = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
        .expect("control: README.md must be readable, or this test checks nothing");
    let badges = badge_urls(&readme);

    // Non-vacuity: a parser that stops matching makes every assertion below pass
    // having examined nothing, and looks identical to a clean README.
    assert!(
        badges.len() >= 4,
        "only {} badges parsed from README.md — the parser is broken, not the README",
        badges.len()
    );

    let mut bad = Vec::new();
    for (alt, url) in &badges {
        if !url.contains(STATIC_BADGE) {
            continue; // live source: docs.rs, crates.io version, workflow status
        }
        let lower = url.to_ascii_lowercase();
        for v in VERDICTS {
            if lower.contains(v) {
                bad.push(format!("[{alt}] hardcodes the verdict {v:?}: {url}"));
            }
        }
    }

    assert!(
        bad.is_empty(),
        "a README badge hardcodes a verdict it can never lose:\n  {}\n\n\
         A `{}` badge renders whatever text it was given, forever. That is fine for a \
         fact that cannot rot (license, protocol version) and fine for a pointer. It is \
         not fine for a VERDICT: nothing can ever falsify it, so it survives exactly as \
         long as nobody checks.\n\n\
         FIX: use a live source (the workflow-status badge), or make the badge a \
         POINTER to the document that holds the real answer rather than a summary of it.",
        bad.join("\n  "),
        STATIC_BADGE
    );
}
