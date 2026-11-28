// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 9635 section 11.16 (client-hosted logo URI): the AS must not fetch a client's `logo_uri`. The only
//! outbound HTTP in the GNAP modules is the `push` delivery in `gnap_push.rs`, which is SSRF-guarded
//! (section 11.34). This test fails the day any other GNAP module takes an HTTP client.

use std::path::Path;

/// Words that name an HTTP client in source. Built by `concat!` so this file does not match itself.
const CLIENT_WORDS: [&str; 5] = [
    concat!("req", "west"),
    concat!("hy", "per::client"),
    concat!("ur", "eq"),
    concat!("sur", "f::"),
    concat!("isa", "hc"),
];

fn mentions_a_client(source: &str) -> Vec<&'static str> {
    CLIENT_WORDS
        .iter()
        .copied()
        .filter(|w| source.contains(w))
        .collect()
}

fn gnap_modules() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocols");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("src/protocols is readable") {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if name.starts_with("gnap") && name.ends_with(".rs") {
            out.push((name, std::fs::read_to_string(&path).unwrap()));
        }
    }
    out.sort();
    out
}

#[test]
fn section_11_16_only_the_push_delivery_makes_outbound_http() {
    let modules = gnap_modules();
    // The scan is over every GNAP module (a population, not a sample).
    assert!(modules.len() >= 10, "found {} modules", modules.len());
    // Positive controls: the scan sees a client where there is one, and not in a clean string.
    let push = modules.iter().find(|(n, _)| n == "gnap_push.rs").unwrap();
    assert!(
        !mentions_a_client(&push.1).is_empty(),
        "gnap_push.rs is the one sender; the scan must see it"
    );
    assert!(mentions_a_client("fn plain() {}").is_empty());
    for (name, source) in &modules {
        if name == "gnap_push.rs" {
            continue;
        }
        let hits = mentions_a_client(source);
        assert!(
            hits.is_empty(),
            "{name} names an HTTP client {hits:?}: a logo_uri must never be fetched (RFC 9635 11.16), and \
             any other outbound call needs the 11.34 guard"
        );
    }
}
