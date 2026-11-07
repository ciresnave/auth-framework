// SPDX-License-Identifier: MIT OR Apache-2.0
//! Standing design rules from the patent decisions (docs/ROADMAP.md, "Standing design rules", CireSnave
//! 2026-11-07), as source scans so that a later change cannot add a redirect or a subscription silently.
//!
//! * R1 (US 9,397,990): `src/protocols/macaroons.rs` has first-party caveats only.
//! * R2 (US 11,349,844): the continuous-access and CAEP code never redirects on an event.
//! * R3 (US 11,349,844, claim 7): the same code never subscribes to a central service.
//!
//! The scan ignores comments and `#[cfg(test)]` items, because the macaroon test module names
//! third-party caveats in order to prove they are refused. Each rule has a positive control: the same scanner
//! flags a sample that breaks it.

const CAEP_FILES: &[(&str, &str)] = &[
    (
        "src/server/security/caep_continuous_access.rs",
        include_str!("../src/server/security/caep_continuous_access.rs"),
    ),
    (
        "src/protocols/caep.rs",
        include_str!("../src/protocols/caep.rs"),
    ),
];
const MACAROONS: &str = include_str!("../src/protocols/macaroons.rs");

/// Split a source file into `(text, skeleton)`. `text` is the file with comments removed (so a rule can be named
/// in a comment); `skeleton` is `text` with the inside of string and character literals blanked, so that braces
/// and attributes can be found without being fooled by a `{` in a JSON string or a `//` in a URL.
fn lex(source: &str) -> (Vec<u8>, Vec<u8>) {
    let b = source.as_bytes();
    let (mut text, mut skel) = (Vec::new(), Vec::new());
    let mut i = 0;
    let both = |text: &mut Vec<u8>, skel: &mut Vec<u8>, byte: u8| {
        text.push(byte);
        skel.push(byte);
    };
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == b'/' && next == Some(b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && next == Some(b'*') {
            let mut depth = 1;
            i += 2;
            while i < b.len() && depth > 0 {
                match (b[i], b.get(i + 1).copied()) {
                    (b'/', Some(b'*')) => {
                        depth += 1;
                        i += 2;
                    }
                    (b'*', Some(b'/')) => {
                        depth -= 1;
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            both(&mut text, &mut skel, b' ');
        } else if c == b'r' && matches!(next, Some(b'"' | b'#')) {
            // a raw string r"..." or r#"..."#, or just an identifier starting with r
            let mut j = i + 1;
            while b.get(j) == Some(&b'#') {
                j += 1;
            }
            if b.get(j) != Some(&b'"') {
                both(&mut text, &mut skel, c);
                i += 1;
                continue;
            }
            let hashes = j - (i + 1);
            let closer: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', hashes))
                .collect();
            let body = j + 1;
            let end = b[body..]
                .windows(closer.len())
                .position(|w| w == closer.as_slice())
                .map(|p| body + p + closer.len())
                .expect("an unterminated raw string");
            for (k, &byte) in b[i..end].iter().enumerate() {
                text.push(byte);
                let structural = i + k < body || i + k >= end - closer.len() || byte == b'\n';
                skel.push(if structural { byte } else { b' ' });
            }
            i = end;
        } else if c == b'"' {
            both(&mut text, &mut skel, b'"');
            i += 1;
            while i < b.len() && b[i] != b'"' {
                let step = if b[i] == 92u8 { 2 } else { 1 }; // 92 is the backslash
                for &byte in &b[i..(i + step).min(b.len())] {
                    text.push(byte);
                    skel.push(if byte == b'\n' { byte } else { b' ' });
                }
                i += step;
            }
            both(&mut text, &mut skel, b'"');
            i += 1;
        } else if c == b'\'' {
            // a character literal ('x' or '\n'), as opposed to a lifetime ('a)
            let literal_end = if next == Some(92u8) {
                b[i + 2..]
                    .iter()
                    .position(|&x| x == b'\'')
                    .map(|p| i + 2 + p + 1)
            } else if b.get(i + 2) == Some(&b'\'') {
                Some(i + 3)
            } else {
                None
            };
            match literal_end {
                Some(end) => {
                    for &byte in &b[i..end] {
                        text.push(byte);
                        skel.push(if byte == b'\'' { byte } else { b' ' });
                    }
                    i = end;
                }
                None => {
                    both(&mut text, &mut skel, c);
                    i += 1;
                }
            }
        } else {
            both(&mut text, &mut skel, c);
            i += 1;
        }
    }
    (text, skel)
}

/// The code of a source file: comments removed, and every `#[cfg(test)]` item removed, wherever it is, by
/// matching its braces. (A cut at the first `#[cfg(test)]` would let a violation placed after the test module
/// through.) Lower-cased.
fn code_only(source: &str) -> String {
    const MARK: &[u8] = b"#[cfg(test)]";
    let (text, skel) = lex(source);
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(found) = skel[at..].windows(MARK.len()).position(|w| w == MARK) {
        let start = at + found;
        out.extend_from_slice(&text[at..start]);
        let after = start + MARK.len();
        let brace = skel[after..]
            .iter()
            .position(|&c| c == b'{')
            .map(|p| after + p);
        let semicolon = skel[after..]
            .iter()
            .position(|&c| c == b';')
            .map(|p| after + p);
        at = match (brace, semicolon) {
            // `#[cfg(test)] use ...;` has no body
            (b, Some(s)) if b.is_none_or(|b| s < b) => s + 1,
            (Some(b), _) => {
                let mut depth = 0usize;
                let mut end = None;
                for (k, &c) in skel[b..].iter().enumerate() {
                    match c {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = Some(b + k + 1);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                end.expect("a #[cfg(test)] item whose braces never close")
            }
            (None, _) => panic!("a #[cfg(test)] attribute with no item"),
        };
    }
    out.extend_from_slice(&text[at..]);
    String::from_utf8_lossy(&out).to_ascii_lowercase()
}

/// Words that mean "send the user elsewhere because of an event" or "subscribe to a central service". (The
/// word "location" alone is not one: CAEP events carry a geographic location.)
const EVENT_FORBIDDEN: &[&str] = &[
    "redirect",
    "header::location",
    "location_header",
    "see_other",
    "statuscode::found",
    "subscribe_to",
    "subscription",
    "conditional_access",
    "reqwest",
];

/// Words that mean third-party caveats or discharge macaroons.
const MACAROON_FORBIDDEN: &[&str] = &[
    "third_party",
    "thirdparty",
    "discharge",
    "verification_id",
    "introspect",
];

fn violations(code: &str, forbidden: &[&str]) -> Vec<String> {
    forbidden
        .iter()
        .filter(|word| code.contains(*word))
        .map(|word| word.to_string())
        .collect()
}

#[test]
fn r2_r3_events_never_redirect_or_subscribe() {
    for (name, source) in CAEP_FILES {
        let code = code_only(source);
        assert!(
            code.len() > 1000,
            "{name}: the scan saw too little code to mean anything"
        );
        assert_eq!(
            violations(&code, EVENT_FORBIDDEN),
            Vec::<String>::new(),
            "{name} breaks a standing design rule (docs/ROADMAP.md R2/R3, US 11,349,844)"
        );
    }
}

#[test]
fn r1_macaroons_are_first_party_only() {
    let code = code_only(MACAROONS);
    assert!(
        code.contains("add_first_party_caveat"),
        "the scan is not looking at the macaroon code"
    );
    assert_eq!(
        violations(&code, MACAROON_FORBIDDEN),
        Vec::<String>::new(),
        "macaroons.rs breaks standing design rule R1 (docs/ROADMAP.md, US 9,397,990)"
    );
}

#[test]
fn the_scanner_flags_what_it_is_meant_to_flag() {
    let redirecting = code_only("fn on_event() { respond(Redirect::to(idp_url)); }");
    assert_eq!(violations(&redirecting, EVENT_FORBIDDEN), vec!["redirect"]);
    let subscribing = code_only("fn start() { client.subscribe_to(central_service); }");
    assert_eq!(
        violations(&subscribing, EVENT_FORBIDDEN),
        vec!["subscribe_to"]
    );
    let header = code_only("response.headers_mut().insert(header::LOCATION, url);");
    assert_eq!(
        violations(&header, EVENT_FORBIDDEN),
        vec!["header::location"]
    );
    let status = code_only("StatusCode::SEE_OTHER");
    assert_eq!(violations(&status, EVENT_FORBIDDEN), vec!["see_other"]);
    let third_party = code_only("pub fn add_third_party_caveat(&self) {}");
    assert_eq!(
        violations(&third_party, MACAROON_FORBIDDEN),
        vec!["third_party"]
    );
    // comments and test modules are not code
    assert!(violations(&code_only("// never redirect\nfn a() {}"), EVENT_FORBIDDEN).is_empty());
    let test_module = "fn a() {}\n#[cfg(test)]\nmod t { fn third_party() { if x { y } } }";
    assert!(violations(&code_only(test_module), MACAROON_FORBIDDEN).is_empty());
    // ... but code after a test module, and after a `#[cfg(test)] use`, is still scanned
    let after_tests = format!("{test_module}\nfn add_third_party_caveat() {{}}");
    assert_eq!(
        violations(&code_only(&after_tests), MACAROON_FORBIDDEN),
        vec!["third_party"]
    );
    let after_use = "#[cfg(test)]\nuse x::y;\nfn add_third_party_caveat() {}";
    assert_eq!(
        violations(&code_only(after_use), MACAROON_FORBIDDEN),
        vec!["third_party"]
    );
}
