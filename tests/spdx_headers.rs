// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every tracked Rust source file starts with the SPDX licence line.
//!
//! The crate is `MIT OR Apache-2.0` (`Cargo.toml`); the CodeRipper `licence` rule asks for an
//! `SPDX-License-Identifier` in the first lines of each source file. Files are enumerated from the git
//! index, so another checkout's files are never read. To fix a failure run `python scripts/add_spdx_headers.py`.

use std::path::Path;
use std::process::Command;

const HEADER: &str = "// SPDX-License-Identifier: MIT OR Apache-2.0";

/// A file passes when line 1 is the header, or line 2 is when line 1 is a shebang.
fn has_header(text: &str) -> bool {
    let mut lines = text.lines();
    match lines.next() {
        Some(first) if first == HEADER => true,
        Some(first) if first.starts_with("#!") => lines.next() == Some(HEADER),
        _ => false,
    }
}

#[test]
fn every_tracked_rust_file_has_the_spdx_header() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let listing = Command::new("git")
        .args(["ls-files", "-z", "--", "*.rs"])
        .current_dir(root)
        .output()
        .expect("git must be on PATH");
    assert!(listing.status.success(), "git ls-files failed: {}", String::from_utf8_lossy(&listing.stderr));
    let names: Vec<String> = listing
        .stdout
        .split(|b| *b == 0)
        .filter(|name| !name.is_empty())
        .map(|name| String::from_utf8(name.to_vec()).expect("a tracked path is UTF-8"))
        .collect();
    assert!(names.len() > 100, "the enumeration found only {} .rs files, so it did not run on the repository", names.len());
    let missing: Vec<&String> = names
        .iter()
        .filter(|name| {
            std::fs::read_to_string(root.join(name)).map(|text| !has_header(&text)).unwrap_or(false)
        })
        .collect();
    assert!(
        missing.is_empty(),
        "{} of {} tracked .rs files lack `{HEADER}` as line 1 (first: {:?}); run `python scripts/add_spdx_headers.py`",
        missing.len(),
        names.len(),
        missing.iter().take(5).collect::<Vec<_>>()
    );
}

#[test]
fn the_header_check_accepts_and_refuses_the_right_shapes() {
    assert!(has_header(&format!("{HEADER}\nfn main() {{}}\n")));
    assert!(has_header(&format!("{HEADER}\r\nfn main() {{}}\r\n")));
    assert!(has_header(&format!("#!/usr/bin/env rust-script\n{HEADER}\nfn main() {{}}\n")));
    assert!(!has_header("fn main() {}\n"));
    assert!(!has_header(&format!("\n{HEADER}\n")), "the header must be line 1");
    assert!(!has_header("// SPDX-License-Identifier: MIT\n"), "the licence expression must match the crate's");
    assert!(!has_header(""));
}
