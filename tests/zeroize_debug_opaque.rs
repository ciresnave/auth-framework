//! `Zeroizing<T>` hides its value from `{:?}` only from zeroize 1.9.1 on: 1.9.0 and earlier derive `Debug`
//! and print `Zeroizing("<the secret>")`. Every `Zeroizing<String>` secret field in this crate (TOTP
//! secrets, configuration secrets, hashed client secrets, ...) relies on that, so the manifest must not
//! allow an older zeroize.

const SECRET: &str = "SECRET-MARKER-7f3a9c";

#[test]
fn zeroizing_debug_does_not_print_its_value() {
    let shown = format!("{:?}", zeroize::Zeroizing::new(SECRET.to_string()));
    assert!(
        !shown.contains(SECRET),
        "Zeroizing prints its value: {shown}"
    );
}

#[test]
fn the_manifest_requires_a_zeroize_whose_debug_is_opaque() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("read Cargo.toml");
    let manifest: toml::Value = toml::from_str(&text).expect("parse Cargo.toml");
    let req = manifest["dependencies"]["zeroize"]["version"]
        .as_str()
        .expect("zeroize has a version requirement");
    let parts: Vec<u32> = req
        .trim_start_matches(['^', '='])
        .split('.')
        .map(|p| p.parse().expect("numeric version part"))
        .collect();
    assert!(
        parts.as_slice() >= [1, 9, 1].as_slice(),
        "Cargo.toml allows zeroize {req}; versions before 1.9.1 print Zeroizing values in Debug"
    );
}
