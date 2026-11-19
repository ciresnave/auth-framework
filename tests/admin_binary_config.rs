// SPDX-License-Identifier: MIT OR Apache-2.0
//! The admin binary must read the configuration it is given (#442, M12): `--config` and `--env-prefix` were
//! accepted and ignored, and the binary printed that it had loaded the file.
#![cfg(feature = "admin-binary")]

use std::process::Command;

fn admin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_auth-framework-admin"))
}

#[test]
fn a_named_config_file_that_is_missing_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.toml");
    let out = admin()
        .args(["--config", missing.to_str().unwrap(), "cli", "config", "show", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a missing --config must fail, not fall back to defaults; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn the_named_config_file_is_what_the_command_shows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.toml");
    std::fs::write(&path, "issuer = \"https://issuer.m12.example.test\"\n").unwrap();
    let out = admin()
        .args(["--config", path.to_str().unwrap(), "cli", "config", "show", "--format", "json"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("https://issuer.m12.example.test"),
        "the file's issuer must appear; status {:?}, stdout: {stdout}, stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}
