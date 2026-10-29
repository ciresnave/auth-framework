//! Every shipped binary answers `--help`, `--version` and a bad flag the way a command-line tool
//! should, and none of them starts serving (or hangs) because of an argument it does not know.
//!
//! Each probe is run with a deadline: a binary that begins serving on any argument is killed and
//! the test fails with that said.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(30);

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(exe: &str, args: &[&str]) -> Run {
    let mut child = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start {exe}: {e}"));
    let started = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if started.elapsed() > DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "{exe} {args:?} was still running after {DEADLINE:?}: it hangs on this argument"
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().unwrap();
    Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// The three probes every binary must pass.
fn basics(exe: &str, name: &str) {
    let version = run(exe, &["--version"]);
    assert_eq!(
        version.code,
        Some(0),
        "{name} --version: {}",
        version.stderr
    );
    assert_eq!(
        version.stdout.trim(),
        format!("{name} {}", env!("CARGO_PKG_VERSION")),
        "{name} --version"
    );

    let short = run(exe, &["-V"]);
    assert_eq!(short.code, Some(0), "{name} -V");
    assert_eq!(short.stdout, version.stdout, "{name} -V");

    let help = run(exe, &["--help"]);
    assert_eq!(help.code, Some(0), "{name} --help: {}", help.stderr);
    assert!(
        help.stdout.contains("Usage"),
        "{name} --help: {}",
        help.stdout
    );

    let bad = run(exe, &["--no-such-flag"]);
    assert!(
        matches!(bad.code, Some(code) if code != 0),
        "{name} accepted an unknown flag (exit {:?})",
        bad.code
    );
    assert!(
        !bad.stderr.trim().is_empty(),
        "{name} rejected an unknown flag without saying so"
    );
}

#[test]
fn security_audit_has_the_basics() {
    basics(env!("CARGO_BIN_EXE_security_audit"), "security_audit");
}

#[cfg(feature = "api-server")]
#[test]
fn the_server_has_the_basics() {
    basics(env!("CARGO_BIN_EXE_auth-framework"), "auth-framework");
}

#[cfg(feature = "api-server")]
#[test]
fn the_test_servers_have_the_basics_and_do_not_serve_unasked() {
    for (exe, name) in [
        (
            env!("CARGO_BIN_EXE_oauth2_test_server"),
            "oauth2_test_server",
        ),
        (env!("CARGO_BIN_EXE_test_oauth2"), "test_oauth2"),
    ] {
        basics(exe, name);
        // No arguments: usage, not a server.
        let bare = run(exe, &[]);
        assert_eq!(
            bare.code,
            Some(0),
            "{name} without arguments: {}",
            bare.stderr
        );
        assert!(bare.stdout.contains("serve"), "{name}: {}", bare.stdout);
    }
}
