//! See README.md. Usage: advisory-ranges <versions.txt> <intended.json> [version,version,...]

use semver::{Version, VersionReq};
use serde::Deserialize;
use std::process::ExitCode;

#[derive(Deserialize)]
struct Advisory {
    id: String,
    #[serde(default)]
    patched: Vec<String>,
    #[serde(default)]
    unaffected: Vec<String>,
}

/// `(major, minor, patch, rc)` with `rc` a number; a stable release is greater than every rc.
fn key(v: &str) -> (u64, u64, u64, u64) {
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let mut it = core
        .split('.')
        .map(|x| x.trim().parse::<u64>().expect("numeric version part"));
    let (a, b, c) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
    let rc = match pre {
        None => u64::MAX,
        Some("0") => 0,
        Some(p) => p
            .strip_prefix("rc")
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("prerelease {p} is not rcN")),
    };
    (a, b, c, rc)
}

/// Does `req` (comma-separated comparators) match `v` with `rcN` read as a number?
fn numeric_matches(req: &str, v: &str) -> bool {
    let vk = key(v);
    req.split(',').all(|c| {
        let c = c.trim();
        let (op, rest) = ["<=", ">=", "<", ">", "="]
            .iter()
            .find_map(|op| c.strip_prefix(op).map(|r| (*op, r)))
            .unwrap_or_else(|| panic!("comparator {c}"));
        let rk = key(rest.trim());
        match op {
            ">=" => vk >= rk,
            "<=" => vk <= rk,
            ">" => vk > rk,
            "<" => vk < rk,
            _ => vk == rk,
        }
    })
}

fn semver_matches(req: &str, v: &str) -> bool {
    let req = req
        .replace(">= ", ">=")
        .replace("<= ", "<=")
        .replace("< ", "<")
        .replace("> ", ">");
    VersionReq::parse(&req)
        .map(|q| q.matches(&Version::parse(v).expect("version")))
        .unwrap_or(false)
}

fn class(p: &[String], u: &[String], v: &str, numeric: bool) -> &'static str {
    let any = |l: &[String]| {
        l.iter().any(|r| {
            if numeric {
                numeric_matches(r, v)
            } else {
                semver_matches(r, v)
            }
        })
    };
    if any(u) {
        "unaffected"
    } else if any(p) {
        "patched"
    } else {
        "AFFECTED"
    }
}

/// A lower-bounded range inside the 0.6.0 prereleases: what semver cannot order numerically.
fn defines_06_line(req: &str) -> bool {
    req.split(',').any(|c| {
        let c = c.trim();
        let lower = c.starts_with('>') || c.starts_with('=');
        let ver = c.trim_start_matches(['>', '<', '=']).trim();
        lower && ver.starts_with("0.6.0-rc")
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: advisory-ranges <versions.txt> <intended.json> [version,version,...]");
        return ExitCode::from(2);
    }
    let mut versions: Vec<String> = std::fs::read_to_string(&args[1])
        .expect("read versions")
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    versions.sort_by_key(|v| key(v));
    let advisories: Vec<Advisory> =
        serde_json::from_str(&std::fs::read_to_string(&args[2]).expect("read intended"))
            .expect("parse intended");
    let spot: Vec<&str> = args
        .get(3)
        .map(|s| s.split(',').collect())
        .unwrap_or_default();

    let mut failed = false;
    for adv in &advisories {
        let mut p: Vec<String> = adv
            .patched
            .iter()
            .filter(|r| !defines_06_line(r))
            .cloned()
            .collect();
        let mut u: Vec<String> = adv
            .unaffected
            .iter()
            .filter(|r| !defines_06_line(r))
            .cloned()
            .collect();
        for v in versions.iter().filter(|v| v.starts_with("0.6.0-rc")) {
            match class(&adv.patched, &adv.unaffected, v, true) {
                "patched" => p.push(format!("={v}")),
                "unaffected" => u.push(format!("={v}")),
                _ => {}
            }
        }
        if adv.patched.iter().any(|r| defines_06_line(r)) {
            p.push(">=0.6.0".to_string());
        }
        let mut bad = 0;
        for v in &versions {
            let (meant, got) = (
                class(&adv.patched, &adv.unaffected, v, true),
                class(&p, &u, v, false),
            );
            if meant != got {
                bad += 1;
                println!("   !! {v}: meant {meant}, semver gives {got}");
            }
        }
        failed |= bad > 0;
        println!("== {}  (mismatches: {bad})", adv.id);
        println!("patched = {}", serde_json::to_string(&p).unwrap());
        println!("unaffected = {}", serde_json::to_string(&u).unwrap());
        for v in &spot {
            println!("   {v}: {}", class(&p, &u, v, false));
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
