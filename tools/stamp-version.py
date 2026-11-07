#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Stamp a version onto a change: the one step that touches the files parallel PRs would otherwise collide on.

    python tools/stamp-version.py 0.6.0-rc234 [--dry-run] [--root DIR]
    python tools/stamp-version.py --check [--root DIR]

A PR edits only its own files plus one CHANGELOG fragment, `changelog.d/<topic>.md` (see changelog.d/README.md).
When the PM allocates the version, run this script. It

 1. replaces the current version (read from Cargo.toml) with the new one in every file that carries it
    (the crates' Cargo.toml and Cargo.lock, the OpenAPI files, the SDK manifests, the Python package, the version
    test and the ROADMAP line), in both spellings: `0.6.0-rc218` and the PEP 440 `0.6.0rc218`;
 2. turns the fragments into one `- <version> -- <entry>` line above the newest CHANGELOG entry;
 3. deletes the fragments it used.

`--check` changes nothing: it fails if a file in the list no longer carries the current version, or a file that
carries it is not in the list (a new version-bearing file nobody told this script about). Standard library only;
each file keeps its line endings.
"""
import argparse
import os
import re
import subprocess
import sys

# Files that carry the version in the `X-rcN` spelling, and in the PEP 440 `XrcN` spelling.
DASHED = [
    "Cargo.toml",
    "Cargo.lock",
    "auth-storage-sqlite/Cargo.toml",
    "docs/api/README.md",
    "docs/api/openapi-bundled.yaml",
    "docs/api/openapi-modular.yaml",
    "docs/api/openapi.yaml",
    "docs/api/schemas/health.yaml",
    "docs/ROADMAP.md",
    "sdks/javascript/package-lock.json",
    "sdks/javascript/package.json",
]
PEP440 = [
    "tests/member_versions_match_cargo.rs",
    "sdks/python/pyproject.toml",
    "sdks/python/src/authframework/__init__.py",
]
FRAGMENTS = "changelog.d"
VERSION = re.compile(r"^(\d+\.\d+\.\d+)-rc(\d+)$")


def die(message):
    print(f"stamp-version: {message}", file=sys.stderr)
    sys.exit(2)


def read(path):
    with open(path, "rb") as f:
        raw = f.read().decode("utf-8")
    return raw.replace("\r\n", "\n"), "\r\n" in raw


def write(path, text, crlf):
    with open(path, "wb") as f:
        f.write((text.replace("\n", "\r\n") if crlf else text).encode("utf-8"))


def current_version(root):
    text, _ = read(os.path.join(root, "Cargo.toml"))
    match = re.search(r'^\s*version\s*=\s*"([^"]+)"', text, re.M)
    if not match or not VERSION.match(match.group(1)):
        die("cannot read an `X.Y.Z-rcN` version from Cargo.toml")
    return match.group(1)


def pep440(version):
    return version.replace("-rc", "rc")


def fragments(root):
    directory = os.path.join(root, FRAGMENTS)
    if not os.path.isdir(directory):
        return []
    return [
        os.path.join(directory, name)
        for name in sorted(os.listdir(directory))
        if name.endswith(".md") and name.lower() != "readme.md"
    ]


def entry_from(paths):
    """One CHANGELOG line from the fragments: each is one paragraph; paragraphs are joined with a space."""
    parts = []
    for path in paths:
        text, _ = read(path)
        body = " ".join(line.strip() for line in text.strip().splitlines() if line.strip())
        if not body:
            die(f"{os.path.relpath(path)} is empty")
        parts.append(body)
    return " ".join(parts)


def tracked_files(root):
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True).stdout
    return [p.decode("utf-8") for p in out.split(b"\0") if p]


def check(root):
    version = current_version(root)
    dashed, spelled = version, pep440(version)
    problems = []
    for rel in DASHED + PEP440:
        text, _ = read(os.path.join(root, rel))
        needle = dashed if rel in DASHED else spelled
        if needle not in text:
            problems.append(f"{rel} does not carry {needle}")
    listed = set(DASHED + PEP440 + ["CHANGELOG.md"])
    for rel in tracked_files(root):
        if rel in listed or rel.startswith(("changelog.d/", "target/")):
            continue
        try:
            text, _ = read(os.path.join(root, rel))
        except (OSError, UnicodeDecodeError):
            continue
        if (f'version = "{dashed}"' in text or f'"version": "{dashed}"' in text or f'version = "{spelled}"' in text) and rel.endswith(
            (".toml", ".json", ".py", ".yaml", ".yml")
        ):
            problems.append(f"{rel} carries the version as a version field and is not in this script's list")
    changelog, _ = read(os.path.join(root, "CHANGELOG.md"))
    if f"- {dashed} -- " not in changelog:
        problems.append(f"CHANGELOG.md has no `- {dashed} -- ` entry")
    for problem in problems:
        print("stamp-version: " + problem, file=sys.stderr)
    if problems:
        sys.exit(1)
    print(f"stamp-version: every version-bearing file carries {dashed}")


def stamp(root, new, dry):
    old = current_version(root)
    if not VERSION.match(new):
        die(f"{new!r} is not an `X.Y.Z-rcN` version")
    if new == old:
        die(f"the version is already {old}")
    paths = fragments(root)
    if not paths:
        die("there is no fragment in changelog.d/: nothing to stamp")
    entry = entry_from(paths)
    plan = []
    for rel in DASHED + PEP440:
        a, b = (old, new) if rel in DASHED else (pep440(old), pep440(new))
        text, crlf = read(os.path.join(root, rel))
        if a not in text:
            die(f"{rel} does not carry {a}: this script's file list is out of date")
        plan.append((rel, text.replace(a, b), crlf))
    changelog_path = os.path.join(root, "CHANGELOG.md")
    changelog, crlf = read(changelog_path)
    anchor = f"- {old} -- "
    if changelog.count(anchor) != 1:
        die(f"CHANGELOG.md must hold exactly one `{anchor}` entry (found {changelog.count(anchor)})")
    plan.append(("CHANGELOG.md", changelog.replace(anchor, f"- {new} -- {entry}\n{anchor}"), crlf))
    for rel, _, _ in plan:
        print(f"stamp-version: {'would update' if dry else 'updating'} {rel}")
    if dry:
        print(f"stamp-version: {old} -> {new}, {len(paths)} fragment(s) would be used and deleted")
        return
    for rel, text, crlf in plan:
        write(os.path.join(root, rel), text, crlf)
    for path in paths:
        os.remove(path)
    print(f"stamp-version: {old} -> {new}, {len(paths)} fragment(s) used and deleted")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("version", nargs="?", help="the new version, e.g. 0.6.0-rc234")
    parser.add_argument("--dry-run", action="store_true", help="print what would change and change nothing")
    parser.add_argument("--check", action="store_true", help="verify the file list against the tree and change nothing")
    parser.add_argument("--root", default=".", help="the repository root (default: the current directory)")
    args = parser.parse_args()
    root = os.path.abspath(args.root)
    if args.check:
        check(root)
    elif args.version:
        stamp(root, args.version, args.dry_run)
    else:
        parser.error("give a version or --check")


if __name__ == "__main__":
    main()
