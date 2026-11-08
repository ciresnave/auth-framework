#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check that a pull request carries exactly one CHANGELOG fragment, or bumps the version itself (legacy).

    python tools/check-fragment.py <base-ref>        e.g. origin/main

Compares HEAD with the merge base of <base-ref>. A PR must do exactly one of:

  * add one `changelog.d/<topic>.md` (not README.md) and leave the version alone; or
  * change the version in Cargo.toml itself (a PR opened before fragments existed, or a release-line backport) and
    add no fragment.

Doing both, adding two fragments, or doing neither fails, with the reason. Standard library only.
"""
import re
import subprocess
import sys


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def package_version(cargo_toml):
    """The crate's own `X.Y.Z-rcN` version (a dependency's `version =` never has that shape)."""
    match = re.search(r'^\s*version\s*=\s*"(\d+\.\d+\.\d+-rc\d+)"', cargo_toml, re.M)
    return match.group(1) if match else None


def judge(added_fragments, version_changed):
    """The verdict for a PR: None when it is fine, else the reason."""
    if added_fragments and version_changed:
        return "this PR both bumps the version and adds a fragment: do one (fragments, once the PM stamps the version)"
    if version_changed:
        return None
    if len(added_fragments) == 1:
        return None
    if not added_fragments:
        return "this PR has no CHANGELOG fragment: add changelog.d/<topic>.md (see changelog.d/README.md)"
    return f"this PR adds {len(added_fragments)} fragments ({', '.join(added_fragments)}): exactly one"


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    base = git("merge-base", sys.argv[1], "HEAD").strip()
    added = [
        line.split("\t", 1)[1]
        for line in git("diff", "--name-status", "--diff-filter=A", base, "HEAD").splitlines()
        if re.match(r"^A\tchangelog\.d/[^/]+\.md$", line) and not line.lower().endswith("/readme.md")
    ]
    version_changed = package_version(git("show", f"{base}:Cargo.toml")) != package_version(git("show", "HEAD:Cargo.toml"))
    reason = judge(added, version_changed)
    if reason:
        print("check-fragment: " + reason, file=sys.stderr)
        sys.exit(1)
    print(f"check-fragment: ok ({'version bumped by the PR' if version_changed else added[0]})")


if __name__ == "__main__":
    main()
