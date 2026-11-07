<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# changelog.d: CHANGELOG fragments

A pull request never edits `CHANGELOG.md`, the version in `Cargo.toml`, `Cargo.lock`, the OpenAPI files, the SDK
manifests or the version test: those are what parallel PRs collide on (every merge moves the version under every other
open PR). It adds **one fragment** instead, `changelog.d/<topic>.md`:

    **Breaking: what changed, in the CHANGELOG's own style.** One paragraph: what, why, what a user must do,
    and the evidence. Plain Markdown; line breaks are joined into one line.

- The text of a fragment becomes `- <version> -- <text>` in `CHANGELOG.md`. Write `**Breaking: ...**` yourself when it
  is breaking (pre-1.0 the second number is the major, so a breaking change is 0.5 -> 0.6).
- Exactly one fragment per PR (the `Changelog fragment` workflow checks it). A PR that still carries its own
  version bump (one opened before this mechanism existed) adds no fragment.
- The PM allocates the version at the gate and runs `python tools/stamp-version.py 0.6.0-rc234`, which sets it in every
  version-bearing file (both spellings), writes the CHANGELOG line and deletes the fragments. `--dry-run` shows the
  plan; `--check` verifies the script's file list against the tree (CI runs it).
- Backports to `release/0.5.x` keep the manual bump for now (that line's CHANGELOG has per-version sections).
