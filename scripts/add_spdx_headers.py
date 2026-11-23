#!/usr/bin/env python3
"""Put `// SPDX-License-Identifier: MIT OR Apache-2.0` on line 1 of every tracked .rs file.

Enumerates from the git index (`git ls-files`), never by walking the disk, so another checkout's
files are never touched. Keeps each file's line ending (CRLF or LF) and does nothing to a file
that already has the header. A file that starts with a shebang gets the header on line 2 (Rust
allows a shebang only on line 1). Run from the repository root; `--check` changes nothing and
exits 1 when any file lacks the header.
"""
import subprocess
import sys

HEADER = "// SPDX-License-Identifier: MIT OR Apache-2.0"


def tracked_rs():
    out = subprocess.run(["git", "ls-files", "-z", "--", "*.rs"], check=True, capture_output=True).stdout
    return [p.decode("utf-8") for p in out.split(b"\0") if p]


def has_header(text):
    lines = text.split("\n", 2)
    first = lines[0].rstrip("\r")
    if first == HEADER:
        return True
    return first.startswith("#!") and len(lines) > 1 and lines[1].rstrip("\r") == HEADER


def main():
    check = "--check" in sys.argv
    files = tracked_rs()
    missing = []
    changed = 0
    for path in files:
        raw = open(path, "rb").read()
        text = raw.decode("utf-8")
        if has_header(text):
            continue
        missing.append(path)
        if check:
            continue
        nl = "\r\n" if "\r\n" in text else "\n"
        if text.startswith("#!"):
            first, _, rest = text.partition("\n")
            new = first + "\n" + HEADER + nl + rest
        else:
            new = HEADER + nl + text
        open(path, "wb").write(new.encode("utf-8"))
        changed += 1
    print(f"{len(files)} tracked .rs files, {len(missing)} without the header, {changed} changed")
    if check and missing:
        for path in missing[:20]:
            print("  missing:", path)
        sys.exit(1)


if __name__ == "__main__":
    main()
