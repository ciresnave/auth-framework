# advisory-ranges

RustSec compares versions with the `semver` crate, which orders prerelease identifiers as **text**: for `0.6.0-rcN`
that is `rc101 < rc126 < rc41 < rc98`. A range such as `>=0.6.0-rc121` therefore patches `rc41..rc98` and misses `rc101..rc114`.

This tool takes the ranges we *mean* (`intended.json`, where `rcN` is a number) and the published versions, and prints the
`patched` / `unaffected` arrays that make `semver` give the same answer: the 0.4.x and 0.5.0 ranges are kept as they are, each
lower-bounded 0.6.0 range becomes exact `=0.6.0-rcN` entries, plus `>=0.6.0` for the stable release. It then re-checks every
entry with `semver` and exits non-zero if any version is classified differently from what was meant.

```
# refresh the published list, regenerate, verify (from the repository root)
curl -s -H "User-Agent: advisory-ranges" "https://crates.io/api/v1/crates/auth-framework/versions?per_page=100" | python -c "import sys,json;print('\n'.join(v['num'] for v in json.load(sys.stdin)['versions']))" > versions.txt && cargo run -q --manifest-path tools/advisory-ranges/Cargo.toml -- versions.txt tools/advisory-ranges/intended.json 0.6.0-rc85,0.6.0-rc114,0.6.0-rc121,0.5.0-rc60
```

`per_page=100` covers today's list; page the request if the crate passes 100 versions.
`versions.example.txt` is the list as of 2026-10-23 plus the planned fix releases.

`intended.json` is `[{"id": "...", "patched": [">= 0.4.7, < 0.5.0-rc1", ">= 0.6.0-rc46"], "unaffected": ["< 0.4.1"]}]`, ranges read numerically.
The optional third argument is a comma-separated list of versions whose verdict is printed under every advisory.
A new rc reads as affected in the published advisory until it is added to `patched`: rerun after each publish.
