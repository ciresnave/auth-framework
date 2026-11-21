# Provenance - non-code assets

Record of where this repository's image assets came from, per CireSnave's provenance rule
(`C:\Projects\CIRESNAVE-EXPECTATIONS.md` section 6.4a, 2026-09-17). Measured at `origin/main` `3d39d991`, 2026-10-24.
Updated 2026-11-21: `auth-framework.png` replaced (see table).

| file | maker / tool | date | licence |
|---|---|---|---|
| `auth-framework.png` (sha256 `83b504714e28e725c84f32517191f7ecba8d99eaa529430d739b8e91aac66001`, 435316 bytes, 1024x1024) | Generated 2026-11-21 by the portfolio PM with ComfyUI 0.43.0 (local) and FLUX.1 [schnell] (`flux1-schnell.safetensors`, clip_l + t5xxl_fp16, `ae.safetensors`; fp8_e4m3fn; euler/simple, 4 steps, cfg 1.0). Candidate 4, seed 44. Prompt: "A bold emblem logo: a stylized steel crab holding a glowing keyhole-shaped shield at its centre, inside a circular gear ring, dark charcoal metal with orange and red accent glow, clean polished logo design on a plain black background, centred and symmetrical, no text, no letters". Picked by CireSnave 2026-11-21: "For AuthFramework, I like the 4th image." Source folder and seeds: `C:\Projects\.lane-state\logo-picks\PROVENANCE.txt`. | 2026-11-21 | FLUX.1 [schnell] is Apache-2.0 per its model card (as recorded by the PM; not re-checked here). |

The previous `auth-framework.png` (Microsoft Image Creator from Designer, personal-use-only terms per CireSnave 2026-10-24; sha256 `23d9023a44fbbef089ab63714679126981a073470777f10728c865dea44552f6`) is removed from the working tree; it remains in git history (first commit `71c55407`), which was not rewritten. The section below describes that old file.

## What the embedded C2PA manifest says

Read-only structural parse of the PNG's `caBX` chunk (40203 bytes; Python `-I`, no third-party libraries; the file was not modified).
Byte searches of the chunk find each of these once or more:

- `c2pa.created` action, `softwareAgent` `Image Creator from Designer`, `when` `2025-08-03T23:48:04Z` (the only timestamp of that form in the chunk),
  `digitalSourceType` `trainedAlgorithmicMedia`.
- Claim generator `Microsoft_Responsible_AI`.
- Signature chain naming `Microsoft Corporation` and issuer `Microsoft SCD Claimants RSA CA`, and a timestamp token from
  `DigiCert SHA256 RSA4096 Timestamp Responder`.
- Three `urn:uuid:` manifest identifiers (not examined further: whether they are separate manifests or one chain was not determined).

**Limit:** the signature and hash assertions were NOT cryptographically validated (no C2PA validator was run), so the manifest is evidence of
what the file claims about itself, not a verified attestation. It does not establish the service's output terms, which were not checked here.
**Control:** the same style of check on vulkane's `vulkan.jpeg` finds the same tool name and a C2PA manifest (recorded in vulkane's `PROVENANCE.md`).

**Method:** first-add commit found with `git log --diff-filter=A -- auth-framework.png` (one result, above); sha256 and size taken from
`git show origin/main:auth-framework.png`. The declared licence of the repository's code is `MIT OR Apache-2.0` (`Cargo.toml`; `LICENSE-MIT`,
`LICENSE-APACHE`); that declaration does not itself license this image.
