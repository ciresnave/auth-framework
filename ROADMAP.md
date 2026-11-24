<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# auth-framework ROADMAP (register of rows)

**Counts and the G5/G7 rows re-read at `origin/main` a49a0b9f (2026-11-19); other rows keep their 525d4465 (2026-11-16) reading, plus #489 and #491 merged since (04112b33, d2346d06).** The long-form plan, history and rationale are `docs/ROADMAP.md`
and `docs/GNAP_RFC9635_GAP.md`; this file is the short register a lane or the PM reads first. A **done** row names
the command that exercises it (counts measured at 525d4465, run from the repo root with `RUSTC_WRAPPER=`); an **open**
row says what blocks it. Version numbers are the PM's, so none appear here.

## Done (command)

| Row | What | Command (passed at 525d4465; counts re-run at a49a0b9f 2026-11-19: keys:: 68, protocols::gnap 249, tokens:: 51, access_control 5, gnap_conformance and gnap_rs_conformance 1 test each, all ok) |
|---|---|---|
| KM1, KM4 | key model, rotation with overlap, `KeyRing` verifying by `kid` | `cargo test --lib keys::` (68) |
| KM5 | revoke and compromise; a revoked client key kills the grants and tokens bound to it (#474, #483, #487) | `cargo test --lib protocols::gnap` (249) |
| KM6 | `export_jwks` publishes ES256/EdDSA/RSA keys, never a revoked one (#477) | `cargo test --lib tokens::` (51) |
| KM7 | self-signed, CSR, `x5t#S256`, and the GNAP `cert` / `cert#S256` key forms proved by `mtls` (#478, #481, #488) | `cargo test --lib keys::` and `protocols::gnap` |
| G5 slice 1 | the request `access_token` in the RFC 9635 shape (#433) | `cargo test --test gnap_conformance` |
| G8 (part) | RS discovery, RS authentication, introspection, resource set registration (#424, #425, #472) | `cargo test --test gnap_rs_conformance` |
| G9, AC4 | agent principals and delegation; the access-control engine behind `GnapAccessPolicy` (#432, #417-#464) | `cargo test --lib access_control` (5) and `protocols::gnap` |

## Open (what blocks it)

| Row | What is left | Blocked by |
|---|---|---|
| G5 | key rotation; the HTTP routes for polling `too_fast`, PATCH and DELETE | polling `too_fast`, PATCH modify and DELETE grant are service methods on the day branch (`with_poll_wait_secs`, `modify_transaction_with_proof`, `delete_transaction_with_proof`); the surface lane adds the routes. The continue URI naming its transaction is PR #493 (the HTTP routes in the surface lane wait on it) |
| G1-G4, G6, G7, G10 | full RFC types, `httpsig` (G2 needs a crates.io check first; a new dependency is an ASK), interaction, policy and storage, HTTP routes | order of work, not an outside party |
| KM2 | X25519 generation for JWE agreement keys | a `KeyStore` trait change: `LocalKey` is signing-only (design: `docs/KEY_AGREEMENT_DESIGN.md`) |
| KM3 | OS keystore, then TPM/PKCS#11/KMS; a non-exportable key signing in place | no store sets `StoreCapabilities::signs_in_place` yet |
| KM5 (rest) | publishing the revocation (CRL/OCSP input, an event) | not started |
| KM6 (rest) | ES384/RS256 in the ring, cache headers matching the overlap window | not started |
| KM7 (rest) | renewal before expiry; CA key custody through the key store | KM3 |
| KM8 | audit-logging every command, `--export-private`, `verify`, an `auth-framework keys` binary name | not started |
| SEC-012 (#463) | 79 structs derive `Debug` over a secret-named field | decided `scheduled`: #491 (merged) redacts 11 types; **done on the day branch**: the renames (`GnapTransactionRequest.access_token_request`, `ServiceProviderConfig.change_password_flag`, wire names kept and tested) and reasoned `// sec012: public - ...` markers on the seven fields the rule names (acme `token`, `access_token_request`, `authorization_code` grant descriptor, `change_password_flag`, `username_token` / `binary_security_token`, `client_credentials` count-only Debug). `coderipper` 0.47.14 `check SEC-012` at the day branch: 0 Medium, 7 Info waived (it reads committed files, so run it after committing). Close #463 when the PR merges |
| chrono ignores | `chrono` 0.4.45 and `chrono-tz` 0.10.4 unmaintained (RUSTSEC-2026-0543, -0555) | no exit row (pm-platform 2026-11-19): chrono is also pulled in by `sqlx` 0.9.0, `role-system` 1.3.0 and `tokio-cron-scheduler` 0.15.1, so leaving it in our own code would not remove it from `Cargo.lock`. The `deny.toml` ignore expires 2026-12-17; at the check take any release of those three that drops chrono, else renew with a new expiry and the blocking dependency named |
| RUSTSEC-2026-0459 | **done on the day branch**: `sqlx` 0.9.1 (crates.io 2026-11-18) allows `libsqlite3-sys <0.41`; `Cargo.lock` now has sqlx 0.9.1 and libsqlite3-sys 0.40.0 (fixed in >=0.39.0), and the ignores are removed from `deny.toml` and `.cargo/audit.toml`. Still open for the 0.5.x line: `wt-sqlite5` (`fix/libsqlite3-sys-0.5`) | the 11-20 PR merging |
| SPDX headers | `chore/spdx-headers` WIP (script and `tests/spdx_headers.rs`), no PR | decision to finish or hand to the PM |
| ARC/MOD, PersistAnt default | queued programmes | none recorded yet |

## Exit from rc (CireSnave 2026-11-19, EXPECTATIONS 6.30)

`0.6.0-rc` is on rc versions for one reason: **too broken to make public** (rule 6.30, reason 1). This project leaves rc, becomes **AuthAnt at 0.1.0**,
when it is "stable and bug free enough for production use". This lane proposes the list below as that meaning (the PM and CireSnave decide);
a row is **in** when leaving it open would leave a known defect, an unfinished RFC 9635 path the HTTP surface needs, or an unreviewed security finding.

**Estimates are in PRs and days, and are UNMEASURED.** Measured basis only: 36 commits on `origin/main` whose subject names gnap or access-control, 2026-11-06..2026-11-18 (docs, tests and fixes included; `git log origin/main --since=2026-11-06 --until=2026-11-19`), about three a day before the one-PR-per-day rule; no per-row history exists, so each figure is this lane's judgement. One PR per project per day, lanes rotating (project lane 11-20, surface 11-21, access-control 11-22, then repeating), so a lane lands one PR every third day.

| # | Row | In the exit? | Why / what is left | PRs (unmeasured) |
|---|---|---|---|---|
| E1 | G5 rest | in | key rotation (RFC 9635 6.1.1) only: `Authorization: GNAP` parsing (7.2) and proved rotate/revoke already exist in `gnap_as_http.rs` (re-read 11-20); polling, PATCH, DELETE landed 11-20. **E1b (found by the E2 re-read; DONE 11-21 on the day branch):** `httpsig`, `jwsd` and `jws` are wired into the proof dispatch, so `dpop`, `mtls`, `httpsig`, `jwsd` and `jws` all verify end to end; what is left of E1 is key rotation only | 1-2 project |
| E2 | G1 rest | in | error object (3.6), `label`/`flags`, `client` and `user` by reference, `instance_id`; the re-read of `docs/GNAP_RFC9635_GAP.md` against the code is DONE (11-20, 13 rows corrected): what is left is making the service use the `gnap_wire.rs` types it still bypasses (`user`, `client` by reference, `class_id`, label echo) and return `GnapError` instead of `AuthError` strings | 1-2 project |
| E3 | G4 rest | in | slices 2-3 (push delivery, user-code lookup and lockout) are built on `ac-g4-push`, PR day 11-22; still to build: redirect callback, `app`/`user_code_uri`, hints, `hash_method` beyond sha-256 | 1 + 1-2 access-control |
| E4 | G7 routes | in | PATCH/DELETE/polling routes (after E1), RS-first (9.1); axum and actix | 1-2 surface |
| E5 | G10 conformance | in | one test per RFC 9635 section 11 item, over E1-E4 | 1 project |
| E6 | SEC-012 rest (#463) | in, **done in the 11-20 PR** | coderipper#359/#360 are merged and released (0.47.14, 2026-11-19; pm-platform's notice 2026-11-20), so the blocker is gone; the rule at 0.47.14 reports 0 Medium on the day branch (all remaining names waived with a reason). Close #463 after the merge | 0 |
| E7 | Dependabot #31/#154 | done | minimatch in `sdks/javascript/package-lock.json` | fold into any PR |
| E8 | Ignores | in | no `deny.toml` ignore past its expiry without a named blocking dependency: RUSTSEC-2026-0459 is removed in the 11-20 PR (sqlx 0.9.1 carries transact-rs/sqlx#4502; the ignore was due 2026-12-09, inside the window); the chrono pair (2026-12-17) is blocked by `sqlx` 0.9.1, `role-system` 1.3.0 and `tokio-cron-scheduler` 0.15.1 and is a renewal or removal at the check, not work | fold, 0 |
| E9 | SPDX headers | in | `chore/spdx-headers` WIP; a published rename should carry licence headers (provenance rule) | 1 project |
| E10 | Open issues | in | #92 (`decided:fixed`) confirmed and closed; no undecided bug issue. #106 (SAML on Windows) stays a documented limitation | fold, 0 |
| E11 | Installers | in | `scripts/install.sh` / `install.ps1` fixed in the 11-20 PR against v0.6.0-rc217 asset names but not run end to end: run both against a real release | needs one release; fold |
| E13 | #504 release.yml on 0.5.x | in (hotfix, outside the day cap) | the three duplicated `permissions:` blocks in `release.yml` on `release/0.5.x` (invalid YAML, the likely cause of the 0-job Release failures on every 0.5.x-line push); fix is #508 to `release/0.5.x` (11 lines deleted), read the next Release run after it merges, then close #504 | 1 hotfix, 0 day PRs |
| E12 | Observation window | in (proposal) | no new High/Critical finding for 7 days after the last row above; the 7 is this lane's guess, CireSnave sets it | 0 PRs, 7 days |
| X1 | G8 rest (downstream tokens 4, token formats 2.2) | **out** | optional RFC 9767 extension; the RS-facing API is done and tested; nothing existing depends on it | 0.2 |
| X2 | KM2, KM3, KM5 rest, KM6 rest, KM7 rest, KM8 | **out** | new capabilities behind traits (X25519 for JWE, OS/TPM/KMS keystores, CRL/OCSP publication, ES384/RS256 in the ring, renewal, a `keys` binary); none repairs a defect. Revocation is already local and enforced (KM5, #474/#483/#487) | 0.2 |
| X3 | ARC/MOD, PersistAnt default | **out** | architectural programmes; the PersistAnt default changes the storage default, which should be a visible breaking step after 0.1.0 | 0.2 |
| X4 | Rename to AuthAnt | **after** the exit | needs its own plan (crate-name move, a pointer release under the old name `auth-framework`, docs, installers' asset names, board 463) | 1-2 PRs + publish |

**How many versions until the exit?** About **9-11 PRs** (E1-E5, E9 across the three lanes; E6, SEC-012, and RUSTSEC-2026-0459 both land in the 11-20 PR), i.e. 9-11 versions. Earliest date if the lanes work every day: with one project PR a day that is **2026-11-30 or 12-01**; with the lane rotation above (my 5 PRs one in three days, 11-20 to 12-02) it is **2026-12-02**; add the 7-day window and the exit lands **about 2026-12-07 to 2026-12-09**. Nothing external blocks it now. All of these dates are UNMEASURED estimates; first task of the next lane day is E2's re-read, which will tighten E2 and E5.
