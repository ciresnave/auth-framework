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
| SEC-012 (#463) | 79 structs derive `Debug` over a secret-named field | decided `scheduled`: #491 (merged) redacts 11 types; the renames (`GnapTransactionRequest.access_token_request`, `ServiceProviderConfig.change_password_flag`, wire names kept and tested) and the `// sec012: public - ...` marker on `AcmeChallenge.token` are on the day branch; the rest of #463 (the remaining flagged types) waits on coderipper#359/#360 |
| Leave chrono | `chrono` 0.4.45 and `chrono-tz` 0.10.4 unmaintained (RUSTSEC-2026-0543, -0555) | move to `jiff` or `time`; the `deny.toml` ignore EXPIRES 2026-12-17 |
| RUSTSEC-2026-0459 | the 0.5.x `libsqlite3-sys` ignore expires 2026-12-09 | sqlx carrying transact-rs/sqlx#4502 |
| SPDX headers | `chore/spdx-headers` WIP (script and `tests/spdx_headers.rs`), no PR | decision to finish or hand to the PM |
| ARC/MOD, PersistAnt default | queued programmes | none recorded yet |
