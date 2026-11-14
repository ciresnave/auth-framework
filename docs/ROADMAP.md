# AuthFramework Development Roadmap

Last updated: October 7, 2026 (storage encryption at rest, board decision 124)

## Strategic Vision

AuthFramework aims to become the premier authentication and authorization solution in the Rust ecosystem and a strong foundation for a broader multi-language SDK ecosystem.

The project remains guided by the same core principles:

- Open source first
- Security by default
- Full featured by default
- Performance-driven implementation
- Strong developer experience
- Production-ready operations

## Product Direction: Batteries-Included Defaults

AuthFramework should trend toward a default experience where the product largely
"just works" out of the box with minimal configuration and minimal feature
selection burden on end users.

This means the roadmap should optimize for:

- A default crate build that includes the major library capabilities most users expect
- Secure and sensible built-in defaults so the first integration path requires as little setup as possible
- The ability to disable subsystems and integrations for optimization, footprint reduction, or specialized deployments
- Documentation and examples that assume the default build path first, with optimization paths documented second
- Feature gating used primarily for optional optimization or exceptional platform concerns, not as a routine barrier to basic usability

## Current State Snapshot

### Product Status

- Current crate version: `0.6.0-rc286`
- The crate already includes substantial functionality across authentication, authorization, API server, admin UI, monitoring, deployment, storage, and web integrations.
- The project direction is now explicitly shifting toward a batteries-included default build with opt-out feature reduction for optimization-focused users.
- `cargo check --all-features` currently passes.
- Recent targeted reruns passed for the SAML and analytics remediation paths.
- A fresh `cargo test --all-features` rerun should still be completed before release sign-off.
- Rustdoc and clippy should be revalidated as part of final release preparation.
- Phase 3 API Maturity is complete: `UserInfo` deduplicated, `#[deprecated]` legacy aliases in place, and advanced RFC types hidden from root autodiscovery.

### Major Capabilities Already Present

- Core `AuthFramework` library with multiple authentication methods
- OAuth 2.0 / OAuth 2.1 server functionality
- OpenID Connect provider support
- JWT issuance and validation
- API key, password, MFA, passkey, client certificate, hardware token, and SAML support
- REST API server and admin web UI
- Monitoring, observability, audit logging, and threat intelligence modules
- Multi-tenant support
- Storage backends and storage abstraction layers
- Axum, Actix Web, and Warp integration modules
- Python and JavaScript/TypeScript SDK repositories already established

### Delivery and Operations Assets Already Present

- GitHub Actions CI/CD workflow in `.github/workflows/ci-cd.yml`
- GitHub Actions release workflow in `.github/workflows/release.yml`
- Docker assets including `docker/Dockerfile`, `docker-compose.yml`, and `docker-compose.production.yml`
- Cross-platform installation scripts in `scripts/install.sh` and `scripts/install.ps1`
- Deployment, troubleshooting, integration, and configuration documentation in `docs/`
- Working examples for Axum, REST API server, CLI, OAuth2 server flows, performance demos, and deployments in `examples/`

## What Changed Since The Original 2025 Roadmap

The original roadmap was heavily weighted toward foundational work that is now already present in the repository. The roadmap is now updated to focus on stabilization, release quality, API clarity, and developer experience consolidation rather than initial project setup.

### Completed or Substantially Landed

- [x] Axum integration module exists
- [x] Actix Web integration module exists
- [x] Warp integration module exists
- [x] Example applications and integration examples exist
- [x] Storage abstraction layer exists
- [x] PostgreSQL support exists
- [x] Redis support exists
- [x] Migration tooling exists
- [x] Docker Compose assets exist
- [x] Cross-platform release workflow exists
- [x] Binary distribution workflow exists
- [x] Checksum generation exists in the release pipeline
- [x] Installation scripts exist
- [x] Configuration and deployment guides exist
- [x] Troubleshooting guide exists
- [x] Contributing guide exists
- [x] Python SDK repository exists
- [x] JavaScript/TypeScript SDK repository exists

### Release-Readiness Items Recently Closed

- [x] Kubernetes manifests are present under `k8s/`
- [x] Community issue templates are present under `.github/ISSUE_TEMPLATE/`
- [x] A code of conduct is present at `CODE_OF_CONDUCT.md`
- [x] The default feature story is clearly documented as a batteries-included baseline
- [ ] Re-run the full all-features test suite after the latest remediation work
- [ ] Reconfirm rustdoc and clippy status immediately before release
- [x] The public Rust API overlap has been substantially reduced by the DX work tracked in this roadmap

## Phase 1: Stabilization and Developer Experience (Current)

This is the active phase for the project.

### Release Readiness

- [x] Fix the 3 failing SAML tests in `src/api/saml.rs`
- [x] Restore a fully green `cargo test --all-features`
- [x] Reduce all current rustdoc warnings to zero
- [x] Reduce all current clippy warnings to zero across library and tests
- [x] Reconcile stale status/version references in CI and documentation
- [x] Review generated and temporary artifacts so release quality is not diluted by audit debris in the repository root

### Default Feature Experience

- [x] Define the canonical default feature set as the batteries-included product baseline
- [x] Review `Cargo.toml` feature flags and invert any gates that unnecessarily block common out-of-the-box functionality
- [x] Ensure the default crate build enables the common authentication, authorization, storage, and integration capabilities users expect first (`enhanced-rbac`, `postgres-storage`, `openid-connect`, `axum-integration`)
- [x] Preserve opt-out paths for deployment footprint, compile-time, and dependency optimization
- [x] Document which capabilities remain intentionally non-default and why
- [x] Make the minimal-configuration path explicit in docs, examples, and quick starts

### Developer Experience and API Consolidation

This is now a first-class workstream, not a secondary polish task.

#### Landed Today

- [x] Add API orientation guidance to `README.md`, `src/lib.rs`, and `src/prelude.rs`
- [x] Add canonical root aliases to reduce naming ambiguity:
  - `ModularAuthFramework`
  - `AppConfigBuilder`
  - `LayeredConfigBuilder`
  - `CoreUserInfo`
- [x] Expose a canonical `SessionManager` export alongside the legacy alias
- [x] Begin splitting the oversized `AuthFramework` surface into grouped accessors:
  - `auth.users()`
  - `auth.sessions()`
  - `auth.tokens()`
  - `auth.authorization()`

#### Next DX Tasks

- [x] Add grouped accessors for MFA, monitoring, audit, and administrative operations
  - `auth.mfa()`
  - `auth.monitoring()`
  - `auth.audit()`
  - `auth.admin()`
- [x] Document the canonical entry path for new users: `AuthFramework` + `prelude`
- [x] Create a deprecation plan for duplicate builder names and legacy aliases
- [x] Consolidate or clearly namespace duplicate `UserInfo`-style types across core, API, integration, and OIDC layers
- [x] Reduce module overlap between `auth`, `auth_modular`, and `authentication`
- [x] Audit function naming for consistency inside grouped accessors so common tasks use shorter, context-appropriate names
- [x] Ensure examples use the preferred public API rather than older or noisier entry points
- [x] Align the preferred public API with the default enabled feature set so the documented path works without manual feature hunting

### Documentation and Onboarding

- [x] Deployment guide exists
- [x] Troubleshooting guide exists
- [x] Developer integration guides exist
- [x] Administrator setup guide exists
- [x] API reference assets exist
- [x] Consolidate overlapping docs so the primary onboarding path is obvious
- [x] Add a true "start here" path for Rust library consumers distinct from binary/server deployment docs
- [x] Update examples and top-level docs to consistently use the new grouped accessors where appropriate
- [x] Make the default install and default crate-consumption path the primary documented path everywhere
- [x] Document optimization and feature-pruning as a secondary advanced path

### Web Framework and Integration Hardening

- [x] Axum integration exists
- [x] Actix Web integration exists
- [x] Warp integration exists
- [x] Make Axum integration the best-documented and most ergonomic default path
- [x] Add stronger framework-specific examples backed by real storage where possible
- [x] Verify feature-gated integrations compile and test cleanly in CI on every release path
- [x] Decide which framework integrations are part of the default batteries-included experience versus optimization-only opt-ins

## Phase 2: Platform Hardening and Ecosystem Expansion

This phase begins once the release-readiness and DX stabilization work above is complete.

### Security and Operations

- [ ] `release/0.5.x` does not pass `cargo clippy --all-targets --all-features -- -D warnings` (measured 2026-11-03 at origin/release/0.5.x
      7743e1e5 with rust:latest, 1.99: 14 errors in the lib, 20 with the lib tests). Main is clean (#103, #120, rc174), so the fixes
      were never taken back. Sites: `src/admin/web.rs` (unwrap in tests at 1627-1699, MutexGuard held across an await at 1693,
      collapsible `if` at 373, redundant field name at 967), `src/admin/cli.rs` 721-738 (literals in format strings),
      `src/admin/tui.rs:325`, `src/api/saml.rs:675`, `src/methods/ldap.rs:354`, `src/methods/mod.rs:379`,
      `src/methods/enhanced_device/mod.rs:164`, `src/storage/unified.rs:224`, `src/security/enhanced_crypto.rs:238`,
      `src/server/security/x509_signing.rs:865`. Either port main's lint fixes to the branch or stop linting `--all-features` there.
- [x] Adaptive MFA and risk-based authentication improvements
- [x] HSM and signing-key integration hardening
- [x] Expanded audit-log querying and operator workflows
- [x] Production-grade admin dashboard configuration editing and safer live-reload flows
- [ ] `Secret<String>` newtype whose `Debug` redacts, so that secrecy lives in the type and not in a field name. The derived-`Debug`
      audit (`tests/debug_field_review.txt`) is a reviewed-field-name list: it makes a human decide for every plain `String` field
      of a `Debug`-deriving type, but it still depends on names; a wrapper type removes the decision.
- [ ] Verify what `Debug` prints for the third-party types our structs hold: `reqwest::Client`, `sqlx` pools and connect options,
      `tokio_postgres::Config`, and `redis` versions before 1.7.1 (1.7.1 redacts the password). Only `jsonwebtoken` 9.3 / 10.x / 11.1
      and `redis` 1.7.1 have been read so far.
- [x] Scheduled `cargo deny` / `cargo audit` on every maintained release branch (weekly and on push; done in 0.6.0-rc110 as `security-audit-branches.yml`): a new advisory reached
      `release/0.4.x` and `release/0.5.x` only when an unrelated PR ran CI, because lockfile refreshes land on `main` alone.
- [ ] The container audit (`[container_ok]` in `tests/debug_field_review.txt`) decides by field NAME, so a new `HashMap<String, Value>` named like an
      existing entry (`metadata`, `parameters`, `custom`, ...) passes without a look at what it holds. Replace the name list with a per-type decision
      (`path:Type:field | reason`) for the free-form bags, and give maps keyed by identifiers a typed key (`SessionId`, `TokenId`) whose `Debug` is
      opaque, so the type system rather than a review list keeps them out of logs.
- [ ] Error-message variants (`AuthError`, `StorageError`, `DatabaseError`, `ConfigError`, ...) are allowed in the derived-`Debug` audit as
      "diagnostic text", but an error is only as clean as the code that builds it: grep every construction site of the allowed variants
      for interpolated secret-typed values (`format!("...{token}")`, a database error that carries a connection string) and fix or
      justify each one.
- [ ] The derived-`Debug` audit scans `String`, `Vec<u8>`, `Vec<String>`, `Option` of those, `Box<str>` and `Arc<str>` fields; values inside
      `HashMap<String, String>` fields (user attributes, headers) are not scanned.

### Dependency Freshness (item 63e)

CireSnave's standing rule: *"my most-recent-versions-at-all-times rule is a
goal to work toward. If we can't bump a dependency right now, we need to
ensure that it is noted in the roadmap for the involved project(s) so they
don't forget."* The 43 semver-compatible bumps landed via #57. These 28
require a manual major/minor-incompatible version bump and have not been
evaluated or scheduled -- tracked here so they aren't lost, not because a
blocker has been fully diagnosed for each one. Measured 2026-09-25 via
`cargo outdated --root-deps-only`; versions will have moved further by the
time anyone picks one up, so re-check before acting on any entry.

**RustCrypto-family, likely need to move together** (shared trait
dependencies like `digest`/`crypto-common` typically force coordinated
bumps within this ecosystem -- not yet confirmed for this specific set):
- [ ] `aes` 0.8.4 -> 0.9.3
- [ ] `aes-gcm` 0.10.3 -> 0.11.1
- [ ] `argon2` 0.5.3 -> 0.6.0
- [ ] `chacha20poly1305` 0.10.1 -> 0.11.0
- [ ] `ed25519-dalek` 2.2.0 -> 3.0.0
- [ ] `hmac` 0.12.1 -> 0.13.0
- [ ] `md-5` 0.10.6 -> 0.11.0
- [ ] `p256` 0.13.2 -> 0.14.0
- [ ] `p384` 0.13.1 -> 0.14.0
- [ ] `rand_core` 0.6.4 -> 0.10.1 (large jump, spans several majors)
- [ ] `sha2` 0.10.9 -> 0.11.0
- [ ] `x25519-dalek` 2.0.1 -> 3.0.0

**OpenTelemetry family:** resolved by removal. No code in this crate called
`opentelemetry`, `opentelemetry-otlp`, `opentelemetry-prometheus`,
`opentelemetry_sdk` or `tracing-opentelemetry`, so the five unused optional
dependencies were removed instead of bumped; `enhanced-observability` now only
enables the built-in `observability` module.

**Independent, each needs its own evaluation:**
- [ ] `askama` 0.15.6 -> 0.16.1
- [ ] `axum-test` 19.1.1 -> 21.1.0 (dev-dependency only)
- [ ] `base64` 0.22.1 -> 0.23.1
- [ ] `bergshamra` 0.3.1 -> 0.9.1 (six minor versions in one jump -- worth scrutiny before attempting)
- [ ] `dirs` 6.0.0 -> 7.0.0
- [ ] `maxminddb` 0.27.3 -> 0.32.0
- [ ] `quick-xml` 0.41.0 -> 0.42.0
- [ ] `sqlx` 0.8.6 -> 0.9.0 -- **known specific blocker**: 0.9.0 obsoletes the `runtime-tokio-rustls` feature this crate uses (`cargo-outdated`'s own warning), so this needs a feature-name change alongside the version bump, not just a `Cargo.toml` edit.
- [ ] `sysinfo` 0.32.1 -> 0.39.6 (seven minor versions in one jump -- worth scrutiny before attempting)
- [ ] `toml` 0.9.12+spec-1.1.0 -> 1.1.6+spec-1.1.0 (major version jump)
- [ ] `zip` 2.4.2 -> 8.6.0 (six major versions in one jump -- treat as a from-scratch compatibility review, not an upgrade)

**`jsonwebtoken` -- deliberately excluded from this list.** CireSnave,
verbatim: *"[jsonwebtoken] should not be pushed forward just to satisfy my
rule but, instead, we should continue to look for other solutions that
solve the RSA problem."* Its `rust_crypto` feature bundles in `rsa`
unconditionally (confirmed against both 10.3.0 and 10.4.0's own
`Cargo.toml`), which is the mechanism behind RUSTSEC-2023-0071's continued
reachability in this crate. A version bump on its own does not change
that -- the crate exposes an alternative `aws_lc_rs` crypto backend that
does not depend on `rsa` at all, but switching to it is a separate,
larger change (different build toolchain requirements, and it would need
to replace `rust_crypto` crate-wide rather than coexist with it) that has
not been scoped or scheduled. Continue looking for a real fix on this
path rather than bumping the version number.

**Third-party versions held back by our own dependencies** (measured 2026-11-06 at 3156a62c with `cargo tree --locked -i <crate> -e normal --all-features`
and crates.io; both are direct dependencies of this crate, `Cargo.toml` lines 227 and 268):

- [ ] `totp-lite` 2.0.1 (already the newest release) pulls `hmac` 0.12.1 and `sha1` 0.10.7, while the tree also carries `hmac` 0.13.0 and `sha1` 0.11.0 for
  other users. Options: an in-crate RFC 6238 implementation on the current `hmac` and `sha1` (with the RFC 6238 test vectors), or drop the crate. Replacement
  crates are an ASK.
- [ ] `tokio-cron-scheduler` 0.15.1 (already the newest release) pulls `croner` 3.0.1 (newest 4.0.3), `strum` 0.27.2 (0.28.0 is also in the tree) and
  `derive_builder` 0.20.2, itself the newest release, which pins `darling` 0.20.11 (newest 0.24.1). Options: replace it, or make it optional. Not
  gated by a feature today.
- [ ] `aes-gcm` 0.10.3 -> 0.11.1 (row above) also moves `aes` 0.8.4, `aead` 0.5.2, `ctr` 0.9.2, `ghash` 0.5.1, `polyval` 0.6.2 and `universal-hash` 0.5.1.

### Storage and Scaling

- [x] SQLite support in a separate crate for lightweight deployments (`auth-storage-sqlite`, a workspace member that carries the root version)
- [ ] Optional third-party or community-maintained SurrealDB integration
- [x] More explicit performance benchmarking and regression gates for auth hot paths
- [x] Improved distributed coordination and large-scale deployment guidance
- [x] Define which storage backends should be enabled by default versus left optional for footprint or platform reasons
- [x] Storage encryption at rest for the KV layer, on by default, fail-closed
      (`StorageEncryption`/`EncryptedStorage`, board decision 124)
- [ ] **Replace the env/file encryption key source with something better.**
      Per board decision 124 (CireSnave): "env/file keys are fine for right
      now but ensure it is noted in the roadmap that we will need to replace
      that with something better." `EnvKeyProvider` is a deliberately narrow
      starting point -- an attacker with read access to the process
      environment or key file can decrypt everything it protects. The
      `KeyProvider` trait exists specifically so a KMS-backed (AWS
      KMS/Vault/age) provider can replace it without changing
      `StorageEncryption` or `EncryptedStorage` at all. Not yet scheduled.
- [ ] Extend storage-at-rest encryption to core token/session storage.
      Today's `EncryptedStorage` only covers the generic KV layer
      (`store_kv`/`get_kv`); `store_token`/`store_session` and friends go
      through each backend's own typed columns and are not covered.
      **Designed, not built:** `docs/architecture/ADR-011-token-session-encryption-at-rest.md`
      (proposed: seal whole records above the backend in the KV namespace with
      blind-indexed lookups, no `AuthStorage` trait change; aligned with
      PersistAnt's `kv.*` capabilities; prerequisites #144, #145, #146, #147, #148;
      decisions D-E1..D-E8 await CireSnave/PM). Stable-release MUST.

### Tracked Issues (open on GitHub)

Measured at `origin/main` 77f7f757 (0.6.0-rc126) unless a row says otherwise. Size: S = a few hours, M = a day or two,
L = a design decision plus several PRs. Priority: P1 = correctness or security of a shipped path, P2 = quality or
operations, P3 = hygiene, Blocked = waiting on someone else.

| Issue | What | Size | Priority | State at 77f7f757 |
| --- | --- | --- | --- | --- |
| #147 | PostgreSQL `list_user_sessions` selects `last_activity`, `ip_address`, `user_agent`, which `migrate()` never creates; four incompatible `sessions` schemas in the tree | M | P1 | Fixed at rc181: the column mismatch at rc162 (`b1a05516`), the schema split at rc181 (`migrate()` owns `sessions`; CLI migration 3 runs its `SESSIONS_SCHEMA_SQL`, migration 6 reconciles old databases; `tests/postgres_sessions_schema.rs`). Close the issue when rc181 is on main |
| #144 | `get_token` / `get_token_by_access_token` return expired tokens on SQLite and both in-memory backends; SQLite also returns expired sessions | M | P1 | Fixed at rc161 (#6acd121e): every backend filters an expired token and session on read; `tests/storage_expired_tokens.rs` runs Memory, DashMap, SQLite, PersistAnt and Postgres (Memory, DashMap and SQLite re-run at 7acc3c27: pass). Issue closed |
| #99 | JARM JWE AES-256-GCM encrypt and decrypt pass no AAD, so the protected header is unauthenticated (RFC 7516 5.1/5.2 step 14) | S | P1 | Fixed at rc157 (#316, `457dad43`): `encrypt_payload` / `decrypt_rsa_oaep_a256gcm` pass the base64url protected header as AAD; `test_jwe_protected_header_is_authenticated` and `test_jwe_content_decrypts_with_the_header_as_aad` (under `rsa-private-key-ops`, which CI's `--all-features` Coverage run enables). Issue closed |
| #92 | The only rate limiter on the wired OAuth2 / introspection routes is per IP, not per client | M | P1 | Partly done (rc165): an authenticated client has its own bucket (`src/api/client_rate_limit.rs`, used at the token endpoint, the refresh grant, `/oauth/revoke` (rc206) and introspection). `register_client` (bearer token) and `authorize`/PAR/device/CIBA (the client is named, not authenticated) are not counted by design. The PM acknowledged hand-rolled limiting on 2026-11-08 (no Ant limiter exists yet) on one condition: callers reach the limiter only through the `RateLimiter` trait (`distributed::rate_limiting`: check by key, answer allow or deny with a retry-after), so an Ant limiter can replace it without touching a caller. Done: the trait, `DistributedRateLimiter` implements it, and the per-client check goes through it. `FapiManager` is A16 |
| #91 | No audit-trail record of client_credentials, introspection or revocation | M | P1 | Introspection and revocation are recorded (#328, rc163); the `client_credentials` grant of `OAuth2Server` is recorded when an audit storage is given with `with_audit_storage` (rc191); `AuthFramework::audit_storage()` and `OidcProvider::with_audit_storage` (A14, rc192) let the OIDC provider's own `OAuth2Server` write to the framework's trail; a caller who builds either must pass it, nothing wires it by default. Issue #91 closed 2026-11-02 with that stated (main 01f08e77) |
| #90 | Three divergent client-credential registries: in-memory `EnhancedTokenStorage`, KV `oauth2_client:` with the secret compared in plaintext, and the token-exchange client store | L | P1 | Done: secrets are Argon2id hashes (#318), `ClientRegistry` and the introspection service moved onto `oauth2_client:` (#333), the unwired introspection module is deleted (rc178); `EnhancedTokenStorage` stays as `OAuth2Server`'s own in-process registry, documented as such |
| #148 | Redis backend on the production path (`storage/core.rs`) uses `KEYS`, leaves the per-user token set without EXPIRE and writes in several round trips | M | P2 | Fixed at rc182: `SCAN` replaces `KEYS`, `store_token` is one script that also sets the user set's TTL to its longest member, `delete_token` is one transaction (`tests/redis_core_storage.rs`; CI's test job already has a Redis service). Close the issue when rc182 is on main |
| #120 | Clippy errors under `cli,admin-binary,postgres-storage,redis-storage,sqlite-storage` | S | P2 | Fixed (rc174, #346): clippy is clean under `--all-features`, which CI now runs; closed with evidence |
| #103 | `cargo clippy --all-targets --all-features -D warnings` fails; decide which feature sets CI lints, then fix to that list | M | P2 | Fixed (rc174, #346): CI lints `--all-features` as well as the feature list, and both are clean; closed with evidence |
| #116 | No test proves the TOTP facade (`AuthFramework`) and the modular `TotpManager` verify each other's secrets | S | P2 | Fixed (rc179, #347): `tests/totp_cross_verify.rs`, 4 tests; closed with evidence |
| #18 | Audit tests read source paths that moved, and every read failure means "no problem found" | S | P3 | Fixed: `final_comprehensive_security_audit.rs` (rc151) and `critical_security_detection.rs` (rc166) fail on a moved or unreadable subject; `code_quality_audit.rs` fails on its findings. Closed with evidence (2026-10-30) |
| #106 | SAML on Windows: `kryptering` hard-gates its `aws-lc` backend to Linux and macOS | - | Blocked | Upstream (`kryptering`); CireSnave's ruling 2026-10-04: accept for now, keep looking |
| #282 | `cargo check --no-default-features` fails: bin `oauth2_test_server` has no `required-features` | S | P2 | Fixed by the PR that adds this table: the bin, one example and five tests that import `auth_framework::api` declare `required-features = ["api-server"]`; `cargo check --locked --no-default-features --all-targets` finishes |

Closed with evidence when this table was written: #93 (`user_profile` round-trips on Memory, DashMap and SQLite; PostgreSQL has the
column since `ALTER TABLE ... ADD COLUMN IF NOT EXISTS user_profile JSONB`), #87 (`test_audit_panics_in_source` now skips
`#[cfg(test)]` items and no longer needs `#[ignore]`), #13 (the storage guides open with a version notice and the README no
longer names a `:latest` tag).

#### CodeRipper portfolio findings (advisory)

Read from the `portfolio` job on the `main` run for 9abbced8 (run 40040499570; CodeRipper pinned at a48fc6cc; 794 findings, job exit 1). The job is advisory and not a required check. One row per failing rule; owner is the auth-framework lane.

| Rule | Count | Severity | What the log says | Owner | State |
| --- | --- | --- | --- | --- | --- |
| reachability | 655 | Medium | Public items with zero callers inside this crate (for example `check_compliance`, `ApiVersion`, `log_message`); a library's public API is called from outside, so each needs a decision: keep as API, or remove | auth-framework lane | Closed as evidence only (PM 2026-11-05). Pilot of 22 rows (`src/analytics`, per-item `git grep -w`, f07e1aeb): 15 false positives (type reached through a field, return or variant), 4 test-only callers, 2 checker misses, 1 true zero (a pub fn of a pub module, no named reason to remove). A library's public API with no in-crate caller is expected, not dead; removing any item is a breaking change the PM rules on one at a time. Evidence: `.lane-state/e8-reachability-evidence.md`; the checker fix is CodeRipper E8. Do not redo the triage |
| SEC-002 | 98 | High | gitleaks hits over git history: 64 `generic-api-key`, 21 `private-key`, 10 `jwt`, 3 `curl-auth-header`. **Waived by path (21 hits in files absent from main, plus the fixture):** root `private.pem` and `private_pkcs8.pem` (commit 71c55407, v0.4.0 to v0.4.5; generated by the README's `openssl genrsa` example and committed by accident; **present in the published 0.4.0 crate** (listed in the .crate tarball from static.crates.io, checked 2026-11-06; absent from 0.4.2 and 0.4.5), not referenced by current code, not on main: public and unused, so burned, never use them, no rotation; an earlier version of this row said they were absent from 0.4.0, which was wrong); `backup-before-enhancements-20251004-080500/`, `backup-working-build-20251004-075914/` and `README.md.backup` (copies of old sources, absent from main); `tests/fixtures/test_private_key.pem` (fixture). History rewrites are CireSnave's decision, none made. **Classified at f07e1aeb (gitleaks 8 over 995 commits with `--redact`, 108 hits now; the 98 above came from an earlier run):** 23 hits are in the waived paths. The other 85 were read per line from the blob at the hit's commit, with secrets masked, and none is a credential that protects anything: (a) 4 hits are two RSA test keys in the `#[cfg(test)]` module of `advanced_token_exchange.rs` (constants `INTROSPECT_TEST_PRIVATE_KEY_PEM` and `INTROSPECT_ATTACKER_PRIVATE_KEY_PEM`, 1210-byte DER, still on main); (b) 1 hit is `tests/server_tests.rs.disabled`, absent from main, whose key body has the same hash as the waived `private_pkcs8.pem`; (c) 9 hits are PEM headers followed by prose or a truncated body (at most 70 characters, a key needs over 1000); (d) 11 JWT hits are documentation samples with an empty signature, test tokens with a non-HS256-length signature, or the known-answer token in `secure_jwt.rs`, which is checked against a secret written beside it in the test; (e) the rest are named placeholders: `SECRET-MARKER-7f3a9c`, the RFC 5849 example credentials in `oauth1.rs`, `abc123def456`, `secret_xyz789`, `test_secret_...`, and `curl` examples with a `Bearer` placeholder. Not provable from the repo: `ak_5421f1778ec...` in `docs/ENDPOINTS_IMPLEMENTATION_COMPLETE.md` (a key printed by a dev run, file absent from main) and the literal `dev_secret` in `examples/debug_server.rs` before it took the secret from the environment (still in history); neither is known to have protected a deployment. History rewrites remain CireSnave's decision, none made. A real secret is a security fix and rotation notice to the PM, not a row | auth-framework lane | Classified, no live secret found (rc189); waived per file with reasons in `.coderipper.toml` (rc226: 48 entries for the 93 findings of CI run 42276945357 at 4eb8f99d; CodeRipper scans every remote branch and tag, honours no in-repo allow comment, and the file waiver is its only answer) |
| lint-suppression | 33 | Low | `allow(...)` with no reason (`deprecated`, `clippy::result_large_err`, `unused_macros`, `dead_code` and others) | auth-framework lane | Done (rc185): every `allow` carries a `reason`; one unneeded allow removed |
| unused-return-values | 4 | Low | A call whose return value is dropped at one of its many call sites (for example `write` at `src/server/security/x509_signing.rs:3630`) | auth-framework lane | Done (rc186): each dropped result is discarded with `let _ =` |
| licence | 3 | Medium | `LICENSE-APACHE` and `LICENSE-MIT` name a person as copyright holder; 404 of 404 source files carry no SPDX identifier | auth-framework lane | Open; the copyright holder is CireSnave's decision |
| version-consistency | 1 | High | `auth-storage-sqlite`, `sdks/python` (0.6.0rc64) and `sdks/javascript` (0.6.0-rc108) trailed the crate version | auth-framework lane | Fixed in this PR: all three at the root version (PEP 440 form for Python); `tests/member_versions_match_cargo.rs` keeps them there. PM ruling 2026-10-24: one version per project |


### Spec-to-roadmap audit (2026-10-24)

Rows from claims in the docs (`SECURITY.md`, `COMPATIBILITY.md`, `docs/api/REST_API_DESIGN_RATIONALE.md`, `docs/DEPLOYMENT_GUIDE.md`)
that the roadmap did not carry. Measured at `origin/main` 8e12a8b3. State: open / held (by whom) / done (PR). None of these is started by the PR that adds them.

| Row | Source | What | State |
| --- | --- | --- | --- |
| A1 | `SECURITY.md` "SHA-1 Usage" | Configurable digest/signature algorithm preference in the SAML handler ("a future release will add...") so SHA-256 can be required | Done (rc211): opt-in `SamlAlgorithmPolicy { allow_sha1: false }` on `SamlTrustAnchors`, judged on the signature that verified; the default still accepts SHA-1 (flipping it is a later Breaking decision, PM) |
| A2 | `SECURITY.md` "Protocol Stubs" | GNAP: validate DPoP proofs and bind the key. The `dpop` proof method was accepted by name and checked nothing else | Done (rc209): `handle_transaction_with_proof` and `continue_transaction_with_proof` verify the DPoP proof against the named key; `httpsig`, `mtls` and `jws` are refused as not supported until they can be verified. Follow-up, Open: verify `httpsig` (RFC 9421), `mtls` and `jws`. Hardened at rc217: an access policy decides what a token carries (default deny), a client key is required, a finish-method transaction needs its one-time `interact_ref`, and a token is stored before it is returned |
| A3 | `SECURITY.md` "Protocol Stubs" | WS-Trust: issued tokens are held in memory only, lost on restart and unshared across instances; persist them through the `AuthStorage` KV layer | Done (rc212, PM to confirm number): `SecurityTokenService::with_storage` and `process_request_stored` persist Issue and Renew, delete on Cancel and read on Validate and Renew (`wstrust:token:<id>`, TTL = token lifetime); `process_request` is unchanged. `tests/wstrust_persistence_tests.rs`, 8 tests. Follow-up, Open: the issue/validate flow is not behind any HTTP route, so nothing in the crate calls the stored entry point yet |
| A4 | `SECURITY.md` "Protocol Stubs" | UMA 2.0: the claims-gathering interaction flow is missing | Slice 1 Done (rc216): `request_rpt` no longer takes a claims argument; a resource set with `required_claims` is refused (`need_info`, ticket kept) until claims are gathered by the service. Open, ordinary feature PRs: structured `NeedInfo`; `begin_claims_interaction` / `complete_claims_interaction` (redirect allow-list, state, single use, claims bound to the ticket); register the issued RPT so it introspects |
| A5 | `SECURITY.md` "Protocol Stubs" | SAML assertions: the doc says no full C14N or signature-chain validation. Measured at f4c512fd: `xml_signature.rs` is a shim; `dsig.rs` verifies on `bergshamra` (real C14N, every reference digest recomputed, pinned certificate, no chain building). Sentence corrected, and the SHA-1 paragraph with it | Done (rc188) |
| A6 | `SECURITY.md` vs `COMPATIBILITY.md` | Kerberos: `SECURITY.md` says AP-REQ validation checks ASN.1 tags only and needs a KDC; `COMPATIBILITY.md` says "Full". `KerberosConfig.kdc_addresses` exists (`kerberos.rs:969`). One of the two docs is wrong; measure and reconcile | Done (rc187), measured at `kerberos.rs` `validate_ap_req` (main 84baa504+): it decrypts the ticket (keytab key) and authenticator (session key), verifies the HMAC, matches realm and client name, and checks expiry, skew and replay; no KDC is contacted. `SECURITY.md` was wrong; `COMPATIBILITY.md` now says Substantial |
| A7 | `COMPATIBILITY.md` "Deprecated" | `AppConfigBuilder` and `ModularAuthFramework` are documented as `#[deprecated]` but `src/lib.rs:328` and `:334` carry no attribute. Add the attribute and remove both in `0.7.0` | Done (rc214): both are `#[deprecated(since = "0.6.0")]` type aliases (they were `pub use` re-exports, which cannot carry the attribute), with a `compile_fail` doctest and a passing control each; the prelude re-exports allow the warning. Removal stays in `0.7.0` (CireSnave/PM 2026-10-24). Note for the removal: `ModularAuthFramework` is `auth_modular::AuthFramework`, a different type from `AuthFramework`, so "use `AuthFramework`" is not a drop-in; the deprecation note also names the by-path alternative |
| A8 | `COMPATIBILITY.md` "Deprecated" | Remove the monolithic `AuthFramework` method surface in `0.7.0` in favour of grouped accessors | Held until `0.7.0` planning |
| A9 | `docs/DEPLOYMENT_GUIDE.md:559-560` | `sdks/go/` and `sdks/java/` are "coming soon"; neither directory exists (only `sdks/javascript` and `sdks/python`). Covered by the Go and Java SDK rows in Phase 3; the guide should say "not started" | Done (rc213): the guide says Go and Java are not started |
| A10 | `docs/api/REST_API_DESIGN_RATIONALE.md` | Webhooks for user, role and auth-failure events | Dropped 2026-10-24 (PM ruling): no consumer has asked and no route exists; removed from the design doc. Reopen when a consumer asks |
| A11 | `docs/api/REST_API_DESIGN_RATIONALE.md` "Planned Additions" | Admin batch operations, advanced filtering, export/import. The other "planned" items (WebAuthn, OIDC discovery, API keys) have routes in `src/api/server.rs` | Dropped 2026-11-06 (PM ruling): `src/api/server.rs` has no batch, export or import route at 8445c472 and no consumer has asked, the same basis as A10. The design document keeps its text with a dropped note. Reopen when a consumer asks |
| A12 | CodeRipper rule OPS-011 `cli-basics` (2026-10-29) | Every shipped binary answers `--help`, `--version` and a bad flag, and none starts serving unasked: `oauth2_test_server` / `test_oauth2` hung on any argument, `auth-framework` had no `--version`, `security_audit` ignored its arguments and printed a fixed `v0.4.0` | Done (rc169): test servers need `serve`; `tests/bin_cli_basics.rs` probes each binary |
| A13 | A6 measurement (2026-10-31) | Kerberos: no test builds a valid AP-REQ end to end (the 25 tests cover primitives, replay and config); `KerberosConfig.kdc_addresses` / `add_kdc` are stored and never used by validation. Add an end-to-end AP-REQ test (valid, expired, wrong key, replayed), `kdc_addresses` / `add_kdc` are deprecated (rc194; PM ruling 2026-11-02: offline acceptor, never used), to be removed at the next breaking rc and noted Breaking then. The realm-only keytab fallback is removed (rc190): the entry is chosen by service principal and key type, with a unit test that a ticket for another service in the realm matches nothing | Done except the optional MIT-krb5 interop fixture (design note slice 5): keytab fallback removed rc190, `kdc_addresses` deprecated rc194, end-to-end test rc196, negative cases and validator mutations rc197 (`tests/kerberos_ap_req_e2e_tests.rs`, design `docs/KERBEROS_E2E_TEST_DESIGN.md`); the test found A15 |
| A14 | #91 remainder (2026-11-01, PM) | The OIDC provider builds its own `OAuth2Server` (`src/server/oidc/core.rs:395`) that audited nothing: add `AuthFramework::audit_storage()` and `OidcProvider::with_audit_storage`, test through `AuthFramework::audit()` | Done (rc192) |
| A15 | A13 slice 2 finding (2026-11-02) | `aes_cts_decrypt` treated a ciphertext whose length is a multiple of 16 as plain CBC; RFC 3962 swaps the last two blocks for those lengths too, so about 1 in 16 valid tickets or authenticators failed the HMAC check and were refused (false rejection, no acceptance path). Found by decrypting the RFC 3962 Appendix B vectors (32, 48, 64 bytes failed; 17, 31, 47 passed). Present since 0.5.0-rc18; `release/0.4.x` has no Kerberos module; `release/0.5.x` (rc82) has the same code. Fixed on main (rc195) with the vector test. Backport to `release/0.5.x` is cheap (same function, same test) | Done. Main rc195 (#370); `release/0.5.x` 0.5.0-rc83 (#372, `cb804492`). The 0.5.x control was measured on that branch's own base (`e146d336` plus only the test, function fix reverted): `RFC 3962 vectors that did not decrypt, by length: [32, 48, 64]`, test FAILED; with the fix, `1 passed`. `release/0.4.x` has no Kerberos module. Publishing 0.5.0-rc83 is held for a later patched 0.5.x release |
| A16 | PM, after the DPoP hardening (2026-11-02) | `FapiManager` has no rate limiter and takes no caller address, and it is not served by `src/api`; the crate's address and per-client limiters (#92) cover only the OAuth2 routes there. Say so in the `FapiManager` docs and `docs/`, then add an optional limiter with an address bucket before any signature work and a per-client bucket after authentication. Design: `docs/FAPI_RATE_LIMIT_DESIGN.md` | Done (rc204, #388): rustdoc, `FapiManager::with_rate_limiter` and the `_from` entry points with the address and per-client buckets; the manager takes `Arc<dyn RateLimiter>` (the trait of #92), so an Ant limiter can replace the built-in one |
| A17 | DPoP review (2026-11-02) | RS256/PS256 DPoP proofs were refused for every RSA key of 2048 bits or more: `verify_dpop_signature` wrote the modulus length in one byte, which wraps at 256, so the DER key it handed to ring was malformed (it failed closed). A proper DER length encoder replaces it; `rs256_and_ps256_proofs_from_a_2048_bit_key_are_accepted` is red before and green after, with a signature over other claims refused. Backport to `release/0.5.x` and `release/0.4.x` when cheap | Main: Done (rc201); `release/0.5.x`: Done (#380, rc85); `release/0.4.x` retired, no backport |
| A18 | DPoP review (2026-11-02) | `DpopManager::validate_dpop_bound_access_token` reads a JWT access token's claims (including `cnf.jkt`) without verifying the token's signature, so it cannot establish that the token is genuine. Nothing in the crate calls it; the FAPI resource check verifies the token first. Either verify the token with the `SecureJwtValidator` (`DpopManager::new` takes one and ignores it, as `_jwt_validator`) or narrow the function to the binding check and say the token must be validated first | Done (rc202): `validate_dpop_bound_jwt` validates the token with the manager's `SecureJwtValidator` first and only then reads `cnf.jkt`; the old function is `#[deprecated]` and always refuses (a forged JWT was reported valid: `a_forged_jwt_is_not_accepted_as_a_bound_token` red before, green after). The same code was on `release/0.5.x` and `release/0.4.x`: `release/0.5.x`: Done (#383, rc86); `release/0.4.x` retired, no backport |

### GNAP (RFC 9635, RFC 9767) and access control (2026-11-06)

CireSnave 2026-11-06, verbatim: *"Add comprehensive GNAP to auth-framework."* and, for agents: *"auth-framework should support
authentication of and authorization for agents as well as for humans and programs."* Board 385 ruled A: auth-framework holds
principals, grants, delegation and the access-control decision engine; Synapse is the first consumer and enforcer. The section-by-section
measurement is `docs/GNAP_RFC9635_GAP.md`; each slice is one PR with born-red tests and a mutation check, every claim cited to the RFC text, and no slice
claims a method it does not verify. Rows are Open until their PR lands.

| Row | What | State |
| --- | --- | --- |
| G0 | Gap note `docs/GNAP_RFC9635_GAP.md`, these rows, rustdoc warnings on `permissions::Delegation` and `check_delegation` | Done (rc218) |
| G1 | Full RFC types and errors: Appendix E polymorphism, `access_token` object or array, access objects, labels, flags, references (8.1), `manage` object, `key` object or string, `client` by reference, `user`, `class_id`, the 3.6 error object and codes | Open |
| G2 | `httpsig` proofing (RFC 9421 + RFC 9530, tag `gnap`). Check crates.io for a maintained crate before writing one; any new dependency is an ASK | Open |
| G3 | `jwsd`, `jws`, `mtls`, key formats `cert` and `cert#S256`; decide the fate of the non-RFC `dpop` method | Open |
| G4 | Interaction: start `redirect`/`app`/`user_code`/`user_code_uri`, finish `redirect`/`push` (SSRF rules of 11.34), `hash_method`, hints, interaction expiry | Open |
| G5 | Continuation: polling with `wait` and `too_fast`, PATCH modify, DELETE revoke grant, grant state machine, token rotate and revoke with proof, key rotation, `Authorization: GNAP` | Open |
| G6 | Policy backed by the access-control engine (AC4), consent records, storage through a trait (PersistAnt-style choice, not one hard-wired store); requirements for agents and rooms from board 384 | Open |
| G7 | HTTP routes (axum, actix) and discovery (9.1 RS-first, 9.2 `OPTIONS`) | Open |
| G8 | RFC 9767 resource-server connections: RS discovery, introspection, resource set registration, downstream tokens | Open |
| G9 | Agent principals and delegation by an account holder (see AC2, AC5, AC6); the creator of a principal holds a strict-subset grant over it, ancestors may revoke it, the account holder always overrides | Open |
| G10 | Conformance: the RFC example vectors (including the 4.2.3 hash example) and one test per section 11 item | Open |
| AC1 | Deny effect (deny wins), `decide(principal, action, resource) -> Decision`, action registry for consumers. `permissions.rs` has no deny at 3156a62c; `src/protocols/opa.rs` has a deny-wins `PolicyEffect` (lines 514-523), the candidate base | Done (#409) |
| AC2 | Attenuation: a shared grant is a subset of what the sharer holds, checked when shared and when used; chains to depth 3, configurable; stored delegations consulted by every check (today none is); revocation cascades (today a delegation survives its delegator losing the permission). Replaces `permissions::Delegation` evaluation. Creator grants (CireSnave 2026-11-06, board 384): creating a principal issues the creator a grant over the new principal, a strict subset of the creator's own grants, revocable by any ancestor up to the account holder, who always holds override (so an agent that creates a sub-agent can set see and send rules about it, for example hide a long-running helper from every other agent). | Done (#411) |
| AC3 | Cache contract (a decision is valid for at most 60 s, explicit invalidation) and a live path: a grant marked sensitive is checked at its source on every use | Done (#413) |
| AC4 | The engine behind `GnapAccessPolicy` (G6) | Done (#432) |
| AC5 | Principal kinds human, program, agent (stable id, owner, keys, lifecycle) | Done (#417) |
| AC6 | An account holder starts with permission to create and edit any rule about its own agents and rooms; anyone may share a subset of what it holds with others, including agents, and a shared grant can only narrow | Done (#420) |
| KM1 | Key model: one `KeyKind` (JWS/JWT signing, JWE encryption, GNAP/DPoP/httpsig client key, mTLS key pair, symmetric HMAC and AEAD), key ids, RFC 7638 thumbprints for every kind, lifecycle states (pending, active, retiring, revoked, destroyed) and a public export (JWK, JWKS, SPKI PEM). See `docs/GNAP_RFC9635_GAP.md` section 8 | Open |
| KM2 | Creation: generate every kind (RSA, P-256, P-384, Ed25519, X25519, 256-bit symmetric) on the one crypto backend already in the tree (aws-lc-rs through rcgen/jsonwebtoken); import; no key is generated by a path that cannot say where its private half went | Open |
| KM3 | Storage by capability, not one hard-wired store: a `KeyStore` trait whose implementations declare what they can do (exportable or not, can sign in place, can persist). Implementations in order: memory, encrypted file (reusing the `KeyProvider`/`StorageEncryption` seam), OS keystore, then TPM/PKCS#11/KMS where the platform has one. A non-exportable key signs through the store and is never returned | Open |
| KM4 | Rotation with overlap for every kind, not only the two `TokenManager` cases: N previous keys for a configured overlap window, verification by `kid`, scheduled and on-demand rotation, retirement that is audited. JWKS publishes active and retiring keys, never revoked ones | Open |
| KM5 | Revocation and compromise: revoking a key stops verification and publishes the fact (CRL entry or OCSP input for certificates, a `revoked` state plus event for JWKs and client keys); a revoked client key kills the grants and tokens bound to its thumbprint | Open |
| KM6 | Public export and publishing: JWKS for RSA, EC and OKP keys (today RSA only), RFC 7638 `kid`, `use`/`key_ops`/`alg`, `x5c`/`x5t#S256` for certificate-bearing keys, cache headers that match the overlap window | Open |
| KM7 | Certificates: CSR creation for a client key (none exists today), self-signed (rcgen), CA-issued (the existing `X509Signer`), `cert` and `cert#S256` GNAP key forms, renewal before expiry, and CA key custody through KM3 instead of a PEM path | Open |
| KM8 | Tooling: the `auth-framework keys` CLI and a library API for create, list, rotate, revoke, export and verify; every command audit-logged; no command prints a private key unless the key is exportable and `--export-private` is given | Open |

CireSnave 2026-11-06, verbatim: *"Auth-framework should include full key management tooling for most, if not all keys that a client or server could need to generate.  That includes key creation."* KM1-KM8 are that request; the measurement of what exists and the per-principal key anchors are `docs/GNAP_RFC9635_GAP.md` sections 8 and 9.

Suggested order after G0 (release numbers are the PM's): AC1, AC2, AC3, then KM1-KM3 (G2, G3 and G9 need the key model), G1-G6 as the build needs them, AC5 and AC6 with G9, KM4-KM8 alongside G3/G5, then G7, G8, G10.

### Standing design rules from the patent decisions (CireSnave, 2026-11-07)

CireSnave, verbatim: *"First-party macaroons are fine.  On continuous access evaluation, go with your recommendation to never add that redirect on an event; answer with a "re-authenticate" challenge the client handles, and do not add a subscribe-to-central-service flow."*

These are standing rules, not backlog. They bind every change to the files named below; changing one needs a fresh claim chart first (`docs/PATENT-SWEEP-CHARTS.md`) and CireSnave's decision.

| Rule | Reason | What it means in code | Where it is enforced |
|---|---|---|---|
| **R1. Macaroons carry first-party caveats only.** No third-party caveat, no discharge macaroon, no issuer-introspection mode. | Google, US 9,397,990: the claims need third-party caveats and discharges. Related: P5 (US 11,595,215). | `Macaroon` holds first-party caveats; a credential that carries a third-party caveat is refused on load. Verification is local. | `src/protocols/macaroons.rs` note at `Macaroon`; `tests/design_rules.rs` (no third-party or discharge API); the existing refusal test in that module |
| **R2. A revocation or policy event never causes a redirect.** An event may revoke, quarantine, log or notify, and may require step-up by answering the next request with a "re-authenticate" challenge that the client handles. The server does not send the user to the identity provider because of an event. | Microsoft, US 11,349,844: the claims need an event from a central service that makes the receiver revoke the session and redirect the user to the identity provider (P1). | `CaepRuleAction::RequireStepUp` is a decision the caller turns into a challenge on the client's next request, never a `Location` header. | `src/server/security/caep_continuous_access.rs` notes at `CaepRuleAction`, `process_event`, `execute_actions`; `tests/design_rules.rs` |
| **R3. No subscribe-to-central-service flow.** The receiver is handed events (`process_event`); it makes no subscription call to a central conditional-access or session-event service and holds no subscription state. | Microsoft, US 11,349,844, claim 7 (P2). | Event delivery is the integrator's transport; the crate exposes handlers, not a client for such a service. | the same notes; `tests/design_rules.rs` |

The re-authenticate challenge is the standing answer to "what should a client do when access is revoked or stepped up": return the challenge (a 401 with a `WWW-Authenticate` or an error body the client's own code handles), and let the client decide whether and where to send the user. `CaepRuleAction::reauthenticate_challenge()` renders it (a 401 with `WWW-Authenticate: Bearer error="insufficient_user_authentication"`, RFC 9470); the integrator's HTTP layer sends it on the client's next request. `tests/design_rules.rs` scans the three files above and also every file under `src/` that names `RequireStepUp`, `CaepRuleAction` or `AllowWithStepUp`, so a route that turned the decision into a redirect is caught; a redirect written in a file that never names the decision is not, and is out of that scan's reach.

### Do not build otherwise (patent sweep, 2026-10-25)

Each row is a design constraint from `docs/PATENT-SWEEP-CHARTS.md`: an element of a patent's independent claims that this crate does not do. Not legal advice. Changing any row needs a fresh chart first.

| # | Do not build | Patent | Where the crate stays clear |
|---|---|---|---|
| P1 | An event received from a central service that makes the receiver revoke a session and redirect the user to the identity provider for re-authentication | US11349844B2 | CAEP handling revokes by back-channel logout and `RequireStepUp` only logs; no redirect (`src/server/security/caep_continuous_access.rs`) |
| P2 | A resource provider subscribing to a central conditional-access / session-event service | US11349844B2 (claim 7) | The receiver is handed events (`process_event`); it makes no subscription call |
| P3 | A device identifier or fingerprint placed inside the token or cookie given to the client and recomputed and compared on each request | US8959650B1 | Session ids are random and the fingerprint is server-side state (`src/security/secure_session.rs`) |
| P4 | Cross-tenant single sign-on: letting an authentication at one tenant satisfy authentication at another tenant of the same user | US9369456B2 | Tenants are isolated frameworks with per-tenant sessions (`src/tenant/registry.rs`) |
| P5 | A macaroon issuer-introspection mode (the issuer authenticates a macaroon the resource server hands back) | US11595215B1 | Verification is local |
| P6 | A weighted reputation formula over threat feeds; a device-tier-dependent key-rotation window or alert on old-key use; usage-monitoring key deactivation; a policy dry-run diff report | US10681071B1; US10462152B2; US9424419B1; US12443741B2 | See the design-around notes in `docs/PATENT-SWEEP.md` |

### Community and Project Hygiene

- [x] Add issue templates
- [x] Add a code of conduct
- [x] Tighten contributor workflows around release quality gates
- [x] Publish clearer compatibility and support expectations for features and integrations

## Phase 3: API and Product Leadership

This phase is focused on making the project not just feature-rich, but the easiest serious auth framework to adopt and extend.

### API Maturity Goals

- [x] Replace duplicated public concepts with canonical types or explicit namespaces — `UserInfo` deduplicated across `methods`, `api`, and `auth_modular`; `api::auth::LoginUserInfo` renamed; `#[deprecated]` aliases added for legacy names
- [x] Narrow the default public surface so auto-complete and docs steer users toward the right abstractions — advanced RFC types (`DpopManager`, `PARManager`, `PrivateKeyJwtManager`, `ServerOAuth2Server`, WS-Security/WS-Trust, OIDC backchannel/frontchannel logout) now carry `#[doc(hidden)]` at root; fully accessible via sub-module paths
- [x] Establish a stable public API map with migration guidance for legacy entry points — canonical names, grouped accessors, deprecated aliases, and type disambiguation tables were completed as part of the API maturity work
- [x] Keep advanced internals available without letting them dominate the onboarding path — `#[doc(hidden)]` on root re-exports keeps advanced types programmatically accessible while removing them from the default docs/autocomplete surface
- [x] Ensure the canonical public API is fully usable on the default build without requiring users to discover extra feature flags first — `AuthFramework`, `prelude::*`, grouped accessors, and all core types work on default features

### Ecosystem Expansion

- [ ] Go SDK
- [ ] Java SDK
- [ ] C# SDK
- [ ] Ruby SDK
- [ ] Additional deployment templates and operator tooling

## Immediate Priorities (Next 30 Days)

1. ✅ Release stabilization — all tests green, rustdoc clean, clippy clean

2. ✅ Default feature policy — batteries-included defaults documented, opt-out paths documented

3. ✅ API consolidation — grouped accessors, canonical types, deprecation plan, stable API map

4. ✅ Documentation consolidation — Rust library onboarding path clear, default paths primary

5. ✅ Release hygiene — version/workflow labeling aligned

**Next priorities:**

1. Release `0.6.0` from the current release-candidate line
   - Stable-release MUST items are listed under "Storage and Scaling" (token/session encryption at rest, ADR-011) and the P1 rows of "Tracked Issues"
   - Confirm changelog is accurate and complete
   - Tag release and trigger release workflow

2. Phase 2 storage expansion
   - Evaluate SQLite support crate feasibility and scope
   - Decide timeline for community-maintained SurrealDB integration

3. Phase 3 ecosystem
   - Begin Go SDK scaffolding
   - Define SDK generation strategy and shared test suite

## Success Criteria For The Current Phase

- `cargo check --all-features` passes
- `cargo test --all-features` passes
- `cargo doc --no-deps` is warning-free
- Clippy is warning-free on the enforced targets
- New users can add the crate and access the primary documented capabilities without manual feature hunting
- New users can identify the default API entry point within the first minute of reading the README or docs
- The most common operations are discoverable under intuitive grouped surfaces rather than only on a monolithic root type
- Advanced users can still disable unneeded subsystems with a clearly documented optimization path

---

This roadmap is now intended to be status-driven. It should be updated whenever a release-readiness blocker is discovered, a DX milestone lands, or a previously planned item materially changes state.
