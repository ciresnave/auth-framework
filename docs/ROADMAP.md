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

- Current crate version: `0.6.0-rc142`
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

### Storage and Scaling

- [ ] SQLite support in a separate crate for lightweight deployments
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
| #147 | PostgreSQL `list_user_sessions` selects `last_activity`, `ip_address`, `user_agent`, which `migrate()` never creates; four incompatible `sessions` schemas in the tree | M | P1 | Open: `postgres.rs:701` selects them, the `sessions` table at `:132` has no such columns |
| #144 | `get_token` / `get_token_by_access_token` return expired tokens on SQLite and both in-memory backends; SQLite also returns expired sessions | M | P1 | Open, re-measured: expired token returned by Memory, DashMap and SQLite on both lookups; expired session returned by SQLite (control: live token returned on all three) |
| #99 | JARM JWE AES-256-GCM encrypt and decrypt pass no AAD, so the protected header is unauthenticated (RFC 7516 5.1/5.2 step 14) | S | P1 | Open: `oidc_advanced_jarm.rs` `cipher.encrypt(nonce, payload.as_bytes())` and `cipher.decrypt(nonce, ciphertext.as_slice())` |
| #92 | The only rate limiter on the wired OAuth2 / introspection routes is per IP, not per client | M | P1 | Open: no `rate_limit` in `src/api/oauth_advanced.rs` or `src/api/oauth2.rs` (control: 11 in `src/api/middleware.rs`) |
| #91 | No audit-trail record of client_credentials, introspection or revocation | M | P1 | Open: no `audit` in `src/api/oauth_advanced.rs`, `src/api/oauth2.rs`, `src/server/oauth/oauth2_server.rs` (control: 242 in `src/audit.rs`) |
| #90 | Three divergent client-credential registries: in-memory `EnhancedTokenStorage`, KV `oauth2_client:` with the secret compared in plaintext, and the token-exchange client store | L | P1 | Open: `oauth_advanced.rs:213` compares the stored plaintext `client_secret` |
| #148 | Redis backend on the production path (`storage/core.rs`) uses `KEYS`, leaves the per-user token set without EXPIRE and writes in several round trips | M | P2 | Open: `KEYS` at `core.rs:844`, `:1334`; needs a Redis service in CI for tests |
| #120 | Clippy errors under `cli,admin-binary,postgres-storage,redis-storage,sqlite-storage` | S | P2 | Open: 7 errors in the lib, 16 in lib tests, mostly `src/admin/web.rs` and `src/admin/cli.rs` |
| #103 | `cargo clippy --all-targets --all-features -D warnings` fails; decide which feature sets CI lints, then fix to that list | M | P2 | Open: 14 errors in the lib, 23 in lib tests |
| #116 | No test proves the TOTP facade (`AuthFramework`) and the modular `TotpManager` verify each other's secrets | S | P2 | Open: no test generates through one and verifies through the other |
| #18 | Audit tests read source paths that moved, and every read failure means "no problem found" | S | P3 | Open: `final_comprehensive_security_audit.rs` still reads the absent `src/server/oidc.rs` |
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
| reachability | 655 | Medium | Public items with zero callers inside this crate (for example `check_compliance`, `ApiVersion`, `log_message`); a library's public API is called from outside, so each needs a decision: keep as API, or remove | auth-framework lane | Open, to triage by module |
| SEC-002 | 98 | High | gitleaks hits over git history: 64 `generic-api-key`, 21 `private-key`, 10 `jwt`, 3 `curl-auth-header`. **Waived by path (21 hits in files absent from main, plus the fixture):** root `private.pem` and `private_pkcs8.pem` (commit 71c55407, v0.4.0 to v0.4.5; generated by the README's `openssl genrsa` example and committed by accident; absent from the published 0.4.0, 0.4.2 and 0.4.5 crates, not referenced by current code, not on main: exposed but unused, no rotation); `backup-before-enhancements-20251004-080500/`, `backup-working-build-20251004-075914/` and `README.md.backup` (copies of old sources, absent from main); `tests/fixtures/test_private_key.pem` (fixture). History rewrites are CireSnave's decision, none made. **Still to classify: the other 77 less the fixture hits,** in `src/`, `tests/`, `benches/`, `examples/`, `docs/` (look like fixtures and placeholders, not verified per line); a real secret is a security fix and rotation notice to the PM, not a row | auth-framework lane | Waivers recorded; remainder open |
| lint-suppression | 33 | Low | `allow(...)` with no reason (`deprecated`, `clippy::result_large_err`, `unused_macros`, `dead_code` and others) | auth-framework lane | Open, S: add `reason = "..."` or remove the allow |
| unused-return-values | 4 | Low | A call whose return value is dropped at one of its many call sites (for example `write` at `src/server/security/x509_signing.rs:3630`) | auth-framework lane | Open, S |
| licence | 3 | Medium | `LICENSE-APACHE` and `LICENSE-MIT` name a person as copyright holder; 404 of 404 source files carry no SPDX identifier | auth-framework lane | Open; the copyright holder is CireSnave's decision |
| version-consistency | 1 | High | `auth-storage-sqlite`, `sdks/python` (0.6.0rc64) and `sdks/javascript` (0.6.0-rc108) trailed the crate version | auth-framework lane | Fixed in this PR: all three at the root version (PEP 440 form for Python); `tests/member_versions_match_cargo.rs` keeps them there. PM ruling 2026-10-24: one version per project |


### Community and Project Hygiene

- [x] Add issue templates
- [x] Add a code of conduct
- [x] Tighten contributor workflows around release quality gates
- [x] Publish clearer compatibility and support expectations for features and integrations

## Phase 3: API and Product Leadership

This phase is focused on making the project not just feature-rich, but the easiest serious auth framework to adopt and extend.

### API Maturity Goals

- [x] Replace duplicated public concepts with canonical types or explicit namespaces — `UserInfo` deduplicated across `methods`, `api`, and `auth_modular`; `api::auth::LoginUserInfo` renamed; `#[deprecated]` aliases added for legacy names
- [x] Narrow the default public surface so auto-complete and docs steer users toward the right abstractions — advanced RFC types (`DpopManager`, `PARManager`, `PrivateKeyJwtManager`, `TokenIntrospectionService`, `ServerOAuth2Server`, WS-Security/WS-Trust, OIDC backchannel/frontchannel logout) now carry `#[doc(hidden)]` at root; fully accessible via sub-module paths
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

1. Release `0.5.0` from the current `rc18` candidate
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
