# AuthFramework Development Roadmap

Last updated: March 21, 2026 (release-readiness audit follow-up)

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

- Current crate version: `0.5.0-rc24`
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
- [x] MySQL support exists
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

**OpenTelemetry family, versioned in lockstep upstream:**
- [ ] `opentelemetry` 0.31.0 -> 0.33.0
- [ ] `opentelemetry-otlp` 0.31.1 -> 0.33.0
- [ ] `opentelemetry-prometheus` 0.31.0 -> 0.33.0
- [ ] `opentelemetry_sdk` 0.32.1 -> 0.33.0
- [ ] `tracing-opentelemetry` 0.32.1 -> 0.34.0

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
