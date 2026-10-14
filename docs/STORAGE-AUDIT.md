# Storage & Persistence Audit

**Date:** 2026-10-04
**Ref audited:** `origin/main` @ `a254de6b`
**Re-verified at:** `origin/main` @ `3239b1c3` (2026-10-14, 74 commits later). Every
claim below is either unchanged and says so, or was corrected in place and is
marked **Corrected at `3239b1c3`**. A bare "Verified" in a table means verified
at `a254de6b`. **`file:line` anchors are as of `a254de6b` and have drifted — go
by the file and symbol, not the line.**
**Scope:** every stateful subsystem under `src/` — does its state flow through the
pluggable `AuthStorage` backends (Postgres/SQLite/Redis/MySQL/memory), and for
everything that does persist, how is it protected at rest. (MySQL was a
backend at the audited ref; `mysql-storage` was removed in #114.)
**Trigger:** CireSnave, verbatim: *"As far as audits of codebases go,
auth-framework has a lot of security information it needs to store. If we
haven't done so recently, lets audit auth-framework top to bottom to ensure
that any data that should survive a restart or be shared across multiple
instances of auth-framework (for instance to allow multiple auth-framework
instances to see the same set of clients), flows through our pluggable
storage backends and stored in a secure fashion."*

**Status: Phase 1 (this table) and Phase 3 (independent adversarial
re-check, by a reviewer working from its own grep of the source, not from
this table) are both complete and merged into this single document — Phase
3 found Phase 1 understated the problem on five ratings and missed roughly
40 additional in-process state containers. Phase 2 (a two-instance
integration-test harness proving cross-instance visibility and
restart-safety, with a deliberate sabotage case) is still pending.**

## Two standalone findings, filed privately ahead of the storage-architecture work

Two issues found during this audit are standalone authentication defects,
not persistence-architecture gaps. Both were security-sensitive and were
filed as private GitHub security advisories; no exploit detail is included
in this public document. One affected TOTP/MFA verification, the other
OAuth2 refresh-token revocation. Both were confirmed present in
previously-published releases, not just on `main`. **Corrected at
`3239b1c3`:** both are fixed on `main` (#111; #112 with 0.6.0-rc9); the
previously-published releases are not patched by that.

**Not to be confused with** the 0.6.0 zeroization sweep (PRs #63-#77): that
work zeroized in-process secret memory on drop, removed `Serialize` from
some secret types, and fixed JWT verification / the password-hash algorithm
/ `AuditConfig::storage`. It was **not** an at-rest persistence audit. Where
this audit's findings overlap with that sweep, it says so explicitly below;
everything else here is new.

## Part 1 — Stateful subsystem inventory

Every `HashMap`/`DashMap`/`RwLock`/`Mutex`/`OnceLock`/`static` holding
request- or session-relevant state in `src/`, whether it is persisted
through an `AuthStorage` backend, whether it survives a process restart,
whether it is safe with N replicas behind a shared backend, whether it has
any dedicated test, and the tracking issue if one already exists. Every row
was read directly against `origin/main` unless marked "Unverified."

| # | Subsystem | State location (file:line) | Persisted via AuthStorage? | Survives restart? | Safe w/ N replicas? | Tested? | Issue # | Verified |
|---|---|---|---|---|---|---|---|---|
| 1 | **OAuth2 client registry #1** (`EnhancedTokenStorage`) | `server/oauth/oauth2_enhanced_storage.rs:186-190` (`refresh_tokens`/`authorization_codes`/`client_credentials`/`users`: plain `HashMap`, wrapped by `Arc<RwLock<EnhancedTokenStorage>>` at `oauth2_server.rs:437`) | **No** — zero `AuthStorage` refs in file | **No** | **No** | None found | **#90** (positive control) | Verified |
| 2 | **OAuth2 client registry #2** (`oauth2_client:` KV, live route) | `api/oauth2.rs:1344` (write), `api/oauth_advanced.rs:150` (read, `/oauth/introspect`) | **Yes**, generic KV | Yes | Yes (shared backend) | None found (no dedicated persistence/restart test) | **#90** | Verified |
| 3 | **OAuth2 client registry #3** (`oauth_client:` KV, `TokenIntrospectionService`) | `server/token_exchange/token_introspection.rs:354-384` | Yes, generic KV | Yes | Yes | None found | **#90** | Verified |
| 4 | **OAuth2 client registry #4** (`ClientRegistrationManager`, RFC 7591) — new find, not in #90 | `server/core/client_registration.rs`; re-exported at `server/mod.rs:28` but **never constructed in `src/api/*.rs`** | Yes, via its own storage calls (2 call sites) | Yes | Yes | None found | not filed — same unwired pattern as #90's registry #3 | Verified |
| 5 | API keys | `auth_modular/user_manager.rs:154-180` (`api_key:{key}` KV) | **Yes** (positive control) | Yes | Yes | None dedicated | — | Verified |
| 6 | Passwords | `auth_modular/user_manager.rs:126-140` (argon2id/bcrypt via `hash_with_algorithm`) | Yes (via user record storage) | Yes | Yes | Yes, `test_password_hashing*` | — | Verified |
| 7 | Sessions (canonical) | `auth_modular/session_manager.rs` → `AuthStorage::store_session`/`get_session` | Yes | Yes | Yes | Covered by broader test suite | — | Verified |
| 8 | Session manager, generic trait — dead code | `session/manager.rs:502` `SessionManager<S: SessionStorage, A: AuditStorage>` — **no non-test implementation of `SessionStorage` exists in the tree** (a `TestSessionStorage` inside the file's own tests was added after `a254de6b`) | N/A — uninstantiable with a real backend | N/A | N/A | Has its own unit tests but can't be used outside them | not filed | Verified (`impl SessionStorage for`: zero hits besides the trait decl) |
| 9 | Session manager, in-memory, widely reused | `server/oidc/oidc_session_management.rs:91-96` `SessionManager { sessions: HashMap<...> }`, no `Arc`/lock at all | **No** | **No** | **No** | Has its own unit tests (in-memory only) | not filed | Verified — constructed via bare `Arc::new(SessionManager::new(...))` in CAEP, stepped-up-auth, RAR, CIBA, token-exchange, backchannel/frontchannel logout (6+ call sites); with no interior mutability, mutating methods (`&mut self`) are **unreachable through every one of those `Arc`-wrapped instances** — likely non-functional glue, not just "in-memory" |
| 10 | DPoP replay-prevention nonces | `server/security/dpop.rs:79` `used_nonces: RwLock<HashMap<...>>` | No | No | No | Not checked | not filed | Verified (field) |
| 11 | JWT revocation list (secondary layer) | `security/secure_jwt.rs:103,195` — doc comment itself says "in-memory" | No | No | No | Not checked | not filed | Verified |
| 12 | Secure session store (separate from #7/#9) | `security/secure_session.rs:231-233` `active_sessions`/`user_sessions`/`ip_changes`: `DashMap` | **No, resolved in Phase 3** — the file imports no storage trait at all; Phase 1's "2 storage calls" was `self.store_session(...)` at `:318`, a PRIVATE method (doc: "Store session in memory (in production, use persistent storage)") that only writes the local `DashMap`s. All other hits are test-only. | **No** | **No** | Has its own tests (in-memory only) | not filed | Verified (Phase 3) |
| 13 | Device authorization grant | `server/oauth/device.rs:118` `authorizations: Arc<RwLock<HashMap<...>>>` | **Yes, resolved in Phase 3** — storage is the actual source of truth: every mutation writes `device_code:{dc}`/`user_code:{uc}` with 600s TTL; reads check storage first, falling back to the local cache only on a miss. Restart-safe. **But has real bugs**: (a) a storage miss can fall back to a stale local cache; (b) **no consume/delete exists anywhere in the file** — RFC 8628 one-time-use is not enforced, `poll_authorization` keeps returning `Authorized` until expiry; (c) `authorize_device` never checks the record is still `Pending`, so a `Denied` record can be flipped to `Authorized`; (d) plaintext key names. Also: nothing in `src/` constructs `DeviceAuthManager` — only re-exported. | Not checked | not filed | Verified (Phase 3) |
| 14 | Pushed Authorization Requests (PAR) | `server/oauth/par.rs` `requests: Arc<RwLock<HashMap<...>>>` (local cache) | **Yes (Phase 3 corrected Phase 1's "Likely No").** `store_request` writes `par:{request_uri}` with a 90s TTL; `consume_request` reads storage first. **Corrected at `3239b1c3`: the single-use defect Phase 3 found is fixed** (`d67594c7`) — `consume_request` claims `par_spent:{request_uri}` with `store_kv_if_absent` before deleting, so at most one redeemer wins (exactly one on a backend with an atomic `store_kv_if_absent`; on a backend that keeps the fail-closed default, #154, every redemption errors), and the marker outlives the request. Cross-replica only on a shared backend (Postgres, SQLite file, Redis), not `MemoryStorage`. The local cache fallback on a storage miss remains. Used by `FapiManager`. | Yes | Yes (single use) on a shared backend with atomic `store_kv_if_absent` | Not re-checked | not filed | Re-verified `3239b1c3` (read `par.rs`) |
| 15 | Rich Authorization Requests (RAR) decisions/resource cache | `server/oauth/rich_authorization_requests.rs:612,615` | **No** — zero storage refs | No | No | Not checked | not filed | Verified |
| 16 | `private_key_jwt` client auth: JTI replay list | `server/jwt/private_key_jwt.rs` `used_jtis: RwLock<JtiStore>` (`JtiStore` is a swept in-memory map; no `AuthStorage` call in the file) | **No** | No | **No** — replay protection is per-instance only | Not checked | not filed | Re-verified `3239b1c3` for the storage claim. Corrected: assertions are now verified against the registered public key (`7cd9a6de`); that is signature verification, not replay storage. |
| 17 | OIDC backchannel/frontchannel logout state | `oidc_backchannel_logout.rs:201,203`, `oidc_frontchannel_logout.rs:116,118` | No | No | No | Not checked | not filed | Verified (fields) |
| 18 | CIBA auth requests | `oidc_enhanced_ciba.rs:509` | No | No | No | Not checked | not filed | Verified (field) |
| 19 | CAEP continuous-access sessions/events/rules | `server/security/caep_continuous_access.rs:497,509,512` | No | No | No | Not checked | not filed | Verified (fields) |
| 20 | FAPI sessions | `server/security/fapi.rs:61` | No | No | No | Not checked | not filed | Verified (field) |
| 21 | mTLS client configs | `server/security/mtls.rs:101` | No | No | No | Not checked | not filed | Verified (field) |
| 22 | X.509 CA/cert store **and revocation list** | `server/security/x509_signing.rs` `certificate_store`/`revocation_list`/`ca_certificates`/`crl_numbers`, all `Arc<RwLock<HashMap>>` | **No** | **No** — a CA's own revocation list resets on restart unless the operator calls `save_state`/`load_state` (opt-in, local file, one writer, not replica-shared; added in `2ce7ac57`, called nowhere else in `src/`) | **No** | Not checked | not filed | Re-verified `3239b1c3` (fields and the opt-in file persistence above; the file's cryptography was rewritten in `2ce7ac57`) |
| 23 | Token exchange policies/active exchanges | `server/token_exchange/core.rs:330,333` | No | No | No | Not checked | not filed | Verified (fields) |
| 24 | Token exchange audit trail | `server/token_exchange/advanced_token_exchange.rs:759` `exchange_audit: Arc<RwLock<Vec<...>>>` | **No** — separate from the real audit-log system (#33) | No | No | Not checked | not filed | Verified |
| 25 | Consent records / device-auth records | `server/core/additional_modules.rs` | **Overstated in Phase 1 ("Yes, heavily") — resolved in Phase 3, conditional with real bugs.** `JwtServer::store_signing_key` writes the caller's raw PEM signing key in **plaintext**, no TTL, under `jwt_key:{kid}` (`:128-132`) — contradicts row 34's "N/A by design," see below. `SamlIdentityProvider` stores bearer SAML assertions in **plaintext**, 1h TTL (`:376-383`). `ConsentManager` only persists via `new_with_storage` — `new()` sets `storage: None`; `has_consent` reads its local cache first and **never checks `expires_at`**, so a revoke on one replica is still honored by every other replica's cache until restart. `DeviceFlowManager::approve` re-stores records containing the **raw access_token** with `TTL=None` despite a comment claiming "preserve remaining TTL" — approved records with plaintext access tokens persist **forever**. None of these managers' constructors are called outside this file. | Conditional | Conditional (consent specifically is NOT replica-safe) | Yes (several `test_saml_idp_*`, consent tests) — none test cross-replica consistency | not filed | Verified (Phase 3) |
| 26 | TOTP secret (storage-backed path) | `auth_modular/mfa/totp.rs` (`user:{id}:totp_secret`) | Yes, KV (**encrypted at rest by the factory wrapper since #119, see Part 3**) | Yes | Yes | Yes (`totp1`/`nobody` tests) | not filed | Verified; encryption note Corrected at `3239b1c3` |
| 27 | TOTP (second, stateless path) | `authentication/mfa.rs:152` `TotpProvider` — holds only config, no storage field at all | N/A — caller's responsibility | N/A | N/A | Not checked | not filed | Verified |
| 28 | SMS/Email MFA OTP codes | `auth_modular/mfa/sms_kit.rs:331`, `mfa/email.rs:159` | Yes, KV, 300s TTL | Yes | Yes (code itself) | SMS/email verification tests exist | not filed | Verified |
| 29 | MFA **challenge records** (type/expiry/user — separate from the code above) | `auth_modular/mfa/mod.rs` `challenges: Arc<RwLock<HashMap<...>>>` (still local at `3239b1c3`; the per-user pending cap `guard_and_store` is local too) | **No** | **No** | **No — a correctness bug, not just durability**: the OTP code lives in shared storage but the challenge record that says "this challenge exists, here's its type/expiry" does not; a verify request landing on a different instance than the one that created the challenge finds no challenge record | Not checked | not filed | Verified |
| 30 | Rate limiter (`utils::rate_limit::RateLimiter`) | `utils/rate_limit.rs:18-21` `Arc<Mutex<HashMap<...>>>` | No | No | No | Yes, extensively tested | not filed | Verified |
| 31 | "Distributed" rate limiter | `distributed/rate_limiting.rs:122,250,532`, primarily `DashMap`-based, **optionally** backed by a real Redis limiter only `#[cfg(feature = "redis-storage")]` and only when `config.distributed && config.redis_url.is_some()` | **Conditional** — in-memory by default, Redis-backed only if explicitly configured | Conditional | Conditional | Not checked | not filed | Verified |
| 32 | Tenant registry | `tenant/registry.rs:59-65` `Arc<DashMap<TenantId, ...>>` | **No** | **No** | **No** | Yes (several `tenant::registry::tests::*`) | not filed | Verified |
| 33 | Audit log events (the real audit system) | `audit.rs` → `build_audit_storage`, `AuditStorage` trait | **WRONG in Phase 1 — resolved in Phase 3.** `build_audit_storage` only offers `Memory` (a fresh private `MemoryStorage`, and the default), `Tracing` (write-only logs), or `UnimplementedAuditStorage` for `File`/`Database`/`External` (errors on every call). `AuditStorage` has NO Postgres/SQLite/Redis/MySQL implementation anywhere. | **No, by default** | **No, by default** | Not re-checked this pass | — | Verified (Phase 3) |
| 34 | JWKS / signing key material (operator-supplied, at `TokenManager` construction) | `tokens/mod.rs` — key comes from operator-supplied PEM/secret, held as `jsonwebtoken::EncodingKey` in-process | **N/A by design for THIS path** — not app state, it's operator config. **But see row 25: `JwtServer::store_signing_key` is a SEPARATE path that DOES persist a caller-supplied signing key, in plaintext, no TTL** — this row's "N/A by design" framing does not generalize to the whole crate. | N/A | N/A | N/A | — | Verified; caveat added Phase 3 |
| 35 | SAML IdP metadata registry | `methods/saml/mod.rs:33` `identity_providers: HashMap<...>` | **No** — zero storage refs in file | No | No | Not checked | not filed | Verified (field) |
| 36 | Passkey/WebAuthn registrations + pending challenges | `methods/passkey/mod.rs` `RwLock<HashMap<...>>` (the in-memory `PasskeyManager`). **Corrected at `3239b1c3`:** the live route `api/webauthn.rs` is separate and persists challenge sessions, credentials and indexes through the framework storage (`store_kv`, and `store_kv_if_absent` for single-use challenge sessions); this row described only the manager. | **No** for `PasskeyManager` — zero storage refs; **Yes** for the API route | No | No | Not checked | not filed | Verified (field) |
| 37 | Client-cert pinning + per-cert revocation | `methods/client_cert/mod.rs:468,523` | **No** | No | No | Not checked | not filed | Verified (fields) |
| 38 | Monitoring metrics/health/security-event history | `monitoring/mod.rs:303,305,307`, `collectors.rs` (`AtomicU64` counters) | No — correctly ephemeral by design (process metrics, not credentials) | No | No | Not checked | N/A | Verified |
| 39 | **Core tokens (access/refresh), the canonical `AuthStorage` token path** — new row, added Phase 3 | `storage/postgres.rs:44-58,151-165`, `storage/sqlite.rs:40,89-99`, `storage/redis.rs:54-55` | Yes | Yes | Yes | Covered by broader test suite | — | Verified (Phase 3) — see Part 2: **stored in plaintext in every backend** |

**Rows #12, #13, #14, #25, #33 were unverified or wrongly rated in the original
Phase 1 pass and have been corrected above following Phase 3's independent
review** (see the per-row notes). Row #39 (core tokens) and roughly 40
additional in-process state containers were found by Phase 3 and were
entirely absent from the original Phase 1 table; the most security-relevant
of those are listed in **Part 1b** below rather than renumbering this whole
table.

## Part 1b — additional state found independently by Phase 3, not in the original 38

Phase 3 ran its own from-scratch census (own `git grep`, not a read of this
table) and found roughly 40 more in-process state containers Phase 1 never
listed. The security-relevant ones:

| Subsystem | State location | Notes |
|---|---|---|
| Process-global IP blacklist | `api/security_simple.rs:21-22`, `lazy_static` | Crate-wide, not per-tenant; in-memory only |
| Admin GUI sessions + login lockout | `admin/mod.rs:140,143` | In-memory — lockout bypassable by spreading attempts across replicas, or by restarting |
| RBAC/ABAC permission checker (role grants/revokes) | `auth_modular/authorization_manager.rs:21`, `authorization.rs:360` | `grant_permission`/`revoke_permission`/`check_user_permission` touch the in-memory `PermissionChecker`. **Corrected at `3239b1c3`:** roles and assignments are also persisted to KV (`rbac:role:`, `rbac:user_roles:`) and reloaded by `load_persisted_roles` via `list_kv_keys` — so durability exists (and depends on a `list_kv_keys` that is not the empty default, see Part 3) — but other replicas load only at startup, so a `remove_role` on replica A is not honored by replica B until B restarts |
| Live OAuth2 authorization-code/refresh-token KV paths | `api/oauth2.rs` | **No Phase 1 row existed for the actual live route at all**, despite being persisted; see Part 2 |
| Live PAR/device/CIBA records that nothing ever reads back | `api/oauth_advanced.rs:401,470,544` (`par_request:`, `device:`, `ciba:`) | Dead writes — these keys have zero read call sites anywhere in `src/api/` |
| `private_key_jwt` JTI replay (JWT best-practices variant) | `server/jwt/jwt_best_practices.rs:217` | Separate from row 16's replay list; also per-instance only |
| Modular backup codes | `auth_modular/mfa/backup_codes.rs:24-33` | Plaintext, no TTL |
| API-path backup codes | `api/mfa.rs:68-89` | Unsalted SHA-256 of an 8-character code from a 32-symbol alphabet (~40 bits) — brute-forceable offline from a dump |
| Distributed rate limiter, fail-open case | `distributed/rate_limiting.rs` `fallback_check` (re-verified `3239b1c3`) | When `distributed: true` but no Redis configured, `fallback_check` builds a **fresh empty in-memory limiter on every call** — every request is allowed |
| Rate-limit middleware key source | `api/middleware.rs` | **Corrected at `3239b1c3`: fixed** (`fc9070fd`, `f5ab5685`). Clients are rate-limited by peer address; `X-Forwarded-For` is honoured only from configured trusted proxies, and the client is the rightmost entry that is not itself a trusted proxy. (At `a254de6b` it keyed on the client-supplied header.) |

Full per-file:line detail for the complete ~40-item census is available on
request; this table lists the subset judged security-relevant rather than
process-metric/cache-only containers.

## Part 2 — At-rest security, for every persisted subsystem

**Corrected at `3239b1c3` — read this before the table.** The cells below were
written at `a254de6b`, when nothing encrypted anything at rest. Since #119,
`storage/factory.rs` wraps every persistent backend in `EncryptedStorage` by
default and refuses to start without a key (Part 3). So for any datum written
through `store_kv`, "plaintext" below now describes what the *application*
writes, and a database dump of the **values** no longer yields it without the
key. Two things are not covered by that wrapper and still hold exactly as
written: **key names** (never encrypted — API keys and OAuth2 token values used
as key names remain readable from a dump of names) and **typed token and
session columns** (`store_token`/`store_session` do not go through `store_kv`).
Cells whose DB-dump conclusion changed are marked.

For every row above marked "Persisted: Yes," how the datum is protected at
rest: plaintext, hashed (algorithm/salt/params), or encrypted (key holder,
rotation, nonce); whether a must-never-be-recoverable secret is actually
one-way, and whether a must-be-recoverable secret (TOTP) is protected at
rest; TTL enforcement; tenant isolation in the storage key; constant-time
comparison; log/Debug/Serialize leakage; and whether a raw database dump
alone is sufficient to compromise the datum.

| Subsystem | Plaintext / Hashed / Encrypted | Recoverable-secret correctness | TTL enforced? | Tenant isolation in key? | Constant-time compare? | Debug/Serialize/log leakage | DB-dump-alone compromise? |
|---|---|---|---|---|---|---|---|
| OAuth2 client registry #2 (`oauth2_client:`) | **Plaintext** (`client_data["client_secret"]` raw JSON) | Must be one-way — **it isn't**: fully recoverable from a read | None (`store_kv(..., None)` at registration) | **No** — key is bare `client_id`, no tenant prefix; collidable across tenants on a shared backend | Yes (`constant_time_string_compare`) | JSON blob round-trips the secret in plain form through any log of `client_data` | **Corrected at `3239b1c3`:** a dump of the value no longer yields the secret without the storage key (encrypted at rest by default, #119). The secret is still stored recoverably (raw in the record) and is readable by anything holding the key or any in-process reader. |
| OAuth2 client registry #3 (`oauth_client:`) | **Plaintext**, same pattern | Same defect | Not checked | Same — bare `client_id` key | Yes (`constant_time_compare`) | Same risk | **Corrected at `3239b1c3`:** as #2 — values are encrypted at rest by default; still stored recoverably. |
| OAuth2 client registry #4 (`ClientRegistrationManager`) | **Hashed** — raw **unsalted SHA-256** (`hash_secret`, `client_registration.rs:704-709`), not bcrypt/argon2/HMAC | Correctly one-way in intent; weak primitive (no salt/cost factor), mitigated by 32 random bytes of secret entropy from `generate_client_secret` | Has `client_secret_expires_at` field (enforcement at read not independently confirmed) | Not checked | Yes, `ConstantTimeEq` for the registration-access-token check | `Debug`/`Serialize` not checked on this struct | Partial — cracking unsalted SHA-256 of a 256-bit random value is infeasible regardless of DB access, so a dump alone is **not** sufficient here (unlike #2/#3) |
| OAuth2 client registry #1 (`EnhancedTokenStorage`) | N/A — not persisted at all | — | — | — | — | — | — |
| API keys | **Fixed in 0.6.0-rc57: rows are now named `api_key_h:{sha256 digest}`; the statement below describes the audited ref `a254de6b`, and rows written before the fix are moved on first read.** **WRONG in Phase 1, corrected Phase 3: the storage key itself is `format!("api_key:{}", api_key)` — the RAW bearer key is in the key name, not just metadata in the value.** | **Incorrectly handled** — `list_kv_keys("api_key:")`, or a dump of key NAMES (not just values), yields every live API key directly | **Yes**, `expires_in` passed straight to `store_kv`'s TTL | **No** — no tenant prefix | N/A (exact-key lookup, not a comparison) | Low risk — the value blob itself has no secret, but the key name does | **Yes — a DB dump (of key names) alone yields every live bearer API key, contrary to Phase 1's claim** |
| Passwords | **Hashed**, argon2id or bcrypt per configured `PasswordHashAlgorithm` | Correctly one-way | N/A | Depends on surrounding user-record key, not independently checked | Timing-oracle-safe by construction (dummy-hash-on-unknown-user path, `user_manager.rs:91-117`) | Not checked for Debug/Serialize leakage this pass | **No** (assuming argon2id/bcrypt cost factors are adequate — not independently re-verified here) |
| **Core tokens (access/refresh) — new row, Phase 3** | **WRONG in Phase 1 ("reasonably protected"). Plaintext everywhere**: Postgres `auth_tokens.access_token`/`refresh_token` are plaintext `TEXT` columns; SQLite the same; Redis puts the raw token **in the key name** (`{prefix}access:{access_token}`). The live OAuth2 refresh-token/auth-code/revocation KV paths (`api/oauth2.rs`) also use raw token values as key names. | Must be one-way or at least opaque to a DB reader — **it isn't, anywhere** | TTL enforced on write; see Part 4 for a read-side caveat | Not checked | Not applicable (not a comparison site) | Not checked | **Yes — a database dump alone lets an attacker replay every live access/refresh token in the system.** |
| Sessions (canonical) | Session data is largely non-secret (IDs/metadata); not independently checked for embedded secret fields | N/A | Enforced via `cleanup_expired`/backend-specific expiry (Part 4) | Not checked | N/A | Not checked | Not checked |
| TOTP secret (storage-backed path) | **Corrected at `3239b1c3`: encrypted at rest by default.** The code still calls `self.storage.store_kv(&key, secret.as_bytes(), None)` (`auth_modular/mfa/totp.rs`); the wrapper from #119 encrypts the value, bound to its key name by AAD. At `a254de6b` this was stored with no encryption at all. | **Correct category** (TOTP secrets must be recoverable to compute codes); protection is now at the storage layer. Rows written before #119 are plaintext at rest and **unreadable** under the default config until the migration tool (`auth-framework-admin security encrypt-kv`) is run (or `allow_plaintext_reads = true` is set transiently) | **None** — `None` TTL, never expires (unchanged) | **No** — key is `user:{user_id}:totp_secret`, no tenant prefix (unchanged) | N/A (not a comparison site) | Not checked | **Corrected at `3239b1c3`: not on a default-configured install once migrated.** It was the most severe at-rest finding at `a254de6b`; a dump of an unmigrated install still yields plaintext. |
| SMS/Email OTP codes | **Plaintext** 6-digit codes | Correct category (low-entropy, short-lived, one-time use — plaintext is defensible) | **Yes**, 300s (`Duration::from_secs(300)`) | No tenant prefix, but low severity given short TTL + narrow blast radius | **Yes**, `ct_eq` (`sms_kit.rs`) and `constant_time_compare` (`email/mod.rs`) | Not checked | A dump during the 5-minute window exposes active codes only — low impact |
| Consent/device-auth records (`additional_modules.rs`) | Not independently read at the byte level this pass | Not checked | Not checked | Not checked | Not checked | Not checked | Not checked |
| Audit log events | `details: HashMap<String,String>` and request metadata (IP, etc.) via `store_event`; **no encryption layer applied** (Part 3) | N/A — not a "secret" in the recoverable/one-way sense, but PII (IPs, user IDs) is sensitive | Backend-specific; `delete_old_events` exists as explicit cleanup, not an automatic TTL | Not checked | N/A | Not checked | A dump exposes the full audit trail, including whatever PII `request_metadata`/`details` carries, in plain form |

## Part 3 — Encryption at rest (rewritten at `3239b1c3`)

**What this part said at `a254de6b`, kept as history:** `src/storage/encryption.rs`
defined `StorageEncryption` (AES-256-GCM) and an `EncryptedStorage<T>`
decorator that nothing constructed. Phase 3 corrected Phase 1's "unreachable
dead code, would fix this" — it was public API, unwired by default — and
found that wiring it as it stood would not have closed the exposures and
would have broken things: it encrypted values only, bound ciphertext to
nothing (no AAD), did not override `list_kv_keys` (the trait default returns an
empty `Vec`, which would have silently emptied RBAC role reload,
maintenance/backup and analytics), and rejected non-UTF-8 values.

**State at `3239b1c3` (verified by reading `storage/factory.rs` and
`storage/encryption.rs`):**

- **Wired, on by default, fail-closed** (#119). `factory.rs` wraps every
  persistent backend in `EncryptedStorage::new(...)` and refuses to start
  without a key unless `storage_encryption.enabled = false` (which only warns);
  memory storage is exempt. **Storage the caller supplies through
  `new_with_storage`/`replace_storage` is NOT wrapped**: it gets a startup
  check (#139) that warns by default and errors only when
  `require_wrapped_storage = true` (default `false`).
- **Ciphertext is bound to its record.** The envelope is versioned with a key id
  for rotation, and v2 binds metadata into the AAD (#133), so a value does not
  decrypt under a different record's key name. Raw bytes are supported.
- **`list_kv_keys` is overridden** (`encryption.rs`), no longer the empty default.
- **A migration tool exists** for data written as plaintext
  (`auth-framework-admin security encrypt-kv`): safe to re-run, supports
  `--dry-run`, preserves TTLs, refuses TTL-blind backends unless
  `--accept-ttl-loss`, and leaves legacy v0/v1 envelopes alone without
  `--accept-legacy-v0` (#119, #138). Backup files are sealed under the storage
  key (#121, #132), except when storage is Memory or encryption is disabled.
- **Pre-#119 plaintext rows are unreadable on a default install** until the
  tool is run: `allow_plaintext_reads` and `allow_legacy_v0` both default to
  `false`, and a non-envelope value is a hard error on read unless
  `allow_plaintext_reads` is set.

**What is still open — these claims from Phase 3 still hold at `3239b1c3`:**

- **Key names are never encrypted** (a comment in `encryption.rs` says so
  explicitly). Every raw-bearer-value-as-key pattern is therefore still
  readable from a dump of key names: API keys (`api_key:{key}`,
  `auth_modular/user_manager.rs`), OAuth2 refresh/auth-code/revocation KV paths,
  and Redis `{prefix}access:{access_token}`.
- **Typed token and session storage is not covered.** `store_token`/
  `store_session` use each backend's own columns (SQLite `auth_tokens.access_token`
  is still a plaintext `TEXT UNIQUE` column), not `store_kv`. The ROADMAP lists
  this as follow-up; its design is a separate document. (The test-only
  `storage::redis::RedisStorage` keys tokens as `{prefix}access:{access_token}`;
  the production core `RedisStorage`'s token key was not re-read at `3239b1c3`.)
- **`list_kv_keys` was the empty-default trait method on five
  implementations** at the audited ref, none of which the factory wraps:
  `DashMapMemoryStorage`, `storage::redis::RedisStorage`, `UnifiedStorage`,
  the `auth-storage-sqlite` crate's `SqliteStorage`, and the test
  `MockStorage`. #145 listed four and missed the crate. Since 0.6.0-rc63
  (#145) the default is an error and all five implement it.
  `EncryptedStorage::list_kv_keys` forwards to its inner storage.

**Open issue index for this part:** #144 (expired tokens returned by SQL and
in-memory `get_token`), #145 (`list_kv_keys` default), #146 (SQLite `store_kv`
TTL truncation), #147 (four `sessions` schemas), #148 (core `RedisStorage` uses
`KEYS` / no `EXPIRE`).

## Part 4 — Backend divergence (TTL enforcement, checked specifically)

No divergence found in TTL enforcement at read time: memory
(`dashmap_memory.rs`) checks `is_expired()` on every `get_kv` and also has a
`cleanup_expired()` sweep; Postgres filters `expires_at > NOW()` in the
`SELECT`; SQLite stores the same `expires_at` column pattern (write path
and `get_kv` filter confirmed at `3239b1c3`); Redis uses native `SET EX`. All four read paths behave
equivalently from a caller's perspective.

**MySQL's KV implementation was not checked this pass.** **Corrected at
`3239b1c3`: moot** — `mysql-storage` was removed in #114 and is no longer a
backend.

**Corrected at `3239b1c3` — the "no divergence" finding above is about KV reads
only.** Typed token and session reads do diverge: `get_token`/
`get_token_by_access_token` return expired tokens on SQLite and the two
in-memory backends, and SQLite `get_session` does too (#144, runtime-evidenced
there; Postgres by reading). SQLite `store_kv` also truncates a TTL to whole
seconds (#146).

## Already covered by the zeroization sweep (#63-#77) vs. new findings here

- **Already covered:** `Zeroizing<String>` wrapping on
  `EnhancedClientCredentials::client_secret_hash` (confirmed still present
  on current `origin/main`); the general direction of removing plaintext
  secret exposure from Debug/Drop paths.
- **New here:** `EnhancedClientCredentials` still derives plain `Serialize`
  *and* `Debug` despite the `Zeroizing<String>` field — `Zeroizing<T>`'s own
  `Debug`/`Serialize` impls delegate to `T`, so they do **not** redact; the
  hash is still fully visible to anything that logs or serializes this
  struct. The sweep zeroized memory on drop; it did not address
  Debug/Serialize exposure for this specific type.
- **New here:** TOTP-secret plaintext-at-rest storage (not a zeroization
  question — zeroization protects in-process memory, this is a durable
  storage gap). **Corrected at `3239b1c3`:** closed for the KV layer by #119.
- **New here:** the unwired `EncryptedStorage` decorator (Part 3).
  **Corrected at `3239b1c3`:** now wired by default (#119); Part 3 lists what
  remains.
- **New here:** the 4th client-credential registry (`ClientRegistrationManager`)
  and the `SessionManager` naming-collision/dead-code pattern (table rows
  4, 8, 9).

## Summary — stated directly, not softened, REVISED after Phase 3

Phase 3's independent review corrected Phase 1's counts in the dangerous
direction — the problem is worse than Phase 1 said, not better. Revised
rather than caveated, per Phase 3's own recommendation:

- Of the **39 stateful subsystems** now listed (38 original + row 39,
  core tokens; the ~40 Phase-3-only finds in Part 1b are additional, not
  counted in this base number): **audit log events (#33) and consent
  records (part of #25) move OUT of "persisted"** — audit has no real
  backend implementation by default, and consent's cache-first read with
  no `expires_at` check means a revoke doesn't actually propagate across
  replicas even when storage-backed. **PAR (#14) and device authorization
  (#13) move IN to "persisted,"** each with a specific replica-safety bug
  (PAR: single use was not enforced at `a254de6b`, fixed since — see row 14; device: no
  one-time-use enforcement at all).
- **At `a254de6b`, every persisted subsystem examined at the byte level
  stored its secret in plaintext, in the key name, the value, or both** — a
  crate-wide pattern: API keys (raw key in the KV key name), core
  access/refresh tokens (plaintext in every backend; Redis puts the raw token
  in the key name too), two of the four OAuth2 client-secret registries, TOTP
  secrets, SAML bearer assertions, and JWT signing keys loaded via
  `JwtServer`. **Corrected at `3239b1c3`:** the *values* written through
  `store_kv` on factory-built storage (OAuth2 client secrets, TOTP secrets) are
  now encrypted at rest by default (#119). SAML assertions and `JwtServer`
  signing keys are encrypted only if the caller hands those managers the
  framework's wrapped storage: they take a caller-supplied `Arc<dyn
  AuthStorage>`, nothing in `src/` constructs them, and `store_signing_key`
  still writes the raw PEM with no TTL. **Still plaintext at rest:** key
  names (API keys, OAuth2 token values, Redis `access:` keys) and the typed
  token/session columns (core access/refresh tokens in Postgres/SQLite).
- **At `a254de6b`, none of the 39 had a dedicated
  persistence-or-restart-or-multi-instance test.** Not re-measured at
  `3239b1c3`; the 74 commits since include concurrency-claim tests (PAR,
  refresh tokens, TOTP steps) but no multi-instance harness (Phase 2 is still
  pending).
- **Encryption at rest:** at `a254de6b` `EncryptedStorage` was unwired and
  would not have been sufficient. **Corrected at `3239b1c3`:** it is wired by
  default with AAD binding and a `list_kv_keys` passthrough (#119, #133).
  **Still open:** key names stay readable and typed token/session storage is
  not covered (Part 3).
- **Two findings were standalone authentication defects, not persistence
  gaps.** Both were confirmed present in previously-published releases, not
  just on `main`. **Corrected at `3239b1c3`:** both are fixed on `main`
  (#111, #112); published releases are not patched by that. No further detail
  is included in this public document.

**Is "completely broken" true?** Not literally — core routing logic works
and most subsystems that ARE persisted do survive a restart and are
visible across replicas. But Phase 3's correction makes the "built for
production use" premise even harder to defend than Phase 1 already found:
most of the "advanced" OIDC/OAuth2 protocol surface remains in-memory-only
(now confirmed to include RBAC role revocation itself — a permission
revoked on one replica is still honored by every other replica until
restart); the subsystems that genuinely are storage-backed turn out, on
closer inspection, to store their secrets in plaintext as a rule rather
than an exception; and two of the findings (fixed on `main` since, see above)
were outright authentication bypasses reachable with no special access at all,
present in the previously-published releases. At `a254de6b` this was
**"fragmented and insecure where it does persist,"** not merely
"fragmented," which was a materially worse answer than Phase 1's own
already-unsoftened conclusion. **Corrected at `3239b1c3`:** the second half
is narrower now (KV values encrypted at rest by default; both bypasses fixed on
`main`); the first half stands — most of the OIDC/OAuth2 protocol surface in
Part 1 is still in-memory-only (re-verified by file for the rows that say so),
and replica-safety is not established.

## Next steps (as of `3239b1c3`)

Done since `a254de6b`: the two standalone findings (#111, #112); storage
encryption at rest for the KV layer, on by default (#119, #133, #139); the PAR
single-use defect; forwarded-header rate-limit keying; MySQL removed (#114).

Open, as individually filed issues where they exist: client registry #90;
#144–#148 (storage-contract defects, Parts 3 and 4). Not yet an issue: the
plaintext-at-rest pattern for key names and typed token/session storage (its
design is pending). Each is fixed in its own PR with a red-first
restart/multi-instance test. Phase 2 (a two-instance integration harness
against a shared backend, Postgres in Docker and SQLite file, with a
deliberate single-subsystem sabotage proving the harness can actually fail) is
still pending.
