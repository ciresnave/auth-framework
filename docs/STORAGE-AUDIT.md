# Storage & Persistence Audit

**Date:** 2026-10-04
**Ref audited:** `origin/main` @ `a254de6b`
**Scope:** every stateful subsystem under `src/` — does its state flow through the
pluggable `AuthStorage` backends (Postgres/SQLite/Redis/MySQL/memory), and for
everything that does persist, how is it protected at rest.
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
restart-safety, with a deliberate sabotage case) is still pending.** No
code changes, no version bump — this PR is docs only.

## Two standalone findings, filed privately ahead of the storage-architecture work

Two issues found during this audit are standalone authentication defects,
not persistence-architecture gaps, and are being tracked/fixed ahead of
everything else below. Both are security-sensitive and are filed as
private GitHub security advisories; no exploit detail is included in this
public document pending advisory publication. One affects TOTP/MFA
verification, the other affects OAuth2 refresh-token revocation. Both are
confirmed present in previously-published releases, not just on `main`.

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
| 8 | Session manager, generic trait — dead code | `session/manager.rs:502` `SessionManager<S: SessionStorage, A: AuditStorage>` — **zero implementations of `SessionStorage` exist anywhere in the tree** | N/A — uninstantiable with a real backend | N/A | N/A | Has its own unit tests but can't be used outside them | not filed | Verified (`impl SessionStorage for`: zero hits besides the trait decl) |
| 9 | Session manager, in-memory, widely reused | `server/oidc/oidc_session_management.rs:91-96` `SessionManager { sessions: HashMap<...> }`, no `Arc`/lock at all | **No** | **No** | **No** | Has its own unit tests (in-memory only) | not filed | Verified — constructed via bare `Arc::new(SessionManager::new(...))` in CAEP, stepped-up-auth, RAR, CIBA, token-exchange, backchannel/frontchannel logout (6+ call sites); with no interior mutability, mutating methods (`&mut self`) are **unreachable through every one of those `Arc`-wrapped instances** — likely non-functional glue, not just "in-memory" |
| 10 | DPoP replay-prevention nonces | `server/security/dpop.rs:79` `used_nonces: RwLock<HashMap<...>>` | No | No | No | Not checked | not filed | Verified (field) |
| 11 | JWT revocation list (secondary layer) | `security/secure_jwt.rs:103,195` — doc comment itself says "in-memory" | No | No | No | Not checked | not filed | Verified |
| 12 | Secure session store (separate from #7/#9) | `security/secure_session.rs:231-233` `active_sessions`/`user_sessions`/`ip_changes`: `DashMap` | **No, resolved in Phase 3** — the file imports no storage trait at all; Phase 1's "2 storage calls" was `self.store_session(...)` at `:318`, a PRIVATE method (doc: "Store session in memory (in production, use persistent storage)") that only writes the local `DashMap`s. All other hits are test-only. | **No** | **No** | Has its own tests (in-memory only) | not filed | Verified (Phase 3) |
| 13 | Device authorization grant | `server/oauth/device.rs:118` `authorizations: Arc<RwLock<HashMap<...>>>` | **Yes, resolved in Phase 3** — storage is the actual source of truth: every mutation writes `device_code:{dc}`/`user_code:{uc}` with 600s TTL; reads check storage first, falling back to the local cache only on a miss. Restart-safe. **But has real bugs**: (a) a storage miss can fall back to a stale local cache; (b) **no consume/delete exists anywhere in the file** — RFC 8628 one-time-use is not enforced, `poll_authorization` keeps returning `Authorized` until expiry; (c) `authorize_device` never checks the record is still `Pending`, so a `Denied` record can be flipped to `Authorized`; (d) plaintext key names. Also: nothing in `src/` constructs `DeviceAuthManager` — only re-exported. | Not checked | not filed | Verified (Phase 3) |
| 14 | Pushed Authorization Requests (PAR) | `server/oauth/par.rs:163` `requests: Arc<RwLock<HashMap<...>>>` | **Yes, resolved in Phase 3 — Phase 1's "Likely No, mostly local" was WRONG.** `store_request` writes `par:{request_uri}` with a 90s TTL; `consume_request` reads storage first and deletes on use. **Cross-replica replay bug**: instance A stores, instance B consumes (storage delete only clears B's own cache), a replay sent to A misses storage, falls back to A's stale local cache (`used == false`, not expired), and re-authorizes — single-use is violated across replicas within the 90s window. get-then-delete is also non-atomic, so two concurrent consumers can both succeed even on ONE shared backend. Used by `FapiManager`. | Not checked | not filed | Verified (Phase 3) |
| 15 | Rich Authorization Requests (RAR) decisions/resource cache | `server/oauth/rich_authorization_requests.rs:612,615` | **No** — zero storage refs | No | No | Not checked | not filed | Verified |
| 16 | `private_key_jwt` client auth: JTI replay list | `server/jwt/private_key_jwt.rs:223,226` `used_jtis: RwLock<HashMap<...>>` | **No** | No | **No** — replay protection is per-instance only | Not checked | not filed | Verified |
| 17 | OIDC backchannel/frontchannel logout state | `oidc_backchannel_logout.rs:201,203`, `oidc_frontchannel_logout.rs:116,118` | No | No | No | Not checked | not filed | Verified (fields) |
| 18 | CIBA auth requests | `oidc_enhanced_ciba.rs:509` | No | No | No | Not checked | not filed | Verified (field) |
| 19 | CAEP continuous-access sessions/events/rules | `server/security/caep_continuous_access.rs:497,509,512` | No | No | No | Not checked | not filed | Verified (fields) |
| 20 | FAPI sessions | `server/security/fapi.rs:61` | No | No | No | Not checked | not filed | Verified (field) |
| 21 | mTLS client configs | `server/security/mtls.rs:101` | No | No | No | Not checked | not filed | Verified (field) |
| 22 | X.509 CA/cert store **and revocation list** | `server/security/x509_signing.rs:46,49,52` `certificate_store`/`revocation_list`/`ca_certificates`, all `Arc<RwLock<HashMap>>` | **No** | **No** — a CA's own revocation list resets on restart | **No** | Not checked | not filed | Verified |
| 23 | Token exchange policies/active exchanges | `server/token_exchange/core.rs:330,333` | No | No | No | Not checked | not filed | Verified (fields) |
| 24 | Token exchange audit trail | `server/token_exchange/advanced_token_exchange.rs:759` `exchange_audit: Arc<RwLock<Vec<...>>>` | **No** — separate from the real audit-log system (#33) | No | No | Not checked | not filed | Verified |
| 25 | Consent records / device-auth records | `server/core/additional_modules.rs` | **Overstated in Phase 1 ("Yes, heavily") — resolved in Phase 3, conditional with real bugs.** `JwtServer::store_signing_key` writes the caller's raw PEM signing key in **plaintext**, no TTL, under `jwt_key:{kid}` (`:128-132`) — contradicts row 34's "N/A by design," see below. `SamlIdentityProvider` stores bearer SAML assertions in **plaintext**, 1h TTL (`:376-383`). `ConsentManager` only persists via `new_with_storage` — `new()` sets `storage: None`; `has_consent` reads its local cache first and **never checks `expires_at`**, so a revoke on one replica is still honored by every other replica's cache until restart. `DeviceFlowManager::approve` re-stores records containing the **raw access_token** with `TTL=None` despite a comment claiming "preserve remaining TTL" — approved records with plaintext access tokens persist **forever**. None of these managers' constructors are called outside this file. | Conditional | Conditional (consent specifically is NOT replica-safe) | Yes (several `test_saml_idp_*`, consent tests) — none test cross-replica consistency | not filed | Verified (Phase 3) |
| 26 | TOTP secret (storage-backed path) | `auth_modular/mfa/totp.rs:10-34` | Yes, KV | Yes | Yes | Yes (`totp1`/`nobody` tests) | not filed | Verified |
| 27 | TOTP (second, stateless path) | `authentication/mfa.rs:152` `TotpProvider` — holds only config, no storage field at all | N/A — caller's responsibility | N/A | N/A | Not checked | not filed | Verified |
| 28 | SMS/Email MFA OTP codes | `auth_modular/mfa/sms_kit.rs:331`, `mfa/email.rs:159` | Yes, KV, 300s TTL | Yes | Yes (code itself) | SMS/email verification tests exist | not filed | Verified |
| 29 | MFA **challenge records** (type/expiry/user — separate from the code above) | `auth_modular/mfa/mod.rs:126` `challenges: Arc<RwLock<HashMap<...>>>` | **No** | **No** | **No — a correctness bug, not just durability**: the OTP code lives in shared storage but the challenge record that says "this challenge exists, here's its type/expiry" does not; a verify request landing on a different instance than the one that created the challenge finds no challenge record | Not checked | not filed | Verified |
| 30 | Rate limiter (`utils::rate_limit::RateLimiter`) | `utils/rate_limit.rs:18-21` `Arc<Mutex<HashMap<...>>>` | No | No | No | Yes, extensively tested | not filed | Verified |
| 31 | "Distributed" rate limiter | `distributed/rate_limiting.rs:122,250,532`, primarily `DashMap`-based, **optionally** backed by a real Redis limiter only `#[cfg(feature = "redis-storage")]` and only when `config.distributed && config.redis_url.is_some()` | **Conditional** — in-memory by default, Redis-backed only if explicitly configured | Conditional | Conditional | Not checked | not filed | Verified |
| 32 | Tenant registry | `tenant/registry.rs:59-65` `Arc<DashMap<TenantId, ...>>` | **No** | **No** | **No** | Yes (several `tenant::registry::tests::*`) | not filed | Verified |
| 33 | Audit log events (the real audit system) | `audit.rs` → `build_audit_storage`, `AuditStorage` trait | **WRONG in Phase 1 — resolved in Phase 3.** `build_audit_storage` only offers `Memory` (a fresh private `MemoryStorage`, and the default), `Tracing` (write-only logs), or `UnimplementedAuditStorage` for `File`/`Database`/`External` (errors on every call). `AuditStorage` has NO Postgres/SQLite/Redis/MySQL implementation anywhere. | **No, by default** | **No, by default** | Not re-checked this pass | — | Verified (Phase 3) |
| 34 | JWKS / signing key material (operator-supplied, at `TokenManager` construction) | `tokens/mod.rs` — key comes from operator-supplied PEM/secret, held as `jsonwebtoken::EncodingKey` in-process | **N/A by design for THIS path** — not app state, it's operator config. **But see row 25: `JwtServer::store_signing_key` is a SEPARATE path that DOES persist a caller-supplied signing key, in plaintext, no TTL** — this row's "N/A by design" framing does not generalize to the whole crate. | N/A | N/A | N/A | — | Verified; caveat added Phase 3 |
| 35 | SAML IdP metadata registry | `methods/saml/mod.rs:33` `identity_providers: HashMap<...>` | **No** — zero storage refs in file | No | No | Not checked | not filed | Verified (field) |
| 36 | Passkey/WebAuthn registrations + pending challenges | `methods/passkey/mod.rs:251,255` `RwLock<HashMap<...>>` | **No** — zero storage refs | No | No | Not checked | not filed | Verified (field) |
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
| RBAC/ABAC permission checker (role grants/revokes) | `auth_modular/authorization_manager.rs:21`, `authorization.rs:360` | `grant_permission`/`revoke_permission`/`check_user_permission` touch only the in-memory `PermissionChecker` — a `remove_role` on replica A is not honored by replica B until B restarts |
| Live OAuth2 authorization-code/refresh-token KV paths | `api/oauth2.rs` | **No Phase 1 row existed for the actual live route at all**, despite being persisted; see Part 2 |
| Live PAR/device/CIBA records that nothing ever reads back | `api/oauth_advanced.rs:401,470,544` (`par_request:`, `device:`, `ciba:`) | Dead writes — these keys have zero read call sites anywhere in `src/api/` |
| `private_key_jwt` JTI replay (JWT best-practices variant) | `server/jwt/jwt_best_practices.rs:217` | Separate from row 16's replay list; also per-instance only |
| Modular backup codes | `auth_modular/mfa/backup_codes.rs:24-33` | Plaintext, no TTL |
| API-path backup codes | `api/mfa.rs:68-89` | Unsalted SHA-256 of an 8-character code from a 32-symbol alphabet (~40 bits) — brute-forceable offline from a dump |
| Distributed rate limiter, fail-open case | `distributed/rate_limiting.rs:240-244` | When `distributed: true` but no Redis configured, `fallback_check` builds a **fresh empty in-memory limiter on every call** — every request is allowed |
| Rate-limit middleware key source | `api/middleware.rs:46-52` | Keys on client-supplied `X-Forwarded-For` — trivially spoofable, bypasses the limiter entirely despite a comment claiming otherwise |

Full per-file:line detail for the complete ~40-item census is available on
request; this table lists the subset judged security-relevant rather than
process-metric/cache-only containers.

## Part 2 — At-rest security, for every persisted subsystem

For every row above marked "Persisted: Yes," how the datum is protected at
rest: plaintext, hashed (algorithm/salt/params), or encrypted (key holder,
rotation, nonce); whether a must-never-be-recoverable secret is actually
one-way, and whether a must-be-recoverable secret (TOTP) is protected at
rest; TTL enforcement; tenant isolation in the storage key; constant-time
comparison; log/Debug/Serialize leakage; and whether a raw database dump
alone is sufficient to compromise the datum.

| Subsystem | Plaintext / Hashed / Encrypted | Recoverable-secret correctness | TTL enforced? | Tenant isolation in key? | Constant-time compare? | Debug/Serialize/log leakage | DB-dump-alone compromise? |
|---|---|---|---|---|---|---|---|
| OAuth2 client registry #2 (`oauth2_client:`) | **Plaintext** (`client_data["client_secret"]` raw JSON) | Must be one-way — **it isn't**: fully recoverable from a read | None (`store_kv(..., None)` at registration) | **No** — key is bare `client_id`, no tenant prefix; collidable across tenants on a shared backend | Yes (`constant_time_string_compare`) | JSON blob round-trips the secret in plain form through any log of `client_data` | **Yes — full compromise**, no app key needed |
| OAuth2 client registry #3 (`oauth_client:`) | **Plaintext**, same pattern | Same defect | Not checked | Same — bare `client_id` key | Yes (`constant_time_compare`) | Same risk | **Yes** |
| OAuth2 client registry #4 (`ClientRegistrationManager`) | **Hashed** — raw **unsalted SHA-256** (`hash_secret`, `client_registration.rs:704-709`), not bcrypt/argon2/HMAC | Correctly one-way in intent; weak primitive (no salt/cost factor), mitigated by 32 random bytes of secret entropy from `generate_client_secret` | Has `client_secret_expires_at` field (enforcement at read not independently confirmed) | Not checked | Yes, `ConstantTimeEq` for the registration-access-token check | `Debug`/`Serialize` not checked on this struct | Partial — cracking unsalted SHA-256 of a 256-bit random value is infeasible regardless of DB access, so a dump alone is **not** sufficient here (unlike #2/#3) |
| OAuth2 client registry #1 (`EnhancedTokenStorage`) | N/A — not persisted at all | — | — | — | — | — | — |
| API keys | **WRONG in Phase 1, corrected Phase 3: the storage key itself is `format!("api_key:{}", api_key)` — the RAW bearer key is in the key name, not just metadata in the value.** | **Incorrectly handled** — `list_kv_keys("api_key:")`, or a dump of key NAMES (not just values), yields every live API key directly | **Yes**, `expires_in` passed straight to `store_kv`'s TTL | **No** — no tenant prefix | N/A (exact-key lookup, not a comparison) | Low risk — the value blob itself has no secret, but the key name does | **Yes — a DB dump (of key names) alone yields every live bearer API key, contrary to Phase 1's claim** |
| Passwords | **Hashed**, argon2id or bcrypt per configured `PasswordHashAlgorithm` | Correctly one-way | N/A | Depends on surrounding user-record key, not independently checked | Timing-oracle-safe by construction (dummy-hash-on-unknown-user path, `user_manager.rs:91-117`) | Not checked for Debug/Serialize leakage this pass | **No** (assuming argon2id/bcrypt cost factors are adequate — not independently re-verified here) |
| **Core tokens (access/refresh) — new row, Phase 3** | **WRONG in Phase 1 ("reasonably protected"). Plaintext everywhere**: Postgres `auth_tokens.access_token`/`refresh_token` are plaintext `TEXT` columns; SQLite the same; Redis puts the raw token **in the key name** (`{prefix}access:{access_token}`). The live OAuth2 refresh-token/auth-code/revocation KV paths (`api/oauth2.rs`) also use raw token values as key names. | Must be one-way or at least opaque to a DB reader — **it isn't, anywhere** | TTL enforced on write; see Part 4 for a read-side caveat | Not checked | Not applicable (not a comparison site) | Not checked | **Yes — a database dump alone lets an attacker replay every live access/refresh token in the system.** |
| Sessions (canonical) | Session data is largely non-secret (IDs/metadata); not independently checked for embedded secret fields | N/A | Enforced via `cleanup_expired`/backend-specific expiry (Part 4) | Not checked | N/A | Not checked | Not checked |
| TOTP secret (storage-backed path) | **Plaintext** — `self.storage.store_kv(&key, secret.as_bytes(), None)`, `auth_modular/mfa/totp.rs:33` | **Correct category** (TOTP secrets must be recoverable to compute codes) but **wrong protection**: stored with zero encryption, should be encrypted at rest given it's a long-lived, recoverable, directly-exploitable-if-leaked secret (unlike a password, leaking the raw TOTP secret lets an attacker generate valid codes forever) | **None** — `None` TTL, never expires | **No** — key is `user:{user_id}:totp_secret`, no tenant prefix | N/A (not a comparison site) | Not checked | **Yes — a DB dump alone fully compromises MFA for every enrolled user.** The single most severe finding in this audit. |
| SMS/Email OTP codes | **Plaintext** 6-digit codes | Correct category (low-entropy, short-lived, one-time use — plaintext is defensible) | **Yes**, 300s (`Duration::from_secs(300)`) | No tenant prefix, but low severity given short TTL + narrow blast radius | **Yes**, `ct_eq` (`sms_kit.rs`) and `constant_time_compare` (`email/mod.rs`) | Not checked | A dump during the 5-minute window exposes active codes only — low impact |
| Consent/device-auth records (`additional_modules.rs`) | Not independently read at the byte level this pass | Not checked | Not checked | Not checked | Not checked | Not checked | Not checked |
| Audit log events | `details: HashMap<String,String>` and request metadata (IP, etc.) via `store_event`; **no encryption layer applied** (Part 3) | N/A — not a "secret" in the recoverable/one-way sense, but PII (IPs, user IDs) is sensitive | Backend-specific; `delete_old_events` exists as explicit cleanup, not an automatic TTL | Not checked | N/A | Not checked | A dump exposes the full audit trail, including whatever PII `request_metadata`/`details` carries, in plain form |

## Part 3 — Encryption-at-rest is built but unwired, and would not be sufficient even if wired (corrected Phase 3)

`src/storage/encryption.rs` defines `StorageEncryption` (AES-256-GCM, key
from the `AUTH_STORAGE_ENCRYPTION_KEY` env var) and a generic
`EncryptedStorage<T: AuthStorage>` decorator that transparently
encrypts/decrypts whatever any backend stores. **The narrow claim holds**:
it is never constructed anywhere outside its own module (zero
`EncryptedStorage::new` hits elsewhere, confirmed independently by both
Phase 1 and Phase 3) — not in `storage/factory.rs`, not in `config/mod.rs`.

**Phase 1's framing of this ("unreachable dead code," "would fix this") was
wrong, corrected in Phase 3:**

- It is **public API** (re-exported from `storage/mod.rs`, documented in
  `docs/storage-backends.md` and `docs/api-reference.md`). A consumer CAN
  wire it in today via `AuthFramework::new_with_storage`/`replace_storage`
  — it is unwired **by default**, not unreachable.
- **Wiring it would not fix the main exposures even if done:**
  - It only encrypts VALUES, never key names — the raw-bearer-value-as-key
    pattern (API keys, core tokens, OAuth2 refresh tokens) stays fully
    exposed regardless.
  - The ciphertext is not bound to its key (no associated data) — values
    could be swapped between records.
- **Wiring it today would also actively BREAK things**, not just fail to
  fully help: it doesn't override `list_kv_keys` (the trait default
  returns an empty `Vec`), which would silently empty RBAC role reload,
  maintenance/backup, and analytics on the next restart; and
  `encrypt_for_storage` rejects non-UTF-8 values, which `SecureMfaService`'s
  raw random salt bytes would hit immediately.

So fixing "secrets at rest" needs more than flipping `EncryptedStorage` on:
key-name hashing for bearer-value-as-key patterns, AAD/key-binding on the
ciphertext, and a `list_kv_keys` passthrough, at minimum, before this
decorator is actually sufficient to close the exposures it's meant to
close.

## Part 4 — Backend divergence (TTL enforcement, checked specifically)

No divergence found in TTL enforcement at read time: memory
(`dashmap_memory.rs`) checks `is_expired()` on every `get_kv` and also has a
`cleanup_expired()` sweep; Postgres filters `expires_at > NOW()` in the
`SELECT`; SQLite stores the same `expires_at` column pattern (write path
confirmed; its `get_kv` filter clause was not independently re-read this
pass — minor gap); Redis uses native `SET EX`. All four read paths behave
equivalently from a caller's perspective.

**MySQL's KV implementation was not checked this pass** — `mysql-storage`
is slated for removal under the separate RSA-removal PR4 plan, so budget
was not spent verifying it here. Flagging the omission rather than
guessing.

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
  storage gap).
- **New here:** the unwired `EncryptedStorage` decorator (Part 3).
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
  (PAR: cross-replica replay within its 90s window; device: no
  one-time-use enforcement at all).
- **Every persisted subsystem examined at the byte level stores its secret
  in plaintext, in the key name, the value, or both** — this is now a
  crate-wide pattern, not a problem isolated to one or two registries:
  API keys (raw key in the KV key name), core access/refresh tokens
  (plaintext in every backend; Redis puts the raw token in the key name
  too), two of the four OAuth2 client-secret registries, TOTP secrets, SAML
  bearer assertions, and JWT signing keys loaded via `JwtServer` are all
  either fully plaintext or trivially reversible at rest.
- **Zero of the 39 have a dedicated persistence-or-restart-or-multi-instance
  test.**
- **Encryption-at-rest (`EncryptedStorage`) is unwired by default and would
  not be sufficient even if wired** (Part 3) — it needs key-name hashing,
  AAD/key-binding, and a `list_kv_keys` passthrough added before it closes
  the exposures above.
- **Two findings are standalone authentication defects, not persistence
  gaps**, and are being tracked and fixed privately, ahead of everything
  else in this audit. Both confirmed present in previously-published
  releases, not just on `main`. No further detail is included in this
  public document pending advisory disposition.

**Is "completely broken" true?** Not literally — core routing logic works
and most subsystems that ARE persisted do survive a restart and are
visible across replicas. But Phase 3's correction makes the "built for
production use" premise even harder to defend than Phase 1 already found:
most of the "advanced" OIDC/OAuth2 protocol surface remains in-memory-only
(now confirmed to include RBAC role revocation itself — a permission
revoked on one replica is still honored by every other replica until
restart); the subsystems that genuinely are storage-backed turn out, on
closer inspection, to store their secrets in plaintext as a rule rather
than an exception; and two of the findings (tracked and fixed privately, see above) are
outright authentication bypasses reachable with no special access at all,
present in every published version anyone has installed. This is
**"fragmented and insecure where it does persist,"** not merely
"fragmented," which is a materially worse answer than Phase 1's own
already-unsoftened conclusion.

## Next steps (not actioned in this PR)

The two standalone findings referenced above are being fixed first,
privately, each with a red-first test, ahead of the broader
storage-architecture work, per the project's own severity ordering.
Remaining findings become individually-filed,
severity-ranked issues (client registry #90 first, since it's already
tracked; the plaintext-at-rest pattern across tokens/API-keys/registries
next), each fixed in its own PR with a red-first restart/multi-instance
test. Phase 2 (a two-instance integration harness against a shared backend,
Postgres in Docker and SQLite file, with a deliberate single-subsystem
sabotage proving the harness can actually fail) is still pending.
