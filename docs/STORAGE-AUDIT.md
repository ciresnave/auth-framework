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

This is **Phase 1** of a 3-phase audit (read-only inventory). Phase 2 (a
two-instance integration-test harness proving cross-instance visibility and
restart-safety, with a deliberate sabotage case) and Phase 3 (an independent
adversarial re-check of this table's completeness) follow once this phase is
reviewed. No code changes, no version bump — this PR is docs only.

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
| 12 | Secure session store (separate from #7/#9) | `security/secure_session.rs:231-233` `active_sessions`/`user_sessions`/`ip_changes`: `DashMap`, but file has 2 storage calls elsewhere | Partially — mixed | Partial | Partial | Has its own tests | not filed | **Partially verified** — did not trace which specific calls hit storage vs. the `DashMap`s |
| 13 | Device authorization grant | `server/oauth/device.rs:118` `authorizations: Arc<RwLock<HashMap<...>>>`, but file has 4 `AuthStorage` refs / 12 storage calls | **Mixed**, unclear | Unclear | Unclear | Not checked | not filed | **Unverified** — contradictory signal (local `HashMap` *and* heavy storage use); needs a closer read |
| 14 | Pushed Authorization Requests (PAR) | `server/oauth/par.rs:163` `requests: Arc<RwLock<HashMap<...>>>`, file has 4 `AuthStorage` refs but only 2 storage calls | Likely **No**, mostly local | No | No | Not checked | not filed | **Unverified** — same ambiguity as #13 |
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
| 25 | Consent records / device-auth records | `server/core/additional_modules.rs:487,819`; file has 19 storage refs / 14 storage calls | Yes, heavily | Yes | Yes | Yes (several `test_saml_idp_*`, consent tests) | not filed | Verified (counts only — did not read each call site) |
| 26 | TOTP secret (storage-backed path) | `auth_modular/mfa/totp.rs:10-34` | Yes, KV | Yes | Yes | Yes (`totp1`/`nobody` tests) | not filed | Verified |
| 27 | TOTP (second, stateless path) | `authentication/mfa.rs:152` `TotpProvider` — holds only config, no storage field at all | N/A — caller's responsibility | N/A | N/A | Not checked | not filed | Verified |
| 28 | SMS/Email MFA OTP codes | `auth_modular/mfa/sms_kit.rs:331`, `mfa/email.rs:159` | Yes, KV, 300s TTL | Yes | Yes (code itself) | SMS/email verification tests exist | not filed | Verified |
| 29 | MFA **challenge records** (type/expiry/user — separate from the code above) | `auth_modular/mfa/mod.rs:126` `challenges: Arc<RwLock<HashMap<...>>>` | **No** | **No** | **No — a correctness bug, not just durability**: the OTP code lives in shared storage but the challenge record that says "this challenge exists, here's its type/expiry" does not; a verify request landing on a different instance than the one that created the challenge finds no challenge record | Not checked | not filed | Verified |
| 30 | Rate limiter (`utils::rate_limit::RateLimiter`) | `utils/rate_limit.rs:18-21` `Arc<Mutex<HashMap<...>>>` | No | No | No | Yes, extensively tested | not filed | Verified |
| 31 | "Distributed" rate limiter | `distributed/rate_limiting.rs:122,250,532`, primarily `DashMap`-based, **optionally** backed by a real Redis limiter only `#[cfg(feature = "redis-storage")]` and only when `config.distributed && config.redis_url.is_some()` | **Conditional** — in-memory by default, Redis-backed only if explicitly configured | Conditional | Conditional | Not checked | not filed | Verified |
| 32 | Tenant registry | `tenant/registry.rs:59-65` `Arc<DashMap<TenantId, ...>>` | **No** | **No** | **No** | Yes (several `tenant::registry::tests::*`) | not filed | Verified |
| 33 | Audit log events (the real audit system) | `audit.rs` → `AuditStorage::store_event` etc.; 12 storage calls | Yes | Yes | Yes | Not re-checked this pass | — | Verified (mechanism only) |
| 34 | JWKS / signing key material | `tokens/mod.rs` — key comes from operator-supplied PEM/secret at construction, held as `jsonwebtoken::EncodingKey` in-process | **N/A by design** — not app state, it's operator config | N/A | N/A | N/A | — | Verified |
| 35 | SAML IdP metadata registry | `methods/saml/mod.rs:33` `identity_providers: HashMap<...>` | **No** — zero storage refs in file | No | No | Not checked | not filed | Verified (field) |
| 36 | Passkey/WebAuthn registrations + pending challenges | `methods/passkey/mod.rs:251,255` `RwLock<HashMap<...>>` | **No** — zero storage refs | No | No | Not checked | not filed | Verified (field) |
| 37 | Client-cert pinning + per-cert revocation | `methods/client_cert/mod.rs:468,523` | **No** | No | No | Not checked | not filed | Verified (fields) |
| 38 | Monitoring metrics/health/security-event history | `monitoring/mod.rs:303,305,307`, `collectors.rs` (`AtomicU64` counters) | No — correctly ephemeral by design (process metrics, not credentials) | No | No | Not checked | N/A | Verified |

**Could not fully verify this pass** (flagged rather than silently dropped): #12
(`secure_session.rs` mixed storage/local split), #13 (`device.rs` —
contradictory storage signal), #14 (`par.rs` — same), #25's individual
call-site content (only the aggregate counts were confirmed).

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
| API keys | **Plaintext JSON** metadata (`user_id`/`created_at`/`expires_at`) — the key material itself (`ak_<32-byte-token>`) is never stored, only its metadata | Correctly handled — bearer value is the key, never persisted | **Yes**, `expires_in` passed straight to `store_kv`'s TTL | **No** — key is `api_key:{key}`, no tenant prefix, but collision risk is negligible given the key itself is the high-entropy secret | N/A (exact-key lookup, not a comparison) | Low risk — metadata blob has no secret | **No** — a dump gives you `user_id`/timestamps per issued key, not the bearer key; cannot forge a working key from the dump |
| Passwords | **Hashed**, argon2id or bcrypt per configured `PasswordHashAlgorithm` | Correctly one-way | N/A | Depends on surrounding user-record key, not independently checked | Timing-oracle-safe by construction (dummy-hash-on-unknown-user path, `user_manager.rs:91-117`) | Not checked for Debug/Serialize leakage this pass | **No** (assuming argon2id/bcrypt cost factors are adequate — not independently re-verified here) |
| Sessions (canonical) | Session data is largely non-secret (IDs/metadata); not independently checked for embedded secret fields | N/A | Enforced via `cleanup_expired`/backend-specific expiry (Part 4) | Not checked | N/A | Not checked | Not checked |
| TOTP secret (storage-backed path) | **Plaintext** — `self.storage.store_kv(&key, secret.as_bytes(), None)`, `auth_modular/mfa/totp.rs:33` | **Correct category** (TOTP secrets must be recoverable to compute codes) but **wrong protection**: stored with zero encryption, should be encrypted at rest given it's a long-lived, recoverable, directly-exploitable-if-leaked secret (unlike a password, leaking the raw TOTP secret lets an attacker generate valid codes forever) | **None** — `None` TTL, never expires | **No** — key is `user:{user_id}:totp_secret`, no tenant prefix | N/A (not a comparison site) | Not checked | **Yes — a DB dump alone fully compromises MFA for every enrolled user.** The single most severe finding in this audit. |
| SMS/Email OTP codes | **Plaintext** 6-digit codes | Correct category (low-entropy, short-lived, one-time use — plaintext is defensible) | **Yes**, 300s (`Duration::from_secs(300)`) | No tenant prefix, but low severity given short TTL + narrow blast radius | **Yes**, `ct_eq` (`sms_kit.rs`) and `constant_time_compare` (`email/mod.rs`) | Not checked | A dump during the 5-minute window exposes active codes only — low impact |
| Consent/device-auth records (`additional_modules.rs`) | Not independently read at the byte level this pass | Not checked | Not checked | Not checked | Not checked | Not checked | Not checked |
| Audit log events | `details: HashMap<String,String>` and request metadata (IP, etc.) via `store_event`; **no encryption layer applied** (Part 3) | N/A — not a "secret" in the recoverable/one-way sense, but PII (IPs, user IDs) is sensitive | Backend-specific; `delete_old_events` exists as explicit cleanup, not an automatic TTL | Not checked | N/A | Not checked | A dump exposes the full audit trail, including whatever PII `request_metadata`/`details` carries, in plain form |

## Part 3 — The single biggest finding: encryption-at-rest is built but completely unwired

`src/storage/encryption.rs` defines `StorageEncryption` (AES-256-GCM, key
from the `AUTH_STORAGE_ENCRYPTION_KEY` env var) and a generic
`EncryptedStorage<T: AuthStorage>` decorator that transparently
encrypts/decrypts whatever any backend stores. **It is never constructed
anywhere outside its own module** (`git grep -n "EncryptedStorage::new" --
'src/**/*.rs'` outside `encryption.rs` itself: zero hits) — not in
`storage/factory.rs` (the actual backend builder, read directly: no
reference to encryption at all), not in `config/mod.rs`, not anywhere.

So regardless of which backend an operator configures (Postgres/SQLite/
Redis/MySQL/memory), **everything persisted through `AuthStorage` is stored
at exactly the plaintext/hash/whatever-the-caller-passed-in level the
application code chose, with zero additional at-rest encryption layer ever
applied.** This is a real, verified capability gap in application wiring,
not a backend-specific one — it affects every backend identically.

**Resolved (P1, 0.6.0-rc12):** `storage/factory.rs` now wraps every
persistent backend in `EncryptedStorage` by default, with a redesigned
`StorageEncryption` (versioned multi-key envelope, AAD-bound nonces, raw-byte
support), fail-closed startup if no key is configured, and a migration tool
for data already written as plaintext. Because the TOTP-secret
plaintext-at-rest finding above (this audit's single most severe finding)
is itself a `store_kv` call, it is directly fixed by this: every new TOTP
secret is now encrypted at rest by default, and the migration tool can
re-encrypt already-stored ones. **Scope note, not fully closed:** this
wrapper covers the KV layer only. Core token/session storage in general
(`store_token`/`store_session`) still goes through each backend's own typed
columns, not `store_kv`, and is not covered. See `docs/ROADMAP.md`'s
"Storage and Scaling" section for that follow-up, and `CHANGELOG.md`'s
`[0.6.0]` "Added" section for the full change.

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

## Summary — stated directly, not softened

Of the **38 stateful subsystems** surveyed: **9 are genuinely persisted**
through the pluggable `AuthStorage` backends and would survive a restart
and work correctly across replicas (API keys, passwords, the canonical
session path, both previously-known client registries #2/#3, the
newly-found registry #4, storage-backed TOTP secrets, SMS/email OTP codes,
consent/device-auth records, and the audit log — overlapping categories
collapsed).

**The remaining ~29 are in-process-only state** — rate limiters, nearly
every "advanced protocol" module's session/request tracking (CAEP, FAPI,
mTLS, PAR, RAR, CIBA, backchannel/frontchannel logout, DPoP nonces,
`private_key_jwt` JTI replay list, X.509 CA/revocation list, tenant
registry, SAML IdP metadata, passkey registrations, client-cert pinning,
the secondary JWT revocation list, and — critically — **MFA challenge
records**, which breaks multi-instance MFA even though the underlying OTP
code is itself stored correctly).

**Zero of the 38 have a dedicated persistence-or-restart-or-multi-instance
test** found in this pass; the only tests found are ordinary
CRUD-in-memory unit tests.

**Of the subsystems that ARE persisted, the one meant to hold a
must-stay-secret recoverable value (TOTP secrets) is stored as unencrypted
plaintext with no expiry**, and the entire crate has a built,
tested-looking, but completely unwired application-level
encryption-at-rest facility (`EncryptedStorage`) that would fix this and
the two plaintext client-secret registries in one move if actually used
anywhere.

**Is "completely broken" true?** Not literally — core auth artifacts
(tokens, sessions, passwords, API keys) are genuinely persisted and
reasonably protected. But **the premise behind "built for production use"
is substantially undermined**: most of the "advanced" OIDC/OAuth2 protocol
surface (CAEP, FAPI, PAR, RAR, CIBA, logout coordination, DPoP replay
protection, step-up auth) is in-memory-only and will silently misbehave the
moment there's more than one instance or a restart; MFA challenge
continuity breaks across replicas even though it looks storage-backed; and
the crate's own answer to "how do I encrypt data at rest" is unreachable
dead code. This is closer to **"large parts of the surface area were built
to look production-ready but were never wired into real persistence or
multi-instance safety"** than to "limited to in-memory storage" — it's
fragmented, not just unfinished.

## Next steps (not actioned in this PR)

Per the audit plan: findings become individually-filed, severity-ranked
issues (client registry #90 first, since it's already tracked), each fixed
in its own PR with a red-first restart/multi-instance test (Phase 2 — needs
a two-instance integration harness against a shared backend, Postgres in
Docker and SQLite file, with a deliberate single-subsystem sabotage proving
the harness can actually fail). Phase 3 is an independent adversarial
review of both the at-rest handling and this table's own completeness,
working from its own grep of statics/caches rather than trusting this
table, so the two methods can disagree-check each other.
