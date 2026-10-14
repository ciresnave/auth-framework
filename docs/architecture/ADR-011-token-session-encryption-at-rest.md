# ADR-011: Encryption at rest for tokens and sessions

**Status:** Proposed (design only; no code). Written for the PM's `[TASK]` of 2026-10-14; it proposes,
CireSnave and the PM decide (open decisions are in §9). **Revision 2**, after an independent audit of
revision 1 found seven blocking defects (delete ordering, a hidden trait change, the login-path session
count, backup/restore, migration resurrection, the index-key derivation, and session scope); each is
fixed below and named where it bites.
**Facts read at:** auth-framework `origin/main` @ `08eb36e8` (0.6.0-rc55); PersistAnt
`docs/DESIGN-KINDS.md` @ `4fed258e`. A line number is a statement about that ref. Everything is by
reading; nothing was built or run.

## 0. The ruling this serves

CireSnave, board 154/156 (2026-10-08, archived verbatim in `C:\Projects\CIRESNAVE-DECIDED-ARCHIVE.md`),
option B: *"Encryption at rest is a must!"* — a stable-0.6.0 MUST, "storage-interface change, design
first". Board 124 already put the **KV layer** under encryption by default and fail-closed
(`StorageEncryption` / `EncryptedStorage`). This document covers what that left out: `store_token` and
`store_session`.

## 1. What is unprotected today (at `08eb36e8`)

| Where | What is in the clear | Evidence |
|---|---|---|
| `EncryptedStorage` | every token/session method delegates to `inner` unchanged | `src/storage/encryption.rs:876-935` |
| Postgres `auth_tokens` | `access_token` (UNIQUE, indexed), `refresh_token`, `user_id`, `client_id`, `scopes`, `metadata` | `src/storage/postgres.rs:44-74` |
| Postgres `sessions` | `session_id` (PK), `user_id`, `data` JSONB (ip, user agent, app data) | `src/storage/postgres.rs:86-105` |
| SQLite, in-tree | `access_token` column (indexed), `user_id`, `data` JSON; `sessions` likewise | `src/storage/sqlite.rs:37-56,101,182` |
| SQLite, `auth-storage-sqlite` | same shape; `access_token` UNIQUE | `auth-storage-sqlite/src/lib.rs:36-52,81,178` |
| Redis (the one the factory builds, `core.rs`) | the raw access token **in the key name** (`access_token:{raw}`), `user_tokens:{user_id}`, `session:{session_id}`; plaintext JSON body | `src/storage/core.rs:694-696,847`; factory `factory.rs:166-167` |

Facts that shape the design:

1. **Session ids and access tokens are bearer secrets.** A session id is `generate_id("sess")` and is
   returned to the client (`src/auth_modular/session_manager.rs:103`). A secret in a **key, primary key
   or unique index** is readable by anyone who can read the store, so sealing the value is not enough.
2. **Callers pass arbitrary strings as the access token** (`AuthTokenBuilder::new(.., impl Into<String>)`,
   `src/tokens/mod.rs:154`), so an unkeyed hash is not a safe index. The index must be keyed.
3. **`token_id` is bearer-adjacent.** It is the JWT `jti` for minted tokens
   (`src/auth.rs:1152-1156`, `auth_modular/mod.rs:674-678`), so every holder of the token knows it, and
   introspection calls `get_token(<raw presented token>)` (`server/token_exchange/token_introspection.rs:298,318`),
   so a raw bearer string reaches `get_token` as a "token id". (Other constructors give a random UUID,
   `tokens/mod.rs:832`; token ids are *not* generally equal to the access token.) Blind-indexing it costs
   nothing and keeps a raw presented token out of key names, so it is treated like the others.
4. **`count_active_sessions` is on the login path**, not an admin call: `create_session` runs it for the
   100 000-session cap on every login (`src/auth_modular/session_manager.rs:283-284`) and `auth.rs:1606`
   after every `delete_session`.
5. **Backup/restore enumerates the whole KV space** (`src/maintenance.rs:307-324`, `list_kv_keys("")`
   then `get_kv` per key) and restore wipes first (`reset_runtime_data`, `maintenance.rs:~486-500`).

## 2. Goals and non-goals

**Goals.** (a) In the token/session namespace, no access token, refresh token, session id, token id,
user id, or record body appears as raw bytes in a backend's data directory, dump, WAL or key space when
encryption is on. (b) Fail closed: on by default; a backend that cannot honour it is refused, never
silently downgraded. (c) Every lookup the framework uses keeps working. (d) Align with PersistAnt's
`kv.*` vocabulary so the sealing layer survives the move to `persistant-kv`.

**Non-goals.** The memory backend. Key custody (`EnvKeyProvider` stays the narrow starting point; the
roadmap item to replace it stands). Hiding that a record exists, its size, approximate expiry or write
timing. **Other KV key names**: KV keys are never encrypted (`encryption.rs`, "Key NAMES are never
encrypted"), and several subsystems put identifiers in them (`rbac:user_roles:{user_id}`, and others);
that is a separate finding, reported to the PM, not solved here. **Sessions held by a consumer-supplied
`session::SessionManager<S: SessionStorage>`**: it is generic over its own trait with no shipped
implementation and never touches `AuthStorage::store_session` (`src/session/manager.rs:472,503`), so this
design does not protect them and says so rather than implying it does. Backup *files* are #121.

## 3. Options considered

| | Option | Verdict |
|---|---|---|
| **A** | **Seal the whole record above the backend, in the KV namespace.** `EncryptedStorage` implements the token/session methods on the inner backend's KV primitives (`store_kv`, `store_kv_if_absent`, `get_kv`, `delete_kv`, `list_kv_keys`, TTL). No backend gains a typed method. | **Recommended** |
| B | Encrypt per column inside each backend. | Rejected: five implementations (Postgres, SQLite x2, core Redis, `redis.rs`) of one security property, and the unique `access_token` column still needs a blind index. |
| C | A new `RecordStore` trait replacing the typed token/session methods. | Rejected for now: breaking for every custom backend. It is where A ends up once `persistant-kv` backs the trait (§6). |

**One small trait change is unavoidable and is stated as such:** `AuthStorage::lists_kv_keys(&self) ->
bool` (default `false`, like `tracks_kv_ttl`). Three shipped backends do not override `list_kv_keys`
(`auth-storage-sqlite`, `src/storage/redis.rs`, `unified.rs`; the default returns empty with a warning,
`core.rs:213-218`), and under Option A an empty list is a silent security-relevant failure (a user's
tokens not listed, so not revoked). Requirements for the change: every shipped backend that lists returns
`true`; `impl AuthStorage for Arc<dyn AuthStorage>` (`core.rs:241-340`) and `EncryptedStorage` forward it
(a missed forward makes the factory's own type report `false` and every deployment refuse to start —
test it); a backend returning `false` is refused where the wrapper is built (§4.5).

## 4. Design (Option A)

### 4.1 Records and key names

Reserved prefix, hidden from callers (§4.5). `BI(x)` is the blind index (§4.2).

```
tok:{BI(token_id)}                       sealed AuthToken (JSON); TTL = expires_at - now
tokat:{BI(access_token)}                 BI(token_id)   (index; a hint — §4.3)
tokuser:{BI(user_id)}:{BI(token_id)}     ""             (membership; one key per token)
sess:{BI(session_id)}                    sealed SessionData (JSON); TTL = expires_at - now
sessuser:{BI(user_id)}:{BI(session_id)}  ""             (membership)
```

There is **no `tokrt:` index**: nothing in `AuthStorage` looks a token up by refresh token (the trait
methods are `get_token`, `get_token_by_access_token`, `update`, `delete`, `list_user_tokens`); the
refresh token lives only inside the sealed body. Sealed bodies carry the real ids for the caller.

Seal = the existing v2 envelope (`encrypt_for_storage`) with the **full key name as AAD**, so a record
copied to another key fails to open.

### 4.2 Keys (this needs a `StorageEncryption` change, stated)

`BI(x) = hex(HMAC-SHA256(index_key[key_id], domain || len(x) || x))`, `domain` distinct per field
(`access_token`, `user_id`, `token_id`, `session_id`). `index_key[key_id] = HMAC-SHA256(data_key,
"auth-framework/blind-index/v1" || key_id)`; `hmac` 0.12 and `sha2` 0.10 are already non-optional
dependencies (`Cargo.toml:195,204`).

**Defect found in revision 1:** `StorageEncryption` builds `ciphers: HashMap<String, Aes256Gcm>` and
zeroizes every raw key at the end of construction (`encryption.rs:548` on error, `:565` on success), so no raw key exists afterwards to
derive from. The change: derive and retain one index key per key id **inside the constructor, before the
raw key is zeroized**, in zeroizing storage within the module's existing zeroization scope; `new_random`
(key id `"test"`) does the same.

**Rotation.** Writes use the current key id. Lookups by access token/session id compute `BI` under every
loaded key id and probe each (N probes, normally 1-2). `list_user_*` unions the N user prefixes and
de-duplicates. `update_token`/`delete_*` remove index entries under the key id the *old record* was
sealed under (read from its envelope), not the current one. `auth-framework-admin security reindex`
rewrites index entries under the current key (enumerating through `tok:`/`sess:` keys, carrying each
record's remaining TTL); until it has run, lookups succeed; removing an old key before it has run makes
those records unreadable with a typed error, as for the KV layer.

### 4.3 Operations — ordering rules and why

The trait has no multi-key transaction. The rules below are chosen so that **every crash or concurrent
interleaving ends in "unreachable" or "harmless", never "wrong subject" and never "revoked token still
valid"**:

* **An index entry is a hint.** Every index read opens the record it points at and checks that the
  record's own field hashes to the queried `BI` (and, for membership, that `user_id` matches). A stale or
  forged index entry yields `None`.
* **Create:** write the record, then the indexes. Crash after the record: the token is unreachable by
  access token and unlisted, but `get_token(token_id)` works; it expires by TTL.
* **Delete: record first, then indexes.** (Revision 1 had this backwards; deleting indexes first leaves a
  live record that validates by id and is invisible to bulk revocation.) Crash after the record: the
  token is gone, orphan index entries are harmless by the hint rule and are removed lazily when seen.
  If the record cannot be opened (its key was rotated out), `delete_*` still deletes the record key and
  leaves its indexes to their TTL, so `reset_runtime_data` can always wipe. `delete_*` also deletes the
  legacy typed row **unconditionally** (§5 rule 3), and returns that error if the legacy delete fails
  after the sealed delete succeeded: a revoke must not report success while a legacy row lives.
* **Access-token uniqueness** (today a UNIQUE column on three backends). `tokat:` is written with
  `store_kv_if_absent`; if an entry exists and verifies to a *different live* token, `store_token`
  fails with a duplicate error; a stale entry (record gone or its access token differs) is overwritten.
  If the entry already verifies to *this same* token (an update that only extends `expires_at`), it is
  rewritten with a plain `store_kv` so its TTL follows the record (`store_kv_if_absent` only takes over
  *expired* rows, `postgres.rs:416`, `sqlite.rs:282`). `delete_token` removes `tokat:` only if it still
  points at *this* token.
* **Update of an absent record is a no-op returning `Ok`** (the Postgres `UPDATE ... WHERE` semantics,
  not the SQLite/Redis upsert), so a concurrent delete is never resurrected by an update that lost the
  race. It must be `Ok`, not an error: `revoke_token` calls `update_token` with the caller's clone and
  only then writes the `revoked_token:{jti}` marker that JWT validation consults (`auth.rs:1495-1516`);
  an error would skip the marker for a legacy-only, TTL-evicted or never-stored token. During migration an
  update first reads through (§5 rule 2) and seals the legacy row, then updates. If the access token, `user_id` or `expires_at` changed: write new indexes
  (with the new TTL) first, then delete the old ones. **Concurrent read-modify-write remains
  last-writer-wins**, as today (`auth.rs:1338-1349` touch vs `auth.rs:1501` revoke); closing that needs
  `kv.compare_and_swap`/`kv.batch_atomic` (§6) and is out of scope. The test plan pins the current
  behaviour so it is not silently worse.
* **`get_token`** also re-checks `expires_at` (TTL is the backstop, the check is the rule); closes the
  #144 class for sealed records.
* **Sessions** follow the same shape. Session mutation in `session_manager.rs:161-163,252-255` is
  get → mutate → store and keeps that shape.

`count_active_sessions`: see §4.4. `cleanup_expired`: delegate to `inner` (TTL does the work).

### 4.4 `count_active_sessions` is a login-path call (decision D-E6)

A scan of `sess:*` per login is unacceptable on core Redis (`KEYS`, then a TTL call per key,
`core.rs:1050-1075`) and O(n) elsewhere. The cap is a DoS guard, not an invariant. Options: (1) exact
scan on every login (rejected); (2) a counter key (rejected: no atomic increment in the trait); (3)
**the exact scan stays for `count_active_sessions()` itself, and two call sites read a per-process
cached count refreshed at most every 30 s: the cap check in
`auth_modular::SessionManager::create_session` (`session_manager.rs:283-284`) and the monitoring count
after every `delete_session` (`auth.rs:1600-1610`)** (recommended; both are part of the implementing PR
and its `files=`). The stats paths (`auth.rs:1683/2046/2764/2779`) keep the exact value at their own
cost. Bound to price: the cap can be exceeded by (login rate x 30 s x processes).

### 4.5 Reserved prefix, maintenance, and the refusal point

* **Hidden from callers.** `EncryptedStorage`'s public `store_kv`/`get_kv`/`delete_kv`/`list_kv_keys`
  reject **reads, writes and deletes** of, and omit from listings, keys under the reserved prefixes (a
  caller `get_kv("tok:<BI>")` would otherwise open a sealed record, AAD = that key, and return the token
  JSON); internals use `inner` directly. Consequence for `maintenance.rs`: snapshot `list_kv_keys("")` does **not** see sealed
  records (they are captured once, through `list_user_*`/typed methods, not duplicated as base64
  plaintext in `kv_entries`); restore's `store_kv` never targets reserved keys (so it cannot abort after
  `reset_runtime_data` has wiped the store); `reset_runtime_data`'s typed deletes remove records *and*
  indexes. The hiding check must use the **same match rule as the scan**: SQL backends list with
  unescaped, ASCII-case-insensitive `LIKE '<prefix>%'` (`postgres.rs:502`, `sqlite.rs:351`), memory with
  `starts_with`, Redis with a glob; the reserved prefixes are lowercase with no `%_*?[`, and a
  caller key `SESS:x` is rejected too.
* **Where the refusal lives.** `EncryptedStorage::new` returns no `Result` today and the factory does not
  wrap custom storage (`factory.rs:67-100`). Add `EncryptedStorage::try_new`, which returns an error
  when `inner.lists_kv_keys()` is false or `inner.tracks_kv_ttl()` is false; the factory uses it; and
  the token/session methods of any `EncryptedStorage` built through the old `new` return a typed
  `Storage` error under the same condition rather than an empty list. **This is a breaking change** for
  direct `EncryptedStorage::new(UnifiedStorage | auth-storage-sqlite | a custom backend)` users and for
  in-tree test backends that do not report `tracks_kv_ttl()`; it goes in the changelog as Breaking.

## 5. Migration (0.6.0 is unreleased, so breaking inside the rc line is allowed)

The audit showed read-through alone is unsound, so the rules are explicit:

1. **Mode.** Legacy fall-through is on only when `allow_plaintext_reads` is true (the existing
   "transitional" flag). With it false, legacy rows are unreachable: fail closed, affected users
   re-authenticate. Because startup cannot enumerate (rule 5), the first sealed miss per process probes
   `inner` for that one id and, if a legacy row exists, logs a `warn` naming `encrypt-tokens`, so the
   plaintext tail is not silent.
2. **Reads.** `get_token`/`get_session`/`get_token_by_access_token` and `update_token` on a sealed miss
   → the matching `inner.*` → if found, seal into the new namespace and delete the legacy row (then, for
   an update, apply it). Every read-through of one row therefore migrates it.
3. **Deletes** also call `inner.delete_*`, **regardless of the flag** (otherwise a row deleted while the
   flag was false is reachable again when it is set back to true, and a deleted token is resurrected by
   the next read-through). A failing legacy delete is returned (§4.3).
4. **Lists and counts** union the sealed namespace with `inner.list_user_tokens` /
   `inner.list_user_sessions` / `inner.count_active_sessions` (typed per-user methods exist; migrated rows
   are deleted from legacy at seal time, so the sets are disjoint). Without this, `revoke_all_user_sessions`
   and the per-user limits (100 tokens, 50 sessions) would not see legacy rows that `get_session` still
   serves.
5. **No startup enumeration.** The trait has no "list all tokens", and the existing
   `stored_envelopes_exist` probe (`factory.rs:35-60`) is a `warn`, only for the env-key source, skipped
   for Redis, and counts envelopes not plaintext rows; it is **not** a precedent for a refusal. Instead
   `auth-framework-admin security encrypt-tokens` enumerates per backend (SQL `COUNT`/`SELECT`, Redis
   `SCAN`), seals, reports the count remaining, and offers `--purge-legacy` (delete: forced re-login).
6. **Plaintext tail** is bounded by the longest lifetime (sessions: 1 year max,
   `session_manager.rs:95`); the operator chooses sweep vs purge.
7. **Prerequisite:** the Postgres typed `sessions` methods used by read-through are the broken ones
   (#147: four `sessions` schemas; `list_user_sessions` selects columns `migrate()` never creates). #147
   lands first or read-through treats that backend's session fall-through as unavailable and says so.

## 6. Alignment with PersistAnt (D5)

| This design needs | PersistAnt id (DESIGN-KINDS §2.2) | Today in auth-framework |
|---|---|---|
| get/put/delete | `kv.get`, `kv.put`, `kv.delete` | `get_kv`, `store_kv`, `delete_kv` |
| expiry; expired invisible to get **and** list | `kv.ttl` | `store_kv(ttl)`; SQLite truncates to whole seconds (#146), so record and index TTLs on SQLite can differ by 1 s |
| list a user's index prefix | `kv.ordered_scan` (PersistAnt **refuses** this on Redis: "`KEYS` is neither ordered nor bounded") | `list_kv_keys`; 3 backends lack it (#145); core Redis uses `KEYS` (#148) |
| access-token uniqueness | `kv.put_if_absent` | `store_kv_if_absent` (atomic on all shipped) |
| session count | `kv.count` | `count_active_sessions` |
| index + record atomic | `kv.batch_atomic` (DESIGN-KINDS names this very use) | absent; §4.3 is built to work without it |
| single-use consume | `kv.take` | not needed by this design |

* Our need is *prefix listing*, not *order*. Under PersistAnt's own rule today's core Redis backend would
  be refused for `kv.ordered_scan`. The proposal to PersistAnt (theirs to accept) is a weaker leaf,
  `kv.prefix_list` (bounded, unordered), that a `SCAN MATCH` backend could pass. Until it exists, the
  core Redis path stays supported through `AuthStorage::list_kv_keys` (after #148) and is **not**
  expressed as a `persistant` need.
* **Acceptance test = `storage.no_plaintext_at_rest`:** distinct canary strings as access token, refresh
  token, session id, user id and token id; search the backend's raw bytes (SQLite file, `pg_dump` and
  WAL, Redis RDB/`DUMP`) and find **none**; positive control: the same search with encryption off finds
  **all** of them.
* When `persistant-kv` backs `AuthStorage`, this sealing layer sits above it unchanged and the typed
  tables are retired; §5 is the import path (PersistAnt non-goal #10).

## 7. Test plan (tests first, red evidence kept)

1. Canary test per shipped backend, **with its positive control** (§6).
2. Round trip across restart; expiry: `get_token` refuses a token past `expires_at` even when the
   backend TTL has not fired (known-bad control: a TTL-ignoring stub).
3. Index integrity: forged `tokat:` pointing at another user's token → `None`; sealed record moved to
   another key → fails to open; **same access string for two tokens → second `store_token` fails**, and
   deleting the first leaves the second reachable.
4. **Delete ordering:** an inner storage that fails after the record delete leaves no state where
   `get_token(token_id)` or `list_user_tokens` returns the token; one that fails after index deletes (old
   ordering) is the known-bad control and must fail this test.
5. Update after delete → `Ok` no-op, never resurrection; `revoke_token` of a legacy-only token during
   the tail, of a TTL-evicted token and of a never-stored token still writes the `revoked_token:{jti}`
   marker; refresh rotation keeps both indexes consistent; an `expires_at`-only update extends `tokat:`.
6. Rotation: seal under A, rotate to B; lookup and list succeed before and after `reindex`; removing A
   without `reindex` yields a typed error, not a wrong token.
7. Maintenance: snapshot contains each token once; restore of that snapshot into a wiped store succeeds
   and the tokens validate; a reserved-prefix `store_kv` from a caller is rejected.
8. Migration: legacy row sealed on read and legacy deleted; `delete_token` on a legacy-only token really
   deletes it; `revoke_all` sees legacy sessions during the tail; `--purge-legacy` leaves canaries absent.
9. A custom backend with the default `list_kv_keys` is refused (`try_new`) and its token methods error;
   the factory's `Arc<dyn AuthStorage>` wrapper reports `lists_kv_keys() == true` for a listing backend.
10. Login/logout cost: with 100 000 stub sessions, `create_session` and `delete_session` issue no scan
    (cached count).
11. Flag toggle: delete while `allow_plaintext_reads=false`, set it true, the token is still gone; a
    record whose key was rotated out is still wiped by `reset_runtime_data`; caller `get_kv`/`delete_kv`
    of a reserved key is rejected.

## 8. Cost and risk

* An extra KV round trip per `get_token_by_access_token`, N under rotation; `list_user_*` is a prefix
  scan (unescaped `LIKE`, ASCII-case-insensitive on SQLite; whether the key index serves it depends on
  collation/`text_pattern_ops` and was not measured).
* Operators: the typed `auth_tokens`/`sessions` tables stop being written when encryption is on.
* `tokuser:{BI(user)}` makes one user's tokens linkable without revealing the user (an accepted
  trade-off, D-E3). Session ids also appear in audit events; the audit backends are tracing/unimplemented
  (`audit.rs:319,401`), so that is not at-rest in a storage backend today.
* `unified.rs` applies a default TTL to a `None` TTL write (`unified.rs:524-529`): irrelevant to this
  design (every sealed write carries a TTL) but a trap for anyone adding a non-expiring index.

## 9. Decisions for CireSnave / the PM

| # | Decision | Options | Recommend |
|---|---|---|---|
| D-E1 | Layer | A seal-above-KV; B per-column; C `RecordStore` trait | **A** |
| D-E2 | Index function | keyed HMAC with key probing; unkeyed SHA-256 | **HMAC** (§1 fact 2) |
| D-E3 | One user's tokens linkable by `BI(user_id)` | accept; scan-all and filter | accept |
| D-E4 | `token_id` | clear; blind-indexed | **blind-indexed** (§1 fact 3) |
| D-E5 | Plaintext tail | sweep or purge at the operator's choice; forced purge at upgrade | operator's choice |
| D-E6 | Session cap check and post-delete count | exact scan; counter; per-process cached count, bound = login rate x 30 s x processes over the cap (§4.4) | **cached count** |
| D-E7 | Build order | #145, #144, #147, #148, #146, then the sealing layer; or sealing first | **prerequisites first** (sealing first would ship `KEYS` per login on Redis and the SQLite TTL truncation) |
| D-E8 | Trait change `lists_kv_keys` (§3) | add; ship Option A without it | **add** |

## 10. UNVERIFIED

* Whether `session::SessionManager<S>` has any non-test `SessionStorage` implementation outside this
  repo; none shipped (`manager.rs:1746` is a test impl).
* Redis `KEYS` behaviour under load; index use by `LIKE 'prefix%'` on each SQL backend (collation).
* Whether the views/triggers in `src/migrations/003_create_sessions_table.sql` are executed anywhere, and
  whether anything outside `src/storage`, `auth-storage-sqlite` and migration SQL reads
  `auth_tokens`/`sessions` directly (a `git grep` at the ref found nothing else; not exhaustive).
* That `token_id` is logged anywhere (a same-line macro search found none; multi-line calls would be
  missed). The earlier claim that it is logged is withdrawn; revocation by id (`revoked_token:{jti}`) is
  verified.
* Size of the §5 plaintext tail for any real deployment.
* Nothing in this document was built or run.
