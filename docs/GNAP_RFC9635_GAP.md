# GNAP: `src/protocols/gnap.rs` against RFC 9635 (and RFC 9767)

Status: **gap note, slice G0**. Written from the RFC text (<https://www.rfc-editor.org/rfc/rfc9635.txt>,
<https://www.rfc-editor.org/rfc/rfc9767.txt>), not from the Internet-Draft the module header used to cite.
Code claims are file:line in `src/protocols/gnap.rs` at `b66692a7` (the `GnapService` hardening, 0.6.0-rc217), re-measure
before acting on any line number. Nothing here is implemented by the change that adds this file.

States: **done** (behaves as the RFC says, verified by a test), **partial** (some of the section, or a different shape),
**missing** (no code), **n/a** (a registry, or the integrator's job by design). The RFC's own section numbers are used.

## 0. What the module is

An in-memory grant engine without an HTTP layer: `GnapService` holds `transactions` and `issued_tokens` in two `HashMap`s
(lines 398-408) and is driven by method calls, not requests. It is not served by `src/api`; an integrator wires it.
Everything is lost on restart and is not shared across instances (compare ROADMAP A3 for WS-Trust).

## 1. Section by section

### 2 Requesting access

| RFC | State | What the code does | Gap |
|---|---|---|---|
| 2.1 `access_token` object / array of objects | **partial, wire shape differs** | `access_token: Option<Vec<GnapAccessRequest>>` (58) is the array of access objects itself | The RFC's `access_token` is an object `{access, label, flags}` or an array of those. A request in RFC shape (`{"access_token": {"access": [...]}}`) does not deserialize. Needs polymorphism (RFC Appendix E) |
| 2.1.1 `label`, `flags` (`bearer`, `split`) | **missing** | none | Label must be echoed back; flags change token behaviour |
| 2.1.2 multiple access tokens | **missing** | one token per grant | |
| 2.2 `subject` (`sub_id_formats`, `assertion_formats`, `sub_ids`) | **partial** | formats are parsed (82, 85); `sub_ids` is not a field | `sub_ids` (a specific subject) and assertions are missing |
| 2.3 `client` by value | **partial** | `GnapClientInfo { key, display }` (89-93); a key is required since rc217 | `class_id` missing; `display.logo_uri` missing (display has `name`, `uri` only, 135-137) |
| 2.3.1 `client` by reference (string) | **missing** | the field is an object only | |
| 2.3.3 authenticating the client instance | **partial** | see 7.3 | only one method verifies |
| 2.4 `user` (and by reference) | **missing** | no field | needed for user hints and for acting on behalf of an account holder |
| 2.5 `interact.start` | **partial** | `start: Vec<String>` (142); only `"redirect"` produces a response (931) | `app`, `user_code`, `user_code_uri` are accepted and ignored; the object form of `start` is not supported |
| 2.5.2 `interact.finish` | **partial** | `{method, uri, nonce}` (148-150); `method` is not validated | `redirect` and `push` are the RFC's values; `hash_method` is missing (sha-256 only, 775-782) |
| 2.5.3 `interact.hints` (`ui_locales`) | **missing** | none | |

### 3 Grant response

| RFC | State | What the code does | Gap |
|---|---|---|---|
| 3.1 `continue` (`uri`, `wait`, `access_token`) | **partial** | `uri` is `{transaction_endpoint}/continue` (999-1000, 1150-1153), `wait` is the constant 5 (1156), a rotated continuation token (done, tested) | `uri` is the configured path, the RFC wants an absolute URI; `wait` is not enforced (`too_fast` is never returned) |
| 3.2.1 access token `value`, `expires_in`, `access` | **done / partial** | `value`, `expires_in` (832), `access` = what the policy granted (the token is no longer the request echoed) | `access` may differ from the request, which the RFC allows; strings (8.1) are not represented |
| 3.2.1 `label`, `flags` | **missing** | none | a key-less token carries no `bearer` flag |
| 3.2.1 `manage` | **wrong type** | a string `{endpoint}/token` (838-839, 1326-1327), the same for every token | RFC: an object `{uri, access_token}`, uri per token, with its own key-bound management token |
| 3.2.1 `key` | **wrong type** | `"key": true` (844, 1330) | RFC: object or string (7.1), absent when the presented key applies; a boolean is not a defined value |
| 3.2.2 multiple access tokens | **missing** | | |
| 3.3 interaction responses | **partial** | `redirect` (931-935), `finish` = the AS nonce (941) | `app`, `user_code`, `user_code_uri`, `expires_in` missing |
| 3.4 subject information | **partial** | `sub_ids` in `opaque`, `email`, `iss_sub` (1439-1471); `iss` is the literal `"self"` (1457) | `assertions` and `updated_at` missing; `iss` should be the AS identifier |
| 3.5 `instance_id` | **missing** | | |
| 3.6 error response | **missing** | failures are `AuthError` strings; the continuation refusals share one message (410) | no `error` object, none of the registered codes (`invalid_request`, `invalid_client`, `invalid_interaction`, `invalid_flag`, `invalid_rotation`, `key_rotation_not_supported`, `invalid_continuation`, `user_denied`, `request_denied`, `unknown_user`, `unknown_interaction`, `too_fast`, `too_many_attempts`) |

### 4 Determining authorization and consent

| RFC | State | What the code does | Gap |
|---|---|---|---|
| 4 AS decides what to grant | **partial** | an integrator's `GnapAccessPolicy` (375-382, `with_access_policy` 437) returns the rights granted; empty denies; no policy denies (803-810) | the policy is a yes/narrow function of (client key thumbprint, requested rights): no consent record, no resource owner, no rule model, no deny effect, no engine behind it (slice G6, rows AC1-AC4) |
| 4.1 starting interaction | **n/a** | the AS's own UI is the integrator's | |
| 4.2 completion: one-time `interact_ref`, hash | **partial** | `approve_transaction` returns `{interact_ref, hash}` (1228, struct at 391); continuation of a finish-method transaction needs the reference; hash per 4.2.3 | the AS does not deliver them (no redirect URI built, no `push` callback, SSRF rules of 11.34 not applicable yet); the hash uses `transaction_endpoint` as given, the RFC wants the absolute grant URL the client used (782) |
| grant states (1.5: pending, processing, approved, finalized) | **partial** | `Pending`, `Approved`, `Denied` (279-283) | no `processing`, no `finalized`; a finished transaction is deleted |

### 5 Continuing a grant request

| RFC | State | What the code does | Gap |
|---|---|---|---|
| 5.1 after interaction (POST `interact_ref`) | **done** | `continue_transaction_with_proof` (1037) | the HTTP shape is the integrator's |
| 5.2 polling | **partial** | a pending transaction answers with a new `continue` (1150-1163) | no `too_fast`, no `too_many_attempts` |
| 5.3 modify (PATCH) | **missing** | | |
| 5.4 revoke a grant (DELETE) | **missing** | `deny_transaction` (1270) is the AS side only | the client cannot cancel; tokens of a cancelled grant are not revoked |

### 6 Token management

| RFC | State | What the code does | Gap |
|---|---|---|---|
| 6.1 rotate | **partial** | `rotate_token(value)` (1292): a new value, same rights and binding | no proof from the client key on the call, no management token, no `invalid_rotation`; 6.1.1 key rotation missing |
| 6.2 revoke | **partial** | `revoke_token(value)` (1282) | no proof from the client key |

### 7 Securing requests

| RFC | State | What the code does | Gap |
|---|---|---|---|
| 7.1 key formats | **partial** | `jwk` (107); thumbprint per RFC 7638 for EC, RSA, OKP (446) | `cert` and `cert#S256` missing; key references (7.1.1) missing |
| 7.2 `Authorization: GNAP <token>` | **missing** | there is no HTTP layer | parsing and the key-bound presentation rules |
| 7.3.1 `httpsig` (RFC 9421, tag `gnap`, Content-Digest RFC 9530) | **missing, refused** | refused as not supported (761) | verified support needs a signature-base builder and verifier; look for a maintained crate before writing one |
| 7.3.2 `mtls` | **missing, refused** | refused (761); the crate has certificate validation elsewhere (`src/server/security/mtls.rs`) | to connect |
| 7.3.3 `jwsd` (detached JWS) | **missing** | the name is not in the accepted list at all (632, 705) | |
| 7.3.4 `jws` (attached JWS) | **missing, refused** | refused (761) | |
| `dpop` | **extension, not in the RFC** | verified through `DpopManager::validate_dpop_proof_for_key` (736-759) | `dpop` is not a registered GNAP key proofing method (RFC 9635 10.16 lists `httpsig`, `mtls`, `jwsd`, `jws`). It is the one method that verifies today; keep it as a named extension or register it, a decision for slice G3 |

Nothing claims a method it does not verify: an unlisted or unverifiable method is refused (761), and the unit-test-only `"test"` method is compiled out of a build (760).

### 8 Resource access rights

| RFC | State | Gap |
|---|---|---|
| 8 access object | **partial** | `type`, `actions`, `locations` (68-74); `datatypes`, `identifier`, `privileges` missing |
| 8.1 references (strings) | **missing** | an `access` entry that is a string cannot be represented |

### 9 Discovery

**Missing.** No `OPTIONS` response on the grant endpoint (9.2) and no RS-first method (9.1). Depends on the HTTP layer (G7).

### 10 and 11

10 is IANA. 11 (security considerations) has no item-by-item test coverage; slice G10 adds one test per item. Specifically open: 11.18 callback URI manipulation, 11.19 redirection status codes, 11.23-11.25 finish modes and the interaction hash, 11.26-11.28 storage and denial of service on continuation, 11.34 SSRF on `push`.

## 2. RFC 9767 (resource-server connections)

**Missing entirely**: RS-facing discovery (3.1), protecting RS requests to the AS (3.2), token introspection (3.3), resource set registration (3.4), deriving a downstream token (4), token formats (2.2). `introspect_token` (1346) is an in-process lookup with a different response shape, not the RFC 9767 introspection.

## 3. Facts about tokens and storage

- What an issued token carries is decided by the integrator's policy (rc217); before that decision the request is only a proposal. Policy implementations are the integrator's: the crate ships none.
- Tokens are stored before the response is returned (rc217), in memory only.
- Continuation tokens and the interaction reference are compared in constant time; the continuation refusals are indistinguishable.
- Persistence: both maps are lost on restart. A storage choice that is not one hard-wired store (the PersistAnt-style choice the PM named) is part of G6.

## 4. Slice plan

Each slice is one PR, with a born-red test before the code, a mutation check, and an RFC-text citation per claim. No slice may claim a method it does not verify.

| Row | Slice | Content |
|---|---|---|
| G0 | gap note | this file, the rows below, rustdoc warnings on `permissions::Delegation` / `check_delegation` |
| G1 | types and errors | RFC types with Appendix E polymorphism: `access_token` object or array, access objects, labels, flags, references (8.1), `manage` object, `key` object/string, `client` by reference, `user`, `class_id`; the 3.6 error object and codes |
| G2 | `httpsig` | RFC 9421 + RFC 9530, tag `gnap`; first check crates.io for a maintained crate (any new dependency is an ask) |
| G3 | `jwsd`, `jws`, `mtls`, key formats | 7.3.2-7.3.4, `cert` / `cert#S256`; decide the fate of the `dpop` extension |

> **Erratum candidate (RFC 9635 section 7.3.2 vs its own example).** The text requires the JOSE `typ` header `gnap-binding-jwsd` (`gnap-binding-jws` for attached), but the section 7.3.2 `jwsd` example header decodes to `gnap-binding+jwsd`. `gnap_jws.rs` enforces the normative spelling and a test pins that the example spelling is refused. Not filed upstream; recorded here only.
| G4 | interaction | start modes `redirect`/`app`/`user_code`/`user_code_uri`, finish `redirect`/`push`, `hash_method`, hints, interaction expiry, callback checks |
| G5 | continuation and tokens | polling with `wait` / `too_fast`, PATCH modify, DELETE revoke grant, grant state machine, rotate and revoke with proof, key rotation, `Authorization: GNAP` parsing |
| G6 | policy, consent, storage | policy backed by the access-control engine (AC4), consent records, storage through a trait (PersistAnt-style), not one hard-wired store |
| G7 | HTTP and discovery | axum and actix routes, `OPTIONS` discovery (9.2), RS-first (9.1) |
| G8 | RFC 9767 | RS connections, introspection, resource set registration, downstream tokens |
| G9 | agents | agent principals and delegation by an account holder (below) |
| G10 | conformance | RFC example vectors (including the 4.2.3 hash example), one test per 11.x item |

## 5. Agent principals (slice G9)

CireSnave, 2026-11-06: *"auth-framework should support authentication of and authorization for agents as well as for humans and programs."*
GNAP's model fits: an agent is a client instance with a key, an account holder is the resource owner, and a grant is what the
owner approves. What the crate needs, none of which exists:

- **An agent identity**: a principal kind next to human and program, with a stable id, an owner (the account holder), one or more
  keys (a GNAP client key), an optional software class (`class_id`), and a lifecycle (register, rotate key, suspend, revoke). Agents
  authenticate by key proof, never by a shared secret.
- **Delegation by an account holder**: an account holder starts with permission to create and edit any rule about its own agents
  and rooms; anyone, human, program or agent, may share a subset of what it holds with others, including agents, and a shared
  grant can only narrow (attenuation). Chains are allowed to a configurable depth (default 3), the effective grant is the
  intersection along the chain, its expiry is the earliest, and revoking any link revokes everything below it (today a stored
  delegation survives its delegator losing the permission).
- **See / send grants**: consumers register their own actions (Synapse: `see`, `send` on rooms and agents) with the engine, and
  ask `decide(principal, action, resource)`. A GNAP token for an agent names the principal acting and the account holder on whose
  behalf it acts.
- **Creator grants**: when a principal creates another (an agent creating a sub-agent), the creator is issued a grant over the new principal, a strict subset of the creator's own grants, revocable by any ancestor up to the account holder, who always holds override.
- **Freshness**: a decision may be cached for at most 60 s; a grant marked sensitive is checked live at its source on every use.

## 6. Access-control engine (rows AC1-AC6, feeding Synapse)

`permissions.rs` has no deny effect; a deny-wins evaluator exists separately in `src/protocols/opa.rs` (`PolicyEffect::Deny`,
lines 514-523) and is the candidate base (board 385, ruled A: auth-framework holds principals, grants, delegation and the decision
engine; Synapse enforces through an `Authorizer` trait).

| Row | Content |
|---|---|
| AC1 | deny effect, deny wins; `decide(principal, action, resource) -> Decision`; action registry for consumers |
| AC2 | attenuation: a shared grant is a subset of what the sharer holds, checked when shared and when used; chains to depth 3 (configurable); stored delegations consulted by every check; revocation cascades. **Creator grants**: creating a principal issues the creator a grant over the new principal, a strict subset of the creator's own grants, revocable by any ancestor up to the account holder, who always holds override (an agent that creates a sub-agent can set see and send rules about it, for example hide a long-running helper from every other agent) |
| AC3 | cache contract (a decision is valid for at most 60 s, explicit invalidation) and a live path for grants marked sensitive |
| AC4 | the engine behind `GnapAccessPolicy` (slice G6) |
| AC5 | principal kinds: human, program, agent (slice G9) |
| AC6 | an account holder's default permission over rules about its own agents and rooms |

Suggested order after G0, so the Synapse lane can plan: **AC1** (deny, `decide`, action registry: small, unblocks enforcement),
**AC2** (attenuation and chains), **AC3** (cache contract and live path), then **G1-G6** in parallel as the GNAP build needs
them, **AC5/AC6 with G9** once principals exist, and **G7-G8, G10** last. Release numbers are the PM's.

## 7. Delegation that exists today (measured, rc214)

Two unrelated mechanisms; see the rustdoc warnings on `permissions::Delegation` and `PermissionChecker::check_delegation`.
`permissions::Delegation` is an evaluator input: `check_delegation` never looks at the delegator, so it must not be fed
caller-supplied records. `AuthorizationManager::delegate_permission` checks that the delegator holds the permission at creation
(and refuses a wider grant than held), allows one level only, and its stored delegations are consulted by no check.

## 8. Key management (rows KM1-KM8)

CireSnave 2026-11-06, verbatim: *"Auth-framework should include full key management tooling for most, if not all keys that a client or server could need to generate.  That includes key creation."*
Measured at `4eb8f99d` (origin/main) by reading the files named; "none found" means a search of `src` for the symbols named, not a proof of absence.

| Key kind | Exists | Missing |
| --- | --- | --- |
| JWS/JWT signing | `tokens/mod.rs` `TokenManager`: HS256 and RS256 only; keys are supplied by the caller as PEM or secret bytes. `rotate_hmac_key`, `rotate_rsa_key` keep exactly one previous key; `retire_previous_key` drops it | Creation (the RSA generator is in `#[cfg(test)]`, line 2053); EC and Ed25519 signing keys; more than one previous key; persistence; rotation on a schedule |
| JWKS publishing | `export_public_jwks` and OIDC `generate_jwks` (`server/oidc/core.rs:1067`) | RSA only (`kty` is hard-coded `"RSA"`); `kid` is SHA-256 of the modulus, not an RFC 7638 thumbprint; the no-feature error text recommends ES256/ES384 which `TokenManager` cannot be built with |
| JWE encryption | JARM response encryption in `server/oidc/oidc_advanced_jarm.rs` | No encryption key creation, rotation or publishing (`use: "enc"`) |
| GNAP client key (JWK) | `gnap.rs` verifies a presented key | Creation, thumbprint helper, `cert` and `cert#S256` forms |
| DPoP key | `server/security/dpop.rs` verifies proofs; RFC 7638 thumbprint is a private method (line 946) | Client-side generation (only `#[cfg(test)]` code makes keys) and export |
| httpsig key | none | everything (G2) |
| mTLS key pair and certificate | `server/security/x509_signing.rs`: CA load from file, PKCS#11 (`hsm` feature, loads the CA certificate), Azure Key Vault and AWS Secrets Manager (certificate only); `generate_development_root_ca` (line 1219); `sign_certificate_request` (line 1399) signs a requester's public key; `methods/client_cert/mod.rs` `cert_thumbprint_s256` (line 581) and a CRL store | CSR creation (none found: `acme.rs` `finalize_order` takes DER the caller built); CA private key custody other than a PEM path; certificate renewal |
| ACME account key | `protocols/acme.rs:326` generates a P-256 key with `ring`; `account_thumbprint`; `revoke_certificate` | persistence of the account key; rotation |
| Symmetric: AEAD | `storage/encryption.rs`: AES-256-GCM `StorageEncryption`, `KeyProvider` trait (`load_keys` returns the current id and a map), `EnvKeyProvider` (env var or a JSON keys file), `generate_key` (line 608), `rewrap_kv_keys` re-encrypts under the current key. ChaCha20-Poly1305 behind `enhanced-crypto` | A provider that creates and stores keys; file permissions are unchecked on Windows; KMS provider |
| Symmetric: HMAC | `rotate_hmac_key` | Creation helper beyond random-token generators (`utils/crypto.rs` has only `generate_token`, `generate_secure_token`, `generate_hex_token`) |
| Ed25519 / X25519 | `security/enhanced_crypto.rs` `Ed25519KeyPair`, `X25519KeyPair` (feature `enhanced-crypto`) | JWK conversion, storage, any link to tokens |
| OS keystore, TPM, KMS | none (no keyring crate; `security-framework` appears in `Cargo.lock` only as a transitive dependency). `cryptoki` exists behind `hsm` | all of it |

Backends in the tree: `ring` 0.17.14, `aws-lc-rs` (through `jsonwebtoken` 11.1 and `kryptering`), `rcgen` 0.14 with its `aws_lc_rs` feature (production use in `x509_signing.rs`).
No new crypto backend is needed for KM1-KM2, KM6 and KM7. Any new crate for KM3 (an OS keystore or TPM binding) is an ASK before use.

**Design choices to settle with the PM before KM3:** a non-exportable key must sign through the store, so `KeyStore` offers `sign(kid, alg, msg)` and does not return private bytes; `TokenManager` and the DPoP, mTLS and httpsig paths take a signer, not PEM bytes.

## 9. Which anchor ties a key to an identity (per principal kind)

Rule from CireSnave 2026-11-06: the agent keeps its private key; the server never holds it. A key proves *possession*; an anchor says *whose* key it is.

| Principal kind | Who generates the key | Anchor | Server holds |
| --- | --- | --- | --- |
| Human | the human's device (passkey or authenticator, or a client key in their app) | registration by the human at an authenticated session, or a passkey ceremony; account recovery is a separate, audited path | public key, thumbprint, state |
| Program (service, confidential client) | the program's operator, in the program's own environment | registration by the account holder (key or `jwks_uri`), or a certificate chain to a CA the account holder trusts (mTLS, `cert`) | public key or trust anchor, thumbprint |
| Agent | the agent itself, at start; the private key never leaves it | registration by the account holder or by the creating agent (creator grants, section 5), which binds the agent's public key and thumbprint to the new agent id; optional attestation from the host runtime where one exists; no attestation means the anchor is the registrar's word only | public key, thumbprint, registrar, state |

Rules: (1) the registrar must hold the grants it confers on the new principal (strict subset, section 5); (2) a key bound to no registrar has no identity and gets no grant; (3) revoking a registrar's grant over a principal revokes that principal's bindings (KM5); (4) a human vouching for another principal is a registration by that human, recorded as such, and carries only what that human holds; (5) "none" is a valid anchor only for an anonymous, unprivileged GNAP client (RFC 9635 permits key-bound clients with no registered identity), and such a client holds no grants beyond what the policy gives every unknown key.
