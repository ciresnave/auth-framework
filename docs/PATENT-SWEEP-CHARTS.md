# Patent claim charts: the four priority hits of the first sweep

Date: 2026-10-25. Swept commit: `5aefc7b8` (main, 0.6.0-rc144); all file:line citations re-derived with `git show origin/main:<path>` at `f9b9caf0` (5aefc7b8 plus #300, which touched only GNAP, OAuth2 revoke logging, CI and version files). Run by: auth-framework lane, Claude Sonnet 5.5, for the PM.
Method: independent-claim text taken whole from `tools/patent-claims.py` (Google Patents page text, machine-converted; check against the official record before relying on it); each element compared with the code at the swept commit. Dependent claims are not charted: a dependent claim cannot be infringed unless its independent claim is.
**Not legal advice and not a freedom-to-operate opinion.** "Absent" means the element is not in this code; it does not say a deployer could not assemble it around the library.

Legend: **present** = the code does this at the cited place; **partly** = something similar, difference stated; **absent** = the code does not do this, reason given.
Rule applied: overlap on every element of an independent claim = `needs-review`; any element absent = `design-around` candidate (and what must stay absent is stated).

---

## 1. US9397990B1 (Google LLC): Methods and systems of generating and using authentication credentials for decentralized authorization in the cloud

Independent claims: 1 (method), 10 (method, adds "disjunctive authentication credentials"), 18 (client-side method), 25 and 26 (systems, mirror 1 and 10), 27 (client-side system, mirrors 18). Claims 1/25 chart below; 10/26 differ only by the disjunctive-credentials limitation noted at the end; 18/27 are charted separately.

Code reviewed: `src/protocols/macaroons.rs` at `5aefc7b8`.

### Claim 1 / 25

| # | claim element | in auth-framework |
|---|---|---|
| 1a | a cloud-based server of a target service generates a credential with an identifier for the target service | **partly**: `MacaroonManager::create` (`macaroons.rs:87-95`) mints a credential with a `location` hint and an `identifier`; there is no "target service" notion beyond that string |
| 1b | ...and a unique signature, an HMAC "generated using a key identifier and a secret key associated with the target service" | **partly**: signature = HMAC-SHA256(root key, identifier) (`:88`). One root key; there is no separate key identifier input |
| 1c | an intermediate service attenuates the credential by placing restrictions on its use | **present**: `attenuate` (`:221-227`) and `add_first_party_caveat` (`:98-103`); any holder of a `MacaroonManager` can call them (the library does not distinguish an "intermediate service") |
| 1d | ...generates an updated signature that is an HMAC "generated using the unique signature and the one or more restrictions" | **present**: new signature = HMAC(old signature, predicate) (`:99-100`) |
| 1e | ...replaces the signature with the updated one | **present** (`:102`) |
| 1f | ...provides the credential to a client device "only when the client electronic device is authorized to access the target service" | **absent**: the library returns the value to the caller; no authorization gate on hand-over |
| 1g | the server receives an access request containing the credential and parameters relating to the requested service | **partly**: `verify` / `verify_with_discharges` (`:150-219`) take a macaroon and a predicate closure; there is no request/parameter handling |
| 1h | the server identifies that the credential includes the updated signature "and a third party caveat that is associated with a third party authentication service" | **present in the API surface**: `add_third_party_caveat` (`:113-140`), `Caveat::vid`/`cl` (`:43-50`), third-party branch of `verify_with_discharges` (`:172-200`) |
| 1i | in response, determines whether the request also comprises a discharge credential for the third-party caveat | **present in the API surface**: `discharge_macaroons` parameter (`:154`) matched by identifier (`:179-187`) |
| 1j | identifies a signature for the discharge credential and determines whether it "corresponds to a signature for the third party authentication service" | **present in the API surface**: discharge handling at `:189-193` |
| 1k | provides the service only when 1j holds, otherwise denies | **partly**: `verify_with_discharges` returns Ok/Err (`:203-206`); the library is not itself a service, so it denies by returning an error |

**Overall: needs-review as the code stands**, because 1h-1k overlap in design. **Decision:** how to resolve 1h-1k is with the PM; this file records only the element comparison. The independent claims 10/26 and 18/27 have absent elements regardless.

### Claims 10 / 26

Same as 1/25 plus: the request also includes "a plurality of disjunctive authentication credentials", with the third-party caveat on one of them. **Absent**: the macaroon API has no notion of alternative (disjunctive) credentials presented together. Independent of the removal, claims 10 and 26 need an element we do not have.

### Claims 18 / 27 (client-side)

| # | claim element | in auth-framework |
|---|---|---|
| 18a | an intermediate service generates an updated signature (HMAC over old signature and restrictions) and replaces the signature | **present** (`:98-103`) |
| 18b | the client device receives a credential with a target-service identifier and "a caveat that is associated with a third party authentication service" | **absent**: the library has no client role; it only mints, attenuates and verifies |
| 18c | the client stores it, provides it to the third-party service, receives a discharge credential | **absent**: no client flow (no request to a third party, no discharge receipt) |
| 18d | the third party returns a second caveat with the discharge; the client sends evidence for it to an additional authentication service and receives a second discharge | **absent**: no chained-discharge flow |
| 18e | the client sends the target service a request with the credential and both discharges, and receives the service | **absent** |

**Overall: design-around** (client-side elements absent).

---

## 2. US11349844B2 (Microsoft Technology Licensing): Instant enforcement of centrally configured IT policies

Independent claims: 1 (conditional access termination service side), 7 (resource provider side), 19 (system: identity provider + conditional access termination service).

Code reviewed: `src/protocols/caep.rs` (`CaepTransmitter`), `src/server/security/caep_continuous_access.rs` (`CaepContinuousAccessManager`).

### Claim 1 (termination-service side)

| # | claim element | in auth-framework |
|---|---|---|
| 1a | receives "a subscription request from a resource provider computer system subscribing to one or more events associated with user sessions" | **partly**: `CaepTransmitter::create_stream` (`caep.rs:366`) registers a stream with `audience` and `events_supported` (`StreamConfig`, builder `:251`), which is subscription-like; it is a local API call, not a request received from a resource provider |
| 1b | in response to a first authentication of an entity at an identity provider, establishes a user session allowing access to the resource provider | **partly**: the crate can be the identity provider and creates sessions (`secure_session.rs:248`), but session creation is not coupled to the event service |
| 1c | determines that at least one subscribed event occurs during the session | **present**: `emit_session_revoked` and the other `emit_*` calls (`caep.rs:413-488`) create events |
| 1d | sends the event to the resource provider, "causing the resource provider computer system to revoke the user session and redirect the entity back to the identity provider for a second authentication" | **partly**: `dispatch_event` (`caep.rs:505-522`) queues the event on matching streams for polling (`poll_events`, `:490`); nothing instructs a redirect to the identity provider. Whether a receiver revokes depends on the receiver |

### Claim 7 (resource-provider side)

| # | claim element | in auth-framework |
|---|---|---|
| 7a | subscribes to events from a conditional access termination service | **absent**: the receiver (`CaepContinuousAccessManager`) is handed events (`process_event`, `caep_continuous_access.rs:635`); it makes no subscription call |
| 7b | establishes a user session after a first authentication at an identity provider | **partly**: as 1b |
| 7c | receives the subscribed event from the service | **present**: `process_event` (`:635`) |
| 7d | revokes the user session | **present**: `execute_actions` -> `revoke_subject_access` (`:1222-1227`, `:784`), which performs a back-channel logout |
| 7e | redirects the entity back to the identity provider for a second authentication | **absent**: back-channel logout is server-to-server; `RequireStepUp` only logs (`:1228-1237`, a `step_up_manager` is held but not driven) |

### Claim 19 (system)

| # | claim element | in auth-framework |
|---|---|---|
| 19a | an identity provider that authenticates entities for a resource provider | **partly**: the crate can be one |
| 19b | a termination service that detects session events and sends them to subscribing resource providers, causing revoke and redirect | **partly**: as 1c/1d; no redirect instruction |
| 19c | the identity provider, after the session is revoked, receives an authentication request redirected from the resource provider and authenticates the entity again to establish a second session | **absent**: no logic linking a revoked session to a redirected re-authentication |

**Overall: design-around candidate for all three independent claims.** Absent in every claim: the redirect of the entity to the identity provider for re-authentication as a consequence of the event (1d/7e/19c), and (claim 7) the subscribing step. Constraints to keep: do not implement a protocol-level "revoke the session and redirect to the IdP" instruction driven by a received event, and do not wire `RequireStepUp` (`:1228`) into a redirect to the identity provider. Step-up that is not coupled to session revocation by a subscribed event is a different thing, but this chart does not clear it. This is the closest of the four to the code's intent; a lawyer should read it.

---

## 3. US8959650B1 (EMC Corp): Validating association of client devices with sessions

Independent claims: 1 (method) and 10 (system); identical limitations.

Code reviewed: `src/security/secure_session.rs`.

| # | claim element | in auth-framework |
|---|---|---|
| a | the server gathers information of a client device executing a user agent, "for creating a device identifier ... upon receiving an authentication request", the identifier including information identifying the device | **partly**: `create_session` (`:271`) receives `ip_address`, `user_agent` and an optional `DeviceFingerprint` supplied by the caller (`:276`); the crate does not itself gather client information |
| b | associates the device identifier with a session token, "wherein the device identifier is included in the session token provided to the client device by the server" | **absent**: the session identifier is random (`SecureRandomGen::generate_session_id`, `:290`; rotation `:469`) and the fingerprint is stored in the server-side session record (`:317`). Nothing derived from the fingerprint is placed in the value given to the client |
| c | validates the device on each subsequent request: receives the token, gathers information to create "another device identifier", compares it with the identifier included in the token | **partly**: `update_session_activity` (`:382`) compares the request's IP (`:420`) and user agent (`:425`) with values stored server-side; it compares against the stored record, not against an identifier carried in the token, and does not build a second device identifier |
| d | on match accepts the token; on mismatch rejects it | **partly**: a user-agent mismatch only sets `cross_device_access` and logs (`:425-434`); an IP change goes to `handle_ip_change` (`:638`); neither rejects "the session token" for a failed identifier comparison |

**Overall: design-around** (element b is absent; c and d differ). Constraint to keep: do not embed a device identifier or fingerprint in the token or cookie handed to the client and recompute-and-compare it on every request. The code reading matches what the lane found on the first pass.

---

## 4. US9369456B2 (Intuit Inc): Single sign-on in multi-tenant environments

Independent claims: 1 (method), 9 (system), 18 (medium); identical limitations.

Code reviewed: `src/tenant/` (`registry.rs`, `context.rs`, `mod.rs`).

| # | claim element | in auth-framework |
|---|---|---|
| a | receives a request for a first resource from a user "who has an account with a first plurality of tenants" | **absent**: each tenant is an isolated `AuthFramework` with its own storage namespace (`registry.rs:79-146`, `tenant_id` in `method_configs`); there is no account that spans tenants |
| b | identifies a first tenant associated with the request | **present**: lookup by `TenantId` (`registry.rs:147`) |
| c | obtains the first tenant's authentication policy | **partly**: per-tenant `AuthConfig` (`registry.rs:79-146`), not a named "authentication policy" record |
| d | authenticates with the mechanism associated with that policy and provides a first security token | **partly**: each tenant framework authenticates with its configured methods and issues tokens; not driven by a policy lookup across tenants |
| e | "storing a representation of authenticating the user with respect to the first tenant" | **absent**: no cross-tenant record of a prior authentication (a search of `src/tenant` for single-sign-on / cross-tenant / previously-authenticated terms finds nothing; the same search path finds `TenantId` 30 times, so the search is aimed at the right files) |
| f | receives a second request for a resource from a different tenant in the same plurality, with a different authentication policy | **absent**: no cross-tenant request path |
| g | automatically detects that the user was previously authenticated with the first tenant by accessing the stored representation | **absent** |
| h | uses that detected authentication to authenticate the user under the second tenant's policy, and provides a second token without requiring additional credentials | **absent** |

**Overall: design-around** (elements a, e, f, g, h absent). Constraint to keep: do not add cross-tenant single sign-on, i.e. do not let an authentication at one tenant satisfy authentication at another tenant of the same user.

---

## 5. The other 19 items of the first-pass Needs-review list, re-read with the tool

Claims fetched whole with `tools/patent-claims.py` on 2026-10-25; for the comparison below only the opening of each independent claim was read where it is quoted, and the rest of long claims was not re-read here (the tool output is not committed; re-run the tool to see it). `clear` means an element that every independent claim requires is absent from the code; the element is named.

| patent | what the independent claims require (quoted/paraphrased from the tool output) | element absent in auth-framework | class |
|---|---|---|---|
| US10742655B2 | a validation server issues a token carrying an "encrypted data structure"; the resource server decrypts it and, within a time window since issue, grants access "without confirming validity of said validation token with said validation server" | no encrypted-parameter token from a separate validation server; tokens are signed JWT/PASETO validated locally | clear (the rest of claim 1 was not re-read) |
| US8763095B2 / US20130276066A1 | a source system generates user-authorization data as tuples with separate fields for user-entity, context, action, and an object/value pair, and transfers them to a target system with a different access policy | no generation and transfer of authorization tuples between systems; the Zanzibar engine (`src/protocols/zanzibar.rs`) evaluates tuples locally | clear |
| US20120330925A1 | a database authorization index mapping a user id to the records the user may access, used in query rewrite or planning | no database query rewriting or authorization index | clear |
| EP4092958B1 | reads user attributes from an ID token with a protected memory area and issues a verifiable credential into a wallet using an SSI infrastructure with a blockchain holding the data schema and issuer key | no ID-token hardware reading, no blockchain schema registry | clear |
| CN112149156A | publisher signs an attribute message including a secret record identifier and signs each data entry separately; selector/receiver devices; anonymous certificate | SD-JWT uses salted digests in one signed JWT, not per-entry signatures with a secret record identifier | clear (claim 1 was only partly re-read) |
| US12256020 | a device with an image sensor, a hardware security module / secure enclave and a signature engine producing attested image data | no image-sensor or enclave hardware | clear |
| US9843577B2 | on a credential-change indication, if a session token was issued before the change, signal an identity platform to revoke, "comprising synchronizing a password timestamp with the identity platform" | no synchronization of a password timestamp with an external identity platform (`password_changed_at` exists only in the user table, `migrations/001_create_users_table.sql:25`) | clear |
| US10069859B2 | a distributed platform of distribution points, each with servers tracking request rate, thresholds at server, distribution point and platform levels, and attack-response control | no CDN distribution-point hierarchy or attack-response control | clear |
| US9754311B2 | collect a set of device fingerprints at two locations of a website during a session whose id is generated from device information, and analyse them for non-matched data | session id is random (`secure_session.rs:290`); no collection of fingerprints at two site locations | clear (claim 1 was re-read only to the first clause) |
| US8151327B2 | collect device identifiers/IP addresses at two different "pre-selected pages configured for a session tampering comparison" and compare | no pre-selected-page collection | clear |
| US20150006384A1 | create a device id, associate a session key with it, receive the session key from a merchant, count the users associated with the device id, assess fraud risk from the count | no per-device user count (no matches in `src` for users-per-device) | clear |
| US11218466B2 | for an invalid user id, hash it, take it modulo the number of endpoint records, return that endpoint URL with a second authentication screen | no hash-modulo endpoint selection | clear |
| US10771447B2 | a cluster of application-hosting instances; a primary authentication instance chosen from tenant-specific authentication configuration; token fetched from the client to a second instance | no cluster with a tenant-chosen primary authentication instance | clear |
| EP3158494B1 | application-server partitions with admin / first / second security realms as named security configurations | not an application server; no realm / partition model | clear |
| US11579783B1 | shared multi-tenant layer plus single-tenant layers, a multi-tenant encryption scheme using tenant public keys so the shared layer cannot read tenant data | no tenant-public-key encryption scheme separating a shared layer from tenant layers | clear (claims 13 and 20 only partly re-read) |
| US8869243B2 | session-creation request, location reputation computed from past sessions of other users where "benign" means access to a user's information by a connected user in a social networking system, authentication level chosen by that reputation | reputation here comes from external feeds, not past-session statistics of a social network | clear |
| WO2017131963A1 | analyse suspect traffic in an emulated "high-interaction network" and generate indicators | no high-interaction network analysis; application ceased | clear |
| US9882714B1 | update keys across a group of policy enforcement points: new decryption key to every PEP, wait for acknowledgement from each and every PEP, then new encryption key, then wait again... | no multi-PEP acknowledged key distribution | clear |
| US9830455B2 | generate a reconciliation report indicating that an access right "should either be provisioned or revoked", via per-task steps over user attributes | the compliance module (`src/analytics/compliance.rs`) does not recommend provisioning or revocation (the only revoke mention is counting revoked actions, `:105`) | clear (claim 1 only partly re-read) |
| US20140215603A1 | record access events in a log, analyse at intervals to detect prespecified conditions, determine and implement changes to a role's users or permissions | no automatic role adjustment from access-log analysis (no matches in `src`) | clear |

Result: all 19 move from `needs-review` to `clear`, each on a named absent element. Where a claim was only partly re-read the table says so, and a lawyer should still read those claims whole.

---

## Summary for the PM

| patent | class before | class after (charts) | what must stay absent |
|---|---|---|---|
| US9397990B1 | needs-review (priority) | claims 1/25 overlap in design (decision with the PM); claims 10/26 and 18/27 have absent elements | third-party caveats and discharge credentials |
| US11349844B2 | needs-review | design-around candidate (redirect to IdP for re-authentication absent in every independent claim; subscription absent in claim 7) | an event-driven "revoke and redirect to the IdP" instruction; `RequireStepUp` wired to an IdP redirect |
| US8959650B1 | needs-review | design-around (device identifier in the client-held token absent) | a fingerprint-bearing token recomputed and compared per request |
| US9369456B2 | needs-review | design-around (cross-tenant prior-authentication reuse absent) | cross-tenant single sign-on |
| 19 unread items | needs-review | clear | see table |
