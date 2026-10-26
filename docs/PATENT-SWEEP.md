# Patent sweep: auth-framework 0.6.0 (release-candidate line; also covers the published 0.4.x and 0.5.x lines) @ 5aefc7b8

Date: 2026-10-25 (first pass); 2026-10-26 (second pass on the formerly unread patents, see "Second-pass reads"); Run by: auth-framework lane, Claude Sonnet 5.5; Method: AI-assisted search and read; NOT legal advice; NOT a freedom-to-operate opinion.

Status: **First pass plus a second read on 2026-10-26 (see "Second-pass reads"). This file exists and names the version lines it covers, but it is NOT a clearance: dependent claims, prosecution files, other family members and maintenance fees were not read, several first-pass `clear*` verdicts still rest on a summary of the claims, and US11349844B2 is rated arguable. The "Needs review" section is the work list.**

## Scope note

Most of this crate implements published standards (OAuth 2.x, OIDC, SAML, WebAuthn, SCIM, DPoP, mTLS, SD-JWT, PASETO, RADIUS, TACACS+, Kerberos, ...). A standard's existence does not clear a patent, but implementers of IETF/OASIS/W3C/FIDO specifications normally rely on the standards body's IPR disclosures and licensing terms. Those are recorded as one group (idea 14) and are not searched claim by claim. The sweep concentrates on what the crate does beyond the specification text.

## Ideas swept

Each is a claim-like sentence about a mechanism in the code at the swept commit.

1. A permission check that can require proof that the presented token was cryptographically validated in this process (a `validated_token` evidence value), and refuses to authorise when only an unvalidated token string is supplied. (`src/auth.rs`, rc97)
2. A tuple-based relationship authorization engine, in-process, that evaluates "does subject S hold relation R on object O" by walking stored relationship tuples and userset rewrites. (`src/protocols/zanzibar.rs`)
3. Bearer credentials built from chained-HMAC caveats, where a holder can attenuate a credential offline and a verifier checks each caveat locally, including third-party caveats satisfied by discharge macaroons. (`src/protocols/macaroons.rs`)
4. Continuous access evaluation: receiving a signed security event (CAEP / Shared Signals) causes revocation or re-authentication of matching sessions and tokens. (`src/protocols/caep.rs`, `src/server/security/caep_continuous_access.rs`)
5. Sliding-window request rate limiting with a pluggable store that lets many server instances enforce one shared limit. (`src/distributed/rate_limiting.rs`)
6. Authentication that equalises the timing of failure paths (unknown user vs wrong secret) and compares secrets in constant time. (`src/security/timing_protection.rs`)
7. Multiple isolated authentication and authorization contexts (tenants) in one process, each with its own configuration and keys. (`src/tenant/`) *Corrected 2026-10-26: the first pass also said "storage namespace". `src/tenant/registry.rs:114-117` writes `tenant_id` into `method_configs` under a comment that storage is namespaced per tenant, but `git grep '"tenant_id"' origin/main -- src` finds that write and no reader; isolation is one `AuthFramework` instance per tenant, not a shared namespace.*
8. Automatic download and scheduling of third-party threat-intelligence feeds whose contents feed authentication decisions (block or flag by IP or indicator). (`src/threat_intelligence.rs`)
9. Binding issued access tokens to a sender, by DPoP proof key or by mTLS client certificate thumbprint, and validating either binding through one validator. (`src/server/security/dpop.rs`, `mtls.rs`)
10. Sessions carrying a device fingerprint and security flags, with concurrent-session limits and sliding validity, evaluated on every request. (`src/security/secure_session.rs`)
11. API-key rotation in which the old and new key are both accepted during an overlap window. (branch `feat/api-key-rotation`, unmerged; not in the swept commit) *Corrected 2026-10-26: at main `rotate_api_key` is merged (`src/auth_modular/user_manager.rs:458-490`) and the old key stops validating; there is no overlap window in the swap path.*
12. Selective-disclosure credentials: SD-JWT issuance and verification, plus OpenID4VCI issuer and OpenID4VP verifier flows. (`src/protocols/sd_jwt.rs`, `openid4vci.rs`, `openid4vp.rs`)
13. Compliance and audit reports derived from stored authorization state and audit events (RBAC compliance monitoring). (`src/analytics/compliance.rs`)
14. Standards implemented as published (OAuth 2.x, OIDC, SAML, WebAuthn/FIDO, SCIM, DPoP, mTLS, PASETO, RADIUS, TACACS+, Kerberos, CIBA, GNAP, UMA, SIWE, SPIFFE, ACME, OPA hooks). Recorded by reference to each standards body's IPR terms, not searched claim by claim.

## How the searches were run

Three Sonnet 5.5 subagents each took a group of ideas (1-3 and 12; 4, 5, 9, 10; 6, 7, 8, 11, 13). Tools were WebSearch (many queries restricted to patents.google.com) and WebFetch of Google Patents pages, all run 2026-10-25. USPTO Patent Center, Espacenet and WIPO were NOT queried directly; there was no CPC-class browsing, no assignee-targeted search and no citation-chain follow-up. WebFetch returns a model summary of a page, not raw text, so "claims read" below means "claims as summarised or partly quoted", and quotes are fragments. Each idea had 2-5 queries (appendix). Status and expiry are Google Patents' own assumptions, not legal conclusions. The lane (not the subagents) cross-checked the macaroon, session-fingerprint and CAEP findings against the code at the swept commit.

## Hits

Verdicts: `clear` = no overlap on any independent claim, with reason; `clear*` = same, but reasoned from a summary of the claims, moderate confidence; `design-around`; `needs-review`.

### Idea 1 (validated-token evidence)
| patent | title | assignee | status | claims read | overlap | our difference | verdict |
|---|---|---|---|---|---|---|---|
| US10587409B2 | Authorization token including fine grain entitlements | T-Mobile USA | active ~2038 | summary of claims 1, 8 | signature validated, then entitlement decision | claims need an entitlement bitmask in the token; we have a typed evidence value as API input | clear* |
| WO2014182865A1 | Authentication and authorization with a bundled token | Microsoft | ceased | claims 1, 7 | none (bundles several tokens) | we do not bundle | clear |
| US12155659B2 | Token based identity verification and consent management | T-Mobile Innovations | active ~2043 | summary of claims 1, 10, 17 | weak | consent-token subject | clear* |
| US10742655B2 | Resource access control using a validation token | ARM IP Ltd | active ~2035 | independents 1, 10 read in full (2026-10-26) | snippet: resource server checks signature, policy parameters, blacklist | Second pass 2026-10-26: no age-threshold "skip confirmation" branch; no encrypted token | clear |
| US11757635B2 | Client authentication and access token ownership validation | Mavenir | active ~2041 | fragments of claims 1, 5, 9 | token ownership checks | claims need an increasing random number or a client-signed request hash | clear* |

### Idea 2 (tuple-based relationship authorization)
| patent | title | assignee | status | claims read | overlap | our difference | verdict |
|---|---|---|---|---|---|---|---|
| US12443741B2 | Fine-grained authorization as a service via relationship-based access control in a multi-tenant system | Okta | active ~2043 | preambles quoted, bodies summarised | same tuple and rewrite style | summary says every independent claim needs a cloud multi-tenant service and a store-revised-model / compare-outcomes / report-discrepancies step; we have none of these | clear* for the current design; re-review if a policy dry-run diff feature is added |
| US8763095B2 / US20130276066A1 | Authorization sharing | SAP SE (not Google) | active ~2032 | independents read in full (2026-10-26) | flat tuples shared between systems | Second pass 2026-10-26: no cross-system tuple generation or transfer; no "context" field | clear |
| US20120330925A1 | Optimizing fine grained access control using authorization indexes | Microsoft (not Google) | abandoned, never granted | not needed | database query access control | Second pass 2026-10-26: abandoned application, no grant event | clear (abandoned) |

No Google patent describing Zanzibar (tuples, userset rewrites, zookies) was found in five queries, but the search tool cannot search by assignee, inventor or class, so absence is weak evidence. The 2019 USENIX ATC Zanzibar paper and the OpenFGA/SpiceDB documentation publicly disclose the model.

### Idea 3 (macaroons)
Code check at the swept commit: `src/protocols/macaroons.rs` implemented third-party caveats (`add_third_party_caveat`, line 99) and discharge verification (`verify_with_discharges`, line 136). **Update 2026-10-26: both were removed in 0.6.0-rc148 (#302) and 0.5.0-rc65; at main and release/0.5.x the module is first-party only, so the third-party/discharge claims below are now avoided by design (see US9397990B1).**

| patent | title | assignee | status | claims read | overlap | our difference | verdict |
|---|---|---|---|---|---|---|---|
| US9397990B1 | Generating and using authentication credentials for decentralized authorization in the cloud | Google | active to 2034-02-15 | preambles quoted; bodies summarised; independents 1, 10, 18, 25-27 | summary: target server issues signed credential, intermediary attenuates and re-signs, target checks third-party caveat and discharge credential | we implement third-party caveats and discharge macaroons, so the subagent's "likely clear" premise does not hold. UPDATE 2026-10-26: third-party caveats and discharge verification were removed in 0.6.0-rc148 (#302) and 0.5.0-rc65; main and release/0.5.x are first-party only, and release/0.4.x has no macaroons module | **clear at main** (third-party caveat and discharge absent); published versions that had them (0.5.0-rc18..rc63, 0.6.0-rc41..rc138) arguable-but-weak, now yanked |
| US11595215B1 | Transparently using macaroons with caveats to delegate authorization | Ping Identity (ex ForgeRock) | active ~2040 | independents 1, 5, 11 quoted in part; claim 13 not read | HMAC-chained caveats, holder attenuation | every independent claim needs an OAuth2 authorization server that issues the macaroon and authenticates it when the resource server passes it back; our verification is local | design-around (keep verification local; do not add an issuer-introspection mode) |
| US11997207B2 | Identifying group membership through discharge macaroon access tokens | Ping Identity | active ~2040 | claims 1, 9 quoted in part | third-party caveat plus discharge macaroon for group membership | claims need group-membership caveats and resource-server introspection; we have no group-membership discharge flow | clear* |

### Idea 12 (SD-JWT, OpenID4VCI, OpenID4VP)
| patent | title | assignee | status | claims read | overlap | our difference | verdict |
|---|---|---|---|---|---|---|---|
| US11886557B1 | Blockchain-based credential batch management with selective disclosure | Intl. Univ., VNU-HCMC | active ~2043 | claim 1 preamble, body summarised | selective disclosure concept | needs blockchain, smart contract, Merkle tree | clear* |
| US9768962B2 | Minimal disclosure credential verification and revocation | Microsoft | expired | claim 1 preamble | verifier role | accumulator revocation | clear |
| WO2020176691A1 | Credential verification and issuance through credential service providers | TBCASoft | ceased | claim 1 summarised | weak | needs distributed ledger | clear |
| EP4092958B1 | Issuing of a digital verifiable credential | Bundesdruckerei | active (granted 2024-07-03) | claims NOT read | issuer flow driven by an ID token | unknown | needs-review |
| CN112149156A | Selective disclosure of recorded attributes and data entries | Koninklijke Philips | CN granted 2022-12-13 (active); US family member US11658827B2 granted 2023-05-23 (active); EP3758279A1 | CN and US claims read (2026-10-26); EP3758279A1 not read | selective disclosure of recorded attributes and data entries | Second pass 2026-10-26: no zero-knowledge proof over per-entry issuer signatures and a secret record identifier (the "China-only" assumption was wrong) | clear |
| US12256020B1 | Generating attested data | Purple Squid LLC | active ~2044 | independents read in full (2026-10-26) | a hardware-camera patent; the snippet's salted-hash comparison to SD-JWT was a misreading | Second pass 2026-10-26: no image sensor, hardware security module, device ID or video-session ZKP | clear |

No patent specifically claiming SD-JWT, OID4VCI or OID4VP was found. The IETF IPR database and OpenID Foundation IPR disclosures were NOT checked; that check is cheap and should be done.

### Idea 4 (continuous access evaluation)
| patent | title | assignee | status | claims read | overlap | our difference | verdict |
|---|---|---|---|---|---|---|---|
| US11349844B2 | Instant enforcement of centrally configured IT policies | Microsoft | active ~2040 | independents 1, 7, 19 | claim 1: subscribing to session events, sending them to the resource provider, "causing the resource provider ... to revoke the user session and redirect the entity back to the identity provider for a second authentication" | every independent claim needs a conditional-access termination service taking a resource-provider subscription and pushing events; we receive a signed SET at a library endpoint. Wording is broad enough that a deployment that subscribes and redirects might read on it | **needs-review** |
| US9843577B2 | Revoking sessions using signaling | Microsoft | active ~2034 | independents 1, 9, 17 | credential-change indication, session token issued before the change, signal to an identity platform to revoke | our trigger is any signed SET; we may also compare token issue time to event time (CAEP does), a partial overlap | needs-review (low severity) |
| US10104071B2 | Revoking sessions using signaling | Microsoft | active ~2034 | summary of claims 1, 8, 15 | user-selected session revocation | no user selection step | clear* |

### Idea 5 (sliding-window rate limit, shared store)
| patent | title | assignee | status | claims read | overlap | our difference | verdict |
|---|---|---|---|---|---|---|---|
| US20130091241A1 (family US8930489, not fetched) | Distributed rate limiting of handling requests | Rackspace | expired (fees) | independents 1, 12, 18 | shared key store, atomic increment | claims need delay/sleep-time throttling on a "running time" and synchronised clock; we reject over-limit requests | clear (US8930489 status unverified) |
| US10069859B2 | Distributed rate limiting | Verizon Digital Media / DRNC | active ~2036 | fragments of claims 1, 8 | CDN multi-tier thresholds across distribution points | different domain | needs-review (claims not fully read; low risk by preamble) |
| US12204933B2 | Asynchronous statistic-based rate limiting in distributed system | Stripe | active ~2043 | summary of claims 1, 6, 11 | clients report counts to a central store | each independent claim reportedly needs a machine-learned adjustment of the limit; we have none | clear* |

### Idea 9 (sender-bound tokens)
| patent | title | assignee | status | claims read | overlap | our difference | verdict |
|---|---|---|---|---|---|---|---|
| US11483155B2 | Access control using proof-of-possession token | T-Mobile USA | active ~2040 | independents 1, 12 | "confirmation (CNF) key" bound to presenter info | needs a PoP token binding presenter and channel, a secure second channel, a trusted server; we implement RFC 9449 / RFC 8705 | clear* |
| US11595215B1 | (see idea 3) | Ping Identity | active | bodies unread | search summary linked a cnf/thumbprint caveat; unconfirmed | macaroon delegation | needs-review (low priority) |
| US12676750B2 (sibling US12676751 not fetched) | Server control of client authorization proof of possession | Synamedia | active ~2042 | summaries of 1, 18, 19 | server-provisioned client key pair plus expiring assertion | not DPoP/mTLS thumbprint validation | clear* |
| US11757635B2 | (see idea 1) | Mavenir | active | fragments | token ownership | needs random number or hash scheme | clear* |

DPoP (RFC 9449) and mTLS-bound tokens (RFC 8705) are published standards; EP2289222A1 (token bound to a client public key checked against a TLS client certificate) is thematically close and was not opened.

### Idea 10 (session fingerprint, concurrent limits, sliding validity)
Code check at the swept commit: `DeviceFingerprint` is a field of the server-side session struct (`src/security/secure_session.rs:34`); no use outside that module and its config was found by grep, and `create_session` (line 290) takes the identifier from `SecureRandomGen::generate_session_id()`, a random value, so the fingerprint is not derived into it at creation. Only the session-creation path was read, not every place a client-held token could be built, so treat "not embedded in a client-held token" as likely but not fully traced. *Update 2026-10-26: `track_device_fingerprints` (`src/session/manager.rs:235`) is set in presets and read nowhere, `SecurityFlag::DeviceAnomaly` is defined and never set, and `SecureSessionManager` compares IP and user agent (`secure_session.rs:420`, `:425`) but not the stored `DeviceFingerprint` on later requests. Not patent issues; they are accepted-and-ignored inputs.*

| patent | title | assignee | status | claims read | overlap | our difference | verdict |
|---|---|---|---|---|---|---|---|
| US8959650B1 | Validating association of client devices with sessions | EMC | active ~2032 | independents 1, 10 | "validating the client device each time the client device sends a subsequent request"; compares a newly gathered identifier with the one included in the session token; rejects on mismatch | claims require the device identifier to be in the token given to the client; ours appears server-side, unconfirmed. UPDATE 2026-10-26: the token does not carry the device identifier, and a mismatch is a step-up (`SessionState::RequiresMfa`), not a rejection. The legacy `SessionManager` (`src/session/manager.rs`, `validate_session` lines 733-753) does recompute and compare a fingerprint on every request; it is still outside the claims for the same reasons, but this sweep did not mention it before | **needs-review** |
| US10715605B2 | Limiting active sessions | ServiceNow | active ~2037 | independents 1, 8, 18 | concurrent-session threshold with invalidation | needs multiple nodes, load balancer, cluster message to terminate; we have none (recheck if cross-instance session termination is added) | clear |
| US11329992B2 | Security measures for extended sessions | F5 / Shape | active ~2040 | independents 1, 5, 9, 13 | extends session by new expiry | needs single-user-device and not-compromised determination from instrumentation telemetry | clear |
| US9754311B2 family (US10089679B2, US8826393, US9196004B2, US8151327B2, WO2008054849A3) | Detection of session tampering and fraud prevention | not fetched | not fetched | not read | fingerprints compared to the session ID to detect hijacking | unknown; large older family | needs-review |
| US20150006384A1 | Device fingerprinting | not fetched | not fetched | not read | device ID tied to a session key | unknown | needs-review (low priority) |

### Idea 6 (equalised failure timing, constant-time compare)
| patent | title | assignee | status | claims read | overlap | our difference | verdict |
|---|---|---|---|---|---|---|---|
| US8875255B1 | Preventing user enumeration by an authentication server | EMC / RSA | active ~2032 | claims 1-8 only (later claims truncated) | same problem; claim 1 returns a "faux authentication session response" | no decoy artifacts; we equalise timing; no claim read mentions timing | clear* |
| US11218466B2 | Endpoint security | Salesforce | active ~2039 | abstract and description only | abstract hashes an invalid identifier modulo the endpoint count and returns an endpoint URL; description equalises latency | no hash-mod-lookup or redirect URL | needs-review |
| US20050044390A1 | Timing attacks against user logon and network I/O | Cisco | expired | claims 1-4 | same field | keystroke-timing classification | clear |

No patent claiming padded failure timing or a dummy hash on unknown users was found; the practice appears in public advisories and bug trackers.

### Idea 7 (tenant isolation in one process)
| patent | title | assignee | status | claims read | overlap | our difference | verdict |
|---|---|---|---|---|---|---|---|
| US9369456B2 | Single sign-on in multi-tenant environments | Intuit | active ~2032 | independents 1, 9, 18 (paraphrased) | claim 1: identify a tenant from a request, obtain that tenant's authentication policy, use the matching mechanism, provide a security token | the claim is an SSO identity-provider flow; ours is in-process config/storage/key isolation. Real overlap on tenant-keyed policy selection followed by token issue | **needs-review** |
| US8819794B2 | Integrating server applications with multiple authentication providers | Microsoft | active ~2032 | independents 1, 7, 11 | tenant id from an approved issuer configuration | issuer-list negotiation and self-issued tokens; we do neither | clear* |
| US10771447B2 | Tenant-aware distributed application authentication | Illumina | active ~2037 | summary embodiments only | tenant config designates a primary authentication service | cross-datacentre token validation | needs-review |
| EP3158494B1 | Security in a multitenant application server environment | Oracle | active (assumed) | claims not reached | per-partition security realms | library, not app-server partitions | needs-review |
| US11579783 | Multi-tenant storage | not seen | not seen | snippet only | per-tenant namespace and keys | unknown | needs-review |

### Idea 8 (threat-intelligence feeds into authentication decisions)
| patent | title | assignee | status | claims read | overlap | our difference | verdict |
|---|---|---|---|---|---|---|---|
| US10681071B1 | Enrichment and analysis of threat intelligence and orchestrating its application to network security events | ThreatConnect | active ~2038 | claims 1, 9, 17 (paraphrased) | claim 1: "receiving, over a communications network, a plurality of data feeds" of IOCs, then reputation score and a countermeasure | needs a confidence-decay and weighted-criticality reputation formula; no authentication decision; we do no scoring | design-around (avoid that weighted reputation formula) |
| US8516595 | Reliability of blacklists of botnet-infected computers | La Caixa / Barcelona Digital | expired | claims 1, 10 | fetches blacklists, matches IPs | estimates blacklist reliability | clear |
| US8869243B2 | Authenticating user sessions based on reputation of user locations | Meta | active ~2032 | claims NOT read; summary only | summary: location reputation determines authentication level | built from internal session statistics; ours ingests scheduled external feeds | needs-review |
| US8806591B2 | Authentication risk evaluation | Verizon | active ~2031 | claims 1, 8, 14 | risk scoring at authentication | scores on factor complexity and lockout time; no feed | clear* |
| WO2017131963A1 | Targeted threat intelligence with high-interaction networks | Acalvio | WO ceased (no national phase listed); US siblings US10230745B2 and US10270789B2 are ACTIVE (~2037) | US siblings read (2026-10-26) | blocking IPs, flagging accounts in description | Second pass 2026-10-26: US siblings claim VM-sandbox / emulated-network analysis, which we do not do; "ceased" applies to the WO only, not the family | clear |

### Idea 11 (API-key rotation with overlap window; unmerged branch)
| patent | title | assignee | status | claims read | overlap | our difference | verdict |
|---|---|---|---|---|---|---|---|
| US10462152B2 | Managing credentials used to authenticate access | Microsoft | active ~2037 | claims 1, 9, 17 (paraphrased) | claim 1: request to replace a first credential, old one kept usable for a window, indication to an administrator when the old credential is used | claim also ties window length to the requesting device's access level and requires transparency to the device; ours is a uniform window | design-around (do not tie the window to device access tier or alert on old-key use) |
| US9424419B1 | Automatic rotation and storage of security credentials | Amazon | active ~2035 | claim 1 only | rotate per policy, notify callers, monitor first set for a time, then deactivate | needs a credentials agent and usage-monitoring deactivation; we use an expiry timestamp | design-around (avoid usage-threshold deactivation) |
| US10063531B2 | Method for key rotation | Duo / Cisco | expired | claims 1, 14 | key rotation | client-generated key pair, rotation message signed with old key | clear |
| US10581820B2 | Key generation and rollover | Oracle | active ~2037 | publication claims 1, 11, 16 | previous/current/next key set | three-slot key set for token signing keys | clear* (do not implement previous/current/next slots) |
| US9882714B1 | Enhanced distribution of security keys | not seen | not seen | not fetched | snippet: both keys exist during an overlap | unknown | needs-review |

### Idea 13 (compliance reports from RBAC state and audit events)
| patent | title | assignee | status | claims read | overlap | our difference | verdict |
|---|---|---|---|---|---|---|---|
| US8984583B2 | Healthcare privacy breach prevention through integrated audit and access control | Accenture | active ~2033 | independents 1, 12, 22 | analyses an access log into role-access pairs and proposes a policy | no proposed policy derivation | clear* |
| US8132231B2 | Managing user access entitlements to IT resources | ServiceNow (ex IBM) | active ~2030 | claim headers only | audit reports from lifecycle events (description) | claims are provisioning; we provision nothing | clear* |
| US9830455B2 | Reconciliation of access rights in a computing system | Bank of America | granted | not read | summary: reconciliation report of rights to provision or revoke | unknown | needs-review |
| US20140215603A1 | Automated role adjustment | not fetched | not fetched | not read | access log vs role activations | unknown | needs-review |

### Idea 14 (standards as published)
Not searched claim by claim. No standards-body IPR declarations were checked in this pass.

## Second-pass reads, 2026-10-26

Two read passes at `origin/main` f9970648 by Claude Sonnet 5.5 subagents (not a lawyer; a claim-to-code comparison, not a freedom-to-operate opinion). Every independent claim of each patent below was read from Google Patents' copy of the claim text; status and expiry are Google's own assumptions, and **maintenance fees were not checked on any USPTO/EPO register**. Not read for any of them: dependent claims, prosecution files, other family members (EP3758279A1; the WO/KR/CN/GB members of US10742655B2; EP4052159B1 and CN114600425B of US11349844B2), live fee status. Where this section and an earlier row disagree, this section is the later reading.

Corrections to the first pass: US8763095B2 is SAP SE (not Google); US20120330925A1 is Microsoft and was abandoned without a grant (not Google); US10742655B2 is ARM IP Ltd; CN112149156A is Koninklijke Philips with US11658827B2 (granted 2023-05-23) and EP3758279A1, not "China-only"; "US12256020" is US12256020B1, Purple Squid LLC, a hardware-camera patent; WO2017131963A1 is ceased but its US siblings US10230745B2 and US10270789B2 are active.

| patent | assignee | status (Google) | verdict | confidence |
|---|---|---|---|---|
| US10742655B2 | ARM IP Ltd | active ~2035 | outside the claims | high |
| US8763095B2 | SAP SE | active ~2032 | outside the claims | medium-high |
| US20120330925A1 | Microsoft | abandoned, never granted | abandoned | high |
| US9397990B1 | Google | active ~2034 | outside the claims at main (third-party caveat and discharge removed in rc148); historical versions arguable-but-weak | high for main |
| EP4092958B1 | Bundesdruckerei | active | outside the claims | high |
| US11349844B2 | Microsoft | active ~2040 | **arguable**: keep CAEP handlers caller-supplied, never ship a handler that revokes and redirects to the IdP | low-medium |
| US9843577B2 | Microsoft | active ~2034 | outside the claims | medium-high |
| US10069859B2 | Verizon/Edgio, now DRNC | active ~2036 | outside the claims | high |
| US11595215B1 | Ping Identity / ForgeRock | active ~2040 | outside the claims | high |
| CN112149156A / US11658827B2 | Koninklijke Philips | active | outside the claims | high (EP3758279 not read) |
| US12256020B1 | Purple Squid LLC | active ~2044 | outside the claims | high |
| US8959650B1 | EMC | active ~2032 | outside the claims (token does not carry the device identifier; mismatch is step-up) | medium |
| US9754311B2 and 8 family members | 41st Parameter | active ~2027 | outside the claims | medium-high |
| US20150006384A1 | PayPal | abandoned, never granted | abandoned | high |
| US11218466B2 | Salesforce | active ~2039 | outside the claims | high |
| US9369456B2 | Intuit | active ~2032 | outside the claims | high |
| US10771447B2 and 2 continuations | Illumina | active ~2037 | outside the claims | high |
| EP3158494B1 | Oracle | active (national validations not shown) | outside the claims | high on claims; territory unchecked |
| US8869243B2 | Meta | active ~2032 | outside the claims | high |
| US9882714B1 | Certes | active ~2034 | outside the claims | high |
| US9830455B2 | Bank of America | active ~2033 | outside the claims | high |
| US20140215603A1 | IBM (granted as US8863276B2, US9087148B2) | both "Expired - Fee Related" | expired; code also lacks the claimed log-driven role change | medium-high |
| WO2017131963A1 / US10230745B2 / US10270789B2 | Acalvio | WO ceased; US siblings active ~2037 | WO lapsed; US siblings outside the claims | high |
| US11579783B1 | VIM Inc. | active ~2042 | outside the claims | high |

## Needs review (to the PM)

**Update 2026-10-25: items 1-5 below were re-read from the full claim text and charted element by element in `docs/PATENT-SWEEP-CHARTS.md`; the four priority hits became design-around candidates and the 19 unread items became clear (each on a named absent element). The text below is the first-pass list, kept for the record.**

Priority, all from claim summaries that a human or attorney should read in full:
1. **US9397990B1** (Google, to 2034): macaroons with third-party caveats and discharge credentials. The swept commit implemented exactly that (`src/protocols/macaroons.rs:113`, `:150`); **retracted 2026-10-26: both were removed in 0.6.0-rc148 (#302) and 0.5.0-rc65, so at main this patent is outside the claims.**
2. **US11349844B2** (Microsoft, to ~2040): event-driven session revocation with forced re-authentication.
3. **US8959650B1** (EMC, to ~2032): per-request device-fingerprint check against an identifier carried in the session token. The session identifier is random (`src/security/secure_session.rs:290`), which points away from overlap, but not every token-building path was traced.
4. **US9369456B2** (Intuit, to ~2032): tenant-keyed authentication policy then token issuance.
5. **Read 2026-10-26 (see "Second-pass reads"): every patent in this item.** First-pass list: US10742655B2, US8763095B2, US20120330925A1, EP4092958B1, CN112149156A, US12256020, US9843577B2 (low), US10069859B2, US9754311B2 family, US20150006384A1, US11218466B2, US10771447B2, EP3158494B1, US11579783, US8869243B2, WO2017131963A1, US9882714B1, US9830455B2, US20140215603A1.
6. Design-around constraints the project must keep (record in the roadmap if accepted): keep CAEP handlers caller-supplied and never ship a relying-party handler that both revokes a session and redirects to the identity provider (US11349844B2, rated arguable, low-medium confidence, in the second pass); no issuer-introspection mode for macaroons (US11595215B1); no weighted reputation formula (US10681071B1); no device-tier-dependent key-rotation window or old-key-use alert (US10462152B2); no usage-monitoring key deactivation (US9424419B1); no policy dry-run diff feature (US12443741B2).
7. Checks not done: IETF and OpenID Foundation IPR disclosures for SD-JWT, OID4VCI, OID4VP, DPoP, mTLS; direct USPTO / Espacenet / WIPO searches; assignee-targeted searches (Google Zanzibar inventors; Microsoft, Okta, Ping, Duo/Cisco); CPC-class browsing; citation chains.

## Limitations

- AI-assisted search through a general web search tool, not a patent-database interface; the fetch tool summarises pages, so claim quotes are fragments and every `clear*` rests on a summary.
- First pass of 2-5 queries per idea; coverage is low to moderate everywhere and lowest for ideas 4, 7 and 8.
- Status and expiry dates are Google Patents' assumptions.
- The idea list comes from reading module headers and sampling code, not a line-by-line audit; mechanisms not listed here were not swept.
- Idea 11 refers to unmerged work and is listed so the sweep covers it when it ships.
- Not legal advice and not a freedom-to-operate opinion. A lawyer's review of the `needs-review` list is a separate purchase.

## Appendix: queries

All run 2026-10-25 by WebSearch (G.P. = restricted to patents.google.com).
- Idea 1: "patent authorization token validated evidence permission check refuse unvalidated token cryptographically verified proof" (G.P.); "patent authorization decision requires evidence that access token was verified signature validated by policy enforcement point unverified token rejected type-safe" (G.P.).
- Idea 2: five queries on Zanzibar, relation tuples, userset rewrite, zookies and relationship-based access control engines (G.P. and open web), including an inventor-name query.
- Idea 3: "patent macaroon bearer credential chained HMAC caveats attenuate delegation"; "patent macaroons offline attenuation credential caveats verifier checks each caveat HMAC chain third-party" (both G.P.).
- Idea 12: four queries on selective-disclosure credentials, SD-JWT, verifiable presentation requests and credential-offer wallet issuance.
- Idea 4: "patent continuous access evaluation security event token revoke session shared signals" (G.P.); "patent security event token receiving event identity provider revoke tokens sessions relying party" (open web).
- Idea 5: three queries on sliding-window and distributed rate limiting with shared stores (G.P. and open web).
- Idea 9: three queries on DPoP, certificate-thumbprint and key-bound access tokens.
- Idea 10: two queries on device fingerprint, concurrent-session limits and sliding expiry (G.P.).
- Idea 6: three queries on constant-time comparison, equalised failure timing and user enumeration.
- Idea 7: two queries on multi-tenant authentication contexts and tenant-specific configuration (G.P.).
- Idea 8: two queries on automatic threat-intelligence feed download and IP-reputation use in authentication (G.P.).
- Idea 11: three queries on API-key rotation with overlap windows and credential rotation.
- Idea 13: two queries on compliance reports from RBAC state and audit events (G.P.).
