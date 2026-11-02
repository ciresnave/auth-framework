# Kerberos end-to-end AP-REQ test: design (ROADMAP A13)

Status: design note, slice 1. Measured at `origin/main` 01f08e77 (rc192). No test code yet.

## What is under test

`KerberosManager::authenticate(base64)` -> `parse_spnego_token` -> `validate_ap_req`
(`src/protocols/kerberos.rs`). It is an **acceptor**: it holds a service key, decrypts
the ticket and the authenticator, checks times and replay. It never contacts a KDC.
So there is no KDC process to run; the "KDC" in this test is a **fixture that issues
tickets** (builds and encrypts the structures a KDC and a client would).

Steps the test must reach, in order: keytab lookup (`select_keytab_entry`), ticket
decrypt (key usage 2), `EncTicketPart` parse, end/start time, authenticator decrypt
(key usage 11, session key from the ticket), crealm/cname match, clock skew, replay
cache, forwarded-flag policy.

## What exists and what does not (read at 01f08e77)

- Decrypt side only: `decrypt_aes_cts`, `derive_key_aes`, `parse_ap_req`,
  `parse_enc_ticket_part`, `parse_authenticator`. **No encrypt path**, and no DER
  *writer* in the module.
- Etypes: 17 (aes128-cts-hmac-sha1-96) and 18 (aes256-cts-hmac-sha1-96).
- The keytab is loaded only through `load_keytab(path)` (file, version 0x0502 or
  0x0501); `keytab_entries` is private. The test therefore writes a real keytab file,
  which also exercises `parse_keytab`.
- Existing tests (25 in the module, 4 doc-reading tests) cover primitives, replay and
  config. None builds a ticket.

## Fixture

A test-only module, `tests/common/kerberos_fixture.rs` (not in `src/`, so no
production code can call it):

1. **Keytab writer**: version 0x0502, entries `(principal, realm, kvno, etype, key)`.
   Service principal `HTTP/app.example.test@EXAMPLE.TEST`, kvno 3, one 32-byte AES-256
   key (a fixed constant; the key is test-only and says so).
2. **DER writer** for `Ticket`, `EncTicketPart`, `Authenticator`, `AP-REQ`, with
   explicit lengths. Small: INTEGER, GeneralString, GeneralizedTime, BIT STRING,
   SEQUENCE, context tags.
3. **AES-CTS encryptor** (RFC 3962: derive Ke/Ki from the base key with usage,
   confounder, AES-CBC-CTS, HMAC-SHA1-96) built on the `aes`, `hmac` and `sha1`
   crates the crate already depends on.
4. **Ticket issuer**: `issue(client, service, session_key, start, end, flags, kvno)`
   returns the `Ticket`; `ap_req(ticket, session_key, ctime, cusec, cname, crealm)`
   returns the AP-REQ, raw and wrapped in the SPNEGO/GSS-API initial token.

### Why the fixture must not share code with the validator

An encryptor written against the validator's own `derive_key_aes` proves only that
the two agree with each other. Two anchors that do not depend on this crate's
decrypt path:

- **RFC 3962 Appendix B known-answer vectors** for the key derivation and CTS
  encryption, asserted against the fixture's encryptor *before* it is used.
  (Expected outputs copied from the RFC, not computed here.)
- **Optional interop slice**: a keytab and AP-REQ produced by MIT krb5
  (`kdb5_util`, `ktutil`, `kinit`, `kvno`) in Docker, committed as bytes with the
  command that made them. The ticket time is baked in, so it is accepted only in a
  test that sets `max_clock_skew_secs` huge and says why; the time checks are then
  covered by the synthetic cases, not by this one.

## Cases and negative controls

Each negative case is derived from the valid one by changing exactly one input, and
each asserts the **specific** error, not just `is_err()`.

| # | Case | One change from the valid token | Expected |
|---|---|---|---|
| 0 | valid (positive control) | none | `Ok`, `client_principal = alice@EXAMPLE.TEST`, `end_time` as issued |
| 1 | wrong service key | ticket encrypted with a different key | decrypt/integrity error |
| 2 | other service | ticket for `HTTP/other.example.test` | "No keytab entry" (already a unit test since rc190; repeated end to end) |
| 3 | expired ticket | `end_time` = now - 2 x skew | "ticket has expired" |
| 4 | not yet valid | `start_time` = now + 2 x skew | "not yet valid" |
| 5 | skewed authenticator | `ctime` = now - 2 x skew | "clock skew too large" |
| 6 | cname mismatch | authenticator `cname` differs from ticket | "cname does not match" |
| 7 | crealm mismatch | authenticator `crealm` differs | "crealm does not match" |
| 8 | replay | same AP-REQ sent twice | second call refused by replay cache |
| 9 | forwarded ticket, delegation off | forwarded flag set | "Delegated ... not allowed"; with `allow_delegation(true)` it is `Ok` with `is_delegated` |
| 10 | kvno rotation | keytab holds kvno 3 and 4; ticket kvno 3 and kvno 5 | both accepted (any kvno of the principal), per `select_keytab_entry` |
| 11 | wrong session key | authenticator encrypted under another key | authenticator decrypt error |
| 12 | SPNEGO wrapper | case 0 wrapped | `Ok`, same result as raw |

**Controls that the test can fail.** Before the suite is trusted, mutate the
validator (not the fixture) four ways and show the named cases go red while case 0
stays green: skip the expiry check; skip the replay insert; skip the cname compare;
accept any keytab entry. A mutation that did not apply looks like one the suite
missed, so each mutation is asserted to change the source (anchor count 1) and to
compile.

Time: cases take `now` from `SystemTime::now()` at fixture time; skews are multiples
of the configured `max_clock_skew_secs`, so no test sleeps and none is flaky near the
boundary (the margin is a full skew).

## `kdc_addresses`

`KerberosConfig.kdc_addresses` and `KerberosConfigBuilder::add_kdc` are stored and
read by nothing except one config test (`git grep` at 01f08e77: lines 969, 987, 1011,
1068-1069 and the test at 1960-1968 of `kerberos.rs`). The validator is an acceptor;
using the field would mean adding a KDC client (AS-REQ/TGS-REQ over UDP or TCP) that
nobody asked for. Recommendation: **keep the field for compatibility, mark
`add_kdc` and the field `#[deprecated]` with a note that validation is offline, and
say so in `SECURITY.md`**. Removing is a breaking change to a published API and
needs the PM's rc rule for breaking changes; deprecating is not. Decision for the PM.

## Slices

1. This note (docs only).
2. Fixture + RFC 3962 known-answer tests + cases 0 and 12.
3. Negative cases 1-11 and the four validator mutations, with the red/green table
   in the PR.
4. `kdc_addresses` per the PM's decision.
5. Optional: MIT-generated interop fixture.

Every slice: fmt, clippy on the CI feature set, and the Kerberos tests, via Docker.
