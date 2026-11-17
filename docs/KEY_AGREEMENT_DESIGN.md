<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Design: X25519 key-agreement keys in the key stores (KM2 remainder)

Status: **proposal, no code.** The PM asked for the design first (2026-11-16): the `KeyStore` surface, the new record
kind, migration of existing stores and rollback. Roadmap row: KM2 ("generate every kind (RSA, P-256, P-384, Ed25519,
X25519, 256-bit symmetric)"). Everything else in KM2 is merged (#410, #455, #478).

## 1. What exists (measured at main 784f8f50)

- `KeyKind::JweEncryption` exists (`src/keys/kind.rs`): `is_asymmetric()` is true and `jwk_use()` is `enc`.
- It cannot be generated or stored. `LocalKey::generate`, `generate_rsa` and `from_pkcs8_der` all call
  `require_signing_kind` (`src/keys/generate.rs`), which refuses every kind whose JWK `use` is not `sig` except `Mtls`
  (admitted by #478). `LocalKey` holds a signing key pair (`Pair::{Ec, Ed, Rsa}`) and `SigningAlg` has no X25519 member.
- Both stores keep one record per key. `FileKeyStore` writes an AES-256-GCM sealed JSON `Record { v: 1, kind, state,
  public, pkcs8, secret, created_at, retiring_at }` and **fails the whole open on a record it cannot parse or whose `v` is
  not 1** (`entry_from_record`: "unsupported key record version"). A file without the `.key` suffix is ignored.
- `publish_jwks`, `rotate`, `revoke`, `compromise`, `retire_expired` and the `KeyRing` are written over `KeyInfo` and
  `NewKey::Local(LocalKey)`; they never look at the algorithm except the `KeyRing`, which loads only `Hmac` and
  `JwsSigning` kinds and ignores the rest.
- Nothing in the crate consumes an ECDH key: `server/oidc/oidc_advanced_jarm.rs:731` says "in production this would
  use ECDH-ES" and does not. `security/enhanced_crypto.rs` has an `X25519KeyPair` on `x25519-dalek`, an optional
  dependency behind the `enhanced-crypto` feature, held in memory only and not connected to the key stores.
- Backends. `LocalKey` uses `ring` (EC, Ed25519, RSA signing) and rcgen (RSA generation). `ring` offers X25519 only as an
  ephemeral key that cannot be exported, so it cannot back a stored key. `aws-lc-rs` has a persistent
  `agreement::PrivateKey` (`generate`, `from_private_key`, `compute_public_key`, `agree`) but it is an **optional**
  dependency here (`rsa-verify`, `rsa-private-key-ops`, `fips-compliance`, version `1.14.1`; it brings AWS-LC's C code,
  the reason RSA operations are opt-in per CireSnave's 2026-09-24 ruling), while the key stores always compile.
  `x25519-dalek` 2.0 (`static_secrets`) is also optional, pure Rust, and already declared (feature `enhanced-crypto`).

## 2. Options

**(a) A new `AgreementKey` type plus `KeyStore` methods** (`insert_agreement`, `export_agreement_private`, `agree`) and
a new `NewKey::Agreement` variant. Cleanest types; but a new `NewKey` variant breaks any caller that matches `NewKey`
exhaustively, every `KeyStore` implementation (ours and third parties') must grow methods (defaults can return an
error), `Entry` and `Record` grow a third private-material field, and `rotate`, the CLI and the key ring all learn a
third key shape.

**(b) Teach `LocalKey` a non-signing pair** (recommended). `LocalKey` stays the one asymmetric key type; a new
constructor `LocalKey::generate_x25519(kind, kid)` (and `from_pkcs8_der` accepting the RFC 8410 X25519 PKCS#8 when the
kind is `JweEncryption`) adds a `Pair::X25519` variant. `Signer::sign` on it returns an error ("an agreement key does not
sign"). The stores, `rotate`, `revoke`, `compromise`, `retire_expired`, `publish_jwks` and the CLI work unchanged
because they see a `LocalKey` with a kind, a state and a public JWK. **No `KeyStore` change and no new `NewKey` variant.**

**(c) A separate `AgreementStore` trait.** Two parallel stores to keep in step (directories, locking, rotation), and
nothing is gained over (b) until a non-exportable store exists. Rejected.

A non-exportable store (KM3: OS keystore, TPM, KMS) will want the private key never to leave it, as `sign` already allows
for signing keys. That is the one real reason to touch the trait, and it can be added **later, without a breaking change**,
as a defaulted method `KeyStore::agree(&self, kid, peer_public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>>` that
returns "not supported" by default. It is out of scope for the first slices.

## 3. Recommendation: option (b), in three slices

1. **Keys.** `Pair::X25519`, `LocalKey::generate_x25519` and X25519 in `from_pkcs8_der`, public JWK
   `{"kty":"OKP","crv":"X25519","x":...,"use":"enc"}` (the `alg` member is an open question, below), thumbprint `kid`
   as for every kind (RFC 7638 already covers OKP), `LocalKey::agree(&self, peer_public)` as a pure primitive returning the
   32-byte shared secret (`Zeroizing`; it rejects the all-zero result of a low-order peer point). A `LocalKey` carries no
   lifecycle state, so the state rule lives where the key is fetched: a free function `keys::agree(store, kid, peer_public)`
   (like `publish_jwks`, over the existing trait) checks `info()` and allows only an `Active` or `Retiring` key (a
   `Retiring` key must still decrypt what was encrypted to it before the rotation; `Revoked`, `Pending` and `Destroyed` may
   not), needs an exportable store, and is the call a JWE layer makes. The stores gain nothing but the record rule in
   section 4. Tests: round trip through both stores, rotation, JWKS contents, agreement with an independent
   implementation (the existing `x25519-dalek` in a test, behind its feature, or the RFC 7748 section 6.1 vectors).
2. **Admin CLI.** `keys generate --kind jwe-encryption`; `rotate` and `compromise` of such a key (they build the replacement
   by kind, so the algorithm lookup has an X25519 branch).
3. **A consumer** (not designed here): ECDH-ES in the OIDC/JWE code paths that today only say they would. Until then the
   keys can be created, stored, rotated, revoked and published, and `agree` is the primitive a JWE implementation calls.

## 4. Storage format, migration and rollback

- **Record.** Same `Record`, `kind: "jwe_encryption"`, `pkcs8` holds the RFC 8410 X25519 private key
  (`302e020100300506032b656e04220420` followed by the 32 bytes, 48 bytes in all), `public` the OKP JWK. Existing fields
  are enough; `secret` stays unused for it.
- **Version.** Write **`v: 2` for an agreement record only**; every existing kind keeps `v: 1`. A store that never gets an
  agreement key is byte-for-byte what it is today, so upgrading changes nothing on disk.
- **Migration.** None: no existing record changes, no rewrite pass, no new directory. The new binary reads `v: 1` and `v: 2`.
- **Rollback / downgrade.** An older binary that finds a `v: 2` record refuses to open the directory with
  "unsupported key record version" (the existing fail-closed rule), so it cannot list, sign with, rotate or overwrite
  anything in a store it does not understand. This is deliberate and loud, not silent corruption. To downgrade, revoke and
  destroy the agreement keys with the new binary first (`keys destroy` removes the private material; a destroyed record is
  still `v: 2`, so delete its file with the directory's other housekeeping, or keep the new binary). We state this in the
  slice's changelog entry. A separate suffix (`.agree`) was considered and rejected: an older binary would silently ignore
  such files and could then create a signing key with the same `kid`, which the newer binary would find twice.
- **Memory-only store.** Nothing to migrate.
- **Authenticated data.** The record's AAD is `auth-framework/keystore/v1:{kid}`; it stays, because `v` is inside the
  sealed JSON and the AAD names the store format rather than the record version.

## 5. Dependencies and backends

The key stores always compile, so the X25519 backend must be chosen without forcing C code on everyone:

- **Recommended: a new opt-in feature `key-agreement = ["dep:x25519-dalek"]`.** Pure Rust, an already declared optional
  dependency (so **no new crate**), consistent with the opt-in shape the RSA features use. `x25519_dalek::StaticSecret`
  gives generation, `PublicKey::from(&secret)` and `diffie_hellman`; slice 1 confirms it zeroizes and states the version
  relied on. The PKCS#8 wrapper (RFC 8410) is a fixed 16-byte prefix written and checked by hand.
- Alternative: gate it on `aws-lc-rs` (`dep:aws-lc-rs`) instead. Same shape, C code, and the persistent
  `agreement::PrivateKey` API; worth it only if a FIPS build needs the key agreement inside AWS-LC.
- Alternative: make one of them a required dependency. Rejected: it changes the build for users who never use the feature.
- **Without the feature**, `LocalKey::generate_x25519` does not exist and a store directory that contains an agreement
  record **fails to open** with a message that names the feature (the same fail-closed rule as section 4), rather than
  holding keys it cannot use. With it, nothing else changes.
- The existing `X25519KeyPair` in `security/enhanced_crypto.rs` is memory-only and unrelated to the stores; it is not reused
  (it would pull the other `enhanced-crypto` dependencies), and tests may cross-check against it when both features are on.

## 6. Compatibility

Recommended option (b) adds public items only: `LocalKey::generate_x25519`, `LocalKey::agree`, and widened input to
`from_pkcs8_der` for one kind. No existing signature changes, so it is a non-breaking minor change. The one behaviour
change is that a `JweEncryption` `LocalKey` can now exist, so a `match` over `SigningAlg` is unaffected (X25519 is not a
`SigningAlg`) but code that assumed every `LocalKey` signs must check: `Signer::sign` returns an error for it, and
`keys::cert` already refuses the kind (`key_pair`), the `KeyRing` already ignores it. `LocalKey::signing_alg()` has no
honest answer for an X25519 key: slice 1 either returns an `Option` (breaking) or documents it as unspecified for
non-signing keys and adds `LocalKey::is_signing()`; the proposal is the second.

## 7. Open questions for the PM

0. **Backend and feature.** Pure-Rust `x25519-dalek` behind a new opt-in `key-agreement` feature (recommended, no new
   crate), or `aws-lc-rs`? (Section 5.)
1. **JWK `alg`.** `ECDH-ES` (direct agreement, the shared secret derives the content key) or `ECDH-ES+A256KW` (key wrap)?
   Proposal: publish `ECDH-ES` and let the JWE layer choose the wrapping, since the key is the same.
2. **Scope.** X25519 only, or also P-256 and P-384 ECDH keys (the same `Pair` variant extended; JWE `ECDH-ES` supports
   them and RFC 7518 requires P-256)? Proposal: X25519 first, P-256 as a follow-up on the same design.
3. **`LocalKey::signing_alg()`** (section 6): keep and document, or make it return an `Option` as a Breaking change at the
   next 0.n bump?
4. **Downgrade note** (section 4): is "an older binary refuses the directory" acceptable, or do you want a one-time
   export/convert tool before the first agreement key can be written?

## 8. P-256 (slice 4; PM ruling 2026-11-17: dependency `p256` approved)

Question 2 above is answered: X25519 shipped first (#496), P-256 follows on the same design, as a second `Pair` variant.

- **Mechanism.** ECDH-ES on NIST P-256 as JWE specifies it (RFC 7518 section 4.6; NIST SP 800-56A). Nothing here is a new
  mechanism, so there is no patent question beyond the standard one: it is the RFC-standard algorithm, implemented by the
  RustCrypto `p256` crate (MIT or Apache-2.0).
- **Dependency.** `p256` 0.14 as a direct, **optional** dependency behind the existing `key-agreement` feature, with
  `default-features = false` and only `ecdh`, `pkcs8` and `std` (no ECDSA, no PEM). `ring` offers only ephemeral
  agreement, so a key a store holds needs it. The default build's dependency tree is unchanged; `Cargo.lock` gains no
  package (`p256` 0.14.0 was already locked, through `passkey-crypto`). Without the feature nothing is compiled.
- **Key.** `Pair::P256(p256::SecretKey)`, kind `JweEncryption`, public JWK `{"kty":"EC","crv":"P-256","x","y","use":"enc",
  "alg":"ECDH-ES"}`, thumbprint `kid`. The record holds the key's RFC 5958 PKCS#8 and is `v: 2` like every agreement
  record, so the rollback rule of section 4 is unchanged: an older build, or one without the feature, refuses the
  directory. `LocalKey::from_pkcs8_der` with kind `JweEncryption` tells the two curves apart by the DER (the RFC 8410
  X25519 prefix, else RFC 5958 P-256); a key of any other curve is refused.
- **Peer encoding.** `LocalKey::agree` takes the peer's public point as an uncompressed SEC1 point, `04 || x || y`, 65
  bytes: exactly what a JWE layer builds from an `epk`'s `x` and `y`. It refuses every other length or tag (compressed and
  hybrid points too), the identity, a coordinate not below the field prime and a point not on the curve (the invalid-curve
  attack). P-256 has cofactor 1, so a point on the curve is in the group and there is no low-order check as for X25519.
  The secret is the x coordinate (`Z` of RFC 7518 section 4.6.2), 32 bytes, `Zeroizing`.
- **Secrets in memory.** The private scalar is a `p256::SecretKey`, the DH output a `p256::ecdh::SharedSecret`, the
  PKCS#8 a `SecretDocument` or `Zeroizing<Vec<u8>>`: all four wipe on drop, asserted at compile time by a test, and the
  random bytes a generated key starts from are `Zeroizing`.
- **Evidence.** The RFC 5903 section 8.1 vectors (public points and the shared x), re-derived independently with plain
  big-integer arithmetic before use, through `LocalKey` and through both stores and a reopen; refusal cases for every
  malformed peer; PKCS#8 exactness and interoperation with a `ring`-generated key.
- **CLI.** `keys generate --kind jwe-encryption-p256`; `rotate` and `compromise` keep the key's curve (read from its
  public JWK), so replacing a P-256 key never yields an X25519 one. `--kind jwe-encryption` stays X25519.
