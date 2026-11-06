# GNAP conformance vectors

`vectors.json` is plain JSON so a client or server in any language can replay it. The Rust
harness is `tests/gnap_conformance.rs`.

Each vector has:

- `id`, `rfc`, `section`: where in the RFC the behaviour comes from.
- `kind`: `positive` (a conforming exchange) or `negative` (a request that must be refused).
- `config`: the server settings to start from (`enabled`, `transaction_endpoint`, `interaction_base_url`).
- `client_key`: `dpop` means the replayer generates a fresh P-256 key and puts it in the request as
  `client.key` (`proof: "dpop"`, with the public key as `jwk`). Absent means the request names no key.
- `proof`: with a `client_key`, what accompanies the request: `valid` (a DPoP proof for `POST` and the
  transaction endpoint URL, signed by that key), `absent` (no `DPoP` header) or `wrong_key` (signed by a
  different key than the one named).
- `request`: the JSON body sent to the transaction endpoint (before the replayer adds `client`).
- `expect.outcome`: `response` (the server answers) or `error` (it refuses).
- `expect.assert`: checks on a response, each a JSON Pointer `path` and an `op`:
  `exists`, `absent`, `is_string`, `is_number`, `is_array`, or `equals` (with `value`).

Rules for adding a vector:

1. Cite the RFC section, and say positive or negative.
2. Keep wording neutral: describe the required behaviour, not an attack.
3. A vector that describes behaviour not yet fixed in a published release is held back until
   that release is out.

Scope of suite version 2: the transaction endpoint with DPoP client-key proofs. The server under test grants whatever is requested (a permissive access policy). Multi-step
(continuation), proofs, token management, RFC 9767 and the RFC 9635 section 11 checks are added
in later versions of the suite.
