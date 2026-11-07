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
- `steps` (optional): an ordered list, for flows of more than one request. Without it the vector is
  one `transaction` step made of its own `request`, `proof` and `expect`. Each step has `do`:
  - `transaction`: `request`, `proof` as above; `jti` fixes the proof's `jti` (to send one proof twice).
  - `approve`: the resource owner approves at the server (not on the wire); saves `interact_ref` and `hash`.
  - `continue`: `transaction`, `token`, `interact_ref`, `interact_hash` (null to omit) and `proof`
    (`valid`, `absent`, `wrong_key`), sent to the continuation URL.
  - `rotate`, `revoke`: `token`; token management (RFC 9635 section 6).
  - `introspect`: `token`; the server's own view of a token (not on the RFC 9635 wire); the response
    has `active` true or false.
  A step may carry `expect` (as below) and `save`: a map of name to `{pointer, tail}` that keeps a
  string from the response (with `tail`, only what follows the last `/`). A later step writes `$name`
  to use it. `not_equals_saved` asserts a response string differs from a saved one.
  A refused step is not retried: later steps run against whatever state the server is left in.
- `request`: the JSON body sent to the transaction endpoint (before the replayer adds `client`).
- `expect.outcome`: `response` (the server answers) or `error` (it refuses).
- `expect.assert`: checks on a response, each a JSON Pointer `path` and an `op`:
  `exists`, `absent`, `is_string`, `is_number`, `is_array`, `equals` (with `value`), `min_length`
  (a string of at least `value` characters) or `not_equals_saved`.

Rules for adding a vector:

1. Cite the RFC section, and say positive or negative.
2. Keep wording neutral: describe the required behaviour, not an attack.
3. A vector that describes behaviour not yet fixed in a published release is held back until
   that release is out.

Scope of suite version 5: the transaction endpoint, continuation, token rotation and revocation, and the RFC 9635 section 11 checks the endpoint can answer, with DPoP client-key proofs. The server under test grants whatever is requested (a permissive access policy). RFC 9767 and the remaining section 11 checks are added
in later versions of the suite.
