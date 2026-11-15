# GNAP resource-server API (RFC 9767)

The resource-server (RS) half of GNAP lives in `src/protocols/gnap_rs.rs` (protocol logic), `src/protocols/gnap_http.rs`
(request and response handling) and the `gnap_axum` / `gnap_actix` integrations (routes). What is open is tracked in
`docs/GNAP_RFC9635_GAP.md` section 2. The conformance suite is `tests/conformance/gnap/rs-vectors.json`.

## What the AS offers

| RFC 9767 | Endpoint | Offered |
|---|---|---|
| 3.1 discovery | `GET /.well-known/gnap-as-rs` | always |
| 3.3 introspection | the `introspection_endpoint` (`POST`) | always |
| 3.4 resource set registration | the `resource_registration_endpoint` (`POST`) | only after `with_registry`; otherwise 404 and no discovery member |

Responses to introspection and registration carry `Cache-Control: no-store`. Errors are HTTP 400 with
`{"error": ...}`: `invalid_resource_server`, `invalid_request` or `invalid_access`. `RsError` is `#[non_exhaustive]`.

## What the deployer supplies

| Trait | Decides |
|---|---|
| `ResourceServerAuthenticator` | who is calling: the RS identity from the call's key proof (3.2) |
| `TokenInfoSource` | what the AS knows about an access token value (`None` for an unknown or revoked token) |
| `ResourceRegistry` (optional) | whether a resource set registration is accepted, and the `resource_reference` it gets |

The crate ships none of the three, and it verifies no RS key proof itself: until G2 (`httpsig`) lands, the
authenticator checks the proof with whatever the deployer uses.

## The RS key registry

RFC 9767 3.2 has the RS sign each call with **its own key**: not the client instance's key and not the token's key.
The deployer's `ResourceServerAuthenticator` is therefore where RS keys are registered. Rules it should follow:

1. Keep a registry of RS key to RS identifier. `AuthenticatedRs::id` is that identifier.
2. Return `None` for a call proved by an unknown key. The API answers `invalid_resource_server`, and for
   registration it does so before the registry is consulted.
3. Never accept a client instance's key or a token's key as an RS key.
4. The identifier is compared with `RsTokenInfo::audience`: a token whose audience is non-empty and does not name the
   caller is answered as inactive. An empty audience means any RS.
5. The `resource_server` member of the request is the RS's identifier or reference. It is **not** a
   `resource_reference`: that opaque handle comes back from registration and is for the RS to publish to client
   developers, not a credential.
6. Rotating an RS key is the deployer's change to its registry; the API holds no key state.

## Registration

`GnapResourceServerApi::with_registry(endpoint, registry)` turns registration on. The endpoint must be `https` with
no fragment, and its path must differ from the introspection endpoint's path and from the discovery path. A request needs
`access` (a non-empty array of strings or objects) and `resource_server`; `token_formats_supported` and
`token_introspection_required` are optional. When the AS lists token formats, the request's list is intersected with it.
The response is `resource_reference`, `instance_id` when the registry returns one, and `introspection_endpoint`.
