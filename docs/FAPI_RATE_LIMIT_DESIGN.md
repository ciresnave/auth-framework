# Rate limiting the FAPI 2.0 endpoints (ROADMAP A16)

Status: slices 1-3 done (rustdoc, then `FapiManager::with_rate_limiter` and the `_from` entry points). Measured at `origin/main` 4301a8da.

## What exists

- The router-wide limiter (`ApiState.rate_limiter`, a `DistributedRateLimiter`, applied by
  `rate_limit_middleware_with_state` in `src/api/server.rs`) counts requests per caller address.
- `src/api/client_rate_limit.rs` adds one bucket per **authenticated** client
  (`oauth_client:<client id>`) on the OAuth2 token and introspection routes (ROADMAP #92, the
  client bucket done at rc165). It counts a request only after the client proved who it is, so a
  third party cannot spend someone else's allowance.
- `FapiManager` (`src/server/security/fapi.rs`) has **no limiter of its own**, and it is not part
  of the router in `src/api`: the crate exports it (`server::security::FapiManager`) for an
  integrator's server to call. Its entry points are `validate_authorization_request`,
  `validate_token_request`, `authenticate_client_jwt` and `validate_sender_constrained_token`.
  None takes a peer address or consults a limiter.

So the FAPI endpoints are limited only if the integrator limits them, and nothing in the crate
says so.

## Why it matters

The `/authorize` and `/token` paths do signature work and keep per-request state before the
caller is authenticated (a request-object or assertion signature, a DPoP proof and its replay
record). An unauthenticated caller can make a server do that work at the rate it can send
requests. The state kept is bounded; the cost per request is what a limiter caps.

## Options

1. **Document only.** Say in the `FapiManager` docs and in `docs/` that the integrator must put a
   limiter in front of the FAPI endpoints, with the two buckets below as the recommendation. No
   code, no API change.
2. **Optional limiter on the manager.** `FapiManager::with_rate_limiter(Arc<DistributedRateLimiter>)`
   and entry points that take the caller's address: `validate_authorization_request_from(peer, ..)`
   and `validate_token_request_from(peer, ..)`. The existing methods keep working and count
   nothing. Without a limiter configured nothing changes, so it is not a breaking change.
3. **Wire FAPI into `src/api`.** Out of scope: the crate does not serve FAPI routes today, and
   adding them is a feature.

Recommendation: **1 now, 2 as the follow-up.** Option 1 closes the "nothing says so" gap in one
small change; option 2 gives integrators the same two buckets #92 uses, instead of each
re-implementing them.

## Buckets (for option 2, and the advice in option 1)

| Bucket | Key | Counted | Why |
|---|---|---|---|
| Caller address | `fapi:<endpoint>:<peer>` | before any signature check | caps the work an unauthenticated caller can cause |
| Authenticated client | `fapi_client:<client id>` | after `authenticate_client_jwt` or the certificate check succeeded | per-client allowance that address rotation does not escape; same rule as `oauth_client:` |

`<endpoint>` is `authorize` or `token`, so one endpoint's traffic does not use the other's
allowance. A limiter that cannot be consulted refuses the request (the behaviour of
`client_rate_limit::check`'s `Unavailable`), it does not serve it unlimited.

## Negative controls (option 2)

Each differs from the accepted request in one input, and asserts the specific refusal:

| Case | One change | Expected |
|---|---|---|
| under the limit (control) | none | accepted |
| over the address limit | N+1 requests from one peer | refused before any signature work (a counter of verifier calls stays flat) |
| another peer | same client, different address | accepted: the address bucket is per peer |
| over the client limit | N+1 authenticated requests, rotating addresses | refused with a retry-after |
| unauthenticated request naming a client | wrong assertion, right client id | does not consume that client's bucket |
| limiter unavailable | limiter returns an error | refused, not served |
| no limiter configured | `FapiManager::new` only | unchanged behaviour |

Mutations to show the tests can fail: skip the address check; count the client bucket before
authentication; treat `Unavailable` as allowed. Each must turn exactly its own test red.

## Slices

1. This note, and the ROADMAP row A16.
2. Option 1: the `FapiManager` rustdoc and `docs/` paragraph, with the two buckets.
3. Option 2: `with_rate_limiter` and the `_from` entry points with the tests above.
