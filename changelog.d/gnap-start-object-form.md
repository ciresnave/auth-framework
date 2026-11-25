GNAP `interact.start` object entries (RFC 9635 2.5.1) must carry a string `mode`; an object without one is now refused as `invalid_request` instead of being kept as an unknown mode.

GNAP token rotation is now idempotent for 30 seconds (RFC 9635 11.33): a client that lost the response and retries with the old token, proving its key again, gets the same new token; the old token is refused once the new one is seen in use. A key rotation is not retried this way. New tests for RFC 9635 11.30, 11.32 and 11.33.
