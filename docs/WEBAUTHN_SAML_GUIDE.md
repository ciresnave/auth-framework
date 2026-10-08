# WebAuthn and SAML Implementation Guide

This guide reflects the current WebAuthn and SAML routes mounted by `ApiServer`.

## WebAuthn

## SAML Route Summary

- `POST /api/v1/webauthn/registration/init`
- `POST /api/v1/webauthn/registration/complete`
- `POST /api/v1/webauthn/authentication/init`
- `POST /api/v1/webauthn/authentication/complete`
- `GET /api/v1/webauthn/credentials/{username}`
- `DELETE /api/v1/webauthn/credentials/{username}/{credential_id}`

## Registration Flow

### 1. Initialize registration

Registration requires `Authorization: Bearer {token}`. The token must belong to
the account named by `username`, or to an admin. The server does not verify
attestation statements, so the only supported attestation preference is `none`
(`WEBAUTHN_ATTESTATION=none`, the default); any other value makes
`registration/init` fail with `ATTESTATION_UNSUPPORTED`. The `registration/complete`
call must use the same bearer token as `registration/init`, and the client data
must include the `origin`.

Sign-in (`authentication/init` + `authentication/complete`) needs the `username`;
the access token it returns is issued for that account's id.

Request:

```http
POST /api/v1/webauthn/registration/init
Content-Type: application/json

{
  "username": "user@example.com",
  "display_name": "Jane Doe",
  "authenticator_attachment": "platform",
  "user_verification": "preferred"
}
```

Current response shape:

```json
{
  "success": true,
  "message": "WebAuthn registration challenge generated",
  "data": {
    "challenge": "base64url-challenge",
    "rp": {
      "id": "localhost",
      "name": "AuthFramework"
    },
    "user": {
      "id": "dXNlckBleGFtcGxlLmNvbQ",
      "name": "user@example.com",
      "display_name": "Jane Doe"
    },
    "pubkey_cred_params": [
      { "type": "public-key", "alg": -7 },
      { "type": "public-key", "alg": -257 }
    ],
    "timeout": 60000,
    "excludeCredentials": null,
    "authenticatorSelection": {
      "authenticator_attachment": "platform",
      "require_resident_key": false,
      "user_verification": "preferred"
    },
    "attestation": "none",
    "session_id": "webauthn_550e8400-e29b-41d4-a716-446655440000"
  }
}
```

Notes:

- `challenge` is base64url encoded.
- `user.id` is the base64url-encoded username.
- The wire format mixes snake_case fields such as `pubkey_cred_params` and `display_name` with the WebAuthn-compatible keys `excludeCredentials` and `authenticatorSelection`.

### 2. Complete registration

Request:

```http
POST /api/v1/webauthn/registration/complete
Content-Type: application/json

{
  "session_id": "webauthn_550e8400-e29b-41d4-a716-446655440000",
  "credential_id": "credential-id-base64",
  "credential_public_key": "base64url-encoded-cose-public-key",
  "attestation_object": "base64url-attestation",
  "client_data_json": "base64url-client-data",
  "authenticator_data": "base64url-authenticator-data",
  "signature": "base64url-signature"
}
```

Success response:

```json
{
  "success": true,
  "message": "WebAuthn credential registered successfully"
}
```

## Authentication Flow

### 1. Initialize authentication

Request:

```http
POST /api/v1/webauthn/authentication/init
Content-Type: application/json

{
  "username": "user@example.com",
  "user_verification": "preferred"
}
```

Response:

```json
{
  "success": true,
  "message": "WebAuthn authentication challenge generated",
  "data": {
    "challenge": "base64url-challenge",
    "allow_credentials": [
      {
        "type": "public-key",
        "id": "credential-id-base64",
        "transports": ["internal", "usb"]
      }
    ],
    "timeout": 60000,
    "user_verification": "preferred",
    "session_id": "webauthn_auth_550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### 2. Complete authentication

Request:

```http
POST /api/v1/webauthn/authentication/complete
Content-Type: application/json

{
  "session_id": "webauthn_auth_550e8400-e29b-41d4-a716-446655440000",
  "credential_id": "credential-id-base64",
  "authenticator_data": "base64url-authenticator-data",
  "client_data_json": "base64url-client-data",
  "signature": "base64url-signature",
  "user_handle": "base64url-user-handle"
}
```

Success response:

```json
{
  "success": true,
  "message": "WebAuthn authentication successful",
  "data": {
    "access_token": "jwt-access-token",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user_id": "user@example.com",
    "authentication_method": "webauthn"
  }
}
```

Important detail: the current WebAuthn authentication response does not include a refresh token.

## Credential Management

### List credentials

```http
GET /api/v1/webauthn/credentials/{username}
Authorization: Bearer {token}
```

Response data is the stored credential JSON for that user.

### Delete a credential

```http
DELETE /api/v1/webauthn/credentials/{username}/{credential_id}
Authorization: Bearer {token}
```

## Browser Integration Example

```javascript
async function registerWebAuthn(accessToken, username, displayName) {
  const initResponse = await fetch('/api/v1/webauthn/registration/init', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
    },
    body: JSON.stringify({
      username,
      display_name: displayName,
      authenticator_attachment: 'platform',
      user_verification: 'preferred',
    }),
  });

  const initPayload = await initResponse.json();
  const options = initPayload.data;

  const credential = await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: base64UrlToArrayBuffer(options.challenge),
      user: {
        ...options.user,
        id: base64UrlToArrayBuffer(options.user.id),
      },
    },
  });

  return fetch('/api/v1/webauthn/registration/complete', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
    },
    body: JSON.stringify({
      session_id: options.session_id,
      credential_id: credential.id,
      credential_public_key: extractCredentialPublicKey(credential),
      attestation_object: arrayBufferToBase64Url(credential.response.attestationObject),
      client_data_json: arrayBufferToBase64Url(credential.response.clientDataJSON),
      authenticator_data: extractAuthenticatorData(credential),
      signature: extractAttestationSignature(credential),
    }),
  });
}
```

## SAML

The SAML routes are mounted only when the crate is built with the `saml` feature.

## Route Summary

- `GET /api/v1/saml/metadata`
- `POST /api/v1/saml/sso`
- `POST /api/v1/saml/acs`
- `POST /api/v1/saml/slo`
- `GET /api/v1/saml/slo/response`
- `POST /api/v1/saml/assertion`
- `GET /api/v1/saml/idps`

## Required Storage Configuration

### Service provider configuration

Store JSON under `saml_sp:config` with:

```json
{
  "entity_id": "https://auth.example.com/saml",
  "acs_url": "https://auth.example.com/api/v1/saml/acs",
  "slo_url": "https://auth.example.com/api/v1/saml/slo/response"
}
```

### Identity provider configuration

Each IdP is loaded from `saml_idp:{entity_id}`. The config must include `sso_url` and, for logout, `slo_url`. Signed response validation expects `signing_cert` when the `saml` feature is enabled.

An index of configured IdPs is stored at `saml_idps:index` as a JSON array of entity IDs.

## Metadata Endpoint

```http
GET /api/v1/saml/metadata
```

This route returns raw XML with content type `application/samlmetadata+xml`.

## SSO Flow

### 1. Initiate SSO

Request:

```http
POST /api/v1/saml/sso
Content-Type: application/json

{
  "idp_entity_id": "https://idp.example.com/saml",
  "relay_state": "/dashboard",
  "force_authn": false,
  "is_passive": false
}
```

Response:

```json
{
  "success": true,
  "data": {
    "redirect_url": "https://idp.example.com/sso?SAMLRequest=...",
    "saml_request": "base64-encoded-authn-request",
    "relay_state": "/dashboard"
  }
}
```

### 2. Assertion Consumer Service

Request:

```http
POST /api/v1/saml/acs
Content-Type: application/x-www-form-urlencoded

SAMLResponse=base64-encoded-response&RelayState=%2Fdashboard
```

Success response:

```json
{
  "success": true,
  "message": "SAML authentication successful",
  "data": {
    "access_token": "jwt-access-token",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "jwt-refresh-token",
    "user_id": "user@example.com",
    "authentication_method": "saml",
    "attributes": {
      "email": "user@example.com",
      "role": "admin"
    },
    "relay_state": "/dashboard"
  }
}
```

## Single Logout

### Initiate logout

Request:

```http
POST /api/v1/saml/slo
Content-Type: application/json

{
  "name_id": "user@example.com",
  "session_index": "optional-session-index",
  "idp_entity_id": "https://idp.example.com/saml"
}
```

Response:

```json
{
  "success": true,
  "message": "SAML logout initiated",
  "data": {
    "redirect_url": "https://idp.example.com/slo?SAMLRequest=...",
    "status": "logout_initiated"
  }
}
```

### Handle SLO response

```http
GET /api/v1/saml/slo/response?SAMLResponse=...&RelayState=...
```

Success response:

```json
{
  "success": true,
  "message": "SAML logout completed successfully"
}
```

## Assertion Generation

`POST /api/v1/saml/assertion` returns a wrapped XML string. The current request body expects:

- `username`
- `audience`
- `email` when `username` is not already an email address

## IdP Listing

`GET /api/v1/saml/idps` returns the JSON configs stored for the entity IDs listed in `saml_idps:index`.
