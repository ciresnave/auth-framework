# OAuth 2.1 & Enhanced Security Features

This document provides an overview of the new OAuth 2.1 and enhanced security features implemented in Auth Framework v0.3.0.

## 1. OAuth 2.1 Authorization Framework

OAuth 2.1 is a consolidation of best practices from OAuth 2.0, providing enhanced security and a more streamlined protocol. The implementation in `src/server/oauth21.rs` provides:

### Key Features

- **Mandatory PKCE**: PKCE (Proof Key for Code Exchange) is required for all clients, preventing authorization code interception attacks
- **No Implicit Flow**: The insecure implicit flow has been removed entirely
- **Enhanced Security Requirements**: Stricter validation rules for all protocol interactions
- **Simplified Grant Types**: Focus on authorization code, client credentials, refresh token, and device code grants

### Example Usage

```rust
// Create OAuth 2.1 server configuration
let mut config = OAuth21ServerConfig::default();
config.issuer = "https://auth.example.com".to_string();
config.require_par = true; // Require Pushed Authorization Requests

// Create OAuth 2.1 server
let server = OAuth21Server::new(config)?;

// Register a client
let client_config = OAuth21ClientConfig {
    client_id: "client123".to_string(),
    client_type: OAuth21ClientType::Confidential,
    redirect_uris: vec!["https://app.example.com/callback".to_string()],
    grant_types: [OAuth21GrantType::AuthorizationCode, OAuth21GrantType::RefreshToken].into(),
    requires_par: true,
};

server.register_client(client_config).await?;
```

## 2. RFC 9126: Pushed Authorization Requests

PAR enhances security by moving authorization request parameters from the front-channel to the back-channel, implemented in `src/server/par.rs`.

### Key Features

- **Back-Channel Authorization Requests**: Authorization parameters sent securely via back-channel
- **Request URI Generation**: Unique URIs generated for authorization requests
- **Expiration Handling**: Automatic expiration of unused requests
- **Request Validation**: Comprehensive validation of all PAR parameters

### Example Usage

```rust
// Create PAR manager
let par_manager = PARManager::new(storage.clone());

// Store a pushed authorization request
let request = PushedAuthorizationRequest {
    client_id: "client123".to_string(),
    response_type: "code".to_string(),
    redirect_uri: "https://app.example.com/callback".to_string(),
    scope: Some("profile email".to_string()),
    state: Some("xyz".to_string()),
    code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
    code_challenge_method: Some("S256".to_string()),
    expires_in: 60,
};

let request_uri = par_manager.store_request(request).await?;
// request_uri: "urn:ietf:params:oauth:request_uri:6a7812c3-b8f5-4031-a2a9-456123a8b456"

// Later, consume the request during authorization
let stored_request = par_manager.consume_request(&request_uri).await?;
```

## 3. RFC 8705: Mutual TLS Client Authentication

This implementation in `src/server/mtls.rs` provides certificate-based client authentication and certificate-bound access tokens.

### Key Features

- **PKI-based Authentication**: Certificate validation against trusted CA chains
- **Self-signed Certificate Support**: Client authentication with self-signed certificates
- **Certificate-Bound Access Tokens**: Access tokens bound to specific client certificates
- **X.509 Certificate Processing**: Complete validation of certificate attributes

### Example Usage

```rust
// Create mTLS manager
let mut mtls_manager = MutualTlsManager::new();

// Add CA certificates for PKI validation
mtls_manager.add_ca_certificate(ca_cert_bytes)?;

// Register client for mTLS authentication
let client_config = MutualTlsClientConfig {
    client_id: "client123".to_string(),
    auth_method: MutualTlsMethod::PkiMutualTls,
    ca_certificates: vec![ca_cert_bytes],
    client_certificate: None,
    expected_subject_dn: Some("CN=Example Client".to_string()),
    certificate_bound_access_tokens: true,
};

mtls_manager.register_client(client_config).await?;

// Authenticate client using certificate
let auth_result = mtls_manager.authenticate_client(
    "client123",
    client_certificate_bytes
).await?;

if auth_result.is_valid {
    // Create certificate-bound access token
    let confirmation = mtls_manager.create_certificate_confirmation(client_certificate_bytes)?;
    // Include confirmation in access token...
}
```

## 4. RFC 9449: DPoP (Demonstrating Proof-of-Possession)

DPoP provides application-layer proof-of-possession for OAuth 2.0 access tokens, implemented in `src/server/dpop.rs`.

### Key Features

- **Proof-of-Possession**: JWT-based proofs bound to HTTP requests
- **Protection Against Token Theft**: Tokens bound to specific client keys
- **Replay Attack Protection**: Nonce management and timestamp validation
- **JWK Thumbprint Calculation**: RFC 7638 compliant thumbprints

### Example Usage

```rust
// Create DPoP manager
let jwt_validator = SecureJwtValidator::new(SecureJwtConfig::default());
let dpop_manager = DpopManager::new(jwt_validator);

// Validate a DPoP proof
let validation_result = dpop_manager.validate_dpop_proof(
    dpop_proof_jwt,
    "POST",
    "https://api.example.com/resource",
    Some(access_token),
    Some(expected_nonce)
).await?;

if validation_result.is_valid {
    // Create DPoP-bound token confirmation
    let confirmation = dpop_manager.create_dpop_confirmation(
        validation_result.public_key_jwk.as_ref().unwrap()
    )?;
    // Include confirmation in access token...
}
```

## 5. RFC 8414: Authorization Server Metadata

This implementation in `src/server/metadata.rs` provides dynamic discovery of authorization server capabilities.

### Key Features

- **Well-Known Configuration**: Discovery of server endpoints and capabilities
- **OAuth 2.0 & 2.1 Support**: Metadata generation for both protocol versions
- **Metadata Builder Pattern**: Easy construction of server metadata
- **Metadata Validation**: Comprehensive validation of metadata completeness

### Example Usage

```rust
// Create metadata for OAuth 2.1 server
let metadata = MetadataBuilder::new("https://auth.example.com".to_string())
    .authorization_endpoint("https://auth.example.com/oauth2/authorize".to_string())
    .token_endpoint("https://auth.example.com/oauth2/token".to_string())
    .jwks_uri("https://auth.example.com/.well-known/jwks.json".to_string())
    .response_types_supported(vec!["code".to_string()]) // Only code in OAuth 2.1
    .code_challenge_methods_supported(vec!["S256".to_string()]) // Only S256 in OAuth 2.1
    .enable_par("https://auth.example.com/oauth2/par".to_string(), true)
    .enable_dpop(vec!["ES256".to_string()])
    .build();

let provider = MetadataProvider::new(metadata);
let json = provider.get_metadata_json()?;

// Serve at /.well-known/oauth-authorization-server
```

## Integration

These components can be combined to create a comprehensive OAuth 2.1 authorization server with enhanced security features:

```rust
// Create OAuth 2.1 server
let par_manager = PARManager::new(storage.clone());
let mtls_manager = MutualTlsManager::new();
let dpop_manager = DpopManager::new(jwt_validator);

let mut oauth21_config = OAuth21ServerConfig::default();
oauth21_config.issuer = "https://auth.example.com".to_string();
oauth21_config.require_par = true;
oauth21_config.par_manager = Some(par_manager);

let oauth21_server = OAuth21Server::new(oauth21_config)?;

// Create metadata provider
let metadata_provider = MetadataProvider::from_oauth21_server(
    &oauth21_server,
    "https://auth.example.com"
)?;

// Expose the metadata endpoint
let metadata_json = metadata_provider.get_metadata_json()?;
```

## Security Benefits

These implementations provide substantial security benefits:

1. **Protection Against CSRF**: PAR and DPoP prevent cross-site request forgery attacks
2. **Defense Against Token Theft**: Certificate and DPoP binding prevent stolen token usage
3. **Elimination of Implicit Flow Vulnerabilities**: OAuth 2.1 removes the insecure implicit flow
4. **Enhanced Client Authentication**: mTLS provides strong client authentication
5. **Discovery Security**: Metadata enables secure client configuration

With these features, Auth Framework now provides one of the most comprehensive and secure OAuth implementations available in Rust.
