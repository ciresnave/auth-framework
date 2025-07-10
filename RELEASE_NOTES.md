# Auth Framework v0.2.0 Release Notes

Released: July 10, 2025

## 🎉 Major Features & Improvements

### 📋 Community-Driven Enhancements

This release addresses key feedback from the community and implements highly requested features:

## 🆕 New Features

### 🔧 Device Flow Support
- **Dedicated Device Flow Authentication** - Complete implementation for CLI apps, IoT devices, and scenarios where the user authenticates on a different device
- **DeviceAuthorizationResponse** type with proper polling support
- **Comprehensive Device Flow Example** (`examples/device_flow.rs`) with error handling patterns
- **Device-specific error types** for authorization_pending, slow_down, expired_token, and access_denied scenarios

### 👤 Standardized User Profiles  
- **Unified `UserProfile` type** works consistently across all OAuth providers
- **Easy conversion utilities** to reduce mapping code between auth-framework and application types
- **Provider-agnostic user information** with standard fields (id, name, email, picture, etc.)
- **Additional data support** for provider-specific information

### 🧪 Testing Utilities
- **Mock implementations** for easy testing without real authentication servers
- **`MockAuthMethod`** with configurable success/failure scenarios  
- **`MockStorage`** for in-memory testing
- **Helper functions** (`helpers::create_test_*`) for generating test data
- **Comprehensive test examples** in documentation

### 🚨 Enhanced Error Handling
- **Device Flow specific errors**: `DeviceFlowError` enum with granular error types
- **OAuth Provider errors**: `OAuthProviderError` for provider-specific issues  
- **Authentication errors**: More specific error types with context
- **Timeout handling**: Proper timeout errors with duration information
- **Provider configuration errors**: Clear messages for missing or invalid provider setup

### ⚙️ Streamlined Provider Configuration
- **Predefined OAuth configurations** for popular providers (GitHub, Google, Microsoft, etc.)
- **Default scopes** automatically included for each provider
- **PKCE support detection** built into provider configurations
- **Device flow capability** detection per provider
- **Simplified custom provider setup** with sensible defaults

### 💻 CLI Integration Helpers
- **Command-line framework integration** utilities for clap and similar tools
- **Device flow CLI patterns** with progress feedback and user instructions
- **Token persistence helpers** for CLI applications
- **Configuration management** for CLI authentication flows

### 🔥 Enhanced Device Flow Integration (NEW)
- **oauth-device-flows integration** - Optional integration with the specialized `oauth-device-flows` crate for production-ready device authentication
- **QR code generation** - Automatic QR code generation for mobile device authentication
- **Advanced polling strategies** - Exponential backoff and robust error handling
- **Multiple provider support** - Built-in support for GitHub, Google, Microsoft, GitLab, and custom providers
- **Token lifecycle management** - Automatic token refresh and secure token handling
- **Enhanced security** - Built on the `secrecy` crate with no sensitive data logging
- **Minimal dependencies** - Optimized for embedded and CLI usage scenarios
- **Feature flag controlled** - Enable with `enhanced-device-flow` feature flag

### 📚 Enhanced Documentation & API Clarity  
- **Comprehensive examples** for all authentication methods
- **Clear credential-to-method relationship** documentation
- **Step-by-step device flow guide** with real-world patterns
- **Error handling examples** for common scenarios
- **Testing guide** with mock implementations
- **CLI integration examples** with popular frameworks

### 📋 Token Persistence & Management
- **Built-in token storage** mechanisms for secure persistence
- **Session-based token management** with automatic cleanup
- **Token refresh handling** with proper error recovery
- **Secure token serialization** for client applications

## 🔧 API Improvements

### Better Method Registration
```rust
// Simplified OAuth provider setup
let github_method = OAuth2Method::new()
    .provider(OAuthProvider::GitHub) // Auto-includes user:email scope
    .client_id("your-client-id")
    .client_secret("your-client-secret");
```

### Unified Credential Types
```rust
// Clear relationship between credentials and methods
let oauth_cred = Credential::oauth_code("authorization_code");
let device_cred = Credential::device_code("device_code", "client_id");  
let api_key_cred = Credential::api_key("api_key_string");
```

### Enhanced UserProfile 
```rust
// Standardized user profiles across providers
let profile = UserProfile::new("user123", "github")
    .with_name("John Doe")
    .with_email("john@example.com")
    .with_email_verified(true);

// Easy conversion to app types
let app_user: AppUser = profile.into();
```

## 🏗️ Infrastructure Improvements

- **Testing feature flag** (`features = ["testing"]`) for optional test utilities
- **Modular architecture** with clear separation of concerns
- **Performance optimizations** with reduced memory usage for large enums
- **Code quality improvements** with comprehensive linting and formatting

## 🔄 Breaking Changes

- **OAuth Provider enum**: The `Custom` variant now uses `Box<OAuthProviderConfig>` for memory efficiency
- **Method constructors**: Some builder methods removed `mut` requirement for fluent API consistency
- **Error types**: New error variants may require match arm updates in existing error handling code

## 📦 Version Requirements

- **Minimum Rust version**: 1.70.0 (unchanged)
- **New dependencies**: None (all new features use existing dependencies)
- **Feature flags**: New optional `testing` feature for test utilities

## 🔗 Migration Guide

### From v0.1.1 to v0.2.0

1. **Update Cargo.toml**:
   ```toml
   [dependencies]
   auth-framework = "0.2.0"
   ```

2. **Error Handling**: Update match arms if you were matching on specific error types:
   ```rust
   // Before v0.2.0
   match auth_error {
       AuthError::InvalidCredential { .. } => { /* handle */ }
       // ...
   }

   // v0.2.0+  
   match auth_error {
       AuthError::InvalidCredential { .. } => { /* handle */ }
       AuthError::DeviceFlow(device_err) => { /* handle device flow errors */ }
       AuthError::OAuthProvider(oauth_err) => { /* handle OAuth errors */ }
       // ...
   }
   ```

3. **Custom OAuth Providers**: If you were constructing custom providers directly:
   ```rust
   // Before v0.2.0
   let provider = OAuthProvider::Custom { name, config };

   // v0.2.0+
   let provider = OAuthProvider::custom(name, config); // Uses Box internally
   ```

4. **Testing**: Add the testing feature for test utilities:
   ```toml
   [dev-dependencies]
   auth-framework = { version = "0.2.0", features = ["testing"] }
   ```

## 🎯 Example Updates

All examples have been updated and verified:

- ✅ `examples/basic.rs` - Basic authentication setup  
- ✅ `examples/oauth.rs` - OAuth integration with multiple providers
- ✅ `examples/device_flow.rs` - Device flow authentication (NEW)
- 🔄 Other examples being updated to match v0.2.0 API

## 🙏 Community Feedback Addressed

This release directly addresses feedback from users:

- ✅ **Device Flow Support** - "explicit device flow functionality exposed in the public API"
- ✅ **Documentation Gaps** - "comprehensive examples for device flow authorization"  
- ✅ **API Clarity** - "relationship between Credential types and authentication methods"
- ✅ **Provider Configuration** - "streamlined way to configure providers with default settings"
- ✅ **User Profile Standardization** - "standardized UserProfile type"
- ✅ **Testing Utilities** - "mock implementations for testing" 
- ✅ **Error Handling** - "more specific error types and better documentation"
- ✅ **CLI Integration** - "helper utilities for CLI frameworks"

## 🔮 What's Next

Future versions will focus on:

- Additional authentication methods (SAML, LDAP)
- More storage backends (PostgreSQL, MongoDB)
- Advanced security features (hardware keys, biometrics)
- Performance optimizations and benchmarking
- Additional OAuth providers and OpenID Connect enhancements

## 📞 Support & Contributing

- 📖 **Documentation**: https://docs.rs/auth-framework
- 🐛 **Issues**: https://github.com/ciresnave/auth-framework/issues  
- 💬 **Discussions**: https://github.com/ciresnave/auth-framework/discussions
- 🤝 **Contributing**: See CONTRIBUTING.md

---

**Thank you to everyone who provided feedback and contributed to making auth-framework better!** 🎉
