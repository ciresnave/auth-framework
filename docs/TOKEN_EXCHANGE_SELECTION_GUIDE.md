# Token Exchange Manager Selection Guide

This document provides guidance on choosing between `TokenExchangeManager` (basic) and `AdvancedTokenExchangeManager` (advanced) implementations.

## Quick Decision Matrix

| Feature | Basic Manager | Advanced Manager |
|---------|---------------|------------------|
| **RFC 8693 Compliance** | ✅ Core spec | ✅ Core + Extensions |
| **Lightweight** | ✅ Minimal deps | ❌ Heavy dependencies |
| **Multi-party Chains** | ❌ Simple delegation | ✅ Complex chains |
| **Context Preservation** | ❌ Basic tracking | ✅ Full context |
| **Audit Trail** | ❌ Simple logging | ✅ Comprehensive audit |
| **Session Integration** | ❌ Stateless | ✅ OIDC sessions |
| **JWT Operations** | ❌ Validation only | ✅ Sign/verify/introspect |
| **Policy Control** | ✅ Client-based | ✅ Advanced conditions |
| **Cross-domain** | ❌ Single domain | ✅ Federation support |

## When to Use Basic Manager (`TokenExchangeManager`)

### ✅ **Use Basic Manager When:**

1. **Simple Service-to-Service Authentication**
   - Direct token exchange between two services
   - Basic delegation scenarios (OnBehalfOf, ActingAs)
   - Lightweight microservice authentication

2. **Minimal Dependencies Required**
   - Want to keep bundle size small
   - Limited external dependencies acceptable
   - Simple deployment scenarios

3. **Standard RFC 8693 Compliance**
   - Core specification compliance is sufficient
   - No need for advanced extensions
   - Basic token validation requirements

4. **Performance Critical**
   - Low latency requirements
   - High throughput scenarios
   - Resource-constrained environments

### 🔧 **Basic Manager Example:**

```rust
use auth_framework::server::{TokenExchangeManager, TokenExchangeRequest};
use auth_framework::secure_jwt::SecureJwtValidator;

async fn setup_basic_exchange() -> Result<(), Box<dyn std::error::Error>> {
    // Simple setup with JWT validator
    let jwt_validator = SecureJwtValidator::new("secret_key".to_string())?;
    let mut manager = TokenExchangeManager::new(jwt_validator);

    // Register a simple policy for a client
    let policy = TokenExchangePolicy::default();
    manager.register_policy("service_a".to_string(), policy).await;

    // Basic exchange request
    let request = TokenExchangeRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
        subject_token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...".to_string(),
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
        requested_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
        actor_token: None,
        actor_token_type: None,
        audience: Some("service_b".to_string()),
        scope: Some("read write".to_string()),
        resource: None,
    };

    let response = manager.exchange_token(request, "service_a").await?;
    println!("Exchanged token: {}", response.access_token);

    Ok(())
}
```

## When to Use Advanced Manager (`AdvancedTokenExchangeManager`)

### ✅ **Use Advanced Manager When:**

1. **Enterprise Integration**
   - Complex multi-service architectures
   - Comprehensive audit requirements
   - Compliance and governance needs

2. **Multi-party Token Chains**
   - Service chains with multiple delegation steps
   - Context preservation across services
   - Complex business process flows

3. **Session Integration Required**
   - OIDC session management integration
   - Step-up authentication flows
   - Session-aware token exchange

4. **Advanced Security Features**
   - JWT cryptographic operations (sign/verify)
   - Cross-domain token exchange
   - Policy-driven exchange control
   - Comprehensive audit trails

5. **Federation Scenarios**
   - Cross-domain identity federation
   - Trust boundary spanning
   - Complex privilege mapping

### 🔧 **Advanced Manager Example:**

```rust
use auth_framework::server::{
    AdvancedTokenExchangeManager, AdvancedTokenExchangeRequest,
    AdvancedTokenExchangeConfig, ExchangeContext,
};
use auth_framework::server::oidc_session_management::SessionManager;
use std::sync::Arc;

async fn setup_advanced_exchange() -> Result<(), Box<dyn std::error::Error>> {
    // Advanced configuration
    let config = AdvancedTokenExchangeConfig {
        enable_multi_party_chains: true,
        max_delegation_depth: 5,
        require_audit_trail: true,
        enable_context_preservation: true,
        // ... other config fields
        ..Default::default()
    };

    // Session manager for OIDC integration
    let session_manager = Arc::new(SessionManager::new(Default::default()));

    let manager = AdvancedTokenExchangeManager::new(config, session_manager)?;

    // Complex exchange request with context
    let context = ExchangeContext {
        transaction_id: "txn_123456".to_string(),
        business_context: serde_json::json!({
            "operation": "payment_processing",
            "amount": 1000.00,
            "currency": "USD",
            "risk_level": "high"
        }),
        delegation_chain: Vec::new(),
        original_request: None,
        security_context: None,
        custom_fields: HashMap::new(),
    };

    let request = AdvancedTokenExchangeRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
        subject_token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...".to_string(),
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
        requested_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
        exchange_context: Some(context),
        policy_requirements: vec![
            "require_mfa".to_string(),
            "audit_financial_operations".to_string(),
        ],
        // ... other fields
        actor_token: None,
        actor_token_type: None,
        scope: Some("payment:write audit:read".to_string()),
        audience: vec!["payment-service".to_string()],
        resource: Vec::new(),
        custom_parameters: HashMap::new(),
    };

    let response = manager.exchange_token(request).await?;

    // Advanced response includes audit information and context preservation
    if let Some(audit_info) = &response.exchange_audit {
        println!("Exchange ID: {}", audit_info.exchange_id);
        println!("Exchange Type: {:?}", audit_info.exchange_type);
    }

    Ok(())
}
```

## Migration Path

### From Basic to Advanced

If you start with the basic manager and later need advanced features:

```rust
// 1. Update your dependencies to include advanced features
// 2. Replace TokenExchangeManager with AdvancedTokenExchangeManager
// 3. Update configuration structure
// 4. Modify request/response handling

// Before (Basic):
let jwt_validator = SecureJwtValidator::new("key".to_string())?;
let manager = TokenExchangeManager::new(jwt_validator);

// After (Advanced):
let config = AdvancedTokenExchangeConfig::default();
let session_manager = Arc::new(SessionManager::new(Default::default()));
let manager = AdvancedTokenExchangeManager::new(config, session_manager)?;
```

## Performance Considerations

### Basic Manager Performance

- **Memory**: ~50KB base memory footprint
- **Latency**: Sub-millisecond token exchange
- **Throughput**: 10,000+ exchanges/second
- **Dependencies**: Minimal (JWT validation only)

### Advanced Manager Performance

- **Memory**: ~500KB+ base memory footprint
- **Latency**: 1-5ms token exchange (depending on features)
- **Throughput**: 1,000-5,000 exchanges/second
- **Dependencies**: Heavy (session management, audit, crypto)

## Factory Pattern Usage

Use the factory to automatically select the appropriate manager:

```rust
use auth_framework::server::{TokenExchangeFactory, ExchangeRequirements, TokenExchangeUseCase};

// Automatic selection based on requirements
let requirements = TokenExchangeFactory::get_recommended_config(
    &TokenExchangeUseCase::EnterpriseIntegration
);

let manager_type = TokenExchangeFactory::determine_manager_type(&requirements);

match manager_type {
    ServiceComplexityLevel::Basic => {
        println!("Use TokenExchangeManager for this use case");
        // Initialize basic manager
    },
    ServiceComplexityLevel::Advanced => {
        println!("Use AdvancedTokenExchangeManager for this use case");
        // Initialize advanced manager
    }
}
```

## Common Patterns

### Pattern 1: API Gateway Token Exchange (Basic)

```rust
// Simple token format conversion in API gateway
let response = basic_manager.exchange_token(request, client_id).await?;
```

### Pattern 2: Microservice Chain (Advanced)

```rust
// Preserve context through multiple services
let response = advanced_manager.exchange_token(request_with_context).await?;
let preserved_context = response.preserved_context;
```

### Pattern 3: Step-up Authentication (Advanced Only)

```rust
// Automatic step-up authentication based on policies
// Advanced manager handles session validation and MFA requirements automatically
```

## Troubleshooting

### Common Issues with Basic Manager

- **Limited delegation**: Use advanced manager for complex chains
- **No audit trail**: Use advanced manager for compliance needs
- **No session integration**: Use advanced manager for OIDC scenarios

### Common Issues with Advanced Manager

- **High memory usage**: Use basic manager for lightweight scenarios
- **Complex configuration**: Start with defaults and customize incrementally
- **Performance impact**: Profile and optimize based on actual usage patterns

## Summary

Choose **Basic Manager** for simple, high-performance scenarios with standard RFC 8693 compliance.

Choose **Advanced Manager** for enterprise scenarios requiring comprehensive features, audit trails, and complex delegation patterns.

Both managers implement the common `TokenExchangeService` trait, making it easy to switch between them or use them polymorphically in your application architecture.
