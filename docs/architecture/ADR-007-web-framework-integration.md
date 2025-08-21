# ADR-007: Web Framework Integration Strategy

## Status

Accepted

## Context

AuthFramework needs to integrate seamlessly with popular web frameworks while maintaining flexibility:

- **Multi-Framework Support**: Different projects use different web frameworks (Axum, Actix-web, Warp, Rocket)
- **Framework Agnostic Core**: Authentication logic should not depend on specific web frameworks
- **Ergonomic Integration**: Each framework should feel natural and idiomatic to use
- **Performance Requirements**: Integration should not add significant overhead
- **Middleware Patterns**: Common authentication middleware patterns across frameworks
- **Type Safety**: Leverage Rust's type system for compile-time authentication guarantees

The goal is to provide first-class integration with major Rust web frameworks while keeping the core authentication logic framework-independent.

## Decision

Implement a layered integration strategy with framework-agnostic core and framework-specific adapters:

**Core Authentication Layer:**

- Framework-independent authentication traits and types
- Pure business logic without HTTP concerns
- Async-first design compatible with all async frameworks
- Generic over request/response types where needed

**Framework Adapter Pattern:**

- Dedicated integration modules for each supported framework
- Framework-specific middleware, extractors, and response types
- Idiomatic API design for each framework's patterns
- Minimal adapter code, maximum delegation to core

**Supported Frameworks:**

- **Axum**: Primary focus with extractors and middleware
- **Actix-web**: Middleware and extractor implementations
- **Warp**: Filter-based integration pattern
- **Rocket**: Request guard and responder implementations

## Rationale

This strategy provides maximum flexibility and usability:

- **Framework Independence**: Core logic remains portable and testable
- **Developer Experience**: Each framework integration feels natural and idiomatic
- **Maintenance Efficiency**: Single core implementation with thin adapters
- **Performance**: Direct integration without unnecessary abstraction layers
- **Extensibility**: Easy to add support for new frameworks
- **Type Safety**: Framework-specific types provide compile-time guarantees

## Consequences

### Positive Consequences

- **Broad Compatibility**: Support for all major Rust web frameworks
- **Developer Productivity**: Idiomatic integration reduces learning curve
- **Code Reuse**: Single core implementation across all frameworks
- **Performance**: Framework-specific optimizations without core compromises
- **Type Safety**: Framework-specific types catch errors at compile time
- **Maintenance**: Centralized authentication logic simplifies updates

### Negative Consequences

- **Implementation Effort**: Each framework requires dedicated integration code
- **Testing Complexity**: Integration tests needed for each framework
- **Documentation Overhead**: Framework-specific documentation and examples
- **Version Compatibility**: Multiple framework version compatibility matrices

### Neutral Consequences

- **Code Organization**: Clear separation between core and integration layers
- **Framework Evolution**: Adapters can evolve independently with framework updates

## Alternatives Considered

### Alternative 1: Single Framework Support

- **Description**: Support only one web framework (e.g., Axum)
- **Why Not Chosen**: Limits adoption and forces framework choice on users
- **Trade-offs**: Simpler implementation but reduced ecosystem compatibility

### Alternative 2: HTTP Abstraction Layer

- **Description**: Create custom HTTP abstraction covering all frameworks
- **Why Not Chosen**: Adds complexity and may not support framework-specific features
- **Trade-offs**: Framework independence but potential feature limitations

### Alternative 3: Proc Macro Approach

- **Description**: Use procedural macros to generate framework integrations
- **Why Not Chosen**: Complex implementation, debugging difficulties, compilation overhead
- **Trade-offs**: Code generation benefits but increased complexity

## Implementation

The web framework integration strategy includes:

1. **Core Authentication Traits**: Framework-agnostic authentication interfaces
2. **HTTP Types**: Generic request/response handling
3. **Framework Modules**: Dedicated integration for each supported framework
4. **Middleware Patterns**: Common authentication middleware implementations
5. **Extractor Types**: Framework-specific request data extraction
6. **Response Helpers**: Framework-specific response generation

Key implementation examples:

```rust
// Framework-agnostic core
pub trait AuthenticateRequest<R> {
    type Output;
    type Error;

    async fn authenticate(&self, request: &R) -> Result<Self::Output, Self::Error>;
}

// Axum integration
#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S
    ) -> Result<Self, Self::Rejection> {
        // Framework-specific extraction logic
    }
}

// Actix-web integration
impl FromRequest for AuthUser {
    type Error = AuthError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        // Framework-specific extraction logic
    }
}
```

## References

- [Axum Authentication Example](../../examples/axum-integration.md)
- [Actix-web Integration Guide](../../examples/actix-integration.md)
- [Framework Comparison](../../guides/framework-comparison.md)
- [Integration Testing Patterns](../../testing/integration-testing.md)
- Related ADRs: ADR-003 (Async Design), ADR-001 (Modular Architecture)

---

**Decision Date**: 2025-08-17
**Decision Maker(s)**: AuthFramework Development Team
**Review Date**: 2026-02-17
