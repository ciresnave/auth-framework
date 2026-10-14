# AuthFramework - Copilot Instructions

## Project Overview
AuthFramework is a high-performance Rust authentication and authorization client and server library designed as a complete authentication and authorization solution. Focus on exceptional performance, comprehensive security, cross-platform compatibility, multi-language SDK support, and a batteries-included developer experience where the product works out of the box with minimal configuration.

## Core Principles

### SOLID Principles
- **Single Responsibility Principle (SRP)**: Each module, struct, and function serves one clear purpose
- **Open/Closed Principle (OCP)**: Design for extension without modification of existing code
- **Liskov Substitution Principle (LSP)**: Ensure proper inheritance and trait implementations
- **Interface Segregation Principle (ISP)**: Create focused, minimal trait interfaces
- **Dependency Inversion Principle (DIP)**: Depend on abstractions, not concretions

### Design Principles
- **DRY (Don't Repeat Yourself)**: Eliminate code duplication through proper abstraction
- **KISS (Keep It Simple, Stupid)**: Prefer simple, clear solutions over complex ones
- **Law of Demeter**: Minimize coupling between modules
- **Boy Scout Rule**: Always leave code cleaner than you found it
- **Polymorphism over Conditionals**: Use traits and generics instead of match/if chains
- **Batteries-Included Defaults**: Prefer default behavior that exposes the major product capabilities without requiring users to manually discover and enable extra features
- **Optimization By Opt-Out**: Let advanced users disable unneeded functionality for footprint and compile-time optimization, but do not make basic usability depend on feature-flag archaeology

### Architecture Guidelines
- **Centralized Configuration**: All settings managed through unified config system
- **Minimal Dependencies**: Only essential external crates, prefer std library
- **Purposeful Layers**: Clear separation between protocol, core logic, and I/O layers
- **Avoid Over-engineering**: Build what's needed, not what might be needed
- **Full Featured By Default**: The default crate build should include the primary end-user capabilities unless there is a strong technical reason not to
- **Minimal Setup Path**: New users should be able to follow the default documented path with as little configuration and feature selection as possible

## Quality Standards

### Performance Requirements
- **Ultra-low Latency**: Every operation optimized for minimal delay
- **Memory Efficiency**: Zero-copy operations where possible
- **Concurrent by Design**: Async/await throughout, proper resource sharing

### Security Requirements
- **Security by Default**: All communications encrypted, secure defaults only
- **No Security Fallbacks**: Reject insecure connections rather than downgrade
- **Configurable Security**: Admin/user control over security requirements
- **Secure Defaults Without Friction**: Prefer secure defaults that still keep the first-run experience straightforward rather than forcing avoidable setup complexity

### Testing Standards
- **Test-Driven Development**: Write tests before implementation
- **No Mocking**: Real implementations only, except for external system boundaries
- **Comprehensive Coverage**: Unit, integration, and property-based tests

### Documentation Requirements
- **Live Documentation**: Update docs with every code change
- **Multiple Audiences**: Admin guides, developer docs, contributor guides
- **Decision Log**: Document all architectural decisions with rationale
- **Default Path First**: Docs and examples should present the default, out-of-the-box path before advanced optimization or feature-pruning variants

## Feature Policy

- Treat the default feature set as the primary product experience, not a minimal demo profile
- Prefer opt-out feature reduction for optimization over opt-in feature discovery for common workflows
- Keep intentionally non-default features limited to cases with strong platform, dependency, or operational justification
- When introducing or changing feature flags, document which user journeys are expected to work on the default build

## Rust-Specific Guidelines

### Code Style
- Use `cargo fmt` and `cargo clippy` standards
- Prefer explicit types in public APIs
- Use `Result<T, E>` for all fallible operations
- Leverage zero-cost abstractions

### Error Handling
- Custom error types with `thiserror`
- Propagate errors with `?` operator
- Provide meaningful error context

### Async Programming
- Use `tokio` for async runtime
- Prefer `async fn` over manual `Future` implementations
- Handle cancellation properly with `select!`

## Project Structure
- Core library in `src/lib.rs`
- Binary targets in `src/bin/`
- FFI bindings in `ffi/` subdirectories
- Tests co-located with code
- Integration tests in `tests/`
- Documentation in `docs/`

## Cross-Platform Considerations
- Use conditional compilation for OS-specific code
- Abstract OS interfaces behind traits
- Test on all target platforms
- Minimize platform-specific dependencies

## Multi-Language SDK Guidelines
- C-compatible FFI layer as foundation
- Language-specific wrappers for ergonomics
- Consistent API design across languages
- Comprehensive examples for each language

Remember: This project aims to become THE authentication and authorization solution everyone uses. Make every decision based on what creates the best, most complete solution, not what's quickest or easiest.
