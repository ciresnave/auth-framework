# ADR-003: Async-First Framework Design

## Status

Accepted

## Context

Modern applications require high concurrency and non-blocking I/O for scalability:

- **Web Applications**: Handle thousands of concurrent requests
- **Microservices**: Efficient resource utilization in containerized environments
- **Database Operations**: Non-blocking database queries and storage operations
- **External APIs**: OAuth providers, MFA services, email/SMS providers
- **Real-time Features**: WebSocket connections, server-sent events

Synchronous blocking operations would severely limit scalability and performance in modern deployment environments.

## Decision

Design the AuthFramework with async/await as the primary programming model:

- All public APIs use `async fn` for I/O operations
- Storage operations are inherently asynchronous
- External service calls use async HTTP clients
- Internal operations maintain async compatibility
- Provide sync wrappers only when absolutely necessary

Use Tokio as the primary async runtime with compatibility for other runtimes.

## Rationale

Async-first design enables several performance and scalability benefits:

- **High Concurrency**: Handle thousands of authentication requests simultaneously
- **Resource Efficiency**: Lower memory and CPU usage per request
- **Scalability**: Better performance under high load
- **Modern Compatibility**: Integrates well with async web frameworks
- **Future-Proof**: Aligns with Rust ecosystem trends

This approach follows modern Rust async best practices and enables optimal performance.

## Consequences

### Positive Consequences

- **High Performance**: Excellent throughput and latency characteristics
- **Resource Efficiency**: Lower memory usage compared to thread-per-request
- **Scalability**: Handles high concurrent load effectively
- **Framework Compatibility**: Works seamlessly with async web frameworks
- **Future-Proof**: Aligns with Rust ecosystem evolution
- **Real-time Support**: Enables WebSocket and SSE implementations

### Negative Consequences

- **Complexity**: Async programming has steeper learning curve
- **Runtime Dependency**: Requires async runtime (Tokio)
- **Debugging Complexity**: Async stack traces can be more difficult
- **Sync Integration**: Bridging to sync code requires careful consideration

### Neutral Consequences

- **API Design**: All I/O operations return futures
- **Error Handling**: Async-compatible error types and handling

## Alternatives Considered

### Alternative 1: Synchronous Design

- **Description**: Traditional blocking I/O with thread-per-request model
- **Why Not Chosen**: Poor scalability, high resource usage, blocking operations
- **Trade-offs**: Simpler programming model but limited performance

### Alternative 2: Hybrid Sync/Async

- **Description**: Provide both sync and async APIs for all operations
- **Why Not Chosen**: API complexity, maintenance burden, performance overhead
- **Trade-offs**: Maximum compatibility but complex implementation

### Alternative 3: Callback-Based Design

- **Description**: Use callbacks instead of async/await for non-blocking operations
- **Why Not Chosen**: Callback hell, error handling complexity, not idiomatic Rust
- **Trade-offs**: Lower-level control but poor developer experience

## Implementation

The async-first design was implemented through:

1. **Core APIs**: All I/O operations use `async fn` signatures
2. **Storage Layer**: `AuthStorage` trait uses async methods
3. **HTTP Clients**: Async HTTP clients for external service communication
4. **Runtime Integration**: Primary Tokio support with runtime flexibility
5. **Error Handling**: Async-compatible error types and propagation
6. **Testing Framework**: Async test utilities and helpers

Key implementation details:

- `#[async_trait]` for storage and method traits
- `tokio::spawn` for concurrent operations
- `async/await` throughout the public API
- Async-compatible error types
- Non-blocking cryptographic operations where possible

## References

- [Tokio Documentation](https://tokio.rs/)
- [Async Book](https://rust-lang.github.io/async-book/)
- [Async Web Framework Compatibility](../integration/web-frameworks.md)
- Related ADRs: ADR-002 (Storage Abstraction), ADR-001 (Modular Architecture)

---

**Decision Date**: 2025-08-17
**Decision Maker(s)**: AuthFramework Development Team
**Review Date**: 2026-02-17
