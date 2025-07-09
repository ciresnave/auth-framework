# Contributing to Auth Framework

Thank you for your interest in contributing to the Auth Framework project! This guide will help you get started with making contributions.

## Code of Conduct

This project adheres to the Rust Code of Conduct. By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check the issue tracker to see if the problem has already been reported. When creating a bug report, include:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Environment information (Rust version, OS, etc.)
- Relevant code snippets or error messages

### Suggesting Enhancements

Enhancement suggestions are welcome! When proposing an enhancement:

- Use a clear, descriptive title
- Provide detailed description of the enhancement
- Explain why this enhancement would be useful
- Include code examples if applicable

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Ensure all tests pass (`cargo test`)
5. Add tests for new functionality
6. Update documentation as needed
7. Run `cargo fmt` to format your code
8. Run `cargo clippy` to check for linting issues
9. Commit your changes (`git commit -m 'Add amazing feature'`)
10. Push to the branch (`git push origin feature/amazing-feature`)
11. Open a Pull Request

## Development Setup

### Prerequisites

- Rust 1.70+ (stable)
- Git

### Local Development

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/auth-framework.git
   cd auth-framework
   ```

2. Install dependencies:

   ```bash
   cargo build
   ```

3. Run tests:

   ```bash
   cargo test
   ```

4. Run examples:

   ```bash
   cargo run --example basic_fixed
   ```

### Project Structure

```text
auth-framework/
├── src/
│   ├── auth.rs           # Main authentication framework
│   ├── config.rs         # Configuration management
│   ├── credentials.rs    # Credential types and handling
│   ├── errors.rs         # Error types and handling
│   ├── lib.rs           # Library entry point
│   ├── methods.rs        # Authentication methods
│   ├── permissions.rs    # Permission system
│   ├── providers.rs      # OAuth providers
│   ├── storage.rs        # Storage backends
│   ├── tokens.rs         # Token management
│   └── utils.rs          # Utility functions
├── examples/            # Example code
└── tests/              # Integration tests
```

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture

# Run doc tests
cargo test --doc
```

### Test Coverage

We aim for comprehensive test coverage. When adding new features:

- Add unit tests for new functions
- Add integration tests for new features
- Test error conditions
- Test edge cases

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_feature() {
        // Test implementation
    }
}
```

## Documentation

### Code Documentation

- Use `///` for public API documentation
- Use `//!` for module-level documentation
- Include examples in documentation when helpful
- Document error conditions and panics

### README Updates

When making changes that affect the public API:

- Update the README.md with new examples
- Update the feature list if applicable
- Update configuration examples

## Coding Standards

### Style Guide

- Follow Rust naming conventions
- Use `cargo fmt` for consistent formatting
- Run `cargo clippy` and address warnings
- Keep functions focused and reasonably sized
- Use meaningful variable and function names

### Error Handling

- Use the `Result` type for fallible operations
- Create specific error types for different failure modes
- Provide helpful error messages
- Don't panic in library code (except for invariant violations)

### Performance Considerations

- Profile performance-critical code
- Use appropriate data structures
- Consider memory allocations in hot paths
- Add benchmarks for performance-sensitive features

## Security Considerations

This is a security-focused library. When contributing:

- Follow secure coding practices
- Consider timing attacks and side-channel vulnerabilities
- Use constant-time operations for sensitive comparisons
- Validate all inputs
- Don't log sensitive information
- Use secure defaults

## Release Process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Create release commit
4. Tag the release
5. Push to main repository
6. Create GitHub release
7. Publish to crates.io

## Getting Help

- Check the documentation
- Look at existing code for patterns
- Ask questions in issues or discussions
- Reach out to maintainers if needed

## Recognition

Contributors will be recognized in the project's README and changelog.

Thank you for contributing to Auth Framework!
