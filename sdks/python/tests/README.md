# AuthFramework Python SDK Testing

This document describes the testing setup for the AuthFramework Python SDK, which includes both **unit tests** (mocked) and **integration tests** (against a real server).

## Test Types

### Unit Tests (Mocked)
- **Location**: `tests/test_*.py` (excluding `integration/` folder)
- **Purpose**: Fast, isolated tests using mocked HTTP responses
- **Dependencies**: No external services required
- **Coverage**: Basic functionality, error handling, type safety

### Integration Tests (Real Server)
- **Location**: `tests/integration/`
- **Purpose**: End-to-end testing against actual AuthFramework server
- **Dependencies**: Requires Rust AuthFramework server to be built and runnable
- **Coverage**: Real API interactions, server connectivity, authentication flows

## Running Tests

### Quick Start
```bash
# Unit tests only (fast, no server required)
uv run python run_tests.py --mode unit

# Integration tests only (requires server)
uv run python run_tests.py --mode integration

# All tests
uv run python run_tests.py --mode all
```

### Advanced Usage
```bash
# Run with verbose output
uv run python run_tests.py --mode unit --verbose

# Run with coverage reporting
uv run python run_tests.py --mode unit --coverage

# Run integration tests on custom port
uv run python run_tests.py --mode integration --server-port 9090

# Run specific test files
uv run pytest tests/integration/test_server_integration.py -v
```

### Direct pytest Usage
```bash
# Unit tests only
uv run pytest tests/ -m "not integration" -v

# Integration tests only  
uv run pytest tests/integration/ -m integration -v

# All tests
uv run pytest tests/ -v
```

## Integration Test Setup

### Prerequisites
1. **Rust AuthFramework server** must be buildable in the workspace
2. **Cargo** must be available to build the server
3. **Available port** for test server (default: 8088)

### How Integration Tests Work
1. **Server Startup**: Test session starts by building and launching AuthFramework server
2. **Health Check**: Tests wait for server to be ready (`/health` endpoint)
3. **Test Execution**: SDK methods tested against real server endpoints
4. **Server Cleanup**: Server is gracefully shut down after tests complete

### Test Server Configuration
The integration test server uses these settings:
```env
HOST=127.0.0.1
PORT=8088 (configurable)
DATABASE_URL=sqlite::memory:
JWT_SECRET=test-secret-for-integration-tests-only-not-secure
LOG_LEVEL=info
```

## Test Categories

### Health Service Tests
- ✅ Basic health check
- ✅ Detailed health with services status
- ✅ Readiness checks
- ✅ Liveness checks  
- ✅ Metrics retrieval

### Authentication Service Tests
- ✅ Server connectivity through auth endpoints
- ✅ Invalid credentials handling
- 🔄 Valid login flow (requires user setup)

### Token Service Tests
- ✅ Invalid token validation
- ✅ Invalid refresh token handling
- 🔄 Valid token operations (requires authentication)

### Admin Service Tests
- ✅ Authentication requirements
- ✅ Rate limiting endpoint existence
- 🔄 Authenticated admin operations

## Test Markers

Tests use pytest markers for organization:
- `@pytest.mark.integration`: Marks tests requiring real server
- `@pytest.mark.asyncio`: Marks async tests (auto-detected)
- `@requires_server()`: Class decorator for integration test classes

## Continuous Integration

### Local Development
```bash
# Quick validation (unit tests only)
uv run python run_tests.py

# Full validation before commit
uv run python run_tests.py --mode all --coverage
```

### CI/CD Pipeline
For automated testing, the CI should:
1. **Unit Tests**: Always run (fast, no dependencies)
2. **Integration Tests**: Run when Rust server changes or SDK changes
3. **Coverage**: Report coverage from unit tests
4. **Performance**: Monitor integration test timing

## Troubleshooting

### Common Issues

#### "Server failed to start"
- Check that Rust/Cargo is installed
- Verify AuthFramework builds: `cargo build --bin auth-framework`
- Check for port conflicts: use `--server-port` with different port

#### "Tests timeout waiting for server"
- Server might be taking too long to start
- Check server logs for startup errors
- Verify no firewall blocking localhost connections

#### "Connection refused"
- Server might not be listening on expected port
- Check server process is still running
- Verify client is connecting to correct URL

#### "Authentication tests failing"
- Some tests require valid user accounts
- Check server supports user creation endpoints
- Verify JWT secret configuration

### Debug Mode
```bash
# Run with maximum debugging
RUST_LOG=debug uv run python run_tests.py --mode integration --verbose
```

## Benefits of This Approach

### ✅ **Comprehensive Coverage**
- Unit tests ensure code correctness and type safety
- Integration tests ensure real-world functionality

### ✅ **Fast Feedback Loop**  
- Unit tests run in < 5 seconds
- Integration tests provide thorough validation

### ✅ **CI/CD Friendly**
- Unit tests can run in any environment
- Integration tests can be optional or environment-specific

### ✅ **Real-World Validation**
- Tests actually exercise the SDK against real server
- Catches integration issues that mocks might miss

### ✅ **Development Confidence**
- Developers can run fast unit tests frequently
- Integration tests provide deployment confidence

---

This testing setup ensures the AuthFramework Python SDK is thoroughly validated at both the unit level and integration level, providing confidence that it works correctly in real-world scenarios.