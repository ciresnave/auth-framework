# AuthFramework JavaScript/TypeScript SDK

Official JavaScript/TypeScript client library for the AuthFramework REST API.

## Installation

```bash
npm install @authframework/js-sdk
# or
yarn add @authframework/js-sdk
# or
pnpm add @authframework/js-sdk
```

## Quick Start

### Basic Usage

```typescript
import { AuthFrameworkClient } from '@authframework/js-sdk';

// Initialize the client
const client = new AuthFrameworkClient({
  baseUrl: 'http://localhost:8080',
  timeout: 30000, // 30 seconds (optional)
  retries: 3, // Retry failed requests (optional)
});

// Login
try {
  const loginResponse = await client.auth.login({
    username: 'user@example.com',
    password: 'password123'
  });

  console.log('Login successful:', loginResponse.user);
  // Access token is automatically set for subsequent requests
} catch (error) {
  console.error('Login failed:', error.message);
}

// Get user profile
try {
  const profile = await client.users.getProfile();
  console.log('User profile:', profile);
} catch (error) {
  console.error('Failed to get profile:', error.message);
}
```

### With API Key

```typescript
const client = new AuthFrameworkClient({
  baseUrl: 'https://api.yourdomain.com',
  apiKey: 'your-api-key', // For endpoints that support API key auth
});
```

## Authentication

### Login and Token Management

```typescript
// Login with username/password
const loginResponse = await client.auth.login({
  username: 'user@example.com',
  password: 'password123',
  remember_me: true // Optional
});

// Access token is automatically stored and used for subsequent requests
console.log('Access token expires in:', loginResponse.expires_in, 'seconds');

// Refresh token when needed
const tokenResponse = await client.auth.refreshToken({
  refresh_token: loginResponse.refresh_token
});

// Validate current token
const userInfo = await client.auth.validate();

// Logout
await client.auth.logout();
```

### Manual Token Management

```typescript
// Set access token manually
client.setAccessToken('your-jwt-token');

// Get current token
const token = client.getAccessToken();

// Clear token
client.clearAccessToken();
```

## User Management

### Profile Operations

```typescript
// Get user profile
const profile = await client.users.getProfile();

// Update profile
const updatedProfile = await client.users.updateProfile({
  first_name: 'John',
  last_name: 'Doe',
  phone: '+1234567890',
  timezone: 'America/New_York'
});

// Change password
await client.users.changePassword({
  current_password: 'oldPassword123',
  new_password: 'newPassword456'
});
```

## Multi-Factor Authentication

### MFA Setup and Management

```typescript
// Setup MFA
const mfaSetup = await client.mfa.setup();
console.log('QR Code:', mfaSetup.qr_code);
console.log('Setup URI:', mfaSetup.setup_uri);
console.log('Backup codes:', mfaSetup.backup_codes);

// Verify MFA code
const verifyResult = await client.mfa.verify({
  code: '123456' // 6-digit TOTP code
});

if (verifyResult.verified) {
  console.log('MFA verification successful');
}

// Disable MFA
await client.mfa.disable({
  password: 'currentPassword',
  code: '123456' // Current MFA code
});
```

## OAuth 2.0

### Authorization Code Flow

```typescript
// Generate authorization URL
const authUrl = client.oauth.getAuthorizeUrl({
  response_type: 'code',
  client_id: 'your-client-id',
  redirect_uri: 'https://yourapp.com/callback',
  scope: 'read write',
  state: 'random-state-string'
});

// Redirect user to authUrl...

// Exchange code for tokens (in your callback handler)
const tokenResponse = await client.oauth.getToken({
  grant_type: 'authorization_code',
  code: 'received-auth-code',
  client_id: 'your-client-id',
  client_secret: 'your-client-secret',
  redirect_uri: 'https://yourapp.com/callback'
});

// Introspect token
const tokenInfo = await client.oauth.introspectToken({
  token: tokenResponse.access_token,
  client_id: 'your-client-id',
  client_secret: 'your-client-secret'
});

// Revoke token
await client.oauth.revokeToken({
  token: tokenResponse.access_token,
  client_id: 'your-client-id',
  client_secret: 'your-client-secret'
});
```

### PKCE Flow (Recommended for SPAs)

```typescript
// Generate code verifier and challenge (you'll need a PKCE library)
import { generateCodeVerifier, generateCodeChallenge } from 'your-pkce-lib';

const codeVerifier = generateCodeVerifier();
const codeChallenge = generateCodeChallenge(codeVerifier);

// Authorization URL with PKCE
const authUrl = client.oauth.getAuthorizeUrl({
  response_type: 'code',
  client_id: 'your-spa-client-id',
  redirect_uri: 'https://yourapp.com/callback',
  scope: 'read write',
  code_challenge: codeChallenge,
  code_challenge_method: 'S256',
  state: 'random-state-string'
});

// Exchange code with PKCE
const tokenResponse = await client.oauth.getToken({
  grant_type: 'authorization_code',
  code: 'received-auth-code',
  client_id: 'your-spa-client-id',
  redirect_uri: 'https://yourapp.com/callback',
  code_verifier: codeVerifier
});
```

## Administrative Functions

### User Management (Admin Only)

```typescript
// List users with pagination
const usersResponse = await client.admin.listUsers({
  page: 1,
  limit: 20,
  search: 'john@',
  role: 'user'
});

console.log('Users:', usersResponse.data);
console.log('Pagination:', usersResponse.pagination);

// Create user
const newUser = await client.admin.createUser({
  username: 'newuser@example.com',
  email: 'newuser@example.com',
  password: 'tempPassword123',
  roles: ['user'],
  first_name: 'Jane',
  last_name: 'Smith'
});

// Get user details
const userDetails = await client.admin.getUser('user-id-123');

// Delete user
await client.admin.deleteUser('user-id-123');

// Get system statistics
const stats = await client.admin.getSystemStats();
console.log('System stats:', stats);
```

## Health Monitoring

### Health Checks

```typescript
// Basic health check
const health = await client.health.getHealth();
console.log('Service status:', health.status);

// Detailed health check
const detailedHealth = await client.health.getDetailedHealth();
console.log('Database status:', detailedHealth.services.database.status);
console.log('Uptime:', detailedHealth.uptime, 'seconds');

// Get Prometheus metrics
const metrics = await client.health.getMetrics();
console.log('Metrics:', metrics);
```

## Error Handling

### Error Types

The SDK provides specific error types for different scenarios:

```typescript
import {
  AuthFrameworkError,
  AuthenticationError,
  AuthorizationError,
  ValidationError,
  NotFoundError,
  RateLimitError,
  isAuthFrameworkError
} from '@authframework/js-sdk';

try {
  await client.auth.login({ username: 'invalid', password: 'wrong' });
} catch (error) {
  if (isAuthFrameworkError(error)) {
    console.log('Error code:', error.code);
    console.log('Status code:', error.statusCode);
    console.log('Details:', error.details);

    if (error instanceof AuthenticationError) {
      console.log('Authentication failed');
    } else if (error instanceof RateLimitError) {
      console.log('Rate limited. Retry after:', error.retryAfter);
    }
  }
}
```

### Retry Logic

The SDK automatically retries failed requests for network errors and 5xx server errors:

```typescript
const client = new AuthFrameworkClient({
  baseUrl: 'https://api.example.com',
  retries: 5, // Retry up to 5 times
  timeout: 10000 // 10 second timeout
});

// You can also override per request
try {
  const profile = await client.users.getProfile({
    retries: 2,
    timeout: 5000
  });
} catch (error) {
  // Handle error after retries exhausted
}
```

## TypeScript Support

The SDK is built with TypeScript and provides full type safety:

```typescript
import {
  UserProfile,
  LoginResponse,
  ApiResponse,
  PaginatedResponse
} from '@authframework/js-sdk';

// Type-safe responses
const loginResponse: LoginResponse = await client.auth.login({
  username: 'user@example.com',
  password: 'password'
});

// Intellisense and type checking
const profile: UserProfile = await client.users.getProfile();
console.log(profile.first_name); // TypeScript knows this is string | undefined

// Generic responses
const users: PaginatedResponse<UserProfile> = await client.admin.listUsers();
```

## Configuration Options

### Client Configuration

```typescript
interface ClientConfig {
  baseUrl: string;          // Required: API base URL
  timeout?: number;         // Request timeout in ms (default: 30000)
  retries?: number;         // Number of retries (default: 3)
  apiKey?: string;          // API key for endpoints that support it
  userAgent?: string;       // Custom user agent
}
```

### Request Options

```typescript
interface RequestOptions {
  timeout?: number;         // Override default timeout
  retries?: number;         // Override default retries
  headers?: Record<string, string>; // Additional headers
}

// Example usage
await client.users.getProfile({
  timeout: 5000,
  retries: 1,
  headers: {
    'X-Custom-Header': 'value'
  }
});
```

## Browser Support

The SDK works in modern browsers and Node.js environments:

- **Browsers**: Chrome 70+, Firefox 65+, Safari 12+, Edge 79+
- **Node.js**: 16+

### Browser Bundle

```html
<!-- Include via CDN -->
<script src="https://unpkg.com/@authframework/js-sdk@latest/dist/index.umd.js"></script>
<script>
  const client = new AuthFramework.AuthFrameworkClient({
    baseUrl: 'https://api.example.com'
  });
</script>
```

## React Integration

Example React hook for authentication:

```typescript
import { useState, useEffect } from 'react';
import { AuthFrameworkClient, UserInfo } from '@authframework/js-sdk';

const client = new AuthFrameworkClient({
  baseUrl: process.env.REACT_APP_API_URL!
});

export function useAuth() {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check for existing token on mount
    const token = localStorage.getItem('access_token');
    if (token) {
      client.setAccessToken(token);
      client.auth.validate()
        .then(setUser)
        .catch(() => localStorage.removeItem('access_token'))
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const login = async (username: string, password: string) => {
    const response = await client.auth.login({ username, password });
    localStorage.setItem('access_token', response.access_token);
    setUser(response.user);
    return response;
  };

  const logout = async () => {
    await client.auth.logout();
    localStorage.removeItem('access_token');
    setUser(null);
  };

  return { user, loading, login, logout, client };
}
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
