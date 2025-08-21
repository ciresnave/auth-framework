/**
 * AuthFramework JavaScript/TypeScript SDK
 *
 * Official client library for the AuthFramework REST API.
 * Provides type-safe access to authentication, user management,
 * MFA, OAuth 2.0, and administrative features.
 */

export * from './client';
export * from './types';
export * from './errors';
export * from './modules';

// Re-export the main client class for convenience
export { AuthFrameworkClient as default } from './client';
