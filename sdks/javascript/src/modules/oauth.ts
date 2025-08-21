/**
 * OAuth 2.0 module for AuthFramework SDK
 */

import { BaseClient } from '../base-client';
import {
  OAuthTokenRequest,
  OAuthTokenResponse,
  RevokeTokenRequest,
  IntrospectTokenRequest,
  TokenIntrospectionResponse,
  OAuthAuthorizeParams,
  RequestOptions
} from '../types';

export class OAuthModule extends BaseClient {
  /**
   * Generate OAuth authorization URL
   */
  getAuthorizeUrl(params: OAuthAuthorizeParams): string {
    const url = new URL('/oauth/authorize', this.config.baseUrl);

    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        url.searchParams.append(key, value.toString());
      }
    });

    return url.toString();
  }

  /**
   * Exchange authorization code for tokens
   */
  async getToken(request: OAuthTokenRequest, options?: RequestOptions): Promise<OAuthTokenResponse> {
    // OAuth token endpoint expects form-encoded data
    const formData: Record<string, string> = {};

    Object.entries(request).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        formData[key] = value.toString();
      }
    });

    return this.postForm<OAuthTokenResponse>('/oauth/token', formData, options);
  }

  /**
   * Revoke an OAuth token
   */
  async revokeToken(request: RevokeTokenRequest, options?: RequestOptions): Promise<void> {
    const formData: Record<string, string> = {};

    Object.entries(request).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        formData[key] = value.toString();
      }
    });

    await this.postForm<void>('/oauth/revoke', formData, options);
  }

  /**
   * Introspect an OAuth token
   */
  async introspectToken(
    request: IntrospectTokenRequest,
    options?: RequestOptions
  ): Promise<TokenIntrospectionResponse> {
    const formData: Record<string, string> = {};

    Object.entries(request).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        formData[key] = value.toString();
      }
    });

    return this.postForm<TokenIntrospectionResponse>('/oauth/introspect', formData, options);
  }
}
