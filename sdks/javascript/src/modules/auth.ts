/**
 * Authentication module for AuthFramework SDK
 */

import { BaseClient } from '../base-client';
import {
  LoginRequest,
  LoginResponse,
  RefreshTokenRequest,
  TokenResponse,
  UserInfo,
  RequestOptions
} from '../types';

export class AuthModule extends BaseClient {
  /**
   * Authenticate user with username and password
   */
  async login(request: LoginRequest, options?: RequestOptions): Promise<LoginResponse> {
    const response = await this.post<LoginResponse>('/auth/login', request, options);

    // Automatically set the access token for subsequent requests
    this.setAccessToken(response.data.access_token);

    return response.data;
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshToken(request: RefreshTokenRequest, options?: RequestOptions): Promise<TokenResponse> {
    const response = await this.post<TokenResponse>('/auth/refresh', request, options);

    // Update the access token
    this.setAccessToken(response.data.access_token);

    return response.data;
  }

  /**
   * Logout and invalidate current session
   */
  async logout(options?: RequestOptions): Promise<void> {
    await this.post<void>('/auth/logout', undefined, options);

    // Clear the access token
    this.clearAccessToken();
  }

  /**
   * Validate current access token and get user info
   */
  async validate(options?: RequestOptions): Promise<UserInfo> {
    const response = await this.post<UserInfo>('/auth/validate', undefined, options);
    return response.data;
  }
}
