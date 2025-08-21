/**
 * Multi-Factor Authentication module for AuthFramework SDK
 */

import { BaseClient } from '../base-client';
import {
  MFASetupResponse,
  MFAVerifyRequest,
  MFAVerifyResponse,
  DisableMFARequest,
  RequestOptions
} from '../types';

export class MFAModule extends BaseClient {
  /**
   * Setup MFA for current user
   */
  async setup(options?: RequestOptions): Promise<MFASetupResponse> {
    const response = await this.post<MFASetupResponse>('/mfa/setup', undefined, options);
    return response.data;
  }

  /**
   * Verify MFA code
   */
  async verify(request: MFAVerifyRequest, options?: RequestOptions): Promise<MFAVerifyResponse> {
    const response = await this.post<MFAVerifyResponse>('/mfa/verify', request, options);
    return response.data;
  }

  /**
   * Disable MFA for current user
   */
  async disable(request: DisableMFARequest, options?: RequestOptions): Promise<void> {
    await this.post<void>('/mfa/disable', request, options);
  }
}
