/**
 * Main AuthFramework client
 */

import { BaseClient } from './base-client';
import { ClientConfig } from './types';
import { AuthModule } from './modules/auth';
import { UsersModule } from './modules/users';
import { MFAModule } from './modules/mfa';
import { OAuthModule } from './modules/oauth';
import { AdminModule } from './modules/admin';
import { HealthModule } from './modules/health';

/**
 * Main AuthFramework API client
 */
export class AuthFrameworkClient extends BaseClient {
  public readonly auth: AuthModule;
  public readonly users: UsersModule;
  public readonly mfa: MFAModule;
  public readonly oauth: OAuthModule;
  public readonly admin: AdminModule;
  public readonly health: HealthModule;

  constructor(config: ClientConfig) {
    super(config);

    // Initialize modules with the same configuration
    this.auth = new AuthModule(config);
    this.users = new UsersModule(config);
    this.mfa = new MFAModule(config);
    this.oauth = new OAuthModule(config);
    this.admin = new AdminModule(config);
    this.health = new HealthModule(config);

    // Sync access tokens between client and modules
    this.syncAccessToken();
  }

  /**
   * Set access token for all modules
   */
  public setAccessToken(token: string): void {
    super.setAccessToken(token);
    this.auth.setAccessToken(token);
    this.users.setAccessToken(token);
    this.mfa.setAccessToken(token);
    this.oauth.setAccessToken(token);
    this.admin.setAccessToken(token);
    this.health.setAccessToken(token);
  }

  /**
   * Clear access token from all modules
   */
  public clearAccessToken(): void {
    super.clearAccessToken();
    this.auth.clearAccessToken();
    this.users.clearAccessToken();
    this.mfa.clearAccessToken();
    this.oauth.clearAccessToken();
    this.admin.clearAccessToken();
    this.health.clearAccessToken();
  }

  /**
   * Sync access token between main client and modules
   */
  private syncAccessToken(): void {
    const token = this.getAccessToken();
    if (token) {
      this.auth.setAccessToken(token);
      this.users.setAccessToken(token);
      this.mfa.setAccessToken(token);
      this.oauth.setAccessToken(token);
      this.admin.setAccessToken(token);
      this.health.setAccessToken(token);
    }
  }
}
