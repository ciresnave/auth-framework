/**
 * Type definitions for the AuthFramework API
 */

// Base API Response Types
export interface ApiResponse<T = any> {
  success: boolean;
  data: T;
  timestamp: string;
}

export interface ApiError {
  success: false;
  error: {
    code: string;
    message: string;
    details?: any;
  };
  timestamp: string;
}

export interface Pagination {
  page: number;
  limit: number;
  total: number;
  has_next: boolean;
  has_prev: boolean;
}

// Authentication Types
export interface LoginRequest {
  username: string;
  password: string;
  remember_me?: boolean;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: UserInfo;
}

export interface RefreshTokenRequest {
  refresh_token: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

// User Types
export interface UserInfo {
  id: string;
  username: string;
  email: string;
  roles: string[];
  mfa_enabled: boolean;
  created_at: string;
  last_login?: string;
}

export interface UserProfile {
  id: string;
  username: string;
  email: string;
  first_name?: string;
  last_name?: string;
  phone?: string;
  timezone?: string;
  locale?: string;
  mfa_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface UpdateProfileRequest {
  first_name?: string;
  last_name?: string;
  phone?: string;
  timezone?: string;
  locale?: string;
}

export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}

export interface CreateUserRequest {
  username: string;
  email: string;
  password: string;
  roles?: string[];
  first_name?: string;
  last_name?: string;
}

// MFA Types
export interface MFASetupResponse {
  secret: string;
  qr_code: string;
  backup_codes: string[];
  setup_uri: string;
}

export interface MFAVerifyRequest {
  code: string;
}

export interface MFAVerifyResponse {
  verified: boolean;
  backup_codes?: string[];
}

export interface DisableMFARequest {
  password: string;
  code: string;
}

// OAuth Types
export interface OAuthTokenRequest {
  grant_type: 'authorization_code' | 'refresh_token' | 'client_credentials';
  code?: string;
  redirect_uri?: string;
  client_id?: string;
  client_secret?: string;
  refresh_token?: string;
  scope?: string;
  code_verifier?: string;
}

export interface OAuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

export interface RevokeTokenRequest {
  token: string;
  token_type_hint?: 'access_token' | 'refresh_token';
  client_id?: string;
  client_secret?: string;
}

export interface IntrospectTokenRequest {
  token: string;
  token_type_hint?: 'access_token' | 'refresh_token';
  client_id?: string;
  client_secret?: string;
}

export interface TokenIntrospectionResponse {
  active: boolean;
  scope?: string;
  client_id?: string;
  username?: string;
  token_type?: string;
  exp?: number;
  iat?: number;
  sub?: string;
  aud?: string;
  iss?: string;
}

// Health Types
export interface HealthStatus {
  status: 'healthy' | 'unhealthy';
  timestamp: string;
}

export interface ServiceHealth {
  status: 'healthy' | 'unhealthy';
  response_time: number;
  last_check: string;
}

export interface DetailedHealthStatus {
  status: 'healthy' | 'unhealthy';
  services: {
    database: ServiceHealth;
    cache: ServiceHealth;
    storage: ServiceHealth;
  };
  uptime: number;
  version: string;
  timestamp: string;
}

// Admin Types
export interface SystemStats {
  users: {
    total: number;
    active: number;
    new_today: number;
  };
  sessions: {
    active: number;
    peak_today: number;
  };
  oauth: {
    clients: number;
    active_tokens: number;
  };
  system: {
    uptime: number;
    memory_usage: number;
    cpu_usage: number;
  };
  timestamp: string;
}

// Client Configuration
export interface ClientConfig {
  baseUrl: string;
  timeout?: number;
  retries?: number;
  apiKey?: string;
  userAgent?: string;
}

// Request Options
export interface RequestOptions {
  timeout?: number;
  retries?: number;
  headers?: Record<string, string>;
}

// Paginated Response
export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  pagination: Pagination;
}

// List Options
export interface ListOptions {
  page?: number;
  limit?: number;
  search?: string;
  sort?: string;
  order?: 'asc' | 'desc';
}

// User List Options
export interface UserListOptions extends ListOptions {
  role?: string;
}

// OAuth Authorization Parameters
export interface OAuthAuthorizeParams {
  response_type: 'code' | 'token';
  client_id: string;
  redirect_uri?: string;
  scope?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: 'plain' | 'S256';
}
