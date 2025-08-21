/**
 * Administrative module for AuthFramework SDK
 */

import { BaseClient } from '../base-client';
import {
  UserInfo,
  CreateUserRequest,
  SystemStats,
  PaginatedResponse,
  UserListOptions,
  RequestOptions
} from '../types';

export class AdminModule extends BaseClient {
  /**
   * List users with pagination and filtering
   */
  async listUsers(options?: UserListOptions & RequestOptions): Promise<PaginatedResponse<UserInfo>> {
    const params: Record<string, any> = {};

    if (options?.page) params.page = options.page;
    if (options?.limit) params.limit = options.limit;
    if (options?.search) params.search = options.search;
    if (options?.role) params.role = options.role;
    if (options?.sort) params.sort = options.sort;
    if (options?.order) params.order = options.order;

    const response = await this.get<UserInfo[]>('/admin/users', {
      ...options,
      params
    });

    return response as PaginatedResponse<UserInfo>;
  }

  /**
   * Create a new user
   */
  async createUser(request: CreateUserRequest, options?: RequestOptions): Promise<UserInfo> {
    const response = await this.post<UserInfo>('/admin/users', request, options);
    return response.data;
  }

  /**
   * Get user details by ID
   */
  async getUser(userId: string, options?: RequestOptions): Promise<UserInfo> {
    const response = await this.get<UserInfo>(`/admin/users/${userId}`, options);
    return response.data;
  }

  /**
   * Delete a user by ID
   */
  async deleteUser(userId: string, options?: RequestOptions): Promise<void> {
    await this.delete<void>(`/admin/users/${userId}`, options);
  }

  /**
   * Get system statistics
   */
  async getSystemStats(options?: RequestOptions): Promise<SystemStats> {
    const response = await this.get<SystemStats>('/admin/stats', options);
    return response.data;
  }
}
