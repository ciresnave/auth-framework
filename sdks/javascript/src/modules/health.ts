/**
 * Health monitoring module for AuthFramework SDK
 */

import { BaseClient } from '../base-client';
import {
  HealthStatus,
  DetailedHealthStatus,
  RequestOptions
} from '../types';

export class HealthModule extends BaseClient {
  /**
   * Get basic health status
   */
  async getHealth(options?: RequestOptions): Promise<HealthStatus> {
    const response = await this.get<HealthStatus>('/health', options);
    return response.data;
  }

  /**
   * Get detailed health status including dependencies
   */
  async getDetailedHealth(options?: RequestOptions): Promise<DetailedHealthStatus> {
    const response = await this.get<DetailedHealthStatus>('/health/detailed', options);
    return response.data;
  }

  /**
   * Get Prometheus metrics (returns raw text)
   */
  async getMetrics(options?: RequestOptions): Promise<string> {
    // Override content type for metrics endpoint
    const response = await this.get<string>('/metrics', {
      ...options,
      headers: {
        'Accept': 'text/plain',
        ...options?.headers
      }
    });

    return response.data;
  }
}
