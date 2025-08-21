/**
 * Base HTTP client for AuthFramework API
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import {
  ApiResponse,
  ApiError,
  ClientConfig,
  RequestOptions
} from './types';
import {
  AuthFrameworkError,
  createErrorFromResponse,
  NetworkError,
  TimeoutError,
  isRetryableError
} from './errors';

/**
 * Base HTTP client with retry logic and error handling
 */
export class BaseClient {
  protected readonly axios: AxiosInstance;
  protected readonly config: ClientConfig & {
    timeout: number;
    retries: number;
    userAgent: string;
  };
  private accessToken?: string;

  constructor(config: ClientConfig) {
    this.config = {
      timeout: 30000,
      retries: 3,
      userAgent: 'AuthFramework-JS-SDK/1.0.0',
      ...config,
    };

    this.axios = axios.create({
      baseURL: this.config.baseUrl,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': this.config.userAgent,
        ...(this.config.apiKey && { 'X-API-Key': this.config.apiKey }),
      },
    });

    // Add request interceptor to add auth header
    this.axios.interceptors.request.use((config: any) => {
      if (this.accessToken) {
        config.headers.Authorization = `Bearer ${this.accessToken}`;
      }
      return config;
    });

    // Add response interceptor for error handling
    this.axios.interceptors.response.use(
      (response: any) => response,
      (error: any) => this.handleResponseError(error)
    );
  }

  /**
   * Set the access token for authenticated requests
   */
  public setAccessToken(token: string): void {
    this.accessToken = token;
  }

  /**
   * Clear the access token
   */
  public clearAccessToken(): void {
    delete (this as any).accessToken;
  }

  /**
   * Get the current access token
   */
  public getAccessToken(): string | undefined {
    return this.accessToken;
  }

  /**
   * Make a GET request
   */
  protected async get<T>(
    url: string,
    options?: RequestOptions & { params?: Record<string, any> }
  ): Promise<ApiResponse<T>> {
    return this.request<T>('GET', url, undefined, options);
  }

  /**
   * Make a POST request
   */
  protected async post<T>(
    url: string,
    data?: any,
    options?: RequestOptions
  ): Promise<ApiResponse<T>> {
    return this.request<T>('POST', url, data, options);
  }

  /**
   * Make a PATCH request
   */
  protected async patch<T>(
    url: string,
    data?: any,
    options?: RequestOptions
  ): Promise<ApiResponse<T>> {
    return this.request<T>('PATCH', url, data, options);
  }

  /**
   * Make a PUT request
   */
  protected async put<T>(
    url: string,
    data?: any,
    options?: RequestOptions
  ): Promise<ApiResponse<T>> {
    return this.request<T>('PUT', url, data, options);
  }

  /**
   * Make a DELETE request
   */
  protected async delete<T>(
    url: string,
    options?: RequestOptions
  ): Promise<ApiResponse<T>> {
    return this.request<T>('DELETE', url, undefined, options);
  }

  /**
   * Make a request with retry logic
   */
  private async request<T>(
    method: string,
    url: string,
    data?: any,
    options?: RequestOptions & { params?: Record<string, any> }
  ): Promise<ApiResponse<T>> {
    const retries = options?.retries ?? this.config.retries;
    const timeout = options?.timeout ?? this.config.timeout;

    const axiosConfig: AxiosRequestConfig = {
      method,
      url,
      data,
      timeout,
      params: options?.params,
      headers: options?.headers,
    };

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const response: AxiosResponse<ApiResponse<T>> = await this.axios(axiosConfig);
        return response.data;
      } catch (error: any) {
        // Don't retry on the last attempt or for non-retryable errors
        if (attempt === retries || !isRetryableError(error)) {
          throw error;
        }

        // Exponential backoff delay
        const delay = Math.min(1000 * Math.pow(2, attempt), 10000);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    // This should never be reached, but TypeScript requires it
    throw new AuthFrameworkError('Max retries exceeded');
  }

  /**
   * Handle axios response errors and convert to AuthFramework errors
   */
  private handleResponseError(error: any): never {
    if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
      throw new TimeoutError('Request timeout', { originalError: error });
    }

    if (!error.response) {
      throw new NetworkError('Network error', { originalError: error });
    }

    const { status, data } = error.response;
    const errorData = data?.error || data;

    throw createErrorFromResponse(status, errorData, error.message);
  }

  /**
   * Make a form-encoded request (for OAuth endpoints)
   */
  protected async postForm<T>(
    url: string,
    data: Record<string, string>,
    options?: RequestOptions
  ): Promise<T> {
    const formData = new URLSearchParams();
    Object.entries(data).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        formData.append(key, value);
      }
    });

    const axiosConfig: AxiosRequestConfig = {
      method: 'POST',
      url,
      data: formData,
      timeout: options?.timeout ?? this.config.timeout,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...options?.headers,
      },
    };

    try {
      const response: AxiosResponse<T> = await this.axios(axiosConfig);
      return response.data;
    } catch (error: any) {
      this.handleResponseError(error);
    }
  }
}
