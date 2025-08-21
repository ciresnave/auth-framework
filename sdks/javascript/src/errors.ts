/**
 * Error classes for the AuthFramework SDK
 */

export class AuthFrameworkError extends Error {
  public readonly code: string;
  public readonly details?: any;
  public readonly statusCode?: number;

  constructor(message: string, code: string = 'UNKNOWN_ERROR', details?: any, statusCode?: number) {
    super(message);
    this.name = 'AuthFrameworkError';
    this.code = code;
    this.details = details;
    this.statusCode = statusCode ?? undefined;

    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if ('captureStackTrace' in Error) {
      (Error as any).captureStackTrace(this, AuthFrameworkError);
    }
  }
}

export class ValidationError extends AuthFrameworkError {
  constructor(message: string, details?: any) {
    super(message, 'VALIDATION_ERROR', details, 400);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends AuthFrameworkError {
  constructor(message: string = 'Authentication failed', details?: any) {
    super(message, 'AUTHENTICATION_ERROR', details, 401);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends AuthFrameworkError {
  constructor(message: string = 'Insufficient permissions', details?: any) {
    super(message, 'AUTHORIZATION_ERROR', details, 403);
    this.name = 'AuthorizationError';
  }
}

export class NotFoundError extends AuthFrameworkError {
  constructor(message: string = 'Resource not found', details?: any) {
    super(message, 'NOT_FOUND_ERROR', details, 404);
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends AuthFrameworkError {
  constructor(message: string = 'Resource conflict', details?: any) {
    super(message, 'CONFLICT_ERROR', details, 409);
    this.name = 'ConflictError';
  }
}

export class RateLimitError extends AuthFrameworkError {
  public readonly retryAfter?: number;

  constructor(message: string = 'Rate limit exceeded', retryAfter?: number, details?: any) {
    super(message, 'RATE_LIMIT_ERROR', details, 429);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter ?? undefined;
  }
}

export class ServerError extends AuthFrameworkError {
  constructor(message: string = 'Internal server error', details?: any, statusCode: number = 500) {
    super(message, 'SERVER_ERROR', details, statusCode);
    this.name = 'ServerError';
  }
}

export class NetworkError extends AuthFrameworkError {
  constructor(message: string = 'Network error', details?: any) {
    super(message, 'NETWORK_ERROR', details);
    this.name = 'NetworkError';
  }
}

export class TimeoutError extends AuthFrameworkError {
  constructor(message: string = 'Request timeout', details?: any) {
    super(message, 'TIMEOUT_ERROR', details);
    this.name = 'TimeoutError';
  }
}

/**
 * Creates an appropriate error instance based on HTTP status code and error response
 */
export function createErrorFromResponse(
  statusCode: number,
  errorResponse?: { code: string; message: string; details?: any },
  defaultMessage?: string
): AuthFrameworkError {
  const message = errorResponse?.message || defaultMessage || 'An error occurred';
  const code = errorResponse?.code || 'UNKNOWN_ERROR';
  const details = errorResponse?.details;

  switch (statusCode) {
    case 400:
      return new ValidationError(message, details);
    case 401:
      return new AuthenticationError(message, details);
    case 403:
      return new AuthorizationError(message, details);
    case 404:
      return new NotFoundError(message, details);
    case 409:
      return new ConflictError(message, details);
    case 429:
      return new RateLimitError(message, undefined, details);
    case 500:
    case 502:
    case 503:
    case 504:
      return new ServerError(message, details, statusCode);
    default:
      return new AuthFrameworkError(message, code, details, statusCode);
  }
}

/**
 * Type guard to check if an error is an AuthFrameworkError
 */
export function isAuthFrameworkError(error: any): error is AuthFrameworkError {
  return error instanceof AuthFrameworkError;
}

/**
 * Type guard to check if an error is a network-related error
 */
export function isNetworkError(error: any): error is NetworkError | TimeoutError {
  return error instanceof NetworkError || error instanceof TimeoutError;
}

/**
 * Type guard to check if an error is retryable (network errors and 5xx server errors)
 */
export function isRetryableError(error: any): boolean {
  if (isNetworkError(error)) {
    return true;
  }

  if (isAuthFrameworkError(error) && error.statusCode) {
    return error.statusCode >= 500;
  }

  return false;
}
