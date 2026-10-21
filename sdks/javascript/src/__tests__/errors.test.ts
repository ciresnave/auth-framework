import {
  AuthFrameworkError,
  AuthenticationError,
  NetworkError,
  RateLimitError,
  ServerError,
  TimeoutError,
  ValidationError,
  createErrorFromResponse,
  isRetryableError,
} from '../errors';

describe('createErrorFromResponse', () => {
  const body = { code: 'X', message: 'boom', details: { a: 1 } };

  it.each([
    [400, ValidationError],
    [401, AuthenticationError],
    [429, RateLimitError],
    [500, ServerError],
    [503, ServerError],
  ])('maps %i to its error class with the status code', (status, cls) => {
    const err = createErrorFromResponse(status, body);
    expect(err).toBeInstanceOf(cls);
    expect(err.statusCode).toBe(status);
    expect(err.message).toBe('boom');
    expect(err.details).toEqual({ a: 1 });
  });

  it('keeps the server code and status for an unmapped status', () => {
    const err = createErrorFromResponse(418, body);
    expect(err.constructor).toBe(AuthFrameworkError);
    expect(err.code).toBe('X');
    expect(err.statusCode).toBe(418);
  });

  it('falls back to the default message when the body has none', () => {
    expect(createErrorFromResponse(404, undefined, 'fallback').message).toBe('fallback');
  });
});

describe('isRetryableError', () => {
  it('retries network, timeout and 5xx errors only', () => {
    expect(isRetryableError(new NetworkError())).toBe(true);
    expect(isRetryableError(new TimeoutError())).toBe(true);
    expect(isRetryableError(new ServerError())).toBe(true);
    expect(isRetryableError(createErrorFromResponse(502))).toBe(true);
    // Controls: client errors and rate limits are not retried.
    expect(isRetryableError(new ValidationError('bad'))).toBe(false);
    expect(isRetryableError(new RateLimitError())).toBe(false);
    expect(isRetryableError(new Error('plain'))).toBe(false);
  });

  it('leaves statusCode undefined for errors that have no HTTP status', () => {
    expect(new NetworkError().statusCode).toBeUndefined();
  });
});
