import { AxiosRequestConfig } from 'axios';
import { AuthFrameworkClient } from '../client';

/** Replace the HTTP adapter so requests go through axios' real pipeline but never the network. */
function stub(client: AuthFrameworkClient, seen: AxiosRequestConfig[]) {
  const inner = (client as any).axios;
  inner.defaults.adapter = async (config: AxiosRequestConfig) => {
    seen.push(config);
    return { data: { success: true }, status: 200, statusText: 'OK', headers: {}, config };
  };
}

describe('AuthFrameworkClient', () => {
  it('sends the API key and user agent, and no bearer token before login', async () => {
    const client = new AuthFrameworkClient({ baseUrl: 'http://api.test', apiKey: 'k-1', retries: 0 });
    const seen: AxiosRequestConfig[] = [];
    stub(client, seen);
    await (client as any).get('/health');
    expect(seen).toHaveLength(1);
    const headers = seen[0]!.headers as any;
    expect(headers.get('X-API-Key')).toBe('k-1');
    expect(headers.get('User-Agent')).toMatch(/AuthFramework-JS-SDK/);
    expect(headers.get('Authorization')).toBeFalsy();
    expect(seen[0]!.baseURL).toBe('http://api.test');
  });

  it('adds the bearer token once set and drops it when cleared', async () => {
    const client = new AuthFrameworkClient({ baseUrl: 'http://api.test', retries: 0 });
    const seen: AxiosRequestConfig[] = [];
    stub(client, seen);

    client.setAccessToken('tok-1');
    expect(client.getAccessToken()).toBe('tok-1');
    await (client as any).get('/me');
    expect((seen[0]!.headers as any).get('Authorization')).toBe('Bearer tok-1');

    client.clearAccessToken();
    expect(client.getAccessToken()).toBeUndefined();
    await (client as any).get('/me');
    expect((seen[1]!.headers as any).get('Authorization')).toBeFalsy();
  });

  it('passes query parameters and a per-request header through', async () => {
    const client = new AuthFrameworkClient({ baseUrl: 'http://api.test', retries: 0 });
    const seen: AxiosRequestConfig[] = [];
    stub(client, seen);
    await (client as any).get('/users', { params: { page: 2 }, headers: { 'X-Trace': 't' } });
    expect(seen[0]!.params).toEqual({ page: 2 });
    expect((seen[0]!.headers as any).get('X-Trace')).toBe('t');
  });
});
