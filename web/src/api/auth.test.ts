import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { authHeaders, getApiKey, hasStoredApiKey, liveSocketUrl, requestLiveTicket, setApiKey } from './auth';

class MemoryStorage {
  private data = new Map<string, string>();
  getItem(key: string) {
    return this.data.has(key) ? this.data.get(key)! : null;
  }
  setItem(key: string, value: string) {
    this.data.set(key, value);
  }
  removeItem(key: string) {
    this.data.delete(key);
  }
}

describe('api key handling', () => {
  beforeEach(() => {
    vi.stubGlobal('sessionStorage', new MemoryStorage());
    setApiKey(null);
  });
  afterEach(() => {
    setApiKey(null);
    vi.unstubAllGlobals();
  });

  it('stores a trimmed key for the session and exposes it as a header', () => {
    setApiKey('  example-key  ');
    expect(getApiKey()).toBe('example-key');
    expect(hasStoredApiKey()).toBe(true);
    expect(authHeaders()).toEqual({ 'X-API-Key': 'example-key' });
    expect(sessionStorage.getItem('hotwash.apiKey')).toBe('example-key');
  });

  it('clears the key', () => {
    setApiKey('example-key');
    setApiKey(null);
    expect(hasStoredApiKey()).toBe(false);
    expect(sessionStorage.getItem('hotwash.apiKey')).toBeNull();
  });

  it('treats a blank value as clearing', () => {
    setApiKey('example-key');
    setApiKey('   ');
    expect(hasStoredApiKey()).toBe(false);
  });

  it('sends no header when no key is set', () => {
    // Development mode may supply a VITE_ fallback; production builds never do.
    if (import.meta.env.DEV && import.meta.env.VITE_HOTWASH_API_KEY) return;
    expect(authHeaders()).toEqual({});
  });
});

describe('live socket tickets', () => {
  afterEach(() => {
    setApiKey(null);
    vi.unstubAllGlobals();
  });

  it('requests a ticket with the key header and returns it', async () => {
    setApiKey('example-key');
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ ticket: 'ticket-1', expires_in: 30 })));
    vi.stubGlobal('fetch', fetchMock);

    await expect(requestLiveTicket('http://api.example', '42')).resolves.toBe('ticket-1');

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://api.example/api/executions/42/live-ticket');
    expect(init.method).toBe('POST');
    expect(init.headers).toEqual({ 'X-API-Key': 'example-key' });
  });

  it('fails when the backend refuses or answers oddly', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 401 })));
    await expect(requestLiveTicket('http://api.example', '42')).rejects.toThrow(/401/);
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ ticket: 5 }))));
    await expect(requestLiveTicket('http://api.example', '42')).rejects.toThrow(/malformed/);
  });

  it('puts only the ticket in the socket URL, never the api key', () => {
    setApiKey('example-key');
    const url = liveSocketUrl('ws://api.example', '42', 'a.b c');
    expect(url).toBe('ws://api.example/api/executions/42/live?ticket=a.b%20c');
    expect(url).not.toContain('example-key');
    expect(url).not.toContain('api_key');
  });
});
