/**
 * API key handling for the browser.
 *
 * The backend key is entered at runtime and held for the browser session only
 * (sessionStorage), so it is never part of the shipped JavaScript bundle. The
 * live execution socket does not carry the key at all: it uses a short-lived
 * ticket minted by an authenticated request.
 */

const STORAGE_KEY = 'hotwash.apiKey';

let memoryKey: string | undefined;

function sessionStore(): Storage | undefined {
  try {
    return globalThis.sessionStorage;
  } catch {
    return undefined;
  }
}

// Local development convenience only. Vite replaces import.meta.env.DEV with
// `false` in production builds, which removes this branch and the value with it.
const devKey: string | undefined = import.meta.env.DEV ? import.meta.env.VITE_HOTWASH_API_KEY : undefined;

export function getApiKey(): string | undefined {
  if (memoryKey) return memoryKey;
  const stored = sessionStore()?.getItem(STORAGE_KEY);
  return stored || devKey || undefined;
}

export function setApiKey(key: string | null): void {
  const trimmed = key?.trim();
  memoryKey = trimmed || undefined;
  const store = sessionStore();
  if (!store) return;
  if (trimmed) store.setItem(STORAGE_KEY, trimmed);
  else store.removeItem(STORAGE_KEY);
}

export function hasStoredApiKey(): boolean {
  return Boolean(memoryKey || sessionStore()?.getItem(STORAGE_KEY));
}

export function authHeaders(): Record<string, string> {
  const key = getApiKey();
  return key ? { 'X-API-Key': key } : {};
}

/** Ask the backend for a short-lived ticket that opens one execution's live socket. */
export async function requestLiveTicket(baseUrl: string, executionId: string): Promise<string> {
  const response = await fetch(`${baseUrl}/api/executions/${encodeURIComponent(executionId)}/live-ticket`, {
    method: 'POST',
    headers: authHeaders(),
  });
  if (!response.ok) throw new Error(`Live ticket request failed (${response.status})`);
  const data = (await response.json()) as { ticket?: unknown };
  if (typeof data.ticket !== 'string' || !data.ticket) throw new Error('Live ticket response was malformed');
  return data.ticket;
}

export function liveSocketUrl(wsBase: string, executionId: string, ticket: string): string {
  return `${wsBase}/api/executions/${encodeURIComponent(executionId)}/live?ticket=${encodeURIComponent(ticket)}`;
}
