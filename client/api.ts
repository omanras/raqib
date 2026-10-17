/**
 * The API client. Same origin only; every mutating request carries the CSRF
 * token (S2.3), fetched on demand and refreshed once if the server says it
 * is stale. A failed request becomes an ApiError that keeps the server's
 * request id so a member can quote it. A request that never reached the
 * server marks the connection offline (A10) instead of pretending.
 */
import { connection } from './store.js';

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;
  readonly details: Record<string, unknown> | null;

  constructor(status: number, code: string, message: string, requestId: string | null, details: Record<string, unknown> | null = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.details = details;
  }

  get offline(): boolean {
    return this.code === 'offline';
  }
}

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

type Method = 'GET' | 'POST' | 'PATCH';

async function send(method: Method, path: string, body: unknown): Promise<Response> {
  const headers: Record<string, string> = { accept: 'application/json' };
  if (method !== 'GET') {
    headers['content-type'] = 'application/json';
    if (csrfToken) headers['x-csrf-token'] = csrfToken;
  }
  try {
    const res = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      cache: 'no-store',
      body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),
    });
    connection.markOnline();
    return res;
  } catch {
    connection.markOffline();
    throw new ApiError(0, 'offline', 'The server cannot be reached.', null);
  }
}

async function refreshCsrf(): Promise<void> {
  const res = await send('GET', '/api/auth/csrf', undefined);
  const data = (await res.json()) as { csrfToken?: string };
  csrfToken = data.csrfToken ?? null;
}

async function errorOf(res: Response): Promise<ApiError> {
  const requestId = res.headers.get('x-request-id');
  try {
    const data = (await res.json()) as { error?: { code?: string; message?: string; requestId?: string; details?: Record<string, unknown> } };
    const e = data.error ?? {};
    return new ApiError(res.status, e.code ?? 'error', e.message ?? res.statusText, e.requestId ?? requestId, e.details ?? null);
  } catch {
    return new ApiError(res.status, 'error', res.statusText, requestId);
  }
}

export async function api<T>(method: Method, path: string, body?: unknown): Promise<T> {
  if (method !== 'GET' && !csrfToken) await refreshCsrf();
  let res = await send(method, path, body);
  if (res.status === 403 && method !== 'GET') {
    const err = await errorOf(res);
    if (err.code !== 'csrf') throw err;
    await refreshCsrf();
    res = await send(method, path, body);
  }
  if (!res.ok) throw await errorOf(res);
  const data = (await res.json()) as T & { csrfToken?: string };
  if (typeof data.csrfToken === 'string') csrfToken = data.csrfToken;
  return data;
}

/** Text endpoints (CSV exports). */
export async function apiText(path: string): Promise<string> {
  const res = await send('GET', path, undefined);
  if (!res.ok) throw await errorOf(res);
  return res.text();
}

export const get = <T>(path: string): Promise<T> => api<T>('GET', path);
export const post = <T>(path: string, body: unknown = {}): Promise<T> => api<T>('POST', path, body);
export const patch = <T>(path: string, body: unknown): Promise<T> => api<T>('PATCH', path, body);
