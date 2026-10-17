import { ApiError } from './api.js';
import { currentLang, t } from './i18n/index.js';
import { en, type MessageKey } from './i18n/en.js';
import { toast } from './store.js';

function isKey(k: string): k is MessageKey {
  return Object.prototype.hasOwnProperty.call(en, k);
}

/** A refusal reason from a state check ({code, reason}), translated when the code is known. */
export function codeText(code: string | undefined, fallback?: string): string {
  const key = `error.${code ?? ''}`;
  if (code && isKey(key)) return t(key);
  return currentLang() === 'en' && fallback ? fallback : t('error.generic');
}

/** A sentence for an error, in the current language when Dawr knows the code. */
export function errorText(err: unknown): string {
  if (!(err instanceof ApiError)) return t('error.generic');
  if (err.offline) return t('error.offline');
  const minutes = Math.max(1, Math.ceil(Number(err.details?.retryAfterSeconds ?? 60) / 60));
  if (err.code === 'weak_password') {
    const key = `error.weak_password.${String(err.details?.problem ?? '')}`;
    if (isKey(key)) return t(key);
  }
  const key = `error.${err.code}`;
  if (isKey(key)) return t(key, { minutes });
  // Codes without a translation keep the server's sentence (English) in English,
  // and fall back to a generic Arabic sentence plus the code otherwise.
  return currentLang() === 'en' ? err.message : `${t('error.generic')} (${err.code})`;
}

export function requestIdOf(err: unknown): string | null {
  return err instanceof ApiError ? err.requestId : null;
}

/** Shows an error toast that carries the server's request id (M2.1 E4). */
export function reportError(err: unknown): void {
  toast(errorText(err), 'error', requestIdOf(err));
}

/** Field-level messages from a 400 invalid_input, keyed by the field name. */
export function fieldErrors(err: unknown): Record<string, string> {
  if (!(err instanceof ApiError) || err.code !== 'invalid_input') return {};
  const issues = (err.details?.issues ?? []) as { path: string; message: string }[];
  const out: Record<string, string> = {};
  for (const i of issues) if (i.path && !out[i.path]) out[i.path] = t('error.invalid_input');
  return out;
}
