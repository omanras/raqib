/**
 * Security headers (ADR-0001 §6, S5.1, S5.2), applied to every response:
 * API JSON, static files and the SPA fallback alike.
 *
 * style-src is 'self' only: the client build emits one stylesheet file and
 * never relies on inline <style> or style="" markup, so 'unsafe-inline' is
 * not needed.
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
].join('; ');

export const PERMISSIONS_POLICY = 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()';

export function securityHeaders(production: boolean): Record<string, string> {
  const headers: Record<string, string> = {
    'content-security-policy': CONTENT_SECURITY_POLICY,
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'permissions-policy': PERMISSIONS_POLICY,
    'x-frame-options': 'DENY',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'same-origin',
  };
  if (production) {
    headers['strict-transport-security'] = 'max-age=31536000; includeSubDomains';
  }
  return headers;
}
