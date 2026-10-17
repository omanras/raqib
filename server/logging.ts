import { pino, type DestinationStream, type Logger } from 'pino';

/**
 * Redaction paths (ADR-0001 §7). The application log is for operators and
 * never carries a password, secret, token, cookie, session id or recovery
 * code. Paths cover the shapes this server logs: request headers, request
 * bodies and ad-hoc objects one or two levels deep.
 */
const SECRET_KEYS = [
  'password',
  'newPassword',
  'currentPassword',
  'secret',
  'token',
  'csrfToken',
  'sessionId',
  'recoveryCode',
  'recoveryCodes',
  'cookie',
  'authorization',
];

export const REDACT_PATHS: string[] = [
  'req.headers.cookie',
  'req.headers.authorization',
  'req.headers["x-csrf-token"]',
  'res.headers["set-cookie"]',
  'headers.cookie',
  'headers.authorization',
  'headers["x-csrf-token"]',
  'headers["set-cookie"]',
  ...SECRET_KEYS,
  ...SECRET_KEYS.map((k) => `*.${k}`),
  ...SECRET_KEYS.map((k) => `*.*.${k}`),
];

export const REDACTED = '[redacted]';

export interface LoggerOptions {
  level?: string | undefined;
  stream?: DestinationStream | undefined;
}

export function createLogger(options: LoggerOptions = {}): Logger {
  return pino(
    {
      level: options.level ?? 'info',
      base: { app: 'dawr' },
      timestamp: pino.stdTimeFunctions.isoTime,
      formatters: { level: (label) => ({ level: label }) },
      redact: { paths: REDACT_PATHS, censor: REDACTED },
    },
    options.stream ?? pino.destination({ dest: 1, sync: false }),
  );
}
