/**
 * The one error type routes throw. The error handler turns it into the
 * client-facing shape {error: {code, message, requestId}} (S8.1); nothing
 * else of the error (stack, cause) ever reaches the client.
 */
export class AppError extends Error {
  readonly statusCode: number;
  readonly code: string;
  readonly details: unknown;

  constructor(statusCode: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

export interface ErrorBody {
  error: { code: string; message: string; requestId: string; details?: unknown };
}

export function errorBody(code: string, message: string, requestId: string, details?: unknown): ErrorBody {
  const error: ErrorBody['error'] = { code, message, requestId };
  if (details !== undefined) error.details = details;
  return { error };
}

/** Fastify's own client errors, mapped to stable codes and fixed messages. */
const FRAMEWORK_CODES: Record<string, { code: string; message: string }> = {
  FST_ERR_CTP_BODY_TOO_LARGE: { code: 'body_too_large', message: 'Request body is larger than 64 KB.' },
  FST_ERR_CTP_INVALID_MEDIA_TYPE: { code: 'unsupported_media_type', message: 'Only application/json is accepted.' },
  FST_ERR_CTP_INVALID_CONTENT_LENGTH: { code: 'invalid_content_length', message: 'Invalid Content-Length.' },
  FST_ERR_CTP_EMPTY_JSON_BODY: { code: 'invalid_json', message: 'Request body is empty.' },
  FST_ERR_CTP_INVALID_JSON_BODY: { code: 'invalid_json', message: 'Request body is not valid JSON.' },
  FST_ERR_BAD_URL: { code: 'bad_url', message: 'Malformed URL.' },
};

export interface MappedError {
  status: number;
  code: string;
  message: string;
  details?: unknown;
  internal: boolean;
}

export function mapError(err: unknown): MappedError {
  if (err instanceof AppError) {
    return { status: err.statusCode, code: err.code, message: err.message, details: err.details, internal: false };
  }
  const e = err as { code?: unknown; statusCode?: unknown };
  const known = typeof e.code === 'string' ? FRAMEWORK_CODES[e.code] : undefined;
  const status = typeof e.statusCode === 'number' ? e.statusCode : 500;
  if (known && status < 500) return { status, ...known, internal: false };
  if (err instanceof SyntaxError && status === 400) {
    return { status: 400, code: 'invalid_json', message: 'Request body is not valid JSON.', internal: false };
  }
  if (status >= 400 && status < 500) {
    return { status, code: 'bad_request', message: 'The request could not be processed.', internal: false };
  }
  return { status: 500, code: 'internal', message: 'Internal error.', internal: true };
}
