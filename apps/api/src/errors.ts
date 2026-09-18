/**
 * HTTP error shape.
 *
 * Every failure returns the same body: a stable machine code and a short
 * message. Spec §5.3 requires a stable reason code on every decision; the
 * control plane follows the same rule so a client never has to parse prose.
 *
 * The message is written for the caller and deliberately says less than the
 * server knows. "No such agent in this workspace" is the same response whether
 * the id is malformed, belongs to another tenant, or never existed — an
 * enumeration oracle is exactly what §12.1's IDOR case is about.
 */

export class HttpError extends Error {
  readonly status: number;
  readonly code: string;

  // Fields assigned explicitly rather than declared as constructor parameter
  // properties. `node --experimental-strip-types` cannot run those — it only
  // erases types, and a parameter property emits an assignment — so a file
  // using them compiles under vitest and then fails the moment anything runs it
  // the way this repo runs its own entry points.
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
    this.name = 'HttpError';
  }
}

export interface ErrorBody {
  readonly error: { readonly code: string; readonly message: string };
}

export const errorBody = (code: string, message: string): ErrorBody => ({
  error: { code, message },
});

/** Shared response schema so error bodies serialise identically everywhere. */
export const ERROR_SCHEMA = {
  type: 'object',
  properties: {
    error: {
      type: 'object',
      properties: { code: { type: 'string' }, message: { type: 'string' } },
      required: ['code', 'message'],
    },
  },
  required: ['error'],
} as const;
