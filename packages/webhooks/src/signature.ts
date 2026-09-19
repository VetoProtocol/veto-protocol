/**
 * Signing a delivery, and verifying one (spec §5.4).
 *
 * Three headers travel with every request:
 *
 *     veto-webhook-id:        evt_...        stable across retries
 *     veto-webhook-timestamp: 1789800000     seconds, when *this attempt* was signed
 *     veto-webhook-signature: v1=<base64url>
 *
 * The MAC covers `id.timestamp.body`, all three, and here is why each is in
 * there:
 *
 *  * **The body**, obviously — otherwise the signature says nothing about what
 *    arrived.
 *  * **The timestamp**, so a captured request cannot be replayed forever. A
 *    receiver rejects anything outside its tolerance window; with the timestamp
 *    outside the MAC, an attacker would simply rewrite it.
 *  * **The event id**, so a signature cannot be moved onto a different event
 *    that happens to have the same body. Two denials of the same action by the
 *    same agent produce identical bodies; they are still different events.
 *
 * ## Retries are re-signed
 *
 * A retry two hours later keeps the same **event id** and gets a **fresh
 * timestamp**. Reusing the original timestamp would fail the receiver's
 * tolerance check on every attempt after the first, which is the same as having
 * no retry at all. The id is what makes the retry recognisable as a duplicate,
 * and it is the value §5.4's "idempotent consumers" requirement hangs on.
 *
 * ## The version prefix
 *
 * `v1=` exists so a future scheme can be added without a receiver silently
 * accepting the old one. A verifier that does not recognise the prefix refuses;
 * it does not guess.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

export const SIGNATURE_HEADER = 'veto-webhook-signature';
export const ID_HEADER = 'veto-webhook-id';
export const TIMESTAMP_HEADER = 'veto-webhook-timestamp';

const VERSION = 'v1';

/** Five minutes either way. Wide enough for ordinary clock drift, narrow enough to matter. */
export const DEFAULT_TOLERANCE_SECONDS = 300;

export interface SignedRequest {
  readonly body: string;
  readonly headers: Readonly<Record<string, string>>;
}

export function signDelivery(
  secret: string,
  input: { eventId: string; body: string; timestampSeconds?: number },
): SignedRequest {
  const timestamp = input.timestampSeconds ?? Math.floor(Date.now() / 1000);
  const signature = mac(secret, input.eventId, timestamp, input.body);

  return {
    body: input.body,
    headers: {
      'content-type': 'application/json',
      [ID_HEADER]: input.eventId,
      [TIMESTAMP_HEADER]: String(timestamp),
      [SIGNATURE_HEADER]: `${VERSION}=${signature}`,
    },
  };
}

export type VerifyFailure =
  | 'missing-headers'
  | 'bad-timestamp'
  | 'stale'
  | 'unknown-version'
  | 'bad-signature';

export type VerifyResult =
  | { readonly ok: true; readonly eventId: string }
  | { readonly ok: false; readonly reason: VerifyFailure };

/**
 * The receiver's half.
 *
 * Shipped in this package rather than left as an exercise because a webhook
 * verifier written from a prose description is where this goes wrong: people
 * compare with `===`, forget the timestamp, or accept any version prefix. It is
 * also what the tests here verify against, so the scheme is checked end to end
 * rather than only against itself.
 */
export function verifyDelivery(
  secret: string,
  input: {
    body: string;
    headers: Readonly<Record<string, string | undefined>>;
    toleranceSeconds?: number;
    nowSeconds?: number;
  },
): VerifyResult {
  const id = input.headers[ID_HEADER];
  const rawTimestamp = input.headers[TIMESTAMP_HEADER];
  const provided = input.headers[SIGNATURE_HEADER];

  if (typeof id !== 'string' || typeof rawTimestamp !== 'string' || typeof provided !== 'string') {
    return { ok: false, reason: 'missing-headers' };
  }

  // Digits only. `parseInt` would accept "300abc" and `Number` accepts
  // whitespace, hex and exponents — none of which is a unix timestamp.
  if (!/^\d{1,15}$/.test(rawTimestamp)) return { ok: false, reason: 'bad-timestamp' };
  const timestamp = Number(rawTimestamp);

  const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  const tolerance = input.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  // Both directions. A timestamp far in the future is as wrong as one far in
  // the past, and refusing only the past leaves an attacker a forward window.
  if (Math.abs(now - timestamp) > tolerance) return { ok: false, reason: 'stale' };

  const [version, signature] = splitOnce(provided, '=');
  if (version !== VERSION || signature === null) return { ok: false, reason: 'unknown-version' };

  if (!equal(signature, mac(secret, id, timestamp, input.body))) {
    return { ok: false, reason: 'bad-signature' };
  }

  return { ok: true, eventId: id };
}

/**
 * The signed string.
 *
 * Joined with a character that cannot appear in an event id or a timestamp, so
 * the three fields cannot be shuffled between each other: `('a.b', 'c')` and
 * `('a', 'b.c')` would otherwise sign the same bytes.
 */
const mac = (secret: string, eventId: string, timestamp: number, body: string): string =>
  createHmac('sha256', secret).update(`${eventId}.${timestamp}.${body}`).digest('base64url');

function splitOnce(value: string, separator: string): [string, string | null] {
  const at = value.indexOf(separator);
  if (at < 0) return [value, null];
  return [value.slice(0, at), value.slice(at + 1)];
}

function equal(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
