/**
 * The cookie carrying a sign-in that verified but has nowhere to go yet.
 *
 * Two cases reach it, and both happen *after* the id token has been fully
 * checked — signature, issuer, audience, nonce, expiry:
 *
 *   * **Nobody knows this subject.** They can create their own workspace
 *     (§1.3's individual professional). `/welcome`.
 *   * **The subject belongs to more than one workspace.** They have to pick.
 *     `/choose`.
 *
 * `flow-cookie.ts` holds the PKCE verifier *during* sign-in and is cleared when
 * the callback finishes. This one starts where that one stops.
 *
 * ## Why the subject is in a cookie and not the URL
 *
 * Because the next request has to prove which human it is about, and a query
 * parameter is something anybody can type. `/welcome?subject=oidc|<the boss>`
 * would otherwise create a workspace in somebody else's name — and
 * `/choose?workspace=ws_theirs` would hand out a session for a tenant the
 * visitor was never in.
 *
 * So the value is signed with the dashboard's own key and written only by the
 * OIDC callback, which is the one place that has verified anything. The page
 * reads the cookie; it never trusts its own URL.
 *
 * Domain-separated from the other two flow cookies (`flow-cookie.ts` for
 * sign-in, `connect-cookie.ts` for Google) so a sealed value from one cannot be
 * renamed into another. Same key, three meanings, no interchange.
 *
 * Ten minutes: long enough to think of a workspace name, short enough that an
 * abandoned tab is not a standing offer.
 */

import 'server-only';
import { createHmac, timingSafeEqual } from 'node:crypto';

export const PENDING_COOKIE = 'veto_pending';
export const PENDING_TTL_MS = 10 * 60 * 1000;

const DOMAIN = 'veto.pending.v1';

export interface PendingIdentity {
  readonly userId: string;
  readonly workspaceId: string;
}

export interface Pending {
  /** The verified OIDC subject. Never read from a request parameter. */
  readonly subject: string;
  /** Empty when nobody knows this subject; more than one when they must choose. */
  readonly candidates: readonly PendingIdentity[];
  readonly expiresAt: number;
}

function secret(): Buffer {
  const raw = (process.env['DASHBOARD_SESSION_SECRET'] ?? '').trim();
  if (raw.length < 32) throw new Error('DASHBOARD_SESSION_SECRET must be at least 32 characters');
  return Buffer.from(raw, 'utf8');
}

export function sealPending(pending: Pending): string {
  const body = Buffer.from(JSON.stringify(pending), 'utf8').toString('base64url');
  return `${body}.${mac(body)}`;
}

export function openPending(raw: string, now: number = Date.now()): Pending | null {
  const dot = raw.indexOf('.');
  if (dot <= 0) return null;

  const body = raw.slice(0, dot);
  if (!equal(raw.slice(dot + 1), mac(body))) return null;

  let pending: Pending;
  try {
    pending = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as Pending;
  } catch {
    return null;
  }

  if (
    typeof pending.subject !== 'string' ||
    pending.subject === '' ||
    !Array.isArray(pending.candidates) ||
    !Number.isFinite(pending.expiresAt) ||
    pending.expiresAt <= now
  ) {
    return null;
  }

  // Each candidate has to be a pair of strings. A malformed entry would reach
  // the session cookie as a workspace id, which is the tenant selector — so it
  // is checked rather than trusted, even though this value is signed.
  for (const candidate of pending.candidates) {
    if (typeof candidate?.userId !== 'string' || typeof candidate?.workspaceId !== 'string') {
      return null;
    }
  }

  return pending;
}

const mac = (body: string): string =>
  createHmac('sha256', secret()).update(DOMAIN).update('.').update(body).digest('base64url');

function equal(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
