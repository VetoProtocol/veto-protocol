/**
 * Dashboard session.
 *
 * A session is a signed, httpOnly cookie holding the workspace, the user, and
 * the credential the API accepts. It is minted by the OIDC callback and by
 * nothing else; this module only reads and verifies.
 *
 * Verification is HMAC over the exact payload bytes, compared in constant time,
 * with the expiry inside the signed region. A cookie is attacker-controlled
 * input: everything that decides identity has to be covered by the signature,
 * because `workspace_id` from an unsigned cookie would be a tenant selector
 * handed to the caller (invariant 4).
 *
 * Absent, malformed, expired, or wrongly signed all return null, and null means
 * signed out. There is no path here that resolves a partial session
 * (invariant 1).
 */

import 'server-only';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { cookies } from 'next/headers';

export const SESSION_COOKIE = 'veto_session';

export interface Session {
  readonly workspaceId: string;
  readonly userId: string;
  /** Bearer credential presented to the control-plane API. */
  readonly credential: string;
  readonly expiresAt: number;
}

interface SessionPayload {
  ws: string;
  usr: string;
  cred: string;
  exp: number;
}

function secret(): Buffer {
  const raw = (process.env['DASHBOARD_SESSION_SECRET'] ?? '').trim();
  // 32 bytes minimum. A short secret is a forgeable session, and a forged
  // session names its own workspace.
  if (raw.length < 32) {
    throw new Error('DASHBOARD_SESSION_SECRET must be at least 32 characters');
  }
  return Buffer.from(raw, 'utf8');
}

export function signSession(session: Session): string {
  const payload: SessionPayload = {
    ws: session.workspaceId,
    usr: session.userId,
    cred: session.credential,
    exp: session.expiresAt,
  };
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return `${body}.${mac(body)}`;
}

export function verifySession(raw: string, now: number = Date.now()): Session | null {
  const dot = raw.indexOf('.');
  if (dot <= 0) return null;

  const body = raw.slice(0, dot);
  const provided = raw.slice(dot + 1);
  if (!constantTimeEquals(provided, mac(body))) return null;

  let payload: SessionPayload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as SessionPayload;
  } catch {
    return null;
  }

  if (
    typeof payload.ws !== 'string' ||
    typeof payload.usr !== 'string' ||
    typeof payload.cred !== 'string' ||
    typeof payload.exp !== 'number'
  ) {
    return null;
  }

  if (!Number.isFinite(payload.exp) || payload.exp <= now) return null;

  return {
    workspaceId: payload.ws,
    userId: payload.usr,
    credential: payload.cred,
    expiresAt: payload.exp,
  };
}

export async function currentSession(): Promise<Session | null> {
  const raw = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!raw) return null;
  try {
    return verifySession(raw);
  } catch {
    // A missing or too-short secret is a deployment fault, not a signed-in
    // user. Treat it as signed out rather than letting the page render.
    return null;
  }
}

const mac = (body: string): string =>
  createHmac('sha256', secret()).update(body).digest('base64url');

function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  // timingSafeEqual throws on a length mismatch, which would itself leak length.
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
