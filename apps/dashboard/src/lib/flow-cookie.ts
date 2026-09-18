/**
 * The short-lived cookie carrying one sign-in attempt.
 *
 * Holds the PKCE verifier, state and nonce between the redirect out and the
 * callback back. Signed with the same key as the session, so a caller cannot
 * substitute their own state and make the callback validate against it.
 *
 * Two minutes. It exists only to survive a redirect; a longer window is just
 * more time for a stale attempt to be replayed.
 */

import 'server-only';
import { createHmac, timingSafeEqual } from 'node:crypto';

export const FLOW_COOKIE = 'veto_oidc_flow';
export const FLOW_TTL_MS = 2 * 60 * 1000;

export interface Flow {
  readonly verifier: string;
  readonly state: string;
  readonly nonce: string;
  readonly expiresAt: number;
}

function secret(): Buffer {
  const raw = (process.env['DASHBOARD_SESSION_SECRET'] ?? '').trim();
  if (raw.length < 32) throw new Error('DASHBOARD_SESSION_SECRET must be at least 32 characters');
  return Buffer.from(raw, 'utf8');
}

export function sealFlow(flow: Flow): string {
  const body = Buffer.from(JSON.stringify(flow), 'utf8').toString('base64url');
  return `${body}.${mac(body)}`;
}

export function openFlow(raw: string, now: number = Date.now()): Flow | null {
  const dot = raw.indexOf('.');
  if (dot <= 0) return null;

  const body = raw.slice(0, dot);
  if (!equal(raw.slice(dot + 1), mac(body))) return null;

  let flow: Flow;
  try {
    flow = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as Flow;
  } catch {
    return null;
  }

  if (
    typeof flow.verifier !== 'string' ||
    typeof flow.state !== 'string' ||
    typeof flow.nonce !== 'string' ||
    !Number.isFinite(flow.expiresAt) ||
    flow.expiresAt <= now
  ) {
    return null;
  }

  return flow;
}

const mac = (body: string): string =>
  createHmac('sha256', secret()).update(body).digest('base64url');

function equal(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
