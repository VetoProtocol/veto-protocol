/**
 * The short-lived cookie carrying one *connect* attempt.
 *
 * Holds the PKCE verifier and the state between the redirect out to Google and
 * the callback back. Deliberately a separate module from `flow-cookie.ts`, which
 * does the same job for sign-in, for two reasons:
 *
 *  1. The two flows end somewhere very different. A sign-in callback issues a
 *     session; a connect callback stores a credential for the workspace the
 *     caller is *already* signed in to. A value minted for one must not satisfy
 *     the other, so the MAC is domain-separated with a label — a sealed sign-in
 *     flow renamed into this cookie fails verification rather than being read
 *     as a connect attempt.
 *  2. This one has no nonce. There is no id token here, so there is nothing a
 *     nonce would bind; carrying an unused field would imply a check nobody
 *     makes.
 *
 * Five minutes. Longer than the sign-in flow because a Google consent screen
 * asks the user to read a scope list and pick an account, and short enough that
 * an abandoned attempt cannot be picked up later.
 */

import 'server-only';
import { createHmac, timingSafeEqual } from 'node:crypto';

export const CONNECT_COOKIE = 'veto_connect_flow';
export const CONNECT_TTL_MS = 5 * 60 * 1000;

/** Mixed into the MAC so this cookie can only ever be read as a connect flow. */
const DOMAIN = 'veto.connect.v1';

export interface ConnectFlow {
  /**
   * The PKCE verifier. Empty only for a provider that has no code to exchange.
   *
   * It stays required for Google: a consent round trip without PKCE is a
   * weaker flow, and an empty string there would mean somebody dropped it.
   */
  readonly verifier: string;
  readonly state: string;
  readonly expiresAt: number;
  /**
   * Which flow this cookie belongs to.
   *
   * Absent means `google`, because that is the only flow that existed when
   * these cookies were first minted and one may still be in a browser.
   *
   * It exists so the two callbacks cannot satisfy each other. They are
   * different round trips with different security properties — one ends in an
   * OAuth grant, the other in a GitHub installation — and a cookie minted for
   * either must not open the other. The same separation the sign-in and
   * connect cookies already keep between themselves.
   */
  readonly provider?: 'google' | 'github' | 'slack';
}

function secret(): Buffer {
  const raw = (process.env['DASHBOARD_SESSION_SECRET'] ?? '').trim();
  if (raw.length < 32) throw new Error('DASHBOARD_SESSION_SECRET must be at least 32 characters');
  return Buffer.from(raw, 'utf8');
}

export function sealConnect(flow: ConnectFlow): string {
  const body = Buffer.from(JSON.stringify(flow), 'utf8').toString('base64url');
  return `${body}.${mac(body)}`;
}

export function openConnect(raw: string, now: number = Date.now()): ConnectFlow | null {
  const dot = raw.indexOf('.');
  if (dot <= 0) return null;

  const body = raw.slice(0, dot);
  if (!equal(raw.slice(dot + 1), mac(body))) return null;

  let flow: ConnectFlow;
  try {
    flow = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as ConnectFlow;
  } catch {
    return null;
  }

  const provider = flow.provider ?? 'google';

  if (
    typeof flow.verifier !== 'string' ||
    typeof flow.state !== 'string' ||
    flow.state === '' ||
    (provider !== 'google' && provider !== 'github') ||
    // PKCE is required where there is a code to exchange, and meaningless
    // where there is not. GitHub hands back an installation id, which is worth
    // nothing without the App private key.
    (provider === 'google' && flow.verifier === '') ||
    !Number.isFinite(flow.expiresAt) ||
    flow.expiresAt <= now
  ) {
    return null;
  }

  return { ...flow, provider };
}

const mac = (body: string): string =>
  createHmac('sha256', secret()).update(DOMAIN).update('.').update(body).digest('base64url');

function equal(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
