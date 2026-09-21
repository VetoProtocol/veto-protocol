/**
 * The short-lived cookie carrying one wallet sign-in attempt.
 *
 * Holds the nonce between issuing it and verifying the signature over it. Signed
 * with the same key as the session, and **domain-separated** from every other
 * cookie here: a value minted for the sign-in flow, the Google connect flow or a
 * pending signup must not satisfy this one. Same key, different label, three
 * cookies that cannot be swapped.
 *
 * The nonce lives here rather than in Redis for the same reason the PKCE
 * verifier does — the dashboard has no Redis, and a value that must survive
 * exactly one round trip is better held somewhere that forgets by default.
 *
 * Five minutes. It exists to survive a wallet popup, and a longer window is
 * more time for a gathered signature to be replayed.
 */

import 'server-only';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const WALLET_COOKIE = 'veto_wallet_flow';
export const WALLET_TTL_MS = 5 * 60 * 1000;

/** The label that makes this cookie unusable as any other. */
const DOMAIN = 'wallet-flow';

export interface WalletFlow {
  readonly nonce: string;
  readonly expiresAt: number;
}

function secret(): Buffer {
  const raw = (process.env['DASHBOARD_SESSION_SECRET'] ?? '').trim();
  if (raw.length < 32) throw new Error('DASHBOARD_SESSION_SECRET must be at least 32 characters');
  return Buffer.from(raw, 'utf8');
}

const mac = (body: string): string =>
  createHmac('sha256', secret()).update(DOMAIN).update('.').update(body).digest('base64url');

/** 96 bits of randomness, hex. Opaque to the client, which only echoes it. */
export const newNonce = (): string => randomBytes(12).toString('hex');

export function sealWalletFlow(flow: WalletFlow): string {
  const body = Buffer.from(JSON.stringify(flow), 'utf8').toString('base64url');
  return `${body}.${mac(body)}`;
}

export function openWalletFlow(raw: string, now: number = Date.now()): WalletFlow | null {
  const dot = raw.indexOf('.');
  if (dot <= 0) return null;

  const body = raw.slice(0, dot);
  const provided = raw.slice(dot + 1);

  const left = Buffer.from(provided, 'utf8');
  const right = Buffer.from(mac(body), 'utf8');
  // timingSafeEqual throws on a length mismatch, which would itself leak length.
  if (left.length !== right.length || !timingSafeEqual(left, right)) return null;

  let flow: WalletFlow;
  try {
    flow = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as WalletFlow;
  } catch {
    return null;
  }

  if (typeof flow.nonce !== 'string' || flow.nonce === '') return null;
  if (!Number.isFinite(flow.expiresAt) || flow.expiresAt <= now) return null;
  return flow;
}
