/**
 * Short-lived internal capability tokens.
 *
 * CLAUDE.md: "Internal service calls use short-lived capability tokens carrying
 * audience, resource, action, expiry, nonce, human, and agent claims." This is
 * that token. The dashboard mints one after a user signs in; the control-plane
 * API verifies it and turns it into a principal.
 *
 * ## Why this is not a JWT
 *
 * A JWT names its own algorithm in a header the verifier reads, and the entire
 * `alg` family of attacks — `none`, HS/RS confusion — exists because a verifier
 * takes instruction from the token it is checking. There is no algorithm field
 * here at all. The verifier knows it is HMAC-SHA256 because that is the only
 * thing this file implements, so there is nothing for an attacker to choose.
 *
 * The format is `base64url(json).base64url(mac)`, where the MAC covers the
 * encoded payload bytes exactly as transmitted. Every claim that decides
 * anything is inside the signed region — audience, workspace, subject and
 * expiry included, because a token whose workspace could be edited in flight
 * would be a tenant selector handed to the caller (invariant 4).
 *
 * ## Why it is deliberately small
 *
 * This is not a general authorization mechanism and must not become one. It
 * asserts "this request is made by this human, in this workspace, to this
 * audience, until this moment". It grants nothing: what the human may do is
 * decided by the pipeline in §3.3, every time, and never by a claim in here
 * (invariant 8).
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export interface CapabilityClaims {
  /** Who may accept this token. A token for one service is not valid at another. */
  readonly aud: string;
  readonly workspaceId: string;
  /** The human on whose behalf the call is made. */
  readonly humanId: string;
  /** The agent, when the call is made for one. Null for a person at a keyboard. */
  readonly agentId: string | null;
  /** Coarse scope, e.g. 'control-plane'. Never a substitute for a policy check. */
  readonly action: string;
  readonly resource: string;
  /** Epoch milliseconds. */
  readonly issuedAt: number;
  readonly expiresAt: number;
  /** Nonce, so two otherwise identical tokens are distinguishable in an audit. */
  readonly nonce: string;
}

export interface MintInput {
  readonly aud: string;
  readonly workspaceId: string;
  readonly humanId: string;
  readonly agentId?: string | null;
  readonly action: string;
  readonly resource: string;
  readonly ttlMs: number;
  readonly now?: number;
}

/**
 * Ceiling on token lifetime.
 *
 * Fifteen minutes. §11 wants revocation effective on the next protected request
 * within five seconds, and a long-lived capability token is the one thing that
 * could outlive a revocation — the gateway would keep accepting it. Short
 * enough that the blast radius of a leaked token is measured in minutes; the
 * real revocation check still runs on every request regardless.
 */
export const MAX_TTL_MS = 15 * 60 * 1000;

/**
 * Who a gateway token is for, and what it says it is for.
 *
 * Here rather than in the gateway because two services now mint these: the
 * gateway's own bridge, and the §8 authorization server's token endpoint. A
 * second definition that drifted would produce tokens the gateway silently
 * refuses — a failure that looks like a broken client and is not.
 *
 * These are labels, not authority. A token carrying them proves only who minted
 * it and for whom; what that agent may do is decided by the pipeline, per
 * request (invariant 8).
 */
export const GATEWAY_AUDIENCE = 'veto-gateway';
export const GATEWAY_SCOPE = 'mcp';

export class CapabilityError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super(`Capability token rejected: ${reason}`);
    this.name = 'CapabilityError';
    this.reason = reason;
  }
}

export function mintCapability(secret: string, input: MintInput): string {
  assertSecret(secret);

  if (!Number.isInteger(input.ttlMs) || input.ttlMs <= 0 || input.ttlMs > MAX_TTL_MS) {
    throw new CapabilityError(`ttl must be between 1 and ${MAX_TTL_MS} ms`);
  }

  const issuedAt = input.now ?? Date.now();
  const claims: CapabilityClaims = {
    aud: input.aud,
    workspaceId: input.workspaceId,
    humanId: input.humanId,
    agentId: input.agentId ?? null,
    action: input.action,
    resource: input.resource,
    issuedAt,
    expiresAt: issuedAt + input.ttlMs,
    nonce: randomBytes(9).toString('base64url'),
  };

  const body = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  return `${body}.${mac(secret, body)}`;
}

export interface VerifyOptions {
  /** Required. A verifier that does not pin its audience accepts other services' tokens. */
  readonly audience: string;
  readonly now?: number;
  /** Tolerance for clock skew between minter and verifier. */
  readonly leewayMs?: number;
}

/**
 * Verify a token, or return null.
 *
 * Null for every failure — bad signature, wrong audience, expired, malformed,
 * issued in the future. The caller's response is identical in all of those
 * cases (deny), and distinguishing them in a return value invites a caller to
 * treat some of them as recoverable.
 */
export function verifyCapability(
  secret: string,
  token: string,
  options: VerifyOptions,
): CapabilityClaims | null {
  assertSecret(secret);

  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1) return null;

  const body = token.slice(0, dot);
  if (!constantTimeEquals(token.slice(dot + 1), mac(secret, body))) return null;

  let claims: CapabilityClaims;
  try {
    claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as CapabilityClaims;
  } catch {
    return null;
  }

  if (!wellFormed(claims)) return null;

  // Audience is checked after the signature, but it is not optional: a valid
  // signature only proves the token came from something holding the key, not
  // that it was meant for this service.
  if (claims.aud !== options.audience) return null;

  const now = options.now ?? Date.now();
  const leeway = options.leewayMs ?? 5_000;

  if (claims.expiresAt <= now - leeway) return null;
  if (claims.issuedAt > now + leeway) return null;
  // A token claiming a longer life than the minter is allowed to grant was not
  // produced by a well-behaved minter, whoever signed it.
  if (claims.expiresAt - claims.issuedAt > MAX_TTL_MS) return null;

  return claims;
}

function wellFormed(claims: CapabilityClaims): boolean {
  return (
    typeof claims.aud === 'string' &&
    claims.aud !== '' &&
    typeof claims.workspaceId === 'string' &&
    claims.workspaceId !== '' &&
    typeof claims.humanId === 'string' &&
    claims.humanId !== '' &&
    (claims.agentId === null || typeof claims.agentId === 'string') &&
    typeof claims.action === 'string' &&
    typeof claims.resource === 'string' &&
    typeof claims.nonce === 'string' &&
    Number.isFinite(claims.issuedAt) &&
    Number.isFinite(claims.expiresAt)
  );
}

function assertSecret(secret: string): void {
  if (secret.length < 32) {
    throw new CapabilityError('signing key must be at least 32 characters');
  }
}

const mac = (secret: string, body: string): string =>
  createHmac('sha256', Buffer.from(secret, 'utf8')).update(body).digest('base64url');

function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
