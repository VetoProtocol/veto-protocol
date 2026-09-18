/**
 * Minting credentials for the control-plane API.
 *
 * The dashboard is a first-party service and holds the capability signing key,
 * so it mints its own tokens rather than exchanging for them. Two scopes, never
 * mixed: one to resolve a sign-in, one for everything a signed-in user does.
 * The API refuses each at the other's routes, so a leak of either stays
 * contained.
 *
 * Session credentials are minted at sign-in and live in the session cookie, so
 * the session cannot outlive the credential — the cookie expiry is set to match.
 */

import 'server-only';
import { mintCapability } from '@veto/tokens';

export const CONTROL_PLANE_AUDIENCE = 'veto-control-plane';
export const SCOPE_CONTROL_PLANE = 'control-plane';
export const SCOPE_IDENTITY_RESOLVE = 'identity-resolve';

/** Ten minutes, inside the token package's fifteen-minute ceiling. */
export const SESSION_TTL_MS = 10 * 60 * 1000;

function key(): string {
  const value = (process.env['VETO_CAPABILITY_SECRET'] ?? '').trim();
  if (value.length < 32) {
    throw new Error('VETO_CAPABILITY_SECRET must be at least 32 characters');
  }
  return value;
}

export const sessionCredential = (workspaceId: string, humanId: string): string =>
  mintCapability(key(), {
    aud: CONTROL_PLANE_AUDIENCE,
    workspaceId,
    humanId,
    action: SCOPE_CONTROL_PLANE,
    resource: 'agents',
    ttlMs: SESSION_TTL_MS,
  });

/**
 * Credential for the sign-in lookup.
 *
 * Carries no real workspace or human, because at this point neither is known —
 * that is the question being asked. The placeholders are inert: the resolve
 * route reads only the subject from the body, and this token is refused
 * everywhere else.
 */
export const resolveCredential = (): string =>
  mintCapability(key(), {
    aud: CONTROL_PLANE_AUDIENCE,
    workspaceId: 'pending',
    humanId: 'pending',
    action: SCOPE_IDENTITY_RESOLVE,
    resource: 'users',
    ttlMs: 60_000,
  });
