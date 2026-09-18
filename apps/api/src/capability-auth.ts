/**
 * The production authenticator: a capability token in the Authorization header.
 *
 * The dashboard mints one of these after a user signs in with OIDC, and this
 * turns it back into a principal. The token proves *who is asking* and nothing
 * more — what they may do is decided by the pipeline on every request
 * (invariant 8). Nothing here consults a claim to authorize anything.
 *
 * Every rejection is the same `null`: missing header, wrong scheme, bad
 * signature, wrong audience, expired. The caller renders all of them as one 401
 * with one reason code, so a prober learns only that they are not signed in.
 */

import type { FastifyRequest } from 'fastify';
import { verifyCapability } from '@veto/tokens';
import type { Authenticator, Principal } from './principal.ts';

/** This service's name, pinned so a token minted for the gateway is refused here. */
export const CONTROL_PLANE_AUDIENCE = 'veto-control-plane';

export function capabilityAuthenticator(secret: string): Authenticator {
  // Fail at construction, not per request. A server started with no signing key
  // would reject every request in a way indistinguishable from users simply not
  // being signed in, which is the hardest kind of outage to diagnose.
  if (secret.trim().length < 32) {
    throw new Error('Capability signing key must be at least 32 characters');
  }

  return async (request: FastifyRequest): Promise<Principal | null> => {
    const header = request.headers['authorization'];
    if (typeof header !== 'string') return null;

    // Case-insensitive scheme, exactly one space, non-empty credential.
    const match = /^Bearer (.+)$/i.exec(header);
    const token = match?.[1];
    if (token === undefined) return null;

    const claims = verifyCapability(secret, token, { audience: CONTROL_PLANE_AUDIENCE });
    if (!claims) return null;

    return {
      workspaceId: claims.workspaceId,
      userId: claims.humanId,
      action: claims.action,
      agentId: claims.agentId,
    };
  };
}
