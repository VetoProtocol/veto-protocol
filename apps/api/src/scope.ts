/**
 * Credential scopes.
 *
 * A capability token says what it was minted for. A token the dashboard mints
 * to resolve a sign-in must not also be usable to register agents, and the
 * reverse holds too — so each route states the scope it accepts and refuses
 * everything else.
 *
 * This is containment, not authorization. It narrows what a leaked or
 * misdirected credential can reach; it never decides whether the human behind
 * it may perform the action. That decision belongs to the pipeline and happens
 * regardless (invariant 8).
 */

import type { FastifyRequest } from 'fastify';
import { HttpError } from './errors.ts';

/** Ordinary dashboard traffic: the agent, connection and policy endpoints. */
export const SCOPE_CONTROL_PLANE = 'control-plane';

/** Sign-in only: exchange a verified OIDC subject for a user and workspace. */
export const SCOPE_IDENTITY_RESOLVE = 'identity-resolve';

export function requireScope(request: FastifyRequest, scope: string): void {
  if (request.principal.action !== scope) {
    // 403, not 401: the caller is authenticated, just not with this credential.
    // Re-authenticating would not help and telling them to would mislead.
    throw new HttpError(403, 'TOOL_NOT_ALLOWED', 'This credential is not valid for that operation');
  }
}
