/**
 * Binding a runtime session to a human *and* an agent (spec §8).
 *
 * Every MCP request resolves both, or the connection is refused. A session that
 * knows only the human cannot attribute the action to the thing that took it;
 * one that knows only the agent has nobody to route an approval to, and §7.1
 * puts the delegating user at the centre of every approval.
 *
 * ## Why the database is consulted on every request
 *
 * The token is not the authority on whether the agent still exists. §11 wants
 * revocation effective on the next protected request, within five seconds, and
 * a capability token minted before a revoke is still cryptographically valid
 * after it. So the agent's row is read every time and a non-active status
 * denies — this is the check that actually makes revocation work, and it is
 * deliberately not cached.
 *
 * Reading the row also re-proves the agent belongs to the token's workspace:
 * `findAgent` is tenant-scoped and RLS is in force, so a token naming another
 * workspace's agent finds nothing (invariant 4).
 */

import type { FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import { findAgent } from '@veto/identity';
import { verifyCapability } from '@veto/tokens';
import { RPC, RpcError } from './jsonrpc.ts';
import { GATEWAY_AUDIENCE, GATEWAY_SCOPE } from '@veto/tokens';

/** Pinned so a control-plane token cannot be replayed at the gateway. */
// Defined in @veto/tokens and re-exported here, because the authorization
// server mints these too and a second definition that drifted would produce
// tokens this file silently refuses.
export { GATEWAY_AUDIENCE, GATEWAY_SCOPE };

export interface GatewaySession {
  readonly workspaceId: string;
  readonly humanId: string;
  readonly agentId: string;
  readonly clientId: string;
}

/**
 * Every failure is the same refusal.
 *
 * Missing header, wrong scheme, bad signature, wrong audience, wrong scope,
 * expired, no agent claim, unknown agent, suspended agent, revoked agent — one
 * error, no detail. A prober learns only that it is not connected, and an agent
 * that has been revoked learns exactly as much as one that never existed
 * (invariant 1).
 */
export function unauthenticated(): RpcError {
  return new RpcError(RPC.UNAUTHENTICATED, 'Not authenticated', {
    reason_code: 'IDENTITY_UNRESOLVED',
  });
}

export async function resolveSession(
  pool: Pool,
  secret: string,
  request: FastifyRequest,
): Promise<GatewaySession> {
  const header = request.headers['authorization'];
  if (typeof header !== 'string') throw unauthenticated();

  const match = /^Bearer (.+)$/i.exec(header);
  const token = match?.[1];
  if (token === undefined) throw unauthenticated();

  const claims = verifyCapability(secret, token, { audience: GATEWAY_AUDIENCE });
  if (!claims) throw unauthenticated();

  // A gateway token minted for some other purpose is not a session.
  if (claims.action !== GATEWAY_SCOPE) throw unauthenticated();

  // §8: bound to a human AND an agent. A token with no agent claim is a
  // control-plane credential wearing the wrong audience, and is refused rather
  // than treated as a human acting directly.
  if (claims.agentId === null || claims.agentId === '') throw unauthenticated();

  const agent = await withWorkspace(pool, claims.workspaceId, (db) =>
    findAgent(db, claims.workspaceId, claims.agentId ?? ''),
  );

  if (!agent) throw unauthenticated();

  // Suspended is refused as firmly as revoked. Suspension is temporary from the
  // operator's point of view; from the gateway's it means "not now".
  if (agent.status !== 'active') throw unauthenticated();

  // The owner on the row wins over the claim. If they ever disagree, the token
  // is describing a delegation that no longer holds.
  if (agent.owner_user_id !== claims.humanId) throw unauthenticated();

  return {
    workspaceId: claims.workspaceId,
    humanId: claims.humanId,
    agentId: agent.id,
    clientId: agent.client_id,
  };
}
