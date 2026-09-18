/**
 * Agent revocation (FR-08).
 *
 * Four effects, in a deliberate order:
 *
 *   1. Flip the database status. This alone makes the gateway deny, because the
 *      status check runs at step 3 of every request.
 *   2. Remove the Permit facts, so nothing grants this agent anything.
 *   3. Drop its sessions, so an in-flight connection cannot keep working.
 *   4. Write the audit event.
 *
 * Ordering is chosen so that every partial failure leaves the system *more*
 * restrictive, never less. If step 2 or 3 throws, step 1 has already committed
 * and the agent is denied locally; the caller sees the error and must retry.
 * The reverse order would leave an agent that Permit no longer knows about but
 * whose row still says active — a state where a later reconciliation could
 * plausibly restore access. Fail closed means the safe half wins (invariant 1).
 */

import type { Pool } from 'pg';
import type Redis from 'ioredis';
import { withWorkspace } from '@veto/db';
import type { PolicyFacts } from '@veto/permit';
import { writeAuditEvent } from './audit.ts';
import { findAgent } from './agents.ts';

export interface RevokeAgentInput {
  readonly workspaceId: string;
  readonly agentId: string;
  /** The user performing the revocation, recorded as the audit actor. */
  readonly actorUserId: string;
  readonly correlationId?: string | null;
}

export interface RevokeAgentResult {
  readonly revoked: boolean;
  readonly alreadyRevoked: boolean;
  readonly sessionsDropped: number;
}

export class AgentNotFoundError extends Error {
  constructor() {
    super('No such agent in this workspace');
    this.name = 'AgentNotFoundError';
  }
}

export async function revokeAgent(
  pool: Pool,
  redis: Redis,
  policy: PolicyFacts,
  input: RevokeAgentInput,
): Promise<RevokeAgentResult> {
  const { workspaceId, agentId } = input;

  // Step 1 — commit the status change before anything else.
  const outcome = await withWorkspace(pool, workspaceId, async (db) => {
    const existing = await findAgent(db, workspaceId, agentId);
    if (!existing) throw new AgentNotFoundError();

    if (existing.status === 'revoked') {
      return { alreadyRevoked: true };
    }

    await db.query(
      `update agents set status = 'revoked', revoked_at = now()
        where workspace_id = $1 and id = $2`,
      [workspaceId, agentId],
    );

    await writeAuditEvent(db, {
      workspaceId,
      actor: input.actorUserId,
      eventType: 'agent.revoked',
      resourceRef: `agent:${agentId}`,
      outcome: 'lifecycle',
      correlationId: input.correlationId ?? null,
    });

    return { alreadyRevoked: false };
  });

  // Steps 2 and 3 run even when the agent was already revoked, so a retry after
  // a partial failure converges instead of silently leaving facts behind.
  await policy.removeAgent(workspaceId, agentId);
  const sessionsDropped = await dropSessions(redis, workspaceId, agentId);

  return {
    revoked: !outcome.alreadyRevoked,
    alreadyRevoked: outcome.alreadyRevoked,
    sessionsDropped,
  };
}

async function dropSessions(redis: Redis, workspaceId: string, agentId: string): Promise<number> {
  const { dropAgentSessions } = await import('./sessions.ts');
  return dropAgentSessions(redis, workspaceId, agentId);
}
