/**
 * Agent identity: registration and lookup.
 *
 * Every function takes a `Db` already bound to a workspace by
 * withWorkspace(), so RLS is in force for each statement here. The explicit
 * workspace_id in each query is the first lock; RLS is the second.
 */

import { newId } from '@veto/core';
import type { Db } from '@veto/db';
import type { PolicyFacts } from '@veto/permit';
import { writeAuditEvent } from './audit.ts';

export type AgentStatus = 'active' | 'suspended' | 'revoked';

/** §3.3 step 3. `observe` changes no answer; see docs/fingerprints.md. */
export type FingerprintMode = 'observe' | 'challenge' | 'deny';

export interface Agent {
  readonly id: string;
  readonly workspace_id: string;
  readonly provider: string;
  readonly client_id: string;
  readonly owner_user_id: string;
  readonly status: AgentStatus;
  /**
   * Legacy and unread. An operator-declared string from migration 0002 that
   * nothing ever compared anything to. The *observed* record is
   * `agent_fingerprints`; see docs/fingerprints.md.
   */
  readonly fingerprint: string | null;
  /**
   * Whether an unrecognised client narrows this agent's answer (§3.3 step 3).
   *
   * Carried here because `findAgent` already reads the whole row at step 3, so
   * the mode costs nothing extra — and because `observe`, the default, lets
   * that step skip the fingerprint lookup altogether.
   */
  readonly fingerprint_mode: FingerprintMode;
  readonly created_at: Date;
  readonly revoked_at: Date | null;
}

export interface RegisterAgentInput {
  readonly workspaceId: string;
  readonly ownerUserId: string;
  readonly provider: string;
  readonly clientId: string;
  readonly fingerprint?: string | null;
  readonly correlationId?: string | null;
}

export class DuplicateLiveAgentError extends Error {
  constructor() {
    super('This user already has a live agent for that client');
    this.name = 'DuplicateLiveAgentError';
  }
}

/**
 * Register a new agent identity.
 *
 * A freshly registered agent holds no policy grants beyond its owner
 * relationship: no connection, no session, no resource roles. Under
 * deny-by-default it can do nothing until those are attached (invariant 2).
 * That is what makes re-registration after a revoke safe.
 */
export async function registerAgent(
  db: Db,
  policy: PolicyFacts,
  input: RegisterAgentInput,
): Promise<Agent> {
  const id = newId('agt_');

  let inserted;
  try {
    inserted = await db.query<Agent>(
      `insert into agents (id, workspace_id, provider, client_id, owner_user_id, fingerprint)
       values ($1, $2, $3, $4, $5, $6)
       returning *`,
      [id, input.workspaceId, input.provider, input.clientId, input.ownerUserId, input.fingerprint ?? null],
    );
  } catch (error) {
    if ((error as { constraint?: string }).constraint === 'agents_one_live_per_client_idx') {
      throw new DuplicateLiveAgentError();
    }
    throw error;
  }

  const agent = inserted.rows[0];
  if (!agent) throw new Error('agent insert returned no row');

  // Permit learns about the principal and its owner relationship (§4.4).
  await policy.syncAgent({
    workspaceId: input.workspaceId,
    agentId: agent.id,
    ownerUserId: input.ownerUserId,
  });

  await writeAuditEvent(db, {
    workspaceId: input.workspaceId,
    actor: input.ownerUserId,
    eventType: 'agent.registered',
    resourceRef: `agent:${agent.id}`,
    outcome: 'lifecycle',
    correlationId: input.correlationId ?? null,
  });

  return agent;
}

export async function listAgents(db: Db, workspaceId: string): Promise<Agent[]> {
  const { rows } = await db.query<Agent>(
    `select * from agents where workspace_id = $1 order by created_at desc, id`,
    [workspaceId],
  );
  return rows;
}

/** Null rather than throwing: a caller in another workspace must not learn that an id exists. */
export async function findAgent(db: Db, workspaceId: string, agentId: string): Promise<Agent | null> {
  const { rows } = await db.query<Agent>(
    `select * from agents where workspace_id = $1 and id = $2`,
    [workspaceId, agentId],
  );
  return rows[0] ?? null;
}
