/**
 * Making a revocation reach everything (spec §11, §12.1, FR-08).
 *
 * The primitives already existed and each did its own job: `revokeAgent` flips
 * the status and drops Redis sessions, the lock column makes step 3 deny,
 * `revokeLiveApprovals` kills outstanding grants. What was missing is a single
 * place that performs *all* the effects of one decision to stop trusting
 * something, so a caller cannot do three quarters of a revocation by omission.
 *
 * ## Ordering
 *
 * Every step is ordered so that a partial failure leaves the system **more**
 * restrictive, never less:
 *
 *   1. Write the fact that denies — the lock column, or the agent's status.
 *      From here on the pipeline refuses at step 3 whatever else happens.
 *   2. Kill the grants that could still be redeemed.
 *   3. Drop the live sessions.
 *   4. Audit.
 *
 * If step 3 throws, steps 1 and 2 have committed and the system is already
 * closed; the caller sees the error and retries, and every step is idempotent
 * so the retry converges. The reverse order would produce moments where the
 * sessions are gone but the authority that denies them is not yet written —
 * a window in which a reconciliation could plausibly restore access.
 *
 * ## Why this is not in @veto/identity
 *
 * Approvals belong to this package; identity cannot import it without a cycle.
 * So identity keeps the identity-layer primitive and this composes on top. The
 * API routes call the composition, never the primitive.
 */

import type { Pool } from 'pg';
import type Redis from 'ioredis';
import { withWorkspace } from '@veto/db';
import type { PolicyFacts } from '@veto/permit';
import {
  dropAgentSessions,
  revokeAgent,
  writeAuditEvent,
  type RevokeAgentInput,
  type RevokeAgentResult,
} from '@veto/identity';
import { setEmergencyLock } from '@veto/presence';
import { revokeLiveApprovals } from './approvals.ts';

export interface RevokeAgentEverywhereResult extends RevokeAgentResult {
  /** Outstanding grants that this revocation killed. */
  readonly grantsRevoked: readonly string[];
}

/**
 * Revoke an agent, and everything that was still true because of it.
 *
 * `revokeAgent` already denies the next request — the gateway reads the agent
 * row every time and never caches it. What it did not do is reach the approvals
 * this agent's decisions produced: an approved challenge names a human and an
 * action, not an agent, so nothing about revoking the agent invalidated it.
 */
export async function revokeAgentEverywhere(
  pool: Pool,
  redis: Redis,
  policy: PolicyFacts,
  input: RevokeAgentInput,
): Promise<RevokeAgentEverywhereResult> {
  const result = await revokeAgent(pool, redis, policy, input);

  const grantsRevoked = await withWorkspace(pool, input.workspaceId, (db) =>
    revokeLiveApprovals(db, { workspaceId: input.workspaceId, agentId: input.agentId }),
  );

  return { ...result, grantsRevoked };
}

export interface LockWorkspaceInput {
  readonly workspaceId: string;
  readonly locked: boolean;
  /** The user throwing the switch, recorded as the audit actor. */
  readonly actorUserId: string;
  readonly correlationId?: string | null;
}

export interface LockWorkspaceResult {
  readonly locked: boolean;
  readonly alreadyInThatState: boolean;
  readonly grantsRevoked: readonly string[];
  readonly sessionsDropped: number;
}

/**
 * Throw — or release — the emergency lock.
 *
 * Locking is the loudest control in the product and the one with the least
 * margin for a partial effect: the reason somebody reaches for it is that they
 * believe something is going wrong right now. So it does not merely set a
 * column that future requests will read. It also kills every outstanding grant
 * and drops every live session, because both are ways for work to continue
 * after the switch was thrown.
 *
 * **Unlocking is not the inverse.** It clears the column and stops there. The
 * grants killed during a lock stay killed and the sessions stay dropped —
 * restoring them would mean handing back authority that somebody deliberately
 * withdrew, on the strength of a second click. Anything that should resume gets
 * re-authorized from scratch, which is the whole premise (§1.1).
 */
export async function lockWorkspace(
  pool: Pool,
  redis: Redis,
  input: LockWorkspaceInput,
): Promise<LockWorkspaceResult> {
  // Step 1 — the fact that denies, committed on its own. Every decision from
  // here refuses at pipeline step 3, before Permit is consulted. `presence`
  // owns the column and the `workspace.locked` event; this only adds the
  // effects that column alone does not have.
  const { changed } = await withWorkspace(pool, input.workspaceId, (db) =>
    setEmergencyLock(db, input.workspaceId, input.locked, input.actorUserId),
  );

  if (!input.locked) {
    // Releasing. Nothing to tear down, and nothing to restore.
    return {
      locked: false,
      alreadyInThatState: !changed,
      grantsRevoked: [],
      sessionsDropped: 0,
    };
  }

  // Step 2 — the grants. Runs even when the workspace was already locked, so a
  // retry after a partial failure converges rather than leaving grants behind.
  const grantsRevoked = await withWorkspace(pool, input.workspaceId, (db) =>
    revokeLiveApprovals(db, { workspaceId: input.workspaceId, agentId: null }),
  );

  // Step 3 — the sessions, for every agent in the workspace. An agent with no
  // sessions costs one empty set read; missing one would leave a connection
  // that keeps working until its own expiry.
  const agentIds = await withWorkspace(pool, input.workspaceId, async (db) => {
    const { rows } = await db.query<{ id: string }>(
      `select id from agents where workspace_id = $1 and status <> 'revoked'`,
      [input.workspaceId],
    );
    return rows.map((row) => row.id);
  });

  let sessionsDropped = 0;
  for (const agentId of agentIds) {
    sessionsDropped += await dropAgentSessions(redis, input.workspaceId, agentId);
  }

  // Step 4 — record what the lock actually tore down, and only when it tore
  // something down. "The switch was thrown" is already in the timeline; this is
  // the separate fact that work in flight was stopped, which is the question an
  // incident review asks. A lock over a quiet workspace writes nothing extra.
  if (grantsRevoked.length > 0 || sessionsDropped > 0) {
    await withWorkspace(pool, input.workspaceId, (db) =>
      writeAuditEvent(db, {
        workspaceId: input.workspaceId,
        actor: input.actorUserId,
        eventType: 'workspace.lock_enforced',
        // Counts, not identifiers. How much was stopped is what a reader needs;
        // which grants they were is already on the rows themselves.
        resourceRef: `workspace:${input.workspaceId}#grants=${grantsRevoked.length},sessions=${sessionsDropped}`,
        outcome: 'lifecycle',
        correlationId: input.correlationId ?? null,
      }),
    );
  }

  return {
    locked: true,
    alreadyInThatState: !changed,
    grantsRevoked,
    sessionsDropped,
  };
}
