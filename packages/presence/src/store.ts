/**
 * Reading and writing presence.
 *
 * Every write goes through `assertTransition`, so an illegal move is refused at
 * the only place that can perform one. Every read goes through
 * `effectiveState`, so a lapsed record is interpreted the same way everywhere
 * rather than each caller remembering to check the expiry.
 */

import type { Db } from '@veto/db';
import { writeAuditEvent } from '@veto/identity';
import {
  DEFAULT_TTL_MS,
  assertTransition,
  effectiveState,
  type Assurance,
  type Presence,
  type PresenceSource,
  type PresenceState,
} from './state.ts';

interface PresenceRow {
  state: PresenceState;
  assurance: Assurance;
  source: string;
  changed_at: Date;
  expires_at: Date | null;
}

const toPresence = (row: PresenceRow): Presence => ({
  state: row.state,
  assurance: row.assurance,
  source: row.source as PresenceSource,
  changedAt: row.changed_at,
  expiresAt: row.expires_at,
});

/** What the record means right now — expiry already applied. */
export async function readPresence(
  db: Db,
  workspaceId: string,
  userId: string,
  now: Date = new Date(),
): Promise<Presence> {
  const { rows } = await db.query<PresenceRow>(
    `select state, assurance, source, changed_at, expires_at
       from presence where workspace_id = $1 and user_id = $2`,
    [workspaceId, userId],
  );
  return effectiveState(rows[0] ? toPresence(rows[0]) : null, now);
}

export interface SetPresenceInput {
  readonly workspaceId: string;
  readonly userId: string;
  readonly state: PresenceState;
  readonly source: PresenceSource;
  readonly assurance: Assurance;
  /** Null means the default window. `locked` ignores it and never expires. */
  readonly ttlMs?: number | null;
  readonly correlationId?: string | null;
}

export async function setPresence(db: Db, input: SetPresenceInput): Promise<Presence> {
  // The transition is judged against what the record *means* now, not what it
  // literally says. A lapsed 'active' is 'away', and moving from it is an
  // away→x transition.
  const current = await readPresence(db, input.workspaceId, input.userId);

  assertTransition(current.state, {
    to: input.state,
    source: input.source,
    assurance: input.assurance,
    ttlMs: input.ttlMs ?? (input.state === 'automation' ? null : DEFAULT_TTL_MS),
  });

  // A lock has no expiry. Clearing it is a decision, not a timeout.
  const expiresAt =
    input.state === 'locked'
      ? null
      : new Date(Date.now() + (input.ttlMs ?? DEFAULT_TTL_MS));

  const { rows } = await db.query<PresenceRow>(
    `insert into presence (workspace_id, user_id, state, source, assurance, expires_at, changed_at)
     values ($1,$2,$3,$4,$5,$6, now())
     on conflict (workspace_id, user_id) do update
        set state = excluded.state,
            source = excluded.source,
            assurance = excluded.assurance,
            expires_at = excluded.expires_at,
            changed_at = now()
     returning state, assurance, source, changed_at, expires_at`,
    [input.workspaceId, input.userId, input.state, input.source, input.assurance, expiresAt],
  );

  // Audited because a presence change alters what is permitted. The record
  // carries the state and the source — both classifications, never a location
  // or a device fingerprint (§11 data minimisation).
  await writeAuditEvent(db, {
    workspaceId: input.workspaceId,
    actor: input.userId,
    eventType: `presence.${input.state}`,
    resourceRef: `presence:${input.source}`,
    outcome: 'lifecycle',
    correlationId: input.correlationId ?? null,
  });

  const row = rows[0];
  if (!row) throw new Error('presence upsert returned no row');
  return toPresence(row);
}

export interface EmergencyLockResult {
  readonly locked: boolean;
  readonly changed: boolean;
}

/**
 * The workspace-wide emergency lock.
 *
 * Distinct from a user's `locked` presence: this denies every protected action
 * for everyone in the workspace, and the pipeline checks it at step 3 before
 * policy is consulted at all.
 */
export async function setEmergencyLock(
  db: Db,
  workspaceId: string,
  locked: boolean,
  actorUserId: string,
): Promise<EmergencyLockResult> {
  const { rows } = await db.query<{ emergency_lock: boolean }>(
    `update workspaces
        set emergency_lock = $2,
            locked_at = case when $2 then now() else null end
      where id = $1
      returning emergency_lock`,
    [workspaceId, locked],
  );

  const row = rows[0];
  if (!row) throw new Error('workspace not found');

  await writeAuditEvent(db, {
    workspaceId,
    actor: actorUserId,
    eventType: locked ? 'workspace.locked' : 'workspace.unlocked',
    resourceRef: `workspace:${workspaceId}`,
    outcome: 'lifecycle',
    correlationId: null,
  });

  return { locked: row.emergency_lock, changed: true };
}
