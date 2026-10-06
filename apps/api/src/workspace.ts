/**
 * Emergency lock check for the control plane.
 *
 * Spec §3.3 step 3 puts the emergency lock ahead of policy evaluation, and
 * invariant 3 keeps it on Veto's side of the line. That pipeline is about
 * protected actions through the gateway, but the same reasoning applies here:
 * an attacker who has taken over a session and triggered a lock response would
 * otherwise register a fresh agent and carry on.
 *
 * So mutations that could *widen* access are refused while the workspace is
 * locked. Reads and revocation are not: revocation only ever narrows, and a
 * locked workspace is precisely when an operator needs to revoke things.
 *
 * A missing workspace row denies too. Under RLS an unset or wrong tenant sees
 * zero rows, so "not found" and "not mine" are the same answer, and the answer
 * is no (invariant 1).
 */

import type { Db } from '@veto/db';
import { HttpError } from './errors.ts';

export async function assertWorkspaceUnlocked(db: Db, workspaceId: string): Promise<void> {
  const { rows } = await db.query<{ emergency_lock: boolean }>(
    `select emergency_lock from workspaces where id = $1`,
    [workspaceId],
  );

  const workspace = rows[0];
  if (!workspace) {
    throw new HttpError(403, 'IDENTITY_UNRESOLVED', 'Workspace is not available');
  }
  if (workspace.emergency_lock) {
    throw new HttpError(423, 'WORKSPACE_LOCKED', 'Workspace is under emergency lock');
  }
}

/**
 * Which tier this workspace is on.
 *
 * Read at request time, never from a session cookie. An upgrade has to take
 * effect on the next page rather than the next sign-in — and a plan cached in a
 * signed cookie is a plan the server cannot revoke.
 *
 * A missing workspace reads as `free`. The caller is already authenticated into
 * one, so this should not happen; if it does, the safe answer is the one that
 * grants less.
 */
export async function workspacePlan(db: Db, workspaceId: string): Promise<'free' | 'pro'> {
  const { rows } = await db.query<{ plan: string }>(
    `select plan from workspaces where id = $1`,
    [workspaceId],
  );
  return rows[0]?.plan === 'pro' ? 'pro' : 'free';
}
