/**
 * Deleting what is finished with.
 *
 * Nothing removed a spent refresh token, a revoked chain or a client that
 * registered once and never came back. A day of testing left 1,648 client rows,
 * and registration is open by design — so the table has no natural ceiling and
 * no floor either.
 *
 * Not urgent and not nothing: unbounded growth in a table an anonymous caller
 * can add to is the disruption half of Boundary 6, and the only bound on it
 * today is a per-address rate limit.
 *
 * ## Deliberately conservative
 *
 * A refresh token is deleted only once it is both finished and old. "Finished"
 * alone is not enough: a rotated token is what makes a *reuse* detectable, and
 * deleting it the moment it is spent would turn the strongest signal in the
 * flow — somebody presenting a token twice — into "unknown token", which says
 * nothing. The grace period is how long that evidence is worth keeping.
 *
 * A client is deleted only if nothing ever descended from it. A client with any
 * refresh row, live or dead, is a client somebody used, and its name is part of
 * what an audit reads.
 */

import type { Db } from '@veto/db';

/**
 * How long a finished token stays readable.
 *
 * Seven days: long enough that a reuse arriving days late is still recognised
 * as a reuse rather than a stranger, short enough that a table does not become
 * a history of every session ever opened.
 */
export const SPENT_GRACE_DAYS = 7;

/** How long an unused registration survives. */
export const UNUSED_CLIENT_DAYS = 30;

export interface PruneReport {
  readonly refreshTokens: number;
  readonly clients: number;
}

/**
 * Remove finished refresh tokens for one workspace.
 *
 * Tenant-scoped, so it runs inside `withWorkspace` like every other query
 * against this table — a sweep is not a reason to leave the tenant boundary.
 */
export async function pruneRefreshTokens(db: Db, workspaceId: string): Promise<number> {
  const { rowCount } = await db.query(
    `delete from oauth_refresh_tokens
      where workspace_id = $1
        and status <> 'active'
        and coalesce(used_at, created_at) < now() - ($2 || ' days')::interval`,
    [workspaceId, String(SPENT_GRACE_DAYS)],
  );
  return rowCount ?? 0;
}

/**
 * Remove client registrations nothing ever used.
 *
 * Not tenant-scoped, because `oauth_clients` has no tenant — see migration 0015.
 * `last_used_at is null` is what keeps this safe: a client any workspace ever
 * obtained a token for carries a stamp and is never touched, whatever its age.
 *
 * Read from the row itself rather than from a subquery against
 * `oauth_refresh_tokens`. That table has FORCEd row-level security and this
 * sweep runs untenanted, so such a subquery returns zero rows — every old
 * client would look unused, including the ones in daily use. The foreign key
 * caught it, which is the constraint doing its job and not a design to lean on.
 */
export async function pruneUnusedClients(db: Db): Promise<number> {
  const { rowCount } = await db.query(
    `delete from oauth_clients
      where created_at < now() - ($1 || ' days')::interval
        and last_used_at is null`,
    [String(UNUSED_CLIENT_DAYS)],
  );
  return rowCount ?? 0;
}
