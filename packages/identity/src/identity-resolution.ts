/**
 * OIDC subject to user and workspace.
 *
 * Thin wrapper over `resolve_identity_subject()` — see migration 0007 for why
 * this one read is allowed to precede a tenant, and how narrow the exception
 * is. The function itself filters to active users, so a suspended person cannot
 * sign in and no caller has to remember to check.
 *
 * A subject may map to several workspaces: `users` is unique on
 * (workspace_id, identity_subject), not on the subject alone. Every match is
 * returned and the caller decides — picking one silently would sign somebody
 * into a workspace they did not choose.
 */

import type { Db } from '@veto/db';

export interface ResolvedIdentity {
  readonly userId: string;
  readonly workspaceId: string;
}

export async function resolveIdentitySubject(
  db: Db,
  subject: string,
): Promise<ResolvedIdentity[]> {
  const { rows } = await db.query<{ user_id: string; workspace_id: string }>(
    `select user_id, workspace_id from resolve_identity_subject($1)`,
    [subject],
  );
  return rows.map((row) => ({ userId: row.user_id, workspaceId: row.workspace_id }));
}
