'use server';

import { revalidatePath } from 'next/cache';
import { ApiError, revokeConnection, syncHierarchy } from '@/lib/api';
import { currentSession } from '@/lib/session';
import type { ActionState } from '../agents/action-state';

/**
 * Disconnect.
 *
 * Two things happen, in this order and for a reason: the stored credential is
 * destroyed locally first, then the API asks Google to revoke it. An outage at
 * Google therefore leaves the credential already unusable here rather than
 * leaving it live while we retry (§9.1).
 */
export async function revokeConnectionAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  const connectionId = String(form.get('connection_id') ?? '').trim();
  if (connectionId === '') return { error: 'No connection selected.', notice: null };

  try {
    const result = await revokeConnection(session.credential, connectionId);
    revalidatePath('/connections');

    // Said plainly, because the two cases differ in what is still true at
    // Google. Silence about a failed provider revocation would be the
    // misleading version.
    return {
      error: null,
      notice: result.provider_revoked
        ? 'Disconnected, and the grant was revoked at Google.'
        : 'Disconnected here. Google was not reachable, so remove the grant at myaccount.google.com too.',
    };
  } catch (error) {
    return {
      error:
        error instanceof ApiError
          ? error.failure.message
          : 'Something went wrong talking to the control plane.',
      notice: null,
    };
  }
}


/**
 * Walk a folder and record what is inside it.
 *
 * ## Why this is a button and not part of granting
 *
 * A grant is a decision somebody made and needs only Permit. This needs Drive
 * reachable and a live connection, and it takes as long as the folder is big.
 * Folding it into the grant would let a Drive outage block a grant that has
 * nothing to do with Drive, and would make a fast operation unpredictably slow.
 *
 * ## It grants nothing
 *
 * Every edge says where a file *is*, not who may read it. Running it against a
 * folder nobody was granted changes nobody's access — which is what makes it
 * safe to expose as a button at all.
 */
export async function syncHierarchyAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  const folderId = String(form.get('folder_id') ?? 'root').trim() || 'root';

  try {
    const report = await syncHierarchy(session.credential, folderId);
    revalidatePath('/connections');

    // `truncated` is reported rather than buried. A walk that stopped early and
    // said it finished would leave somebody believing a grant reaches files it
    // does not — the failure this whole feature exists to remove.
    const found = `${report.links} item${report.links === 1 ? '' : 's'} across ${report.folders} folder${report.folders === 1 ? '' : 's'}`;
    return {
      error: null,
      notice: report.truncated
        ? `Recorded ${found}. Stopped at the ${report.depth}-level limit — anything deeper is not reachable yet, so run it again on a subfolder if you need it.`
        : `Recorded ${found}. A grant on that folder now reaches everything inside it.`,
    };
  } catch (error) {
    return {
      error:
        error instanceof ApiError
          ? error.failure.message
          : 'Something went wrong talking to the control plane.',
      notice: null,
    };
  }
}
