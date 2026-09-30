'use server';

import { revalidatePath } from 'next/cache';
import { ApiError, revokeConnection, syncHierarchy } from '@/lib/api';
import { describeWalk } from './walk-state';
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
    const job = await syncHierarchy(session.credential, folderId);
    revalidatePath('/connections');

    // Started, not finished. Saying "recorded N items" here would be a number
    // invented before the work happened — the walk has barely begun.
    if (job.status === 'running') {
      return {
        error: null,
        notice:
          'Walking that folder now. It writes one entry at a time to the policy ' +
          'engine, so a large folder takes a minute — reload this page to see how it went.',
      };
    }

    // Fast enough to finish inside the request, which happens on a small
    // folder. Report it properly rather than telling somebody to wait for
    // something already done.
    return { error: null, notice: describeWalk(job) };
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
