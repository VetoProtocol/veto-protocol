'use server';

import { revalidatePath } from 'next/cache';
import { ApiError, revokeConnection } from '@/lib/api';
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
