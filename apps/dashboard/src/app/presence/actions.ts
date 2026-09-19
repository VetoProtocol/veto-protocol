'use server';

import { revalidatePath } from 'next/cache';
import { ApiError, setEmergencyLock, setPresence } from '@/lib/api';
import { currentSession } from '@/lib/session';
import type { ActionState } from '../agents/action-state';

/**
 * Presence set from the dashboard is `medium` assurance, never `high`.
 *
 * A person clicking a button is authenticated but not freshly verified — a
 * stolen session clicks just as well. Only a passkey assertion carries `high`,
 * and the API refuses a dashboard source that claims it.
 */
export async function setPresenceAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  const state = String(form.get('state') ?? '');

  try {
    const presence = await setPresence(session.credential, {
      state,
      source: 'dashboard',
      assurance: 'medium',
    });
    revalidatePath('/presence');
    return { error: null, notice: `You are now ${presence.state}.` };
  } catch (error) {
    return { error: describe(error), notice: null };
  }
}

export async function emergencyLockAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  const locked = form.get('locked') === 'true';

  try {
    const result = await setEmergencyLock(session.credential, locked);
    revalidatePath('/presence');

    if (!locked) {
      // Said plainly, because it is the part people assume wrong. Unlocking
      // restores the ability to ask; it does not restore what the lock took.
      return {
        error: null,
        notice: 'Workspace unlocked. Anything the lock stopped has to be re-authorized.',
      };
    }

    // What it actually stopped, not just what it will stop. Somebody throwing
    // this switch believes something is going wrong right now, and "locked"
    // alone does not tell them whether work in flight was caught.
    const stopped = [
      result.grants_revoked > 0 ? `${result.grants_revoked} approved request${plural(result.grants_revoked)}` : null,
      result.sessions_dropped > 0 ? `${result.sessions_dropped} live session${plural(result.sessions_dropped)}` : null,
    ].filter((part): part is string => part !== null);

    return {
      error: null,
      notice:
        stopped.length === 0
          ? 'Workspace locked. Every protected action is denied until you unlock it. Nothing was in flight.'
          : `Workspace locked. Stopped ${stopped.join(' and ')}.`,
    };
  } catch (error) {
    return { error: describe(error), notice: null };
  }
}

function describe(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.failure.code === 'AUTOMATION_WINDOW_VIOLATION') return error.failure.message;
    return error.failure.message;
  }
  return 'Something went wrong talking to the control plane.';
}

const plural = (n: number): string => (n === 1 ? '' : 's');
