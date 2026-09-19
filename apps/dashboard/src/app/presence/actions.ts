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
    await setEmergencyLock(session.credential, locked);
    revalidatePath('/presence');
    return {
      error: null,
      notice: locked
        ? 'Workspace locked. Every protected action is denied until you unlock it.'
        : 'Workspace unlocked.',
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
