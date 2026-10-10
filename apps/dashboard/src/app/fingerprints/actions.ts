'use server';

import { revalidatePath } from 'next/cache';
import { ApiError, judgeFingerprint, setFingerprintMode } from '@/lib/api';
import { currentSession } from '@/lib/session';
import type { ActionState } from '../agents/action-state';

// Only async functions may live in a `'use server'` module: every export
// becomes a callable endpoint, and a constant beside the actions is refused at
// runtime rather than by `next build`. Shared state types stay in their own
// file, which `test/use-server.test.ts` guards.

const MODES = new Set(['observe', 'challenge', 'deny']);

export async function setModeAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  const agentId = String(form.get('agent_id') ?? '').trim();
  const mode = String(form.get('mode') ?? '').trim();

  if (agentId === '' || !MODES.has(mode)) {
    return { error: 'Pick an agent and one of the three settings.', notice: null };
  }

  try {
    await setFingerprintMode(session.credential, agentId, mode as 'observe' | 'challenge' | 'deny');
  } catch (error) {
    return {
      error: error instanceof ApiError ? error.failure.message : 'The API did not answer.',
      notice: null,
    };
  }

  revalidatePath('/fingerprints');

  return {
    error: null,
    notice:
      mode === 'observe'
        ? 'Recording only. This agent’s answers are no longer affected by which software calls.'
        : mode === 'challenge'
          ? 'Unrecognised software now needs your approval before it can act.'
          : 'Unrecognised software is now refused outright.',
  };
}

export async function judgeFingerprintAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  const agentId = String(form.get('agent_id') ?? '').trim();
  const fingerprint = String(form.get('fingerprint') ?? '').trim();
  const status = String(form.get('status') ?? '').trim();

  if (agentId === '' || fingerprint === '' || (status !== 'pinned' && status !== 'refused')) {
    return { error: 'Pick a client and whether to trust or refuse it.', notice: null };
  }

  try {
    await judgeFingerprint(session.credential, agentId, fingerprint, status);
  } catch (error) {
    return {
      error: error instanceof ApiError ? error.failure.message : 'The API did not answer.',
      notice: null,
    };
  }

  revalidatePath('/fingerprints');

  return {
    error: null,
    notice:
      status === 'pinned'
        ? 'Trusted. This software may act for the agent while enforcement is on.'
        : 'Refused. This software is turned away wherever enforcement is on.',
  };
}
