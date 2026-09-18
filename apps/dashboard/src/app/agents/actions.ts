'use server';

import { revalidatePath } from 'next/cache';
import { ApiError, registerAgent, revokeAgent } from '@/lib/api';
import { currentSession } from '@/lib/session';

export interface ActionState {
  readonly error: string | null;
  readonly notice: string | null;
}

export const EMPTY: ActionState = { error: null, notice: null };

/**
 * Register an agent.
 *
 * The form carries a provider and a client id and nothing else. There is no
 * owner field and no workspace field, because the API would reject them — both
 * come from the authenticated principal. That is worth restating in the UI
 * layer: a form that *offered* an owner picker would be describing a capability
 * the server does not have.
 */
export async function registerAgentAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  const provider = String(form.get('provider') ?? '').trim();
  const clientId = String(form.get('client_id') ?? '').trim();
  const fingerprint = String(form.get('fingerprint') ?? '').trim();

  if (!provider || !clientId) {
    return { error: 'Provider and client id are both required.', notice: null };
  }

  try {
    const agent = await registerAgent(session.credential, {
      provider,
      client_id: clientId,
      ...(fingerprint === '' ? {} : { fingerprint }),
    });
    revalidatePath('/agents');
    return { error: null, notice: `Registered ${agent.id}.` };
  } catch (error) {
    return { error: describe(error), notice: null };
  }
}

export async function revokeAgentAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  const agentId = String(form.get('agent_id') ?? '').trim();
  if (!agentId) return { error: 'No agent selected.', notice: null };

  try {
    const result = await revokeAgent(session.credential, agentId);
    revalidatePath('/agents');
    return {
      error: null,
      notice: result.already_revoked
        ? `${agentId} was already revoked.`
        : `Revoked ${agentId}. ${result.sessions_dropped} live session(s) dropped.`,
    };
  } catch (error) {
    return { error: describe(error), notice: null };
  }
}

/**
 * Turn a failure into something a person can act on.
 *
 * The API's own message is used when there is one — it is written for a caller
 * and deliberately says no more than it should. Anything else becomes a generic
 * line: an unexpected error is exactly the case where detail is most likely to
 * be internal and least likely to help.
 */
function describe(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.failure.code === 'AGENT_ALREADY_REGISTERED') {
      return 'You already have a live agent for that client. Revoke it first, or use a different client id.';
    }
    if (error.failure.code === 'WORKSPACE_LOCKED') {
      return 'This workspace is under emergency lock. New agents cannot be registered until it is lifted.';
    }
    return error.failure.message;
  }
  return 'Something went wrong talking to the control plane.';
}
