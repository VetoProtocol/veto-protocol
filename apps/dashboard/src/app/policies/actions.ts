'use server';

import { revalidatePath } from 'next/cache';
import { ApiError, createGrant, createPolicy, deletePolicy, revokeGrant } from '@/lib/api';
import { currentSession } from '@/lib/session';
import type { ActionState } from '../agents/action-state';
import { kindReach } from './resource-kinds';

export async function createPolicyAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  const subject = String(form.get('subject') ?? '').trim();
  const action = String(form.get('action') ?? '').trim();
  const effect = String(form.get('effect') ?? '').trim();
  const resourceType = String(form.get('resource_type') ?? '').trim();
  const matchKind = String(form.get('match_kind') ?? 'prefix');
  const matchValue = String(form.get('match_value') ?? '').trim();

  if (subject === '' || action === '' || effect === '' || resourceType === '') {
    return { error: 'Agent, action, effect and resource type are all required.', notice: null };
  }

  // Empty means "everything of this type", which is a real and sometimes
  // correct rule. It is not a mistake to catch here — the form says what it
  // means before you submit it.
  const filter: { type: string; ids?: string[]; prefix?: string } = { type: resourceType };
  if (matchValue !== '') {
    if (matchKind === 'ids') {
      const ids = matchValue
        .split(/[\n,]/)
        .map((id) => id.trim())
        .filter((id) => id !== '');
      if (ids.length === 0) return { error: 'That list had nothing in it.', notice: null };
      filter.ids = ids;
    } else {
      filter.prefix = matchValue;
    }
  }

  const presence = form
    .getAll('presence')
    .map(String)
    .filter((p) => p !== '');
  const rawMax = String(form.get('max_per_day') ?? '').trim();

  const conditions: {
    presence?: string[];
    maxPerDay?: number;
    requireIntent?: boolean;
    schedule?: { from: string; to: string; days?: number[] };
  } = {};
  if (presence.length > 0) conditions.presence = presence;
  if (rawMax !== '') {
    const max = Number(rawMax);
    if (!Number.isInteger(max) || max < 1) {
      // Zero is not a limit, it is a deny, and it should be written as one.
      return { error: 'A daily cap has to be a whole number of 1 or more.', notice: null };
    }
    conditions.maxPerDay = max;
  }
  if (form.get('require_intent') === 'on') conditions.requireIntent = true;

  const from = String(form.get('schedule_from') ?? '').trim();
  const to = String(form.get('schedule_to') ?? '').trim();

  // One without the other is somebody who started typing a window and stopped.
  // Dropping it silently would store a rule that applies at all hours while
  // its author believes it does not.
  if ((from === '') !== (to === '')) {
    return { error: 'A window needs both a start and an end.', notice: null };
  }
  if (from !== '' && from === to) {
    // Passes every pattern and matches nothing, ever.
    return { error: 'A window that starts when it ends never applies.', notice: null };
  }
  if (from !== '') {
    const days = form
      .getAll('schedule_days')
      .map((value) => Number(String(value)))
      .filter((day) => Number.isInteger(day) && day >= 0 && day <= 6);

    // Empty means every day, which is what the API takes — so the key is left
    // off rather than sent as an empty list, which would mean *no* days.
    conditions.schedule = days.length > 0 ? { from, to, days } : { from, to };
  }

  try {
    const rule = await createPolicy(session.credential, {
      subject,
      action,
      effect,
      resource_filter: filter,
      ...(Object.keys(conditions).length === 0 ? {} : { conditions }),
    });
    revalidatePath('/policies');

    return {
      error: null,
      // Never "this agent can now read that" — a rule is one of three layers
      // and the others may still refuse. The wording says what was written,
      // not what will happen.
      notice: `Rule added: ${rule.effect} ${rule.action} on ${rule.resource_filter.type ?? 'anything'}.`,
    };
  } catch (error) {
    return { error: describe(error), notice: null };
  }
}

/**
 * Remove a rule.
 *
 * Deleting an `allow` narrows what is possible. Deleting a `deny` widens it,
 * which is the direction worth being deliberate about — the form makes that one
 * a separate confirmation, and the notice here says which just happened.
 */
export async function deletePolicyAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  const policyId = String(form.get('policy_id') ?? '').trim();
  const effect = String(form.get('effect') ?? '').trim();
  if (policyId === '') return { error: 'No rule selected.', notice: null };

  try {
    await deletePolicy(session.credential, policyId);
    revalidatePath('/policies');

    return {
      error: null,
      notice:
        effect === 'deny'
          ? 'Deny rule removed. Anything it was blocking is now decided by the other rules.'
          : 'Rule removed. Anything it allowed is denied again unless another rule covers it.',
    };
  } catch (error) {
    return { error: describe(error), notice: null };
  }
}

/**
 * Connect an agent to a folder or file.
 *
 * Different from a rule, and the difference is the one that costs an afternoon:
 * a rule says under what conditions, a grant says whether the connection exists
 * at all. Both must say yes.
 */
export async function createGrantAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  const agentId = String(form.get('agent_id') ?? '').trim();
  const resourceType = String(form.get('resource_type') ?? '').trim();
  const resourceKey = String(form.get('resource_key') ?? '').trim();

  if (agentId === '' || resourceType === '' || resourceKey === '') {
    return { error: 'Agent, kind and id are all required.', notice: null };
  }

  if (!/^[A-Za-z0-9_-]+$/.test(resourceKey)) {
    // Caught here so the message can say what is wrong. The API refuses it too,
    // but a 400 from a schema cannot explain that a path is not a Drive id.
    return {
      error:
        'That is not a Google Drive id. Ids are letters, digits, - and _ — a path like /Work will not work.',
      notice: null,
    };
  }

  try {
    await createGrant(session.credential, {
      agent_id: agentId,
      resource_type: resourceType,
      resource_key: resourceKey,
    });
    revalidatePath('/policies');
    return {
      error: null,
      notice: `Connected. The agent can reach ${kindReach(resourceType)} — a rule still decides when.`,
    };
  } catch (error) {
    return { error: describe(error), notice: null };
  }
}

export async function revokeGrantAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  try {
    await revokeGrant(session.credential, {
      agent_id: String(form.get('agent_id') ?? ''),
      resource_type: String(form.get('resource_type') ?? ''),
      resource_key: String(form.get('resource_key') ?? ''),
    });
    revalidatePath('/policies');
    return { error: null, notice: 'Disconnected. That agent can no longer reach it.' };
  } catch (error) {
    return { error: describe(error), notice: null };
  }
}

function describe(error: unknown): string {
  if (error instanceof ApiError) return error.failure.message;
  return 'Something went wrong talking to the control plane.';
}
