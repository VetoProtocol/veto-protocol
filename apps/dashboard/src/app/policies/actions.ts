'use server';

import { revalidatePath } from 'next/cache';
import { ApiError, createPolicy, deletePolicy } from '@/lib/api';
import { currentSession } from '@/lib/session';
import type { ActionState } from '../agents/action-state';

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

  const conditions: { presence?: string[]; maxPerDay?: number; requireIntent?: boolean } = {};
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

function describe(error: unknown): string {
  if (error instanceof ApiError) return error.failure.message;
  return 'Something went wrong talking to the control plane.';
}
