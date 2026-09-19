'use server';

import { revalidatePath } from 'next/cache';
import { ApiError, removeLabel, setLabel } from '@/lib/api';
import { currentSession } from '@/lib/session';
import type { ActionState } from '../agents/action-state';

export async function setLabelAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  const pattern = String(form.get('pattern') ?? '').trim();
  const resourceType = String(form.get('resource_type') ?? '').trim();
  const sensitivity = String(form.get('sensitivity') ?? '').trim();
  const note = String(form.get('note') ?? '').trim();

  if (pattern === '' || resourceType === '' || sensitivity === '') {
    return { error: 'Resource type, pattern and level are all required.', notice: null };
  }

  try {
    const label = await setLabel(session.credential, {
      resource_type: resourceType,
      pattern,
      sensitivity,
      exact: form.get('exact') === 'on',
      ...(note === '' ? {} : { note }),
    });
    revalidatePath('/labels');
    return { error: null, notice: `${label.pattern} is now ${label.sensitivity}.` };
  } catch (error) {
    return { error: describe(error), notice: null };
  }
}

/**
 * Removing a label takes protection away. It grants nothing — a resource no
 * rule allows stays denied — but it is still the direction worth confirming, so
 * the control sits behind a disclosure in the UI and the API audits it.
 */
export async function removeLabelAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  const labelId = String(form.get('label_id') ?? '').trim();
  if (labelId === '') return { error: 'No label selected.', notice: null };

  try {
    await removeLabel(session.credential, labelId);
    revalidatePath('/labels');
    return { error: null, notice: 'Label removed. The resource keeps whatever its rules already say.' };
  } catch (error) {
    return { error: describe(error), notice: null };
  }
}

function describe(error: unknown): string {
  if (error instanceof ApiError) return error.failure.message;
  return 'Something went wrong talking to the control plane.';
}
