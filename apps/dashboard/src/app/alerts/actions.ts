'use server';

import { revalidatePath } from 'next/cache';
import { ApiError, createEndpoint, disableEndpoint, drainDeliveries } from '@/lib/api';
import { currentSession } from '@/lib/session';
import type { AlertState } from './state';

export async function createEndpointAction(
  _previous: AlertState,
  form: FormData,
): Promise<AlertState> {
  const session = await currentSession();
  if (!session) return fail('Your session has expired. Sign in again.');

  const url = String(form.get('url') ?? '').trim();
  const events = form
    .getAll('events')
    .map(String)
    .filter((e) => e !== '');

  if (url === '') return fail('An endpoint needs a URL.');
  if (events.length === 0) {
    // Not a default. An endpoint subscribed to everything because nobody chose
    // is an endpoint that will be ignored within a week.
    return fail('Choose at least one event. Subscribing to nothing would send nothing.');
  }

  try {
    const created = await createEndpoint(session.credential, { url, events });
    revalidatePath('/alerts');

    return {
      error: null,
      notice: `Endpoint added for ${created.events.length} event${created.events.length === 1 ? '' : 's'}.`,
      // The one and only time this value is available. It is not stored here,
      // not logged, and there is no route that reads it back.
      secret: created.secret,
    };
  } catch (error) {
    return fail(describe(error));
  }
}

export async function disableEndpointAction(
  _previous: AlertState,
  form: FormData,
): Promise<AlertState> {
  const session = await currentSession();
  if (!session) return fail('Your session has expired. Sign in again.');

  const endpointId = String(form.get('endpoint_id') ?? '').trim();
  if (endpointId === '') return fail('No endpoint selected.');

  try {
    await disableEndpoint(session.credential, endpointId);
    revalidatePath('/alerts');
    return {
      error: null,
      // Disabled, not deleted — "this endpoint used to receive your security
      // alerts" is a fact worth keeping after somebody turns it off.
      notice: 'Stopped. The endpoint stays on the list, receiving nothing.',
      secret: null,
    };
  } catch (error) {
    return fail(describe(error));
  }
}

/**
 * Run the delivery worker now.
 *
 * There is no scheduler in this deployment, so queued events sit until
 * something runs them. A button is honest about that; a page that silently
 * drained on every render would make "why has nothing arrived" unanswerable.
 *
 * Declared with no parameters on purpose. `useActionState` passes the previous
 * state and the form data, and a function that takes neither is assignable to
 * that signature — which is more honest than naming two arguments this action
 * has no use for.
 */
export async function drainAction(): Promise<AlertState> {
  const session = await currentSession();
  if (!session) return fail('Your session has expired. Sign in again.');

  try {
    const result = await drainDeliveries(session.credential);
    revalidatePath('/alerts');

    if (result.attempted === 0) {
      return { error: null, notice: 'Nothing was waiting.', secret: null };
    }

    const parts = [
      result.delivered > 0 ? `${result.delivered} delivered` : null,
      result.retrying > 0 ? `${result.retrying} will be retried` : null,
      result.failed > 0 ? `${result.failed} gave up` : null,
    ].filter((part): part is string => part !== null);

    return { error: null, notice: `${parts.join(', ')}.`, secret: null };
  } catch (error) {
    return fail(describe(error));
  }
}

const fail = (error: string): AlertState => ({ error, notice: null, secret: null });

function describe(error: unknown): string {
  if (error instanceof ApiError) return error.failure.message;
  return 'Something went wrong talking to the control plane.';
}
