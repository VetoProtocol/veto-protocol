'use server';

/**
 * Recording that the signed-in person agreed.
 *
 * A `'use server'` module may export only async functions — every export
 * becomes a callable endpoint, and a constant beside the actions is refused at
 * runtime rather than at build time. So there is exactly one thing here.
 *
 * The action takes no arguments. Which documents are in force, and at which
 * version, is the control plane's answer — the browser posts that it agrees,
 * not what it is agreeing to. There is nothing here a caller could forge.
 */

import { revalidatePath } from 'next/cache';
import { acceptLegal } from '@/lib/api';
import { currentSession } from '@/lib/session';

export async function acceptLegalAction(): Promise<{ ok: boolean; error: string | null }> {
  const session = await currentSession();
  if (!session) return { ok: false, error: 'Your session has expired. Sign in again.' };

  try {
    await acceptLegal(session.credential);
  } catch {
    // Deliberately not specific. The only useful action is to try again, and
    // the failure detail belongs in the server log rather than a dialogue a
    // person cannot dismiss.
    return { ok: false, error: 'That could not be recorded. Please try again.' };
  }

  // The layout reads acceptance on every render, so the gate lifts everywhere
  // at once rather than on the next navigation.
  revalidatePath('/', 'layout');
  return { ok: true, error: null };
}
