'use server';

import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { cookieOptions } from '@/lib/cookie-options';
import { sessionCredential, SESSION_TTL_MS } from '@/lib/credential';
import { PENDING_COOKIE, openPending } from '@/lib/pending-cookie';
import { SESSION_COOKIE, signSession } from '@/lib/session';
import type { ActionState } from '../agents/action-state';

/**
 * Sign in to one of the workspaces this subject actually belongs to.
 *
 * The posted `workspace_id` is a value from a form, which means it is a value
 * from a stranger. It is never used directly — it is *matched* against the
 * sealed candidate list the sign-in lookup produced, and the session is built
 * from the entry that matched. A workspace id nobody offered finds nothing.
 *
 * That distinction is the whole file. `workspace_id` is the tenant selector for
 * every query in the system, so accepting the posted value and trusting it
 * would be handing the caller their own choice of tenant.
 */
export async function chooseWorkspaceAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const jar = await cookies();
  const sealed = jar.get(PENDING_COOKIE)?.value;
  const pending = sealed ? openPending(sealed) : null;

  if (!pending) {
    return {
      error: 'That took too long, or the page was opened on its own. Sign in again to start over.',
      notice: null,
    };
  }

  const wanted = String(form.get('workspace_id') ?? '');
  const chosen = pending.candidates.find((c) => c.workspaceId === wanted);

  if (!chosen) {
    // Not "no such workspace" — that would confirm whether one exists. They
    // were offered a list and picked something that was not on it.
    return { error: 'That is not one of your workspaces.', notice: null };
  }

  jar.set(
    SESSION_COOKIE,
    signSession({
      workspaceId: chosen.workspaceId,
      userId: chosen.userId,
      credential: sessionCredential(chosen.workspaceId, chosen.userId),
      expiresAt: Date.now() + SESSION_TTL_MS,
    }),
    { ...cookieOptions(), maxAge: Math.floor(SESSION_TTL_MS / 1000) },
  );
  jar.delete(PENDING_COOKIE);

  // Outside any try: `redirect` throws by design.
  redirect('/agents');
}
