'use server';

import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { ApiError, provisionWorkspace } from '@/lib/api';
import { cookieOptions } from '@/lib/cookie-options';
import { resolveCredential, sessionCredential, SESSION_TTL_MS } from '@/lib/credential';
import { PENDING_COOKIE, openPending } from '@/lib/pending-cookie';
import { SESSION_COOKIE, signSession } from '@/lib/session';
import type { ActionState } from '../agents/action-state';

/**
 * Create the workspace, then sign them in.
 *
 * The subject comes from the signed cookie and from nowhere else. That is the
 * whole security story of this file: the form posts a workspace *name*, and a
 * name is the only thing a visitor gets to choose. Which human this is about
 * was settled by the id token the OIDC callback verified.
 */
export async function createWorkspaceAction(
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

  const name = String(form.get('workspace_name') ?? '').trim();
  if (name === '') return { error: 'Give the workspace a name.', notice: null };
  if (name.length > 120) {
    return { error: 'That name is too long — 120 characters at most.', notice: null };
  }

  let created: { user_id: string; workspace_id: string };
  try {
    created = await provisionWorkspace(resolveCredential(), {
      subject: pending.subject,
      workspace_name: name,
    });
  } catch (error) {
    if (error instanceof ApiError && error.failure.status === 409) {
      // Somebody already knows this subject — a second tab, or an invitation
      // that arrived while this page was open. Signing in again finds it, which
      // is better than making a second identity for one human.
      return {
        error: 'That account already has a workspace. Sign in again and it will find it.',
        notice: null,
      };
    }
    return {
      error:
        error instanceof ApiError
          ? error.failure.message
          : 'Something went wrong talking to the control plane.',
      notice: null,
    };
  }

  // Straight into a session. Making somebody sign in a second time immediately
  // after proving who they are is friction with no security behind it — the id
  // token was verified minutes ago and the subject has not changed hands.
  jar.set(
    SESSION_COOKIE,
    signSession({
      workspaceId: created.workspace_id,
      userId: created.user_id,
      credential: sessionCredential(created.workspace_id, created.user_id),
      expiresAt: Date.now() + SESSION_TTL_MS,
    }),
    { ...cookieOptions(), maxAge: Math.floor(SESSION_TTL_MS / 1000) },
  );
  jar.delete(PENDING_COOKIE);

  // Outside the try: `redirect` works by throwing, and catching it here would
  // turn a successful signup into an error message.
  redirect('/agents');
}
