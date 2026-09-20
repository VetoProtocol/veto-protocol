'use server';

import { redirect } from 'next/navigation';
import { oauthServerCredential } from '@/lib/oauth-config';
import { currentSession } from '@/lib/session';
import type { ActionState } from '../agents/action-state';

const CONTROL_PLANE = process.env['VETO_API_URL'] ?? 'http://127.0.0.1:4000';

/**
 * Approve an authorization, and send the client its code.
 *
 * ## Everything decided here, nothing at the exchange
 *
 * The workspace, the human and the agent are read from the *session* and the
 * form, and written into the code. The client never gets to influence them, and
 * nothing is re-derived when the code is redeemed — because the client is
 * precisely who must not be able to change what was approved between the screen
 * and the exchange.
 *
 * ## The approving human is the delegating human
 *
 * §7.1 requires the approver to be the original delegator. Here that holds by
 * construction: the session is the only source of the human id, so a screen
 * approved by one person cannot authorize an agent on behalf of another. The
 * control plane checks the agent's owner again anyway, because a check that
 * only holds by construction stops holding the moment somebody restructures the
 * construction.
 */
export async function approveAuthorizationAction(
  _previous: ActionState,
  form: FormData,
): Promise<ActionState> {
  const session = await currentSession();
  if (!session) return { error: 'Your session has expired. Sign in again.', notice: null };

  const agentId = String(form.get('agent_id') ?? '').trim();
  const clientId = String(form.get('client_id') ?? '').trim();
  const redirectUri = String(form.get('redirect_uri') ?? '').trim();
  const codeChallenge = String(form.get('code_challenge') ?? '').trim();
  const resource = String(form.get('resource') ?? '').trim();
  const rawState = String(form.get('state') ?? '');

  if (agentId === '') return { error: 'Choose which agent this is for.', notice: null };

  const response = await fetch(`${CONTROL_PLANE}/v1/oauth/codes`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${oauthServerCredential()}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      workspace_id: session.workspaceId,
      user_id: session.userId,
      agent_id: agentId,
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: codeChallenge,
      resource,
    }),
    signal: AbortSignal.timeout(10_000),
  }).catch(() => null);

  if (response === null) {
    return { error: 'The control plane could not be reached. Nothing was approved.', notice: null };
  }

  const payload = (await response.json().catch(() => ({}))) as Record<string, unknown>;

  if (!response.ok) {
    // Reported on this page rather than redirected. A refusal here means the
    // agent is revoked or not this human's, and the person who needs to know
    // that is the one looking at the screen — not the client waiting for a code.
    const detail = (payload['error'] as { message?: string } | undefined)?.message;
    return { error: detail ?? 'That authorization was refused.', notice: null };
  }

  const target = new URL(redirectUri);
  target.searchParams.set('code', String(payload['code']));
  // Echoed exactly as received. The client uses it to bind this response to its
  // own request, which is its CSRF defence and not ours to alter.
  if (rawState !== '') target.searchParams.set('state', rawState);

  // Throws, by design — `redirect` is how a server action leaves the page.
  redirect(target.href);
}
