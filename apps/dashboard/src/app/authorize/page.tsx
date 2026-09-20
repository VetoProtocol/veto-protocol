import { redirect } from 'next/navigation';
import { Panel } from '@/components/panel';
import { listAgents } from '@/lib/api';
import { currentSession } from '@/lib/session';
import { oauthServerCredential } from '@/lib/oauth-config';
import { ApproveForm } from './approve-form';
import { errorRedirect, validateAuthorize, type AuthorizeClient } from './validate';

export const dynamic = 'force-dynamic';

const CONTROL_PLANE = process.env['VETO_API_URL'] ?? 'http://127.0.0.1:4000';

async function loadClient(clientId: string): Promise<AuthorizeClient | null> {
  if (!/^oac_[A-Za-z0-9_-]{1,64}$/.test(clientId)) return null;

  const response = await fetch(
    `${CONTROL_PLANE}/v1/oauth/clients/${encodeURIComponent(clientId)}`,
    {
      headers: { authorization: `Bearer ${oauthServerCredential()}` },
      signal: AbortSignal.timeout(10_000),
      cache: 'no-store',
    },
  ).catch(() => null);

  if (response === null || !response.ok) return null;
  const body = (await response.json().catch(() => null)) as {
    client_id?: string;
    client_name?: string;
    redirect_uris?: string[];
  } | null;
  if (!body?.client_id) return null;

  return {
    id: body.client_id,
    clientName: body.client_name ?? body.client_id,
    redirectUris: body.redirect_uris ?? [],
  };
}

/**
 * The consent screen.
 *
 * ## The sentence this page exists to get right
 *
 * "This app will read your Drive" would be a lie. The app will be able to
 * *ask*, and every ask is decided again, at the moment it is made, against
 * policy, presence and a lock the person can pull. Saying otherwise would sell
 * the product as the thing it was built not to be.
 *
 * So the screen says what approving actually does, and says plainly what it
 * does not do. A person who reads it and later sees a denial should find the
 * denial unsurprising.
 *
 * ## Two kinds of refusal
 *
 * An unknown client or an unregistered redirect URI is refused *here*, on the
 * page, with nothing sent anywhere. Redirecting an error to a URI that has not
 * been validated is an open redirect, and an open redirect on an authorization
 * endpoint is a way to deliver somebody else's code. Everything past that point
 * is reported to the client, because by then the target has earned it.
 */
export default async function AuthorizePage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const raw = await searchParams;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(raw)) {
    // A repeated parameter is ambiguous and a classic way to make a server and
    // a client read different values from one URL. First wins, and only one.
    if (typeof value === 'string') params.set(key, value);
    else if (Array.isArray(value) && value[0] !== undefined) params.set(key, value[0]);
  }

  const clientId = params.get('client_id') ?? '';
  const client = await loadClient(clientId);
  const checked = validateAuthorize(params, client);

  if (checked.kind === 'fatal') {
    return (
      <Panel title="AUTHORIZATION REFUSED" meta="§8 / OAUTH">
        <div style={{ padding: 22, maxWidth: 620 }}>
          <p style={{ margin: '0 0 12px', fontSize: 13 }}>
            {checked.reason === 'CLIENT_UNKNOWN'
              ? 'That application is not registered with this server.'
              : 'That application asked to be sent somewhere it has not registered.'}
          </p>
          <p style={{ margin: 0, color: 'var(--text-dim)', fontSize: 12, lineHeight: 1.7 }}>
            Nothing was sent anywhere, and nothing was approved. This page will not redirect to an
            address the application did not register beforehand &mdash; that is how an
            authorization code ends up delivered to somebody else.
          </p>
        </div>
      </Panel>
    );
  }

  if (checked.kind === 'redirect') {
    redirect(
      errorRedirect(
        params.get('redirect_uri') ?? '',
        params.get('state'),
        checked.error,
        checked.description,
      ),
    );
  }

  // Signing in has to come after the client and redirect URI are validated:
  // bouncing an unvalidated request through a login is a way to have somebody
  // authenticate into somebody else's flow.
  const session = await currentSession();
  // A flag from a closed set, never a URL to return to. Implementing a `next`
  // redirect is where open redirects come from, and the previous version passed
  // one that nothing consumed — so a signed-out user was silently dropped on
  // the dashboard while the client waited for a code that was never coming.
  //
  // Resuming the request after sign-in would be better and is not free: it
  // means holding the authorization parameters in a signed cookie across the
  // OIDC round trip. Until then the screen says what to do instead of
  // pretending it happened.
  if (!session) redirect('/signed-out?reason=authorize');

  const agents = (await listAgents(session.credential)).agents.filter(
    (agent) => agent.status !== 'revoked',
  );

  const { request } = checked;

  return (
    <Panel title="APPROVE ACCESS" meta="§8 / OAUTH">
      <div style={{ padding: '22px 18px', maxWidth: 680 }}>
        <p className="path" style={{ margin: '0 0 14px' }}>
          ~/{session.workspaceId}/authorize
        </p>

        <h1 className="headline" style={{ fontSize: 24, margin: '0 0 14px' }}>
          {client?.clientName} wants to connect
        </h1>

        <p style={{ color: 'var(--text-dim)', fontSize: 13, lineHeight: 1.75, margin: '0 0 8px' }}>
          Approving lets it <strong style={{ color: 'var(--text)' }}>ask</strong> Veto for things on
          your behalf. It does not grant access to anything.
        </p>
        <p style={{ color: 'var(--text-dim)', fontSize: 13, lineHeight: 1.75, margin: '0 0 20px' }}>
          Every request it makes is decided when it is made &mdash; against your policies, your
          presence, and the connections you have attached. You can revoke this at any time, and a
          revocation takes effect on its next request.
        </p>

        {/* The name is self-declared and could be anybody's. Saying so is the
            only honest defence against a client that names itself after this
            product; a filter on the name would move the problem somewhere it
            cannot be solved. */}
        <div
          style={{
            border: '1px solid var(--border)',
            background: 'var(--bg-raised)',
            padding: '14px 16px',
            marginBottom: 22,
            fontSize: 11.5,
            lineHeight: 1.7,
            color: 'var(--text-faint)',
          }}
        >
          <div style={{ marginBottom: 6 }}>
            <span style={{ color: 'var(--text-dim)' }}>it will be sent back to</span>{' '}
            <code style={{ color: 'var(--text)', wordBreak: 'break-all' }}>
              {request.redirectUri}
            </code>
          </div>
          <div>
            The name above is what the application calls itself. Check the address is one you
            expect before approving.
          </div>
        </div>

        {agents.length === 0 ? (
          <p style={{ color: 'var(--challenge)', fontSize: 12.5 }}>
            You have no active agents. Register one first, then start this again.
          </p>
        ) : (
          <ApproveForm
            agents={agents.map((agent) => ({ id: agent.id, clientId: agent.client_id }))}
            clientId={request.clientId}
            redirectUri={request.redirectUri}
            codeChallenge={request.codeChallenge}
            resource={request.resource}
            state={request.state}
          />
        )}
      </div>
    </Panel>
  );
}
