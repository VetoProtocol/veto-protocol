/**
 * Shadow Agents — what reaches your accounts without passing through Veto.
 *
 * Every other screen in this product reports on traffic Veto saw. This one
 * reports on the gap: an AI tool wired straight into the company Drive is
 * invisible everywhere else, and those screens stay green while it happens.
 *
 * ## The one thing this page must never do
 *
 * Say "nothing found" when it means "nobody looked".
 *
 * Reading the list needs administrative access a connection may not have —
 * Google's is Workspace-admin only, GitHub's is organisation-scoped — so the
 * common case today is that we cannot see. An empty table would read as
 * all-clear, which is the reassurance somebody acts on and stops checking.
 *
 * So `unavailable` renders as a refusal with a reason and a next step, in the
 * deny tone, and never as an empty list.
 */

import { redirect } from 'next/navigation';
import { Panel } from '@/components/panel';
import { Chip } from '@/components/chip';
import { ApiError, listShadowAgents, type ShadowProviderView } from '@/lib/api';
import { currentSession } from '@/lib/session';

export const dynamic = 'force-dynamic';

const cell: React.CSSProperties = {
  padding: '11px 14px 11px 0',
  borderBottom: '1px solid var(--border)',
  fontSize: 12,
  verticalAlign: 'top',
};

const head: React.CSSProperties = {
  textAlign: 'left',
  padding: '0 14px 6px 0',
  borderBottom: '1px solid var(--text)',
  fontSize: 9,
  letterSpacing: '0.14em',
  textTransform: 'uppercase',
  color: 'var(--text-dim)',
  fontWeight: 600,
};

const PROVIDER_NAME: Record<string, string> = {
  google: 'Google',
  github: 'GitHub',
};

/** Each reason is a different conversation, so each gets its own sentence. */
const WHY: Record<string, { what: string; next: string }> = {
  not_configured: {
    what: 'Veto has not been given a way to read this account’s app list.',
    next: 'Connect an administrator account for this provider.',
  },
  no_admin_scope: {
    what: 'The connected account can read your data but cannot see who else can.',
    next: 'Reconnect with an administrator who can read the account’s security settings.',
  },
  not_a_workspace_account: {
    what: 'This is a personal Google account. The app list is a Workspace feature.',
    next: 'Connect a Google Workspace account to see this.',
  },
  not_an_organization: {
    what: 'This is a personal GitHub account. The audit surface belongs to organisations.',
    next: 'Install the GitHub App on an organisation to see this.',
  },
  provider_unavailable: {
    what: 'The provider did not answer when we asked.',
    next: 'This is usually temporary. Try again shortly.',
  },
};

function Unavailable({ provider }: { provider: ShadowProviderView }) {
  const why = WHY[provider.reason ?? ''] ?? {
    what: 'This account could not be read.',
    next: 'Check the connection.',
  };

  return (
    <div
      style={{
        margin: '4px 18px 22px',
        padding: '16px 18px',
        border: '1px solid var(--deny)',
        background: 'var(--deny-bg)',
      }}
    >
      <p style={{ margin: 0, color: 'var(--deny)', fontSize: 12.5, fontWeight: 600 }}>
        Nobody looked — this is not a clean bill of health.
      </p>
      <p style={{ margin: '8px 0 0', color: 'var(--text-dim)', fontSize: 12.5, lineHeight: 1.7 }}>
        {why.what} Until that changes, Veto cannot tell you whether anything else reaches this
        account, and an empty list here would be a guess.
      </p>
      <p style={{ margin: '8px 0 0', color: 'var(--text)', fontSize: 12.5 }}>{why.next}</p>
    </div>
  );
}

export default async function ShadowPage() {
  const session = await currentSession();
  if (!session) redirect('/signed-out');

  let view;
  try {
    view = await listShadowAgents(session.credential);
  } catch (error) {
    if (error instanceof ApiError && error.failure.status === 402) {
      return (
        <Panel title="SHADOW AGENTS" meta="PRO">
          <div
            style={{
              padding: '20px 22px 24px',
              color: 'var(--text-dim)',
              fontSize: 12.5,
              lineHeight: 1.75,
              maxWidth: 620,
            }}
          >
            <p style={{ margin: '0 0 10px', color: 'var(--text)' }}>
              Find the agents that never came through Veto.
            </p>
            <p style={{ margin: '0 0 10px' }}>
              Veto only sees what passes through it. Anything wired straight into your Google or
              GitHub account is invisible on every other screen here — and those screens stay
              green while it happens.
            </p>
            <p style={{ margin: 0 }}>Part of the Pro plan for this workspace.</p>
          </div>
        </Panel>
      );
    }

    return (
      <Panel title="UNAVAILABLE" meta="CONTROL PLANE">
        <div style={{ padding: 22, color: 'var(--text-dim)', fontSize: 12.5 }}>
          {error instanceof ApiError ? error.failure.message : 'The API did not answer.'}
        </div>
      </Panel>
    );
  }

  const blind = view.providers.filter((p) => p.state === 'unavailable').length;

  return (
    <>
      <div>
        <p className="path" style={{ margin: '0 0 12px' }}>
          ~/{session.workspaceId}/shadow
        </p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
          <h1 className="headline" style={{ fontSize: 30, margin: 0 }}>
            {view.shadow_count === null
              ? 'Partial view'
              : `${String(view.shadow_count)} outside Veto`}
          </h1>
          {blind > 0 ? (
            <Chip tone="deny">{`${String(blind)} account${blind === 1 ? '' : 's'} unreadable`}</Chip>
          ) : (
            <Chip tone="allow">every account read</Chip>
          )}
        </div>

        <p style={{ color: 'var(--text-dim)', maxWidth: 680, marginTop: 12, fontSize: 12.5, lineHeight: 1.7 }}>
          Every other screen here reports on traffic Veto decided. This one reports on the gap:
          which other applications hold standing access to the same accounts.
        </p>
        <p style={{ color: 'var(--text-faint)', maxWidth: 680, marginTop: 8, fontSize: 11.5, lineHeight: 1.7 }}>
          <strong style={{ color: 'var(--text-dim)' }}>This lists who can, not who did.</strong> An
          application here may never have touched anything. Reading it needs administrative access
          to the provider, and where we do not have that, this page says so rather than showing an
          empty table — &ldquo;nobody looked&rdquo; and &ldquo;nothing found&rdquo; are different
          answers and only one of them is reassuring.
        </p>
      </div>

      {view.providers.map((provider) => (
        <Panel
          key={provider.provider}
          title={(PROVIDER_NAME[provider.provider] ?? provider.provider).toUpperCase()}
          meta={provider.state === 'read' ? 'READ' : 'NOT READ'}
        >
          {provider.state === 'unavailable' ? (
            <Unavailable provider={provider} />
          ) : provider.apps.length === 0 ? (
            <div style={{ padding: '18px', color: 'var(--text-dim)', fontSize: 12.5 }}>
              Read successfully. Nothing at all holds access to this account — not even Veto, which
              is worth a second look at the connection.
            </div>
          ) : (
            <div style={{ margin: '12px 18px 20px', overflowX: 'auto' }}>
              <table style={{ borderCollapse: 'collapse', width: '100%', minWidth: 560 }}>
                <thead>
                  <tr>
                    <th style={head}>application</th>
                    <th style={head}>reaches</th>
                    <th style={head}>through veto</th>
                  </tr>
                </thead>
                <tbody>
                  {provider.apps.map((item) => (
                    <tr key={item.app_id}>
                      <td style={{ ...cell, color: 'var(--text)' }}>
                        {item.display_name}
                        <div style={{ color: 'var(--text-faint)', fontSize: 10.5, marginTop: 3 }}>
                          {item.app_id}
                        </div>
                      </td>
                      <td style={{ ...cell, color: 'var(--text-dim)' }}>
                        {item.reaches_protected_data ? item.scopes.join(', ') : 'nothing protected'}
                      </td>
                      <td style={cell}>
                        {item.is_veto ? (
                          <Chip tone="allow">yes</Chip>
                        ) : item.reaches_protected_data ? (
                          <Chip tone="deny">no</Chip>
                        ) : (
                          <Chip tone="neutral">no — harmless</Chip>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      ))}
    </>
  );
}
