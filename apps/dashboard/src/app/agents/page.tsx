import { redirect } from 'next/navigation';
import { Panel } from '@/components/panel';
import { ConnectSnippet } from './connect-snippet';
import { Chip, type Tone } from '@/components/chip';
import { ApiError, listAgents, type Agent } from '@/lib/api';
import { currentSession } from '@/lib/session';
import { RegisterForm } from './register-form';
import { RevokeControl } from './revoke-control';

// Authorization state is read fresh on every request. A cached agent list could
// show a revoked agent as active, which is the one direction that must not
// happen (invariant 1).
export const dynamic = 'force-dynamic';

const STATUS_TONE: Record<Agent['status'], Tone> = {
  active: 'allow',
  suspended: 'challenge',
  revoked: 'deny',
};

export default async function AgentsPage() {
  const session = await currentSession();
  // One place to land when there is no session, shared with every failed
  // sign-in, so the product has a single answer to "you are not signed in".
  if (!session) redirect('/signed-out');

  let agents: Agent[];
  try {
    agents = (await listAgents(session.credential)).agents;
  } catch (error) {
    return <Unavailable detail={error instanceof ApiError ? error.failure.message : null} />;
  }

  const live = agents.filter((a) => a.status !== 'revoked').length;

  return (
    <>
      <Panel title="AGENTS" meta="IDENTITY / 001">
        <div style={{ padding: '22px 18px 8px' }}>
          <p className="path" style={{ margin: '0 0 14px' }}>
            ~/{session.workspaceId}/agents
          </p>
          <h1 className="headline" style={{ fontSize: 34 }}>
            {live} live {live === 1 ? 'agent' : 'agents'}
            <span style={{ color: 'var(--text-faint)' }}> · {agents.length} total</span>
          </h1>
          <p style={{ color: 'var(--text-dim)', maxWidth: 620, marginTop: 12, fontSize: 12.5 }}>
            Every identity registered in this workspace. Registering an agent grants it nothing —
            it can act only once a connection and policy attach to it.
          </p>

          <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginTop: 16 }}>
            <span style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>
              signed in as {session.userId}
            </span>
            {/* POST, so no third-party page can sign the user out by linking. */}
            <form action="/logout" method="post">
              <button
                type="submit"
                style={{
                  font: 'inherit',
                  fontSize: 11.5,
                  background: 'none',
                  border: 0,
                  padding: 0,
                  color: 'var(--text-dim)',
                  cursor: 'pointer',
                  borderBottom: '1px dotted var(--border-strong)',
                }}
              >
                sign out
              </button>
            </form>
          </div>
        </div>

        {agents.length === 0 ? (
          <div
            style={{
              margin: '4px 18px 22px',
              padding: '20px 18px',
              border: '1px dashed var(--border-strong)',
              color: 'var(--text-faint)',
              fontSize: 12.5,
            }}
          >
            No agents registered yet. Register one below — it starts with no access at all.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
              <caption className="label" style={{ textAlign: 'left', padding: '10px 18px 6px' }}>
                Registered agents
              </caption>
              <thead>
                <tr style={{ borderTop: '1px solid var(--border)' }}>
                  {['', 'agent', 'client', 'provider', 'status', 'registered', ''].map((h, i) => (
                    <th
                      key={i}
                      scope="col"
                      className="label"
                      style={{ textAlign: 'left', padding: '10px 14px', fontWeight: 400 }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {agents.map((agent, index) => (
                  <tr key={agent.id} style={{ borderTop: '1px solid var(--border)' }}>
                    <td style={{ padding: '12px 14px', color: 'var(--text-faint)', width: 40 }}>
                      {String(index + 1).padStart(2, '0')}
                    </td>
                    <th
                      scope="row"
                      style={{ padding: '12px 14px', textAlign: 'left', fontWeight: 400 }}
                    >
                      {agent.id}
                    </th>
                    <td style={{ padding: '12px 14px' }}>{agent.client_id}</td>
                    <td style={{ padding: '12px 14px', color: 'var(--text-dim)' }}>
                      {agent.provider}
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      <Chip tone={STATUS_TONE[agent.status]}>{agent.status}</Chip>
                    </td>
                    <td style={{ padding: '12px 14px', color: 'var(--text-dim)' }}>
                      <time dateTime={agent.created_at}>{agent.created_at.slice(0, 10)}</time>
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      <RevokeControl agentId={agent.id} disabled={agent.status === 'revoked'} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {live > 0 ? (
        <Panel title="CONNECT" meta="POINT A CLIENT AT THIS WORKSPACE">
          <ConnectSnippet
            agents={agents
              .filter((a) => a.status !== 'revoked')
              .map((a) => ({ id: a.id, clientId: a.client_id }))}
            // The same address the gateway publishes, so a pasted config and a
            // discovered one point at one place. Nothing else is needed: which
            // agent a client acts as is chosen on the approval screen.
            gatewayUrl={`${(process.env['GATEWAY_PUBLIC_URL'] ?? 'http://localhost:4100').replace(/\/$/, '')}/mcp`}
          />
        </Panel>
      ) : null}

      <Panel title="REGISTER" meta="NEW IDENTITY">
        <RegisterForm />
      </Panel>
    </>
  );
}

function Unavailable({ detail }: { detail: string | null }) {
  return (
    <Panel title="UNAVAILABLE" meta="CONTROL PLANE">
      <div style={{ padding: 22, display: 'grid', gap: 12 }}>
        <h1 className="headline" style={{ fontSize: 26 }}>
          Cannot reach the control plane.
        </h1>
        <p style={{ color: 'var(--text-dim)', maxWidth: 560, fontSize: 12.5, margin: 0 }}>
          {detail ?? 'The API did not answer.'} Nothing is shown rather than a stale list — an
          agent list that cannot be verified is worse than none.
        </p>
      </div>
    </Panel>
  );
}
