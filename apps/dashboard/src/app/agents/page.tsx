import { Panel } from '@/components/panel';
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
  if (!session) return <SignedOut />;

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
        </div>

        {agents.length === 0 ? (
          <p style={{ padding: '4px 18px 24px', color: 'var(--text-faint)' }}>
            No agents registered yet.
          </p>
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

      <Panel title="REGISTER" meta="NEW IDENTITY">
        <RegisterForm />
      </Panel>
    </>
  );
}

function SignedOut() {
  return (
    <Panel title="SIGN IN" meta="IDENTITY REQUIRED">
      <div style={{ padding: 22, display: 'grid', gap: 12 }}>
        <p className="path" style={{ margin: 0 }}>
          ~/auth
        </p>
        <h1 className="headline" style={{ fontSize: 28 }}>
          You are not signed in.
        </h1>
        <p style={{ color: 'var(--text-dim)', maxWidth: 560, fontSize: 12.5, margin: 0 }}>
          The dashboard reads and changes authorization state, so it shows nothing without a
          verified identity. OIDC sign-in is the next piece of this phase; until it lands there is
          no way to obtain a session, which is the correct behaviour rather than a placeholder.
        </p>
      </div>
    </Panel>
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
