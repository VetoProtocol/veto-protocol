import { redirect } from 'next/navigation';
import { Nav } from '@/components/nav';
import { Panel } from '@/components/panel';
import { Chip, type Tone } from '@/components/chip';
import { ApiError, listAgents, listPolicies, type PolicyView } from '@/lib/api';
import { currentSession } from '@/lib/session';
import { CreatePolicyForm, DeletePolicy } from './forms';

export const dynamic = 'force-dynamic';

const TONE: Record<PolicyView['effect'], Tone> = {
  allow: 'allow',
  challenge: 'challenge',
  deny: 'deny',
};

/** Deny beats challenge beats allow — the order the matcher resolves them in. */
const RANK: Record<PolicyView['effect'], number> = { deny: 3, challenge: 2, allow: 1 };

function describeFilter(filter: PolicyView['resource_filter']): string {
  const type = filter.type ?? 'anything';
  if (filter.ids !== undefined) {
    return filter.ids.length === 1
      ? `${type} · ${filter.ids[0]}`
      : `${type} · ${filter.ids.length} named items`;
  }
  if (filter.prefix !== undefined) return `${type} · ${filter.prefix} and below`;
  return `${type} · every one`;
}

function describeConditions(conditions: PolicyView['conditions']): string[] {
  const parts: string[] = [];
  if (conditions.presence !== undefined && conditions.presence.length > 0) {
    parts.push(`only when ${conditions.presence.join(' or ')}`);
  }
  if (conditions.maxPerDay !== undefined) parts.push(`max ${conditions.maxPerDay}/day`);
  if (conditions.requireIntent === true) parts.push('must state a purpose');
  return parts;
}

export default async function PoliciesPage() {
  const session = await currentSession();
  if (!session) redirect('/signed-out');

  let policies: PolicyView[];
  let agents: Array<{ id: string; client_id: string; status: string }>;
  try {
    [policies, agents] = await Promise.all([
      listPolicies(session.credential).then((r) => r.policies),
      listAgents(session.credential).then((r) => r.agents),
    ]);
  } catch (error) {
    return (
      <>
        <Nav active="policies" />
        <Panel title="UNAVAILABLE" meta="CONTROL PLANE">
          <div style={{ padding: 22, color: 'var(--text-dim)', fontSize: 12.5 }}>
            {error instanceof ApiError ? error.failure.message : 'The API did not answer.'}
          </div>
        </Panel>
      </>
    );
  }

  // Most restrictive first, which is the order that decides. Showing allows at
  // the top would suggest the first match wins, and it does not.
  const ordered = [...policies].sort((a, b) => RANK[b.effect] - RANK[a.effect]);

  const live = agents.filter((a) => a.status === 'active');
  const allows = policies.filter((p) => p.effect === 'allow').length;

  return (
    <>
      <Nav active="policies" />

      <Panel title="POLICIES" meta="THE RULES THAT DECIDE / §3.3 STEP 4">
        <div style={{ padding: '22px 18px 18px' }}>
          <p className="path" style={{ margin: '0 0 12px' }}>
            ~/{session.workspaceId}/policies
          </p>
          <h1 className="headline" style={{ fontSize: 30 }}>
            {policies.length} {policies.length === 1 ? 'rule' : 'rules'}
            <span style={{ color: 'var(--text-faint)' }}> · {allows} can allow</span>
          </h1>

          {policies.length === 0 ? (
            <p
              role="status"
              style={{
                margin: '18px 0 0',
                padding: '12px 14px',
                border: '1px solid var(--deny)',
                background: 'var(--deny-bg)',
                color: 'var(--deny)',
                fontSize: 12.5,
                maxWidth: 660,
              }}
            >
              <strong>Everything is being denied right now.</strong> No rule means no permission —
              that is the correct starting state, not a misconfiguration. Nothing an agent asks for
              will succeed until a rule below says otherwise.
            </p>
          ) : null}

          <p style={{ color: 'var(--text-dim)', maxWidth: 660, marginTop: 14, fontSize: 12.5 }}>
            A rule says which agent may do what to which resources, and under what conditions. The
            most restrictive matching rule wins, so a{' '}
            <span style={{ color: 'var(--deny)' }}>deny</span> always beats an{' '}
            <span style={{ color: 'var(--allow)' }}>allow</span> no matter which was written first.
          </p>
        </div>

        {ordered.length > 0 ? (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
              <caption className="label" style={{ textAlign: 'left', padding: '10px 18px 6px' }}>
                Most restrictive first — that is the order that decides
              </caption>
              <thead>
                <tr style={{ borderTop: '1px solid var(--border)' }}>
                  {['', 'effect', 'agent', 'action', 'resources', 'conditions', ''].map((h, i) => (
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
                {ordered.map((rule, index) => {
                  const conditions = describeConditions(rule.conditions);
                  return (
                    <tr key={rule.id} style={{ borderTop: '1px solid var(--border)' }}>
                      <td style={{ padding: '12px 14px', color: 'var(--text-faint)', width: 40 }}>
                        {String(index + 1).padStart(2, '0')}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <Chip tone={TONE[rule.effect]}>{rule.effect}</Chip>
                      </td>
                      <th
                        scope="row"
                        style={{
                          padding: '12px 14px',
                          textAlign: 'left',
                          fontWeight: 400,
                          wordBreak: 'break-all',
                        }}
                      >
                        {rule.subject === '*' ? (
                          <span style={{ color: 'var(--challenge)' }}>every agent</span>
                        ) : (
                          rule.subject
                        )}
                        <span style={{ display: 'block', color: 'var(--text-faint)', fontSize: 11 }}>
                          {rule.version}
                        </span>
                      </th>
                      <td style={{ padding: '12px 14px', whiteSpace: 'nowrap' }}>
                        {rule.action === '*' ? (
                          <span style={{ color: 'var(--challenge)' }}>anything</span>
                        ) : (
                          rule.action
                        )}
                      </td>
                      <td
                        style={{
                          padding: '12px 14px',
                          color: 'var(--text-dim)',
                          wordBreak: 'break-all',
                        }}
                      >
                        {describeFilter(rule.resource_filter)}
                      </td>
                      <td style={{ padding: '12px 14px', color: 'var(--text-dim)' }}>
                        {conditions.length === 0 ? '—' : conditions.join(' · ')}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <DeletePolicy policyId={rule.id} effect={rule.effect} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : null}
      </Panel>

      <Panel title="ADD A RULE" meta="NECESSARY, NOT SUFFICIENT">
        {live.length === 0 ? (
          <div
            style={{
              margin: 18,
              padding: '20px 18px',
              border: '1px dashed var(--border-strong)',
              color: 'var(--text-faint)',
              fontSize: 12.5,
            }}
          >
            No active agents to write a rule about. Register one on the{' '}
            <a href="/agents" style={{ color: 'var(--text)' }}>
              agents
            </a>{' '}
            screen first.
          </div>
        ) : (
          <CreatePolicyForm agents={live.map((a) => ({ id: a.id, clientId: a.client_id }))} />
        )}
      </Panel>

      <Panel title="WHY A RULE MIGHT NOT BE ENOUGH" meta="THREE LAYERS, ALL MUST AGREE">
        <div style={{ padding: 18, color: 'var(--text-dim)', fontSize: 12.5, lineHeight: 1.8 }}>
          <p style={{ margin: '0 0 12px' }}>
            Every request passes three checks in order. Any one of them can refuse, and all three
            must agree before an action happens:
          </p>
          <ol style={{ margin: 0, paddingLeft: 20 }}>
            <li>
              <span style={{ color: 'var(--text)' }}>These rules.</span> No match means denied.
            </li>
            <li>
              <span style={{ color: 'var(--text)' }}>The relationship check.</span> Permit answers
              whether this agent is actually connected to that resource. A newly registered agent
              holds nothing until a connection attaches it.
            </li>
            <li>
              <span style={{ color: 'var(--text)' }}>The risk checks.</span> Credential-shaped
              arguments, private destinations, a purpose that does not match the action.
            </li>
          </ol>
          <p style={{ margin: '12px 0 0' }}>
            So a rule saying <span style={{ color: 'var(--allow)' }}>allow</span> means this layer
            has no objection — not that the action will succeed. If something is still refused after
            you add a rule, the{' '}
            <a href="/audit" style={{ color: 'var(--text)' }}>
              audit timeline
            </a>{' '}
            names which layer said no.
          </p>
        </div>
      </Panel>
    </>
  );
}
