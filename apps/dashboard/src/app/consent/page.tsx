/**
 * Consent Grants — what every agent may reach right now, and when it last did.
 *
 * The question this screen exists to answer is "what can this agent actually
 * see?", which until now took three screens and a mental join: Permit grants
 * and Veto rules on `/policies`, provider consents on `/connections`.
 *
 * It shows **grants only**. A rule can narrow what a grant allows but never
 * widen it, so a grant is the outer bound — which is the honest thing to put on
 * a page somebody reads before deciding what to take away. The copy says so,
 * rather than letting the omission imply the list is the whole story.
 */

import { redirect } from 'next/navigation';
import { Panel } from '@/components/panel';
import { Chip } from '@/components/chip';
import { ApiError, listConsentGrants } from '@/lib/api';
import { currentSession } from '@/lib/session';
import { kindLabel, kindReach } from '../policies/resource-kinds';
import { RevokeGrant } from '../policies/forms';

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

/** A date somebody can read, without pretending to precision we do not need. */
const day = (iso: string | null): string => (iso === null ? '—' : iso.slice(0, 10));

function lastUse(days: number | null): string {
  if (days === null) return 'never';
  if (days === 0) return 'today';
  if (days === 1) return 'yesterday';
  return `${String(days)} days ago`;
}

export default async function ConsentPage() {
  const session = await currentSession();
  if (!session) redirect('/signed-out');

  let view;
  try {
    view = await listConsentGrants(session.credential);
  } catch (error) {
    return (
      <Panel title="UNAVAILABLE" meta="CONTROL PLANE">
        <div style={{ padding: 22, color: 'var(--text-dim)', fontSize: 12.5 }}>
          {error instanceof ApiError ? error.failure.message : 'The API did not answer.'}
        </div>
      </Panel>
    );
  }

  const stale = view.grants.filter((g) => g.stale).length;
  const inert = view.grants.filter((g) => g.inert).length;

  return (
    <>
      <div>
        <p className="path" style={{ margin: '0 0 12px' }}>
          ~/{session.workspaceId}/consent
        </p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
          <h1 className="headline" style={{ fontSize: 30, margin: 0 }}>
            {view.grants.length} {view.grants.length === 1 ? 'grant' : 'grants'}
          </h1>
          {stale > 0 ? <Chip tone="deny">{`${String(stale)} unused`}</Chip> : null}
          {inert > 0 ? <Chip tone="neutral">{`${String(inert)} reach nothing`}</Chip> : null}
        </div>
        <p style={{ color: 'var(--text-dim)', maxWidth: 680, marginTop: 12, fontSize: 12.5 }}>
          Everything your agents are connected to, and what a policy rule actually permits for each
          one. Both have to agree: a grant with no matching rule reaches nothing, because the rule
          check refuses before the connection is ever consulted.
        </p>
      </div>

      <Panel title="GRANTS" meta={`UNUSED FOR ${String(view.stale_after_days)} DAYS IS MARKED`}>
        {view.grants.length === 0 ? (
          <div style={{ padding: '18px 18px 20px', color: 'var(--text-dim)', fontSize: 12 }}>
            Nothing is granted, so every agent is refused. That is the starting state rather than a
            problem — an agent reaches nothing until somebody connects it to something.
          </div>
        ) : (
          <div style={{ padding: '14px 18px 4px', overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={head}>agent</th>
                  <th style={head}>can reach</th>
                  <th style={head}>a rule permits</th>
                  <th style={head}>granted</th>
                  <th style={head}>by</th>
                  <th style={head}>last used</th>
                  <th style={head} aria-label="revoke" />
                </tr>
              </thead>
              <tbody>
                {view.grants.map((g) => (
                  <tr key={`${g.agent_id}:${g.resource_type}:${g.resource_key}`}>
                    <td style={{ ...cell, color: 'var(--text)' }}>{g.agent_id}</td>
                    <td style={cell}>
                      <div>{kindLabel(g.resource_type)}</div>
                      <div style={{ color: 'var(--text-faint)', fontSize: 11.5, marginTop: 2 }}>
                        {g.resource_key}
                      </div>
                      {/* A folder or account grant reaches everything beneath
                          it. Leaving that unsaid would make this list look
                          exhaustive when it is a list of roots. */}
                      {g.inherits ? (
                        <div style={{ color: 'var(--text-dim)', fontSize: 11, marginTop: 4 }}>
                          reaches {kindReach(g.resource_type)}
                        </div>
                      ) : null}
                    </td>
                    <td style={cell}>
                      {/* A grant is half an answer. With no matching rule the
                          pipeline refuses at step 4, before Permit is asked, so
                          the grant reaches nothing at all. */}
                      {g.inert ? (
                        <span style={{ color: 'var(--deny)' }}>
                          nothing — no rule matches
                        </span>
                      ) : (
                        g.effective.map((e) => (
                          <div key={e.action} style={{ marginBottom: 2 }}>
                            {e.action}
                            {e.effect === 'challenge' ? (
                              <span style={{ color: 'var(--challenge)', marginLeft: 6 }}>
                                needs approval
                              </span>
                            ) : null}
                          </div>
                        ))
                      )}
                    </td>
                    <td style={{ ...cell, color: 'var(--text-dim)' }}>{day(g.granted_at)}</td>
                    <td style={{ ...cell, color: 'var(--text-dim)' }}>{g.granted_by ?? '—'}</td>
                    <td style={cell}>
                      <span style={{ color: g.stale ? 'var(--deny)' : 'var(--text)' }}>
                        {lastUse(g.days_since_last_use)}
                      </span>
                    </td>
                    <td style={{ ...cell, textAlign: 'right' }}>
                      <RevokeGrant
                        agentId={g.agent_id}
                        resourceType={g.resource_type}
                        resourceKey={g.resource_key}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div
          style={{
            borderTop: '1px solid var(--border)',
            padding: '12px 18px',
            color: 'var(--text-faint)',
            fontSize: 11,
            lineHeight: 1.7,
          }}
        >
          {/* "Never" is a claim about our records, not about the world. Saying
              how far back they go keeps it an honest one — otherwise this
              screen invites somebody to revoke on evidence it does not have. */}
          {view.recording_since === null
            ? 'No decisions have been recorded yet, so “never used” here means only that nothing has happened since this workspace was created.'
            : `“Never used” means no allowed request since ${day(
                view.recording_since,
              )}, which is as far back as the decision record goes. Revoking takes effect on the next request.`}
        </div>
      </Panel>
    </>
  );
}
