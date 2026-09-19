import { redirect } from 'next/navigation';
import { Panel } from '@/components/panel';
import { Chip, type Tone } from '@/components/chip';
import { StatTile } from '@/components/stat';
import { ApiError, listAuditEvents, type AuditEventView } from '@/lib/api';
import { currentSession } from '@/lib/session';

export const dynamic = 'force-dynamic';

const TONE: Record<string, Tone> = {
  allow: 'allow',
  challenge: 'challenge',
  deny: 'deny',
  lifecycle: 'neutral',
};

/**
 * What happened, newest first.
 *
 * Counted from the audit trail rather than from a separate metrics store,
 * because the audit trail is the thing that is verifiable. A dashboard number
 * that disagrees with the timeline is a number nobody can act on.
 */
export default async function ActivityPage() {
  const session = await currentSession();
  if (!session) redirect('/signed-out');

  let events: AuditEventView[];
  try {
    events = (await listAuditEvents(session.credential, { limit: 200 })).events;
  } catch (error) {
    return (
      <Panel title="UNAVAILABLE" meta="CONTROL PLANE">
        <div style={{ padding: 22, color: 'var(--text-dim)', fontSize: 12.5 }}>
          {error instanceof ApiError ? error.failure.message : 'The API did not answer.'}
        </div>
      </Panel>
    );
  }

  const decisions = events.filter((e) => e.outcome !== 'lifecycle');
  const allowed = decisions.filter((e) => e.outcome === 'allow').length;
  const challenged = decisions.filter((e) => e.outcome === 'challenge').length;
  const denied = decisions.filter((e) => e.outcome === 'deny').length;
  const stopped = challenged + denied;

  const recent = events.slice(0, 8);

  return (
    <>
      <div>
        <p className="path" style={{ margin: '0 0 12px' }}>
          ~/{session.workspaceId}/activity
        </p>
        <h1 className="headline" style={{ fontSize: 30, margin: 0 }}>
          {decisions.length} {decisions.length === 1 ? 'decision' : 'decisions'}
          <span style={{ color: 'var(--text-faint)' }}> · {stopped} stopped</span>
        </h1>
      </div>

      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
        <StatTile value={allowed} label="allowed" tone="allow" />
        <StatTile value={challenged} label="challenged" tone="challenge" />
        <StatTile value={denied} label="denied" tone="deny" />
        <StatTile value={events.length} label="events recorded" />
      </div>

      <Panel title="DECISIONS" meta="NEWEST FIRST">
        {recent.length === 0 ? (
          <div
            style={{
              margin: 18,
              padding: '20px 18px',
              border: '1px dashed var(--border-strong)',
              color: 'var(--text-faint)',
              fontSize: 12.5,
            }}
          >
            Nothing has happened yet. An entry appears here the first time an agent asks for
            something — including, and especially, when the answer is no.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
              <thead>
                <tr>
                  {['time', 'actor', 'event', 'resource', 'result'].map((h) => (
                    <th
                      key={h}
                      scope="col"
                      className="label"
                      style={{ textAlign: 'left', padding: '9px 14px', fontWeight: 400 }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {recent.map((event) => (
                  <tr key={event.id} style={{ borderTop: '1px solid var(--border)' }}>
                    <td style={{ padding: '11px 14px', whiteSpace: 'nowrap' }}>
                      {new Date(event.occurred_at).toISOString().slice(11, 19)}
                    </td>
                    <td style={{ padding: '11px 14px', wordBreak: 'break-all' }}>{event.actor}</td>
                    <td style={{ padding: '11px 14px' }}>{event.event_type}</td>
                    <td
                      style={{
                        padding: '11px 14px',
                        color: 'var(--text-dim)',
                        wordBreak: 'break-all',
                      }}
                    >
                      {event.resource_ref ?? '—'}
                    </td>
                    <td style={{ padding: '11px 14px' }}>
                      <Chip tone={TONE[event.outcome] ?? 'neutral'}>{event.outcome}</Chip>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="WHERE TO START" meta="IN THIS ORDER">
        <div style={{ padding: 18, color: 'var(--text-dim)', fontSize: 12.5, lineHeight: 1.8 }}>
          <ol style={{ margin: 0, paddingLeft: 20 }}>
            <li>
              <a href="/agents" style={{ color: 'var(--text)' }}>
                Register an agent
              </a>{' '}
              — an identity for the client software. Grants it nothing.
            </li>
            <li>
              <a href="/connections" style={{ color: 'var(--text)' }}>
                Connect Google
              </a>{' '}
              — read-only, one service at a time.
            </li>
            <li>
              <a href="/policies" style={{ color: 'var(--text)' }}>
                Write a rule and connect a resource
              </a>{' '}
              — both are needed, and the screen says why.
            </li>
            <li>
              <a href="/alerts" style={{ color: 'var(--text)' }}>
                Point alerts somewhere
              </a>{' '}
              — so a refusal reaches you without this screen.
            </li>
          </ol>
        </div>
      </Panel>
    </>
  );
}
