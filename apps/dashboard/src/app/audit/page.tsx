import { redirect } from 'next/navigation';
import { Nav } from '@/components/nav';
import { Panel } from '@/components/panel';
import { Chip, StatusDot, type Tone } from '@/components/chip';
import { ApiError, listAuditEvents, verifyAuditChain, type AuditEventView } from '@/lib/api';
import { currentSession } from '@/lib/session';

export const dynamic = 'force-dynamic';

const TONE: Record<AuditEventView['outcome'], Tone> = {
  allow: 'allow',
  challenge: 'challenge',
  deny: 'deny',
  lifecycle: 'neutral',
};

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<{ before?: string }>;
}) {
  const session = await currentSession();
  if (!session) redirect('/signed-out');

  const { before } = await searchParams;
  // The cursor is a sequence number. Anything else is ignored rather than
  // passed through — a crafted query must not reach the API as-is.
  const cursor = before !== undefined && /^[0-9]{1,18}$/.test(before) ? Number(before) : undefined;

  let page;
  let chain;
  try {
    [page, chain] = await Promise.all([
      listAuditEvents(session.credential, { limit: 40, ...(cursor === undefined ? {} : { before: cursor }) }),
      verifyAuditChain(session.credential),
    ]);
  } catch (error) {
    return (
      <>
        <Nav active="audit" />
        <Panel title="UNAVAILABLE" meta="CONTROL PLANE">
          <div style={{ padding: 22, color: 'var(--text-dim)', fontSize: 12.5 }}>
            {error instanceof ApiError ? error.failure.message : 'The API did not answer.'}
          </div>
        </Panel>
      </>
    );
  }

  return (
    <>
      <Nav active="audit" />

      <Panel title="AUDIT" meta="APPEND-ONLY">
        <div style={{ padding: '22px 18px 6px' }}>
          <p className="path" style={{ margin: '0 0 12px' }}>
            ~/{session.workspaceId}/audit
          </p>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
            <h1 className="headline" style={{ fontSize: 30 }}>
              Timeline
            </h1>
            {/* The verification result is shown plainly, including when it
                fails. A badge that only ever says "verified" is decoration. */}
            {chain.verified ? (
              <StatusDot tone="allow">hash chain verified</StatusDot>
            ) : (
              <StatusDot tone="deny">{`chain breaks at #${chain.broken_at ?? '?'}`}</StatusDot>
            )}
          </div>
          <p style={{ color: 'var(--text-dim)', maxWidth: 660, marginTop: 12, fontSize: 12.5 }}>
            Every event is hashed with its predecessor, so a removed or edited row breaks the chain.
            References only — never document contents, tokens, or passkey challenges.
          </p>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
            <caption className="label" style={{ textAlign: 'left', padding: '10px 18px 6px' }}>
              Audit events, newest first
            </caption>
            <thead>
              <tr style={{ borderTop: '1px solid var(--border)' }}>
                {['#', 'time', 'actor', 'event', 'resource', 'outcome'].map((h) => (
                  <th
                    key={h}
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
              {page.events.map((event) => (
                <tr key={event.id} style={{ borderTop: '1px solid var(--border)' }}>
                  <td style={{ padding: '11px 14px', color: 'var(--text-faint)' }}>{event.seq}</td>
                  <td style={{ padding: '11px 14px', color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>
                    <time dateTime={event.occurred_at}>{event.occurred_at.slice(0, 19).replace('T', ' ')}</time>
                  </td>
                  <td style={{ padding: '11px 14px' }}>{event.actor}</td>
                  <td style={{ padding: '11px 14px' }}>{event.event_type}</td>
                  <td style={{ padding: '11px 14px', color: 'var(--text-dim)', wordBreak: 'break-all' }}>
                    {event.resource_ref ?? '—'}
                  </td>
                  <td style={{ padding: '11px 14px' }}>
                    <Chip tone={TONE[event.outcome]}>{event.outcome}</Chip>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {page.events.length === 0 ? (
          <div
            style={{
              margin: '4px 18px 22px', padding: '20px 18px',
              border: '1px dashed var(--border-strong)', color: 'var(--text-faint)', fontSize: 12.5,
            }}
          >
            Nothing recorded yet.
          </div>
        ) : null}

        <div style={{ borderTop: '1px solid var(--border)', padding: '13px 18px', display: 'flex', gap: 16 }}>
          {cursor !== undefined ? (
            <a href="/audit" style={{ color: 'var(--text-dim)', fontSize: 11.5 }}>
              ← newest
            </a>
          ) : null}
          {page.next_cursor !== null ? (
            <a href={`/audit?before=${page.next_cursor}`} style={{ marginLeft: 'auto', color: 'var(--text-dim)', fontSize: 11.5 }}>
              older →
            </a>
          ) : null}
        </div>
      </Panel>
    </>
  );
}
