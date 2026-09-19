import { redirect } from 'next/navigation';
import { Nav } from '@/components/nav';
import { Panel } from '@/components/panel';
import { Chip } from '@/components/chip';
import { ApiError, listApprovals, listPasskeys } from '@/lib/api';
import { currentSession } from '@/lib/session';
import { EnrolPasskey, Expiry, ResolveApproval } from './ceremony';

export const dynamic = 'force-dynamic';

export default async function ApprovalsPage() {
  const session = await currentSession();
  if (!session) redirect('/signed-out');

  let approvals;
  let passkeys;
  try {
    [approvals, passkeys] = await Promise.all([
      listApprovals(session.credential),
      listPasskeys(session.credential),
    ]);
  } catch (error) {
    return (
      <>
        <Nav active="approvals" />
        <Panel title="UNAVAILABLE" meta="CONTROL PLANE">
          <div style={{ padding: 22, color: 'var(--text-dim)', fontSize: 12.5 }}>
            {error instanceof ApiError ? error.failure.message : 'The API did not answer.'}
          </div>
        </Panel>
      </>
    );
  }

  const waiting = approvals.approvals;

  return (
    <>
      <Nav active="approvals" />

      <Panel title="APPROVALS" meta="AWAITING YOU">
        <div style={{ padding: '22px 18px 6px' }}>
          <p className="path" style={{ margin: '0 0 12px' }}>
            ~/{session.workspaceId}/approvals
          </p>
          <h1 className="headline" style={{ fontSize: 30 }}>
            {waiting.length === 0 ? 'Nothing waiting' : `${waiting.length} waiting`}
          </h1>
          <p style={{ color: 'var(--text-dim)', maxWidth: 640, marginTop: 12, fontSize: 12.5 }}>
            Each one names the exact action it covers. Change any argument and it no longer applies —
            the agent has to ask again. Only you can resolve these.
          </p>
        </div>

        {waiting.length === 0 ? (
          <div
            style={{
              margin: '4px 18px 22px', padding: '20px 18px',
              border: '1px dashed var(--border-strong)', color: 'var(--text-faint)', fontSize: 12.5,
            }}
          >
            No agent is waiting on you.
          </div>
        ) : (
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {waiting.map((approval) => (
              <li key={approval.id} style={{ borderTop: '1px solid var(--border)', padding: '16px 18px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 13 }}>{approval.tool ?? 'unknown tool'}</span>
                  <Chip tone="challenge">{approval.reason_code ?? 'APPROVAL_REQUIRED'}</Chip>
                  <Expiry at={approval.expires_at} />
                </div>

                <dl
                  style={{
                    margin: '12px 0 0', display: 'grid',
                    gridTemplateColumns: 'max-content 1fr', gap: '4px 14px',
                    fontSize: 11.5, lineHeight: 1.7,
                  }}
                >
                  <dt style={{ color: 'var(--text-dim)' }}>resource</dt>
                  <dd style={{ margin: 0, wordBreak: 'break-all' }}>{approval.resource_ref ?? '—'}</dd>
                  <dt style={{ color: 'var(--text-dim)' }}>action</dt>
                  <dd style={{ margin: 0 }}>{approval.action ?? '—'}</dd>
                  {/* The digest is shown because it is what the grant is bound
                      to. Two approvals that look alike are different actions if
                      these differ. */}
                  <dt style={{ color: 'var(--text-dim)' }}>digest</dt>
                  <dd style={{ margin: 0, color: 'var(--text-faint)', wordBreak: 'break-all' }}>
                    {approval.action_digest.slice(0, 23)}…
                  </dd>
                </dl>

                <div style={{ marginTop: 14 }}>
                  {passkeys.passkeys.length === 0 ? (
                    <p style={{ margin: 0, color: 'var(--challenge)', fontSize: 11.5 }}>
                      Enrol a passkey below before you can resolve this.
                    </p>
                  ) : (
                    <ResolveApproval approval={approval} />
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="PASSKEYS" meta={`${passkeys.passkeys.length} ENROLLED`}>
        {passkeys.passkeys.length > 0 ? (
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {passkeys.passkeys.map((key) => (
              <li
                key={key.id}
                style={{
                  borderTop: '1px solid var(--border)', padding: '12px 18px',
                  display: 'flex', gap: 14, alignItems: 'baseline', fontSize: 12.5,
                }}
              >
                <span>{key.label ?? key.id}</span>
                <span style={{ marginLeft: 'auto', color: 'var(--text-dim)', fontSize: 11.5 }}>
                  {key.last_used_at === null
                    ? 'never used'
                    : `last used ${key.last_used_at.slice(0, 10)}`}
                </span>
              </li>
            ))}
          </ul>
        ) : null}
        <div style={{ borderTop: '1px solid var(--border)' }}>
          <EnrolPasskey hasAny={passkeys.passkeys.length > 0} />
        </div>
      </Panel>
    </>
  );
}
