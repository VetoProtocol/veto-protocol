import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { Panel } from '@/components/panel';
import { PENDING_COOKIE, openPending } from '@/lib/pending-cookie';
import { CreateWorkspaceForm } from './form';

export const dynamic = 'force-dynamic';

export default async function WelcomePage() {
  const sealed = (await cookies()).get(PENDING_COOKIE)?.value;
  const pending = sealed ? openPending(sealed) : null;

  // Reachable only with a verified sign-in behind it. Opening this URL directly
  // gets nothing, because the thing that makes it meaningful is a cookie only
  // the OIDC callback can write.
  if (!pending) redirect('/signed-out?reason=expired');

  // Already a member — they arrived here by going backwards after signing up,
  // or an invitation landed mid-flow. Sign-in will find them now.
  if (pending.candidates.length > 0) redirect('/choose');

  return (
    <Panel title="WELCOME" meta="FIRST WORKSPACE">
      <div style={{ padding: 24, display: 'grid', gap: 20 }}>
        <div>
          <p className="path" style={{ margin: '0 0 12px' }}>
            ~/new
          </p>
          <h1 className="headline" style={{ fontSize: 30, margin: 0 }}>
            Name your workspace.
          </h1>
          <p style={{ color: 'var(--text-dim)', maxWidth: 560, marginTop: 12, fontSize: 12.5 }}>
            Your Google account checked out. You are not a member of anything yet, so this makes
            you one — a workspace of your own, with nothing in it and nobody else in it.
          </p>
        </div>

        <CreateWorkspaceForm suggestion="My workspace" />

        <div
          style={{
            borderTop: '1px solid var(--border)',
            paddingTop: 16,
            color: 'var(--text-dim)',
            fontSize: 12,
            lineHeight: 1.75,
            maxWidth: 560,
          }}
        >
          <p style={{ margin: '0 0 8px' }}>
            <span style={{ color: 'var(--text)' }}>Expecting to join a team?</span> This is not that.
            Being added to somebody else&rsquo;s workspace is something they do, not something
            signing in can do — ask them to invite this account.
          </p>
          <p style={{ margin: 0 }}>
            Your new workspace starts with <span style={{ color: 'var(--text)' }}>no rules</span>,
            which means every request an agent makes is refused. That is the correct starting point,
            and the policies screen walks you out of it.
          </p>
        </div>
      </div>
    </Panel>
  );
}
