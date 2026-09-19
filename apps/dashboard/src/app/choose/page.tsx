import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { Panel } from '@/components/panel';
import { PENDING_COOKIE, openPending } from '@/lib/pending-cookie';
import { ChooseWorkspaceForm } from './form';

export const dynamic = 'force-dynamic';

/**
 * Pick a workspace.
 *
 * Unreachable until self-signup shipped, and unavoidable afterwards: the moment
 * somebody can have a workspace of their own *and* be invited to an employer's,
 * sign-in starts returning two answers. The old code called that "ambiguous"
 * and refused.
 *
 * The list comes from the signed cookie, which came from the sign-in lookup. A
 * workspace nobody offered is not on the page and is refused if posted anyway.
 */
export default async function ChoosePage() {
  const sealed = (await cookies()).get(PENDING_COOKIE)?.value;
  const pending = sealed ? openPending(sealed) : null;

  if (!pending) redirect('/signed-out?reason=expired');
  if (pending.candidates.length === 0) redirect('/welcome');

  return (
    <Panel title="CHOOSE" meta="MORE THAN ONE WORKSPACE">
      <div style={{ padding: 24, display: 'grid', gap: 20 }}>
        <div>
          <p className="path" style={{ margin: '0 0 12px' }}>
            ~/choose
          </p>
          <h1 className="headline" style={{ fontSize: 30, margin: 0 }}>
            Which workspace?
          </h1>
          <p style={{ color: 'var(--text-dim)', maxWidth: 560, marginTop: 12, fontSize: 12.5 }}>
            This account belongs to {pending.candidates.length}. They are separate: agents,
            policies, connections and the audit trail in one are invisible from the other.
          </p>
        </div>

        <ChooseWorkspaceForm workspaceIds={pending.candidates.map((c) => c.workspaceId)} />

        <p
          style={{
            borderTop: '1px solid var(--border)',
            paddingTop: 16,
            color: 'var(--text-faint)',
            fontSize: 11.5,
            margin: 0,
            maxWidth: 560,
          }}
        >
          Sign out and back in to switch. There is no way to be in two at once — the session names
          exactly one, and every query is scoped by it.
        </p>
      </div>
    </Panel>
  );
}
