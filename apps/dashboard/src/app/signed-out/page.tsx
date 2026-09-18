import { Panel } from '@/components/panel';

/**
 * Where every unsuccessful sign-in lands.
 *
 * The reason is a fixed code from a closed set, looked up here — the query
 * string never reaches the page as text, so a crafted link cannot put words in
 * the product's mouth.
 */
const REASONS: Record<string, string> = {
  expired: 'That sign-in attempt timed out. Start again.',
  rejected: 'Sign-in could not be verified. Start again.',
  unknown: 'That account is not a member of any workspace here. Ask an administrator for an invitation.',
  ambiguous: 'That account belongs to more than one workspace. Choosing between them is not built yet.',
};

export default async function SignedOut({
  searchParams,
}: {
  searchParams: Promise<{ reason?: string }>;
}) {
  const { reason } = await searchParams;
  const message = (reason && REASONS[reason]) || 'You are signed out.';

  return (
    <Panel title="SIGN IN" meta="IDENTITY">
      <div style={{ padding: 22, display: 'grid', gap: 14, justifyItems: 'start' }}>
        <p className="path" style={{ margin: 0 }}>
          ~/auth
        </p>
        <h1 className="headline" style={{ fontSize: 28 }}>
          {reason ? 'Not signed in.' : 'Signed out.'}
        </h1>
        <p style={{ color: 'var(--text-dim)', maxWidth: 560, fontSize: 12.5, margin: 0 }}>{message}</p>
        <a
          href="/login"
          style={{
            display: 'inline-block',
            padding: '8px 16px',
            fontSize: 12,
            background: 'var(--text)',
            color: 'var(--bg)',
            border: '1px solid var(--text)',
          }}
        >
          Sign in
        </a>
      </div>
    </Panel>
  );
}
