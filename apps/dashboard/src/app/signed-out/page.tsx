import { Mark } from '@/components/mark';
import { WalletSignIn } from './wallet-button';

/**
 * Where every unsuccessful sign-in lands, and where signing out ends.
 *
 * The reason is a fixed code from a closed set, looked up here — the query
 * string never reaches the page as text, so a crafted link cannot put words in
 * the product's mouth.
 */
const REASONS: Record<string, string> = {
  expired: 'That attempt timed out. Start again.',
  rejected: 'Sign-in could not be verified. Start again.',
  unknown: 'That account is not a member of any workspace here.',
  ambiguous: 'That account belongs to more than one workspace.',
  // An application asked to connect while nobody was signed in. Sign-in cannot
  // resume the request — it lands on the dashboard — so the honest instruction
  // is to start it again from the application.
  authorize: 'Sign in, then start the connection again from the application that asked.',
};

export default async function SignedOut({
  searchParams,
}: {
  searchParams: Promise<{ reason?: string }>;
}) {
  const { reason } = await searchParams;
  const message = reason ? REASONS[reason] : null;

  return (
    <div className="auth-ground" style={{ minHeight: 'calc(100vh - 44px)', padding: 24 }}>
      <div style={{ position: 'relative', width: 380, maxWidth: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12 }}>
          <Mark size={28} />
          <span style={{ fontSize: 20, letterSpacing: '0.02em' }}>veto</span>
        </div>

        <h1
          className="headline"
          style={{
            margin: '52px 0 0',
            fontSize: 30,
            textAlign: 'center',
            letterSpacing: '-0.028em',
          }}
        >
          Sign in to your workspace
        </h1>

        <p
          style={{
            color: 'var(--text-dim)',
            fontSize: 13,
            margin: '14px 0 0',
            textAlign: 'center',
            lineHeight: 1.65,
          }}
        >
          {/* Both outcomes in one sentence, because the button does both: an
              account nobody knows is offered a workspace of its own. */}
          Or create a new one — the same button does both.
        </p>

        {message ? (
          <p
            role="status"
            style={{
              margin: '20px 0 0',
              padding: '10px 12px',
              border: '1px solid var(--border-strong)',
              background: 'var(--bg-panel)',
              color: 'var(--text-dim)',
              fontSize: 12,
              textAlign: 'center',
              lineHeight: 1.6,
            }}
          >
            {message}
          </p>
        ) : null}

        <div style={{ marginTop: message ? 28 : 44, display: 'grid', gap: 12 }}>
          <a
            href="/login"
            style={{
              fontSize: 13.5,
              padding: '15px 22px',
              background: 'var(--text)',
              color: 'var(--bg)',
              border: '1px solid var(--text)',
              textAlign: 'center',
              letterSpacing: '0.01em',
              fontWeight: 500,
            }}
          >
            Continue with Google
          </a>

          {/* Second, and second for a reason: one of these can be recovered
              and the other cannot. The dialog behind it says so before a
              wallet is ever asked to connect. */}
          <WalletSignIn />
        </div>

        <p
          style={{
            color: 'var(--text-faint)',
            fontSize: 11,
            margin: '44px 0 0',
            textAlign: 'center',
            lineHeight: 1.75,
          }}
        >
          A passkey is bound to this device the first time you approve something.
          <br />
          Veto never sees your password.
        </p>
      </div>

      <div
        aria-hidden="true"
        style={{
          position: 'absolute',
          left: 0,
          right: 0,
          bottom: 22,
          textAlign: 'center',
          fontSize: 10.5,
          letterSpacing: '0.16em',
          textTransform: 'uppercase',
          color: '#4a4a4a',
        }}
      >
        veto protocol · preview
      </div>
    </div>
  );
}
