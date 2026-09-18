/**
 * The bordered state chip, in the site's allow / approve / block vocabulary.
 *
 * Agent lifecycle states map onto the §5.3 decision palette because they mean
 * the same things to a reader: an active agent's requests can be allowed, a
 * suspended one's are paused pending a human, a revoked one's are refused.
 *
 * Colour is never the only carrier. Each chip prints its own word, so the
 * difference survives greyscale, low vision, and every form of colour blindness
 * — which matters more here than usual, since red and green are two thirds of
 * the palette and the distinction is "can this thing act".
 */

export type Tone = 'allow' | 'challenge' | 'deny' | 'neutral';

const TONES: Record<Tone, { fg: string; bg: string; border: string }> = {
  allow: { fg: 'var(--allow)', bg: 'var(--allow-bg)', border: 'var(--allow)' },
  challenge: { fg: 'var(--challenge)', bg: 'var(--challenge-bg)', border: 'var(--challenge)' },
  deny: { fg: 'var(--deny)', bg: 'var(--deny-bg)', border: 'var(--deny)' },
  neutral: { fg: 'var(--text-dim)', bg: 'transparent', border: 'var(--border-strong)' },
};

export function Chip({ tone = 'neutral', children }: { tone?: Tone; children: string }) {
  const t = TONES[tone];
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px 3px',
        border: `1px solid ${t.border}`,
        color: t.fg,
        background: t.bg,
        fontSize: 11,
        letterSpacing: '0.04em',
        lineHeight: 1.45,
        whiteSpace: 'nowrap',
      }}
    >
      {children}
    </span>
  );
}

/** Small filled dot plus lowercase text, as in "systems operational". */
export function StatusDot({ tone = 'allow', children }: { tone?: Tone; children: string }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 11.5 }}>
      <span
        aria-hidden="true"
        style={{
          width: 5,
          height: 5,
          borderRadius: '50%',
          background: TONES[tone].fg,
          flex: '0 0 auto',
        }}
      />
      <span style={{ color: 'var(--text-dim)' }}>{children}</span>
    </span>
  );
}
