/**
 * One number, large, with a tracked label under it.
 *
 * The tone is the §5.3 decision colour when the number counts decisions, and
 * plain text when it counts anything else. A latency figure in green would read
 * as "allowed", which is the one thing a colour must never say by accident.
 */

import type { Tone } from './chip';

const COLOUR: Record<Tone, string> = {
  allow: 'var(--allow)',
  challenge: 'var(--challenge)',
  deny: 'var(--deny)',
  neutral: 'var(--text)',
};

export function StatTile({
  value,
  label,
  tone = 'neutral',
}: {
  value: string | number;
  label: string;
  tone?: Tone;
}) {
  return (
    <div
      style={{
        flex: 1,
        minWidth: 0,
        border: '1px solid var(--border)',
        background: 'var(--bg-panel)',
        padding: '16px 18px',
      }}
    >
      <div
        style={{
          fontFamily: 'var(--font-sans)',
          fontSize: 30,
          fontWeight: 500,
          letterSpacing: '-0.02em',
          lineHeight: 1.1,
          color: COLOUR[tone],
        }}
      >
        {value}
      </div>
      <div
        style={{
          fontSize: 10.5,
          letterSpacing: '0.14em',
          textTransform: 'uppercase',
          color: 'var(--text-dim)',
          marginTop: 4,
        }}
      >
        {label}
      </div>
    </div>
  );
}
