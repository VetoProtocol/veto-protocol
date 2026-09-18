/**
 * The bordered panel with a chrome bar that the whole site is built from.
 *
 * Header layout, left to right: an uppercase tracked title, a dimmer secondary
 * label, then three dots pushed to the right. The dots are decoration borrowed
 * from a window title bar and carry no meaning, so they are hidden from screen
 * readers rather than read out as "circle circle circle".
 */

import type { ReactNode } from 'react';

export function Panel({
  title,
  meta,
  children,
  as: Tag = 'section',
}: {
  title: string;
  meta?: string;
  children: ReactNode;
  as?: 'section' | 'div' | 'article';
}) {
  return (
    <Tag
      style={{
        border: '1px solid var(--border)',
        background: 'var(--bg-panel)',
      }}
    >
      <header
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 14,
          padding: '13px 18px',
          borderBottom: '1px solid var(--border)',
        }}
      >
        <span
          className="label"
          style={{ color: 'var(--text)', fontWeight: 500, letterSpacing: '0.16em' }}
        >
          {title}
        </span>
        {meta ? (
          <span className="label" style={{ color: 'var(--text-faint)' }}>
            {meta}
          </span>
        ) : null}
        <span aria-hidden="true" style={{ marginLeft: 'auto', display: 'flex', gap: 5 }}>
          {[0, 1, 2].map((i) => (
            <span
              key={i}
              style={{
                width: 4,
                height: 4,
                borderRadius: '50%',
                background: 'var(--border-strong)',
              }}
            />
          ))}
        </span>
      </header>
      {children}
    </Tag>
  );
}
