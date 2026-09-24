/**
 * Chrome for the two public legal pages.
 *
 * These are the only pages in the product a stranger is meant to read, and the
 * only ones Google will fetch during verification. They are deliberately plain:
 * no session, no data, no rail.
 */

import Link from 'next/link';
import type { ReactNode } from 'react';
import { Mark } from '@/components/mark';

export function Legal({
  title,
  updated,
  children,
}: {
  title: string;
  updated: string;
  children: ReactNode;
}) {
  return (
    <div style={{ padding: '48px 24px 96px' }}>
      <article style={{ maxWidth: 760, margin: '0 auto' }}>
        <Link
          href="/"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 10, color: 'var(--text)' }}
        >
          <Mark size={22} />
          <span style={{ fontSize: 16, letterSpacing: '0.02em' }}>veto</span>
        </Link>

        <h1
          className="headline"
          style={{ fontSize: 34, margin: '36px 0 8px', letterSpacing: '-0.028em' }}
        >
          {title}
        </h1>
        <p className="label" style={{ color: 'var(--text-faint)', margin: 0 }}>
          Last updated {updated}
        </p>

        <div style={{ marginTop: 40, fontSize: 14, lineHeight: 1.75, color: 'var(--text-dim)' }}>
          {children}
        </div>

        <footer
          style={{
            marginTop: 56,
            paddingTop: 20,
            borderTop: '1px solid var(--border)',
            display: 'flex',
            gap: 20,
            fontSize: 12.5,
            color: 'var(--text-faint)',
          }}
        >
          <Link href="/privacy">Privacy</Link>
          <Link href="/terms">Terms</Link>
        </footer>
      </article>
    </div>
  );
}

/** A section heading inside a legal page. */
export function H({ children }: { children: ReactNode }) {
  return (
    <h2
      style={{
        fontFamily: 'var(--font-sans)',
        fontSize: 19,
        fontWeight: 500,
        letterSpacing: '-0.02em',
        color: 'var(--text)',
        margin: '38px 0 12px',
      }}
    >
      {children}
    </h2>
  );
}

/** A list that does not fight the prose around it. */
export function UL({ children }: { children: ReactNode }) {
  return <ul style={{ margin: '12px 0', paddingLeft: 20 }}>{children}</ul>;
}
