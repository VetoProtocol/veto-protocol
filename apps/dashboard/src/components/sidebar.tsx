/**
 * The left rail.
 *
 * Replaces the horizontal tab strip. Tabs were fine for five screens and stop
 * working at ten — the rail groups them, gives each an icon, and leaves room
 * for the workspace and the signed-in person without a second bar.
 *
 * `aria-current="page"` marks the active item, not colour alone. The left
 * border and the lighter background are reinforcement; someone who cannot see
 * the contrast difference still gets told which page they are on.
 *
 * ## The enterprise section
 *
 * Three rows that are **not links and not focusable**, because they do nothing.
 * A disabled-looking anchor that Tab lands on and Enter ignores is worse than
 * no anchor: it promises an action it will not perform. These are marks in the
 * design, so they render — but as plain text with a badge, which is what they
 * honestly are until those features exist.
 */

'use client';

import { usePathname } from 'next/navigation';
import type { ReactNode } from 'react';

const ICON = {
  width: 13,
  height: 13,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.5,
  'aria-hidden': true,
} as const;

const icons: Record<string, ReactNode> = {
  dashboard: (
    <svg {...ICON}>
      <rect x="3" y="3" width="8" height="8" />
      <rect x="13" y="3" width="8" height="8" />
      <rect x="3" y="13" width="8" height="8" />
      <rect x="13" y="13" width="8" height="8" />
    </svg>
  ),
  agents: (
    <svg {...ICON} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21c0-4.4 3.6-8 8-8s8 3.6 8 8" />
    </svg>
  ),
  policies: (
    <svg {...ICON} strokeLinecap="round" strokeLinejoin="round">
      <path d="M6 3h9l4 4v14a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" />
      <path d="M15 3v4h4" />
      <line x1="8" y1="12" x2="16" y2="12" />
      <line x1="8" y1="16" x2="14" y2="16" />
    </svg>
  ),
  connections: (
    <svg {...ICON} strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1" />
      <path d="M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1" />
    </svg>
  ),
  labels: (
    <svg {...ICON} strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 12V5a2 2 0 0 1 2-2h7l9 9-9 9-9-9z" />
      <circle cx="7.5" cy="7.5" r="1.2" />
    </svg>
  ),
  approvals: (
    <svg {...ICON} strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 11.1V12a10 10 0 1 1-5.9-9.1" />
      <path d="M22 4L12 14.01l-3-3" />
    </svg>
  ),
  presence: (
    <svg {...ICON} strokeLinejoin="round">
      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  ),
  audit: (
    <svg {...ICON} strokeLinecap="round">
      <line x1="8" y1="6" x2="20" y2="6" />
      <line x1="8" y1="12" x2="20" y2="12" />
      <line x1="8" y1="18" x2="20" y2="18" />
      <circle cx="4" cy="6" r="1.5" />
      <circle cx="4" cy="12" r="1.5" />
      <circle cx="4" cy="18" r="1.5" />
    </svg>
  ),
  alerts: (
    <svg {...ICON} strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.7 21a2 2 0 0 1-3.4 0" />
    </svg>
  ),
  shield: (
    <svg {...ICON} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  ),
  fingerprint: (
    <svg {...ICON} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 11v4" />
      <path d="M8 8a4 4 0 0 1 8 0v5" />
      <path d="M5 12a7 7 0 0 1 14 0v3" />
      <path d="M12 4a8 8 0 0 1 8 8" />
    </svg>
  ),
  shadow: (
    <svg {...ICON} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="8" r="4" strokeDasharray="2 2" />
      <path d="M4 21c0-4.4 3.6-8 8-8s8 3.6 8 8" strokeDasharray="2 2" />
    </svg>
  ),
  settings: (
    <svg {...ICON} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 0 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 0 1-4 0v-.1a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 0 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 0 1 0-4h.1a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 0 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 0 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 0 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 0 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
    </svg>
  ),
  help: (
    <svg {...ICON} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <path d="M9.5 9a2.5 2.5 0 0 1 5 0c0 1.5-2.5 2-2.5 4" />
      <circle cx="12" cy="17" r="0.6" fill="currentColor" stroke="none" />
    </svg>
  ),
};

/** Route, label, icon. Order is the order somebody sets the product up in. */
const OVERVIEW = [
  ['/', 'Dashboard', 'dashboard'],
  ['/agents', 'Agents', 'agents'],
  ['/policies', 'Policies', 'policies'],
  ['/connections', 'Connections', 'connections'],
  ['/labels', 'Labels', 'labels'],
  ['/approvals', 'Approvals', 'approvals'],
  ['/presence', 'Presence', 'presence'],
  ['/audit', 'Audit', 'audit'],
  ['/alerts', 'Alerts', 'alerts'],
] as const;

const ENTERPRISE = [
  ['Consent Grants', 'shield'],
  ['Agent Fingerprints', 'fingerprint'],
  ['Shadow Agents', 'shadow'],
] as const;

const sectionLabel: React.CSSProperties = {
  padding: '0 16px 6px',
  fontSize: 9,
  letterSpacing: '0.16em',
  textTransform: 'uppercase',
  color: 'var(--text-faint)',
};

const row: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 10,
  padding: '8px 16px',
  fontSize: 12,
  borderLeft: '2px solid transparent',
};

const truncate: React.CSSProperties = {
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
};

const avatar = (size: number): React.CSSProperties => ({
  width: size,
  height: size,
  background: 'var(--bg-raised)',
  border: '1px solid var(--border-strong)',
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  fontSize: 10,
  color: 'var(--text)',
  letterSpacing: '0.06em',
  flex: '0 0 auto',
});

export function Sidebar({ workspaceId, userId }: { workspaceId: string; userId: string }) {
  // Read here rather than threaded through every page: the rail is rendered
  // once by the layout, and a page should not have to announce where it is.
  const active = usePathname();

  return (
    <nav
      aria-label="Sections"
      style={{
        width: 'var(--rail)',
        flex: '0 0 var(--rail)',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <div
        style={{
          padding: '11px 14px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          gap: 10,
        }}
      >
        <span aria-hidden="true" style={avatar(22)}>
          {workspaceId.replace(/^ws_/, '').slice(0, 1).toUpperCase()}
        </span>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div
            style={{
              fontSize: 9,
              letterSpacing: '0.16em',
              textTransform: 'uppercase',
              color: 'var(--text-faint)',
              lineHeight: 1,
            }}
          >
            workspace
          </div>
          <div style={{ ...truncate, fontSize: 12, lineHeight: 1.3, marginTop: 3 }}>
            {workspaceId.replace(/^ws_/, '')}
          </div>
        </div>
      </div>

      <div style={{ padding: '10px 0 4px' }}>
        <div style={sectionLabel}>overview</div>
        {OVERVIEW.map(([href, label, icon]) => {
          const on = href === active;
          return (
            <a
              key={href}
              href={href}
              {...(on ? { 'aria-current': 'page' as const } : {})}
              style={{
                ...row,
                color: on ? 'var(--text)' : 'var(--text-dim)',
                background: on ? 'var(--bg-raised)' : 'transparent',
                borderLeftColor: on ? 'var(--text)' : 'transparent',
              }}
            >
              {icons[icon]}
              <span>{label}</span>
            </a>
          );
        })}
      </div>

      <div style={{ padding: '6px 0 4px', borderTop: '1px solid var(--border)' }}>
        <div style={{ ...sectionLabel, paddingTop: 10 }}>enterprise</div>
        {ENTERPRISE.map(([label, icon]) => (
          // Not an <a>. These do nothing, so nothing here is focusable or
          // clickable — a control that ignores Enter is a broken promise.
          <div key={label} style={{ ...row, color: 'var(--text-faint)' }}>
            {icons[icon]}
            <span style={{ flex: 1 }}>{label}</span>
            <span
              style={{
                fontSize: 8.5,
                letterSpacing: '0.14em',
                padding: '1.5px 5px',
                border: '1px solid var(--accent)',
                color: 'var(--accent)',
                background: 'var(--accent-bg)',
              }}
            >
              PRO
            </span>
          </div>
        ))}
      </div>

      <div style={{ marginTop: 'auto', borderTop: '1px solid var(--border)' }}>
        <a href="/logout" style={{ ...row, padding: '9px 16px', color: 'var(--text-dim)' }}>
          {icons['settings']}
          <span>Sign out</span>
        </a>
        <a
          href="https://vetoprotocol.live"
          style={{ ...row, padding: '9px 16px', color: 'var(--text-dim)' }}
        >
          {icons['help']}
          <span>Get Help</span>
        </a>
        <div
          style={{
            borderTop: '1px solid var(--border)',
            padding: '11px 14px',
            display: 'flex',
            alignItems: 'center',
            gap: 10,
          }}
        >
          <span aria-hidden="true" style={avatar(26)}>
            {userId.replace(/^usr_/, '').slice(0, 2).toUpperCase()}
          </span>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ ...truncate, fontSize: 12, lineHeight: 1.2 }}>
              {userId.replace(/^usr_/, '')}
            </div>
            <div style={{ ...truncate, fontSize: 10, color: 'var(--text-faint)', lineHeight: 1.2 }}>
              signed in
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}
