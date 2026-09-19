/**
 * The section nav.
 *
 * Plain links, styled as the site's tracked uppercase labels. `aria-current`
 * rather than colour alone marks the active one, so the distinction survives
 * for anyone who cannot see the contrast difference.
 */

const ITEMS = [
  ['/agents', 'agents'],
  ['/policies', 'policies'],
  ['/connections', 'connections'],
  ['/presence', 'presence'],
  ['/labels', 'labels'],
  ['/approvals', 'approvals'],
  ['/audit', 'audit'],
  ['/alerts', 'alerts'],
] as const;

export function Nav({ active }: { active: string }) {
  return (
    <nav
      aria-label="Sections"
      style={{ display: 'flex', gap: 2, borderBottom: '1px solid var(--border)', marginBottom: 4 }}
    >
      {ITEMS.map(([href, label]) => {
        const on = label === active;
        return (
          <a
            key={href}
            href={href}
            {...(on ? { 'aria-current': 'page' as const } : {})}
            style={{
              padding: '9px 14px',
              fontSize: 10.5,
              letterSpacing: '0.14em',
              textTransform: 'uppercase',
              color: on ? 'var(--text)' : 'var(--text-dim)',
              borderBottom: `1px solid ${on ? 'var(--text)' : 'transparent'}`,
              marginBottom: -1,
            }}
          >
            {label}
          </a>
        );
      })}
    </nav>
  );
}
