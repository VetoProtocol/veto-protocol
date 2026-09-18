import type { Metadata } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import { Mark } from '@/components/mark';
import { StatusDot } from '@/components/chip';
import './globals.css';

// Self-hosted by next/font, so the page pulls no stylesheet from a third party
// and there is no request to an external host carrying a referrer.
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-jetbrains-mono', display: 'swap' });
const sans = Inter({ subsets: ['latin'], variable: '--font-inter', display: 'swap' });

export const metadata: Metadata = {
  title: 'Veto Protocol',
  description: 'Continuous consent for autonomous agents.',
  // Authorization state is not for search engines, and a shared link should not
  // resolve to a cached preview of somebody's agent list.
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${mono.variable} ${sans.variable}`}>
      <body>
        <a href="#main" className="skip-link">
          Skip to content
        </a>

        <header
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '0 22px',
            height: 44,
            borderBottom: '1px solid var(--border)',
          }}
        >
          <span style={{ display: 'flex', alignItems: 'center', gap: 9, color: 'var(--text)' }}>
            <Mark />
            <span style={{ fontSize: 13, letterSpacing: '0.02em' }}>veto</span>
          </span>
          <span style={{ marginLeft: 'auto' }}>
            <StatusDot tone="allow">systems operational</StatusDot>
          </span>
        </header>

        <main id="main" className="grid-ground" style={{ minHeight: 'calc(100vh - 44px)', padding: 22 }}>
          <div style={{ maxWidth: 1180, margin: '0 auto', display: 'grid', gap: 22 }}>{children}</div>
        </main>
      </body>
    </html>
  );
}
