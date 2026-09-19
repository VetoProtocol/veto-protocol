import type { Metadata } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import { Mark } from '@/components/mark';
import { StatusDot } from '@/components/chip';
import { Sidebar } from '@/components/sidebar';
import { currentSession } from '@/lib/session';
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

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Read once, here, rather than in every page. The rail needs the workspace
  // and the person; the pages already read it for their own data.
  const session = await currentSession();

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

        {session ? (
          // Signed in: the rail, and the working surface beside it.
          <div style={{ display: 'flex', minHeight: 'calc(100vh - 44px)' }}>
            <Sidebar workspaceId={session.workspaceId} userId={session.userId} />
            <main
              id="main"
              className="grid-ground"
              style={{ flex: '1 1 auto', minWidth: 0, padding: 20, display: 'grid', gap: 18, alignContent: 'start' }}
            >
              {children}
            </main>
          </div>
        ) : (
          // Signed out. No rail — every link on it would refuse, and offering a
          // list of places somebody cannot go is worse than offering none.
          <main
            id="main"
            className="grid-ground"
            style={{ minHeight: 'calc(100vh - 44px)', padding: 22 }}
          >
            <div style={{ maxWidth: 620, margin: '0 auto', display: 'grid', gap: 22 }}>
              {children}
            </div>
          </main>
        )}
      </body>
    </html>
  );
}
