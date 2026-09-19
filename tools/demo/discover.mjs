/* global document */
/**
 * Phase 1 of a demo recording: visit each screen and report what is really on
 * it.
 *
 * Written before any recording script, because you cannot script what you have
 * not seen. Field types, button labels and row counts all drift, and a selector
 * that silently resolves to nothing produces a video that looks fine until
 * somebody watches it.
 *
 * The `page.evaluate` body runs in the browser, which is why this file declares
 * `document` as a global.
 */
import { chromium } from 'playwright';

const BASE = process.env.DEMO_BASE_URL || 'http://localhost:3000';
const COOKIE = process.env.DEMO_SESSION_COOKIE;
const PAGES = ['/', '/agents', '/policies', '/connections', '/presence', '/approvals', '/audit', '/alerts'];

const out = (line) => process.stdout.write(`${line}\n`);

if (!COOKIE) {
  console.error('DEMO_SESSION_COOKIE is not set');
  process.exit(2);
}

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
await context.addCookies([
  { name: 'veto_session', value: COOKIE, domain: 'localhost', path: '/', httpOnly: true, secure: false, sameSite: 'Lax' },
]);
const page = await context.newPage();

for (const route of PAGES) {
  const response = await page
    .goto(BASE + route, { waitUntil: 'networkidle' })
    .catch((e) => ({ status: () => e.message }));

  const info = await page
    .evaluate(() => {
      const visible = (el) => el.offsetParent !== null;
      const seen = [];
      document.querySelectorAll('input, select, textarea, button, a[href], [contenteditable]').forEach((el) => {
        if (!visible(el)) return;
        seen.push(
          [el.tagName, el.type || '', (el.textContent || '').trim().slice(0, 34), el.getAttribute('href') || '']
            .filter(Boolean)
            .join(' | '),
        );
      });
      const h1 = document.querySelector('h1');
      return {
        heading: h1 ? h1.textContent.trim().slice(0, 50) : '(none)',
        rows: document.querySelectorAll('tr, [data-row]').length,
        controls: [...new Set(seen)].slice(0, 14),
      };
    })
    .catch(() => null);

  out(`\n=== ${route} -> ${page.url().replace(BASE, '') || '/'} [${response.status ? response.status() : '?'}]`);
  if (!info) {
    out('  (no DOM)');
    continue;
  }
  out(`  h1: ${info.heading}   rows: ${info.rows}`);
  for (const control of info.controls) out(`   - ${control}`);
}

await browser.close();
