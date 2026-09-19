/* global document, window */
/**
 * Veto dashboard demo recording.
 *
 * Phase 3 of discover -> rehearse -> record. Run with `--rehearse` first: it
 * checks every selector resolves and exits non-zero if one does not, which is
 * cheaper than discovering it in the finished video.
 *
 * The demo is strictly read-only. `Confirm revoke`, `remove` and `stop` all
 * exist on these screens and all destroy real state, so nothing here clicks
 * anything that is not navigation. A demo that wrecks the workspace it is
 * demonstrating is worse than no demo.
 *
 * Several function bodies are handed to `page.evaluate` and run in the browser
 * rather than in Node, which is why this file declares the browser globals.
 */
import { chromium } from 'playwright';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BASE = process.env.DEMO_BASE_URL || 'http://localhost:3000';
const COOKIE = process.env.DEMO_SESSION_COOKIE;
const DECISION = process.env.DEMO_DECISION_ID || 'dec_2mYzQpD3dydv6ctO';
const OUT_DIR = process.env.DEMO_OUT_DIR || path.join(HERE, 'out');
const OUT_NAME = 'veto-dashboard-demo.webm';
const REHEARSAL = process.argv.includes('--rehearse');

const out = (line) => process.stdout.write(`${line}\n`);

// ---------- overlays ----------

async function injectCursor(page) {
  await page.evaluate(() => {
    if (document.getElementById('demo-cursor')) return;
    const cursor = document.createElement('div');
    cursor.id = 'demo-cursor';
    cursor.innerHTML =
      '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">' +
      '<path d="M5 3L19 12L12 13L9 20L5 3Z" fill="white" stroke="black" stroke-width="1.5" stroke-linejoin="round"/></svg>';
    cursor.style.cssText =
      'position:fixed;z-index:999999;pointer-events:none;width:24px;height:24px;' +
      'transition:left .1s,top .1s;filter:drop-shadow(1px 1px 2px rgba(0,0,0,.4));';
    cursor.style.left = '0px';
    cursor.style.top = '0px';
    document.body.appendChild(cursor);
    document.addEventListener('mousemove', (event) => {
      cursor.style.left = `${event.clientX}px`;
      cursor.style.top = `${event.clientY}px`;
    });
  });
}

async function injectSubtitleBar(page) {
  await page.evaluate(() => {
    if (document.getElementById('demo-subtitle')) return;
    const bar = document.createElement('div');
    bar.id = 'demo-subtitle';
    bar.style.cssText =
      'position:fixed;bottom:0;left:0;right:0;z-index:999998;text-align:center;padding:12px 24px;' +
      'background:rgba(0,0,0,.78);color:#fff;font-family:-apple-system,"Segoe UI",sans-serif;' +
      'font-size:16px;font-weight:500;letter-spacing:.3px;transition:opacity .3s;pointer-events:none;';
    bar.textContent = '';
    bar.style.opacity = '0';
    document.body.appendChild(bar);
  });
}

async function showSubtitle(page, text) {
  await page.evaluate((value) => {
    const bar = document.getElementById('demo-subtitle');
    if (!bar) return;
    if (value) {
      bar.textContent = value;
      bar.style.opacity = '1';
    } else {
      bar.style.opacity = '0';
    }
  }, text);
  if (text) await page.waitForTimeout(800);
}

/** Both overlays live in the document, so a navigation destroys them. */
async function dress(page) {
  await injectCursor(page);
  await injectSubtitleBar(page);
}

async function scrollTo(page, top) {
  await page.evaluate((y) => window.scrollTo({ top: y, behavior: 'smooth' }), top);
}

// ---------- helpers ----------

async function ensureVisible(page, selector, label) {
  const el = page.locator(selector).first();
  if (await el.isVisible().catch(() => false)) {
    out(`REHEARSAL OK: "${label}"`);
    return true;
  }
  console.error(`REHEARSAL FAIL: "${label}" - ${selector}`);
  const found = await page
    .evaluate(() =>
      Array.from(document.querySelectorAll('button, input, select, a'))
        .filter((el) => el.offsetParent !== null)
        .map((el) => `${el.tagName} "${(el.textContent || '').trim().slice(0, 28)}"`)
        .join('\n  '),
    )
    .catch(() => '(no DOM)');
  console.error(`  visible:\n  ${found}`);
  return false;
}

async function moveAndClick(page, selector, label, postClickDelay = 900) {
  const el = page.locator(selector).first();
  if (!(await el.isVisible().catch(() => false))) {
    console.error(`WARNING: skipped click - "${label}" not visible`);
    return false;
  }
  try {
    await el.scrollIntoViewIfNeeded();
    await page.waitForTimeout(300);
    const box = await el.boundingBox();
    if (box) {
      // Never teleport. A cursor that jumps reads as a script, not a person.
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 12 });
      await page.waitForTimeout(400);
    }
    await el.click();
  } catch (error) {
    console.error(`WARNING: click failed on "${label}": ${error.message}`);
    return false;
  }
  await page.waitForTimeout(postClickDelay);
  return true;
}

async function panElements(page, selector, maxCount = 6) {
  const elements = await page.locator(selector).all();
  for (let i = 0; i < Math.min(elements.length, maxCount); i += 1) {
    try {
      const box = await elements[i].boundingBox();
      if (box && box.y < 660 && box.y > 40) {
        await page.mouse.move(box.x + Math.min(box.width / 2, 400), box.y + box.height / 2, { steps: 8 });
        await page.waitForTimeout(650);
      }
    } catch (error) {
      console.warn(`WARNING: pan skipped ${i} (${selector}): ${error.message}`);
    }
  }
}

async function goSidebar(page, label, href) {
  await moveAndClick(page, `a[href="${href}"]`, `sidebar ${label}`, 400);
  await page.waitForLoadState('networkidle').catch(() => {});
  await dress(page);
  await page.waitForTimeout(1400);
}

// ---------- the demo ----------

const SIDEBAR = [
  ['Agents', '/agents'],
  ['Connections', '/connections'],
  ['Policies', '/policies'],
  ['Presence', '/presence'],
  ['Audit', '/audit'],
];

if (!COOKIE) {
  console.error('DEMO_SESSION_COOKIE is not set');
  process.exit(2);
}
fs.mkdirSync(OUT_DIR, { recursive: true });

const browser = await chromium.launch({ headless: true });
const contextOptions = { viewport: { width: 1280, height: 720 } };
if (!REHEARSAL) contextOptions.recordVideo = { dir: OUT_DIR, size: { width: 1280, height: 720 } };

const context = await browser.newContext(contextOptions);
await context.addCookies([
  { name: 'veto_session', value: COOKIE, domain: 'localhost', path: '/', httpOnly: true, secure: false, sameSite: 'Lax' },
]);
const page = await context.newPage();

if (REHEARSAL) {
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  let ok = await ensureVisible(page, 'h1', 'dashboard heading');
  for (const [label, href] of SIDEBAR) {
    ok = (await ensureVisible(page, `a[href="${href}"]`, `sidebar ${label}`)) && ok;
  }
  await page.goto(`${BASE}/decisions/${DECISION}`, { waitUntil: 'networkidle' });
  ok = (await ensureVisible(page, 'h1', 'decision heading')) && ok;
  await browser.close();
  if (!ok) {
    console.error('REHEARSAL FAILED - fix selectors before recording');
    process.exit(1);
  }
  out('REHEARSAL PASSED');
} else {
  try {
    await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
    await dress(page);
    await page.waitForTimeout(1200);

    await showSubtitle(page, 'Veto — a consent gateway for AI agents');
    await page.waitForTimeout(2200);
    await showSubtitle(page, 'Every action is allowed, challenged or denied');
    await panElements(page, 'h1, section', 5);
    await page.waitForTimeout(1600);
    await showSubtitle(page, '');
    await page.waitForTimeout(600);

    await goSidebar(page, 'Agents', '/agents');
    await showSubtitle(page, 'The agents allowed to act on your behalf');
    await panElements(page, 'tr', 4);
    await page.waitForTimeout(1800);

    await goSidebar(page, 'Connections', '/connections');
    await showSubtitle(page, 'Google is connected read-only — one service at a time');
    await panElements(page, 'tr, a[href*="google/start"]', 4);
    await page.waitForTimeout(1800);

    await goSidebar(page, 'Policies', '/policies');
    await showSubtitle(page, 'Rules decide the conditions — not who is connected to what');
    await scrollTo(page, 260);
    await page.waitForTimeout(1500);
    await panElements(page, 'tr', 5);
    await page.waitForTimeout(1500);
    await scrollTo(page, 0);
    await page.waitForTimeout(1000);

    await goSidebar(page, 'Presence', '/presence');
    await showSubtitle(page, 'Presence can only narrow an answer. It never grants');
    await panElements(page, 'label, input[type="radio"]', 4);
    await page.waitForTimeout(2000);

    await goSidebar(page, 'Audit', '/audit');
    await showSubtitle(page, 'Every decision recorded, hash-chained to the one before');
    await scrollTo(page, 320);
    await page.waitForTimeout(1800);
    await scrollTo(page, 0);
    await page.waitForTimeout(1200);

    await showSubtitle(page, 'And any one of them opens in full');
    await page.goto(`${BASE}/decisions/${DECISION}`, { waitUntil: 'networkidle' });
    await dress(page);
    await page.waitForTimeout(1500);

    await showSubtitle(page, 'A refusal, and which of the nine steps stopped it');
    await panElements(page, 'h1', 3);
    await page.waitForTimeout(1600);
    await scrollTo(page, 300);
    await page.waitForTimeout(2200);

    await showSubtitle(page, 'Permit answered one question. The decision was Veto’s');
    await scrollTo(page, 620);
    await page.waitForTimeout(2600);

    await showSubtitle(page, 'Nothing was sent upstream');
    await page.waitForTimeout(2400);
    await showSubtitle(page, '');
    await page.waitForTimeout(1500);
  } catch (error) {
    console.error('DEMO ERROR:', error.message);
  } finally {
    await context.close();
    const video = page.video();
    if (video) {
      const source = await video.path();
      const destination = path.join(OUT_DIR, OUT_NAME);
      try {
        fs.copyFileSync(source, destination);
        out(`Video saved: ${destination}`);
      } catch (error) {
        console.error(`ERROR copying video: ${error.message} (${source} -> ${destination})`);
      }
    }
    await browser.close();
  }
}
