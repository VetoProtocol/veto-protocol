/**
 * Enrol a passkey in a real browser, with a virtual authenticator.
 *
 * WebAuthn cannot be exercised by an HTTP client: the ceremony happens in the
 * browser and needs a device. Chromium's CDP provides one, which is why this is
 * the only way to find out whether the button on `/approvals` works rather than
 * merely exists.
 *
 * `docs/next-steps.md` recorded enrolment as "no browser half". The component
 * was there the whole time. This script is the difference between believing
 * that and knowing it.
 */
import { chromium } from 'playwright';
import { loadRepoEnv } from '@veto/db';

loadRepoEnv();

const DASH = 'http://localhost:3000';
const [cookie] = process.argv.slice(2);
const say = (l: string) => process.stdout.write(`${l}\n`);
let failures = 0;
const check = (ok: boolean, label: string, detail = '') => {
  if (!ok) failures += 1;
  say(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ` — ${detail}` : ''}`);
};

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext();
await context.addCookies([
  { name: 'veto_session', value: cookie ?? '', domain: 'localhost', path: '/',
    httpOnly: true, secure: false, sameSite: 'Lax' },
]);
const page = await context.newPage();

// A device that always says yes. The ceremony is what is under test, not the
// user's thumb.
const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');
const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
  options: {
    protocol: 'ctap2',
    transport: 'internal',
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
});

await page.goto(`${DASH}/approvals`, { waitUntil: 'networkidle' });
check(page.url().includes('/approvals'), 'the approvals page loads', page.url().slice(0, 60));

const button = page.getByRole('button', { name: /enrol a passkey/i });
check(await button.isVisible().catch(() => false), 'the enrol button is on the page');

await page.getByPlaceholder('MacBook Touch ID').fill('E2E virtual device').catch(() => {});
await button.click();
await page.waitForTimeout(6000);

const status = (await page.locator('[aria-live="polite"]').first().innerText().catch(() => '')).trim();
check(status !== '', 'the page says what happened', status.slice(0, 90));
check(!/did not complete|failed|error/i.test(status), 'enrolment succeeded', status.slice(0, 90));

const credentials = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
check(credentials.credentials.length > 0, 'the device holds a credential',
  `${credentials.credentials.length} stored`);

// ---------------------------------------------------------------------------
// Resolving an approval with that device — §13 stage 3's exit condition.
//
// "An away-state sensitive action requires correct user approval." Every part
// of it is unit-tested; the whole of it, through a browser, with a device that
// signs, has never been run.
// ---------------------------------------------------------------------------

const { createPool, withWorkspace } = await import('@veto/db');
const { mintCapability } = await import('@veto/tokens');

const WS = process.argv[3] ?? '';
const USER = process.argv[4] ?? '';
const pool = createPool(process.env['DATABASE_URL']);

const agentId = await withWorkspace(pool, WS, async (db) => {
  const { rows } = await db.query<{ id: string }>(
    `select id from agents where workspace_id = $1 and status = 'active' limit 1`,
    [WS],
  );
  return rows[0]?.id ?? '';
});

// A rule that challenges rather than allows, and presence away so it bites.
await withWorkspace(pool, WS, async (db) => {
  await db.query(
    `insert into policies (id,workspace_id,subject,action,resource_filter,conditions,effect,version)
     values ($1,$2,$3,'read',$4,'{}'::jsonb,'challenge',$5)`,
    [
      `pol_e2e${Date.now().toString(36)}`,
      WS,
      agentId,
      JSON.stringify({ type: 'google_folder', ids: ['root'] }),
      `polv_e2e${Date.now().toString(36)}`,
    ],
  );
  await db.query(
    `insert into presence (workspace_id,user_id,state,source,assurance)
     values ($1,$2,'away','dashboard','low')
     on conflict (workspace_id,user_id) do update set state='away'`,
    [WS, USER],
  );
});

const gatewayToken = mintCapability(process.env['VETO_CAPABILITY_SECRET'] ?? '', {
  aud: 'veto-gateway', workspaceId: WS, humanId: USER, agentId,
  action: 'mcp', resource: 'mcp', ttlMs: 600_000,
});

const ask = async (approvalId?: string) => {
  const response = await fetch('http://127.0.0.1:4100/mcp', {
    method: 'POST',
    headers: { authorization: `Bearer ${gatewayToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: {
        name: 'google_drive.list_folder',
        arguments: { folder_id: 'root', ...(approvalId ? { approval_id: approvalId } : {}) },
      },
    }),
  });
  return (await response.json()) as Record<string, unknown>;
};

const challenged = await ask();
const error = challenged['error'] as { data?: { reason_code?: string; decision_id?: string } } | undefined;
check(
  error?.data?.reason_code === 'USER_AWAY_SENSITIVE_RESOURCE' ||
    error?.data?.reason_code === 'APPROVAL_REQUIRED',
  'an away-state read is challenged, not allowed',
  String(error?.data?.reason_code),
);

await page.goto(`${DASH}/approvals`, { waitUntil: 'networkidle' });
const resolve = page.getByRole('button', { name: /approve/i }).first();
check(await resolve.isVisible().catch(() => false), 'the approval is waiting on the screen');

const buttons = await page.getByRole('button').allInnerTexts();
say(`    buttons: ${JSON.stringify(buttons)}`);
await page.getByRole('button', { name: /approve with passkey/i }).first().click().catch(() => {});
await page.waitForTimeout(7000);
// The database, not the DOM. A resolved approval disappears from the page, so
// an empty status region means either success or a component that never
// rendered — and the row says which.
const { rows: after } = await withWorkspace(pool, WS, (db) =>
  db.query<{ status: string }>(
    `select status from approvals where workspace_id = $1 order by created_at desc limit 1`,
    [WS],
  ),
);
check(after[0]?.status === 'approved', 'the passkey resolved it', String(after[0]?.status));

await pool.end();
await browser.close();
say(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILED`}`);
if (failures > 0) process.exitCode = 1;
