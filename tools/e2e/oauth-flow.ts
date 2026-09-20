/**
 * The whole OAuth flow, the way a client runs it.
 *
 * Register, authorize, exchange, call the gateway, refresh, and replay. Against
 * the live services, because the point is that the pieces are wired to each
 * other — the unit tests already prove each one alone.
 *
 * The browser step is the one thing simulated: it posts the consent form with a
 * session cookie instead of a person clicking Approve.
 */
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { chromium } from 'playwright';
import { loadRepoEnv } from '@veto/db';
import { mintCapability } from '@veto/tokens';

loadRepoEnv();

const DASH = 'http://localhost:3000';
const GW = 'http://127.0.0.1:4100/mcp';
const WS = process.argv[2] ?? '';
const USER = process.argv[3] ?? '';
const REDIRECT = 'http://127.0.0.1:33418/callback';

const say = (l: string) => process.stdout.write(`${l}\n`);
let failures = 0;
const check = (ok: boolean, label: string, detail = '') => {
  if (!ok) failures += 1;
  say(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ` — ${detail}` : ''}`);
};

const verifier = randomBytes(32).toString('base64url');
const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');

// 1 — register
const reg = await (
  await fetch(`${DASH}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'Flow test client', redirect_uris: [REDIRECT] }),
  })
).json() as Record<string, string>;
check(typeof reg['client_id'] === 'string', 'client registers', reg['client_id']);
const clientId = reg['client_id'] ?? '';

// 2 — the browser half, with a session standing in for a person
const cookie = (() => {
  const secret = process.env['DASHBOARD_SESSION_SECRET'] ?? '';
  const cred = mintCapability(process.env['VETO_CAPABILITY_SECRET'] ?? '', {
    aud: 'veto-control-plane', workspaceId: WS, humanId: USER, agentId: null,
    action: 'control-plane', resource: 'agents', ttlMs: 600_000,
  });
  const body = Buffer.from(
    JSON.stringify({ ws: WS, usr: USER, cred, exp: Date.now() + 600_000 }), 'utf8',
  ).toString('base64url');
  return `${body}.${createHmac('sha256', Buffer.from(secret, 'utf8')).update(body).digest('base64url')}`;
})();

const agents = await (
  await fetch('http://127.0.0.1:4000/v1/agents', {
    headers: {
      authorization: `Bearer ${mintCapability(process.env['VETO_CAPABILITY_SECRET'] ?? '', {
        aud: 'veto-control-plane', workspaceId: WS, humanId: USER, agentId: null,
        action: 'control-plane', resource: 'agents', ttlMs: 600_000,
      })}`,
    },
  })
).json() as { agents: Array<{ id: string; status: string }> };
const agentId = agents.agents.find((a) => a.status !== 'revoked')?.id ?? '';
check(agentId !== '', 'an active agent exists', agentId);

/**
 * Click Approve, in a browser.
 *
 * The consent form is a React server action, which a plain form POST does not
 * reach — and simulating it by calling the control plane directly would test
 * the idea of the flow rather than the flow. So this drives the real page.
 */
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext();
await context.addCookies([
  { name: 'veto_session', value: cookie, domain: 'localhost', path: '/', httpOnly: true, secure: false, sameSite: 'Lax' },
]);

async function approveInBrowser(): Promise<string> {
  const page = await context.newPage();
  const url = `${DASH}/authorize?${new URLSearchParams({
    client_id: clientId,
    redirect_uri: REDIRECT,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    resource: GW,
    state: 'st8',
  }).toString()}`;

  // Nothing listens on that loopback port, so the browser's navigation to it
  // dies before anything can read the URL. Intercepting the request and
  // answering it is how the code is captured — and it is also what a real
  // client does: it *is* the listener on that port.
  let landed = '';
  await page.route(`${REDIRECT}*`, async (route) => {
    landed = route.request().url();
    await route.fulfill({ status: 200, contentType: 'text/plain', body: 'ok' });
  });

  await page.goto(url, { waitUntil: 'domcontentloaded' });
  // By text, not by type: the sidebar's Sign out is also a submit button and
  // comes first in the DOM, so `.first()` signs the tester out instead.
  await page.getByRole('button', { name: 'Approve' }).click();
  await page.waitForTimeout(3000);
  await page.close();

  return landed === '' ? '' : (new URL(landed).searchParams.get('code') ?? '');
}

const code = await approveInBrowser();
check(code !== '', 'approving in the browser yields a code', code.slice(0, 20));

// 3 — exchange
const exchange = async (extra: Record<string, string> = {}) =>
  fetch(`${DASH}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', client_id: clientId, code,
      code_verifier: verifier, redirect_uri: REDIRECT, resource: GW, ...extra,
    }),
  });

const wrongPkce = await (await exchange({ code_verifier: randomBytes(32).toString('base64url') })).json() as Record<string, string>;
check(wrongPkce['error'] === 'invalid_grant' || wrongPkce['error'] === 'invalid_request',
  'a wrong verifier is refused', String(wrongPkce['error']));

// That attempt spent the code, so a fresh approval is needed.
const code2 = await approveInBrowser();

const tokens = await (
  await fetch(`${DASH}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', client_id: clientId, code: code2,
      code_verifier: verifier, redirect_uri: REDIRECT, resource: GW,
    }),
  })
).json() as Record<string, string>;
check(typeof tokens['access_token'] === 'string', 'exchange yields an access token');
check(typeof tokens['refresh_token'] === 'string', 'exchange yields a refresh token');

// 4 — the token actually works at the gateway
const call = await (
  await fetch(GW, {
    method: 'POST',
    headers: { authorization: `Bearer ${tokens['access_token']}`, 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  })
).json() as Record<string, unknown>;
check(call['result'] !== undefined, 'the gateway accepts it', JSON.stringify(call).slice(0, 60));

// 5 — replay the spent code
const replay = await (
  await fetch(`${DASH}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', client_id: clientId, code: code2,
      code_verifier: verifier, redirect_uri: REDIRECT, resource: GW,
    }),
  })
).json() as Record<string, string>;
check(replay['error'] === 'invalid_grant', 'a spent code cannot be replayed', String(replay['error']));

// 6 — refresh, then reuse the old one
const refreshed = await (
  await fetch(`${DASH}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token', client_id: clientId, refresh_token: tokens['refresh_token'] ?? '',
    }),
  })
).json() as Record<string, string>;
check(typeof refreshed['access_token'] === 'string', 'refresh yields a new access token');
check(refreshed['refresh_token'] !== tokens['refresh_token'], 'the refresh token rotated');

const reused = await (
  await fetch(`${DASH}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token', client_id: clientId, refresh_token: tokens['refresh_token'] ?? '',
    }),
  })
).json() as Record<string, string>;
check(reused['error'] === 'invalid_grant', 'the spent refresh token is refused', String(reused['error']));

const afterReuse = await (
  await fetch(`${DASH}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token', client_id: clientId, refresh_token: refreshed['refresh_token'] ?? '',
    }),
  })
).json() as Record<string, string>;
check(afterReuse['error'] === 'invalid_grant', 'reuse revoked the whole chain', String(afterReuse['error']));

await browser.close();
say(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILED`}`);
if (failures > 0) process.exitCode = 1;
