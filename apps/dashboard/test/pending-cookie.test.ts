/**
 * The pending cookie — a verified sign-in with nowhere to go yet.
 *
 * It carries two things a visitor must not be able to choose: **which human**
 * this is (the subject, used to create a workspace) and **which workspaces they
 * may enter** (the candidate list, used to issue a session). Both are the sort
 * of value that would normally sit in a query string, and neither can.
 *
 * So the assertions here are forgery, substitution and expiry — the same shape
 * as `flow-cookie.test.ts` and `connect-cookie.test.ts`, because it is the same
 * class of secret.
 */

import { beforeAll, describe, expect, it } from 'vitest';

const SECRET = 'p'.repeat(48);

let sealPending: typeof import('../src/lib/pending-cookie.ts').sealPending;
let openPending: typeof import('../src/lib/pending-cookie.ts').openPending;
let sealFlow: typeof import('../src/lib/flow-cookie.ts').sealFlow;
let sealConnect: typeof import('../src/lib/connect-cookie.ts').sealConnect;

beforeAll(async () => {
  process.env['DASHBOARD_SESSION_SECRET'] = SECRET;
  const mod = await import('../src/lib/pending-cookie.ts');
  sealPending = mod.sealPending;
  openPending = mod.openPending;
  sealFlow = (await import('../src/lib/flow-cookie.ts')).sealFlow;
  sealConnect = (await import('../src/lib/connect-cookie.ts')).sealConnect;
});

const pending = () => ({
  subject: 'oidc|newcomer',
  candidates: [{ userId: 'usr_mine', workspaceId: 'ws_mine' }],
  expiresAt: Date.now() + 60_000,
});

describe('pending cookie', () => {
  it('round trips', () => {
    const p = pending();
    expect(openPending(sealPending(p))).toEqual(p);
  });

  it('refuses a substituted subject carrying the original signature', () => {
    // The attack this cookie exists to stop: change the subject and a workspace
    // gets created in somebody else's name.
    const p = pending();
    const [, mac] = sealPending(p).split('.');
    const body = Buffer.from(JSON.stringify({ ...p, subject: 'oidc|theboss' })).toString(
      'base64url',
    );
    expect(openPending(`${body}.${mac}`)).toBeNull();
  });

  it('refuses an added candidate workspace', () => {
    // The other attack: append a tenant you were never in, then "choose" it.
    const p = pending();
    const [, mac] = sealPending(p).split('.');
    const body = Buffer.from(
      JSON.stringify({
        ...p,
        candidates: [...p.candidates, { userId: 'usr_x', workspaceId: 'ws_theirs' }],
      }),
    ).toString('base64url');
    expect(openPending(`${body}.${mac}`)).toBeNull();
  });

  it('refuses a sign-in or connect cookie presented as a pending one', () => {
    // Three cookies, one key, three meanings. Domain separation is what keeps
    // them from being interchangeable.
    const flow = sealFlow({
      verifier: 'v'.repeat(43),
      state: 'state-abc',
      nonce: 'nonce-abc',
      expiresAt: Date.now() + 60_000,
    });
    const connect = sealConnect({
      verifier: 'v'.repeat(43),
      state: 'state-abc',
      expiresAt: Date.now() + 60_000,
    });

    expect(openPending(flow)).toBeNull();
    expect(openPending(connect)).toBeNull();
  });

  it('refuses an expired hand-off', () => {
    expect(openPending(sealPending({ ...pending(), expiresAt: Date.now() - 1 }))).toBeNull();
  });

  it('refuses a blank subject', () => {
    // A blank subject would reach the provision route and be rejected there
    // too, but it should never get that far.
    expect(openPending(sealPending({ ...pending(), subject: '' }))).toBeNull();
  });

  it('refuses a malformed candidate even though the value is signed', () => {
    // Signed by us, so it "should" be fine — but a non-string workspace id would
    // reach the session cookie, which is the tenant selector. Checked anyway.
    const broken = sealPending({
      ...pending(),
      candidates: [{ userId: 'usr_x', workspaceId: 42 }] as never,
    });
    expect(openPending(broken)).toBeNull();
  });

  it('accepts an empty candidate list, which is what a newcomer has', () => {
    const fresh = { ...pending(), candidates: [] };
    expect(openPending(sealPending(fresh))?.candidates).toEqual([]);
  });

  it('refuses garbage', () => {
    for (const bad of ['', 'nodot', '.mac', 'bm90anNvbg.mac']) {
      expect(openPending(bad), bad).toBeNull();
    }
  });
});
