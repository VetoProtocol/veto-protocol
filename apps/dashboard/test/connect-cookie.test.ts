/**
 * The connect flow cookie.
 *
 * It carries the PKCE verifier and state across the redirect to Google and
 * back. Forging one is the OAuth CSRF case §12.1 requires a test for: an
 * attacker who could supply a state matching a callback they crafted would
 * attach *their* Google account to the victim's workspace.
 */

import { beforeAll, describe, expect, it } from 'vitest';

const SECRET = 'c'.repeat(48);

let sealConnect: typeof import('../src/lib/connect-cookie.ts').sealConnect;
let openConnect: typeof import('../src/lib/connect-cookie.ts').openConnect;
let sealFlow: typeof import('../src/lib/flow-cookie.ts').sealFlow;

beforeAll(async () => {
  process.env['DASHBOARD_SESSION_SECRET'] = SECRET;
  const mod = await import('../src/lib/connect-cookie.ts');
  sealConnect = mod.sealConnect;
  openConnect = mod.openConnect;
  sealFlow = (await import('../src/lib/flow-cookie.ts')).sealFlow;
});

const flow = () => ({
  verifier: 'v'.repeat(43),
  state: 'state-abc',
  provider: 'google' as const,
  expiresAt: Date.now() + 60_000,
});

describe('connect cookie', () => {
  it('round trips', () => {
    const f = flow();
    expect(openConnect(sealConnect(f))).toEqual(f);
  });

  it('rejects a substituted state carrying the original signature', () => {
    const f = flow();
    const [, mac] = sealConnect(f).split('.');
    const body = Buffer.from(JSON.stringify({ ...f, state: 'attacker-state' })).toString(
      'base64url',
    );
    expect(openConnect(`${body}.${mac}`)).toBeNull();
  });

  it('rejects a cookie signed with a different secret', async () => {
    const sealed = sealConnect(flow());
    process.env['DASHBOARD_SESSION_SECRET'] = 'd'.repeat(48);
    try {
      const fresh = await import('../src/lib/connect-cookie.ts?other');
      expect(fresh.openConnect(sealed)).toBeNull();
    } finally {
      process.env['DASHBOARD_SESSION_SECRET'] = SECRET;
    }
  });

  it('refuses a sign-in flow cookie presented as a connect flow', () => {
    // Domain separation. The two flows end somewhere very different — one
    // issues a session, the other stores a credential against a workspace —
    // so a value minted for one must not satisfy the other even though both
    // are signed with the same key.
    const sealed = sealFlow({
      verifier: 'v'.repeat(43),
      state: 'state-abc',
      nonce: 'nonce-abc',
      expiresAt: Date.now() + 60_000,
    });
    expect(openConnect(sealed)).toBeNull();
  });

  it('refuses an expired attempt', () => {
    const sealed = sealConnect({ ...flow(), expiresAt: Date.now() - 1 });
    expect(openConnect(sealed)).toBeNull();
  });

  it('refuses a well-signed cookie with a blank verifier', () => {
    // A blank verifier would be sent to Google as `code_verifier=`, which is a
    // PKCE exchange with no proof in it. Null here, not an empty string.
    expect(openConnect(sealConnect({ ...flow(), verifier: '' }))).toBeNull();
  });

  it('treats a cookie with no provider as Google', () => {
    // One minted before the field existed may still be in a browser. Google is
    // the only flow that could have minted it, and it still needs a verifier.
    const legacy: Record<string, unknown> = { ...flow() };
    delete legacy['provider'];
    expect(openConnect(sealConnect(legacy as never))?.provider).toBe('google');
  });

  it('accepts a GitHub flow with no verifier, because there is no code', () => {
    // The bug this test exists for: an empty verifier is correct for GitHub,
    // and rejecting it made every install callback report a timeout. Shipped,
    // deployed, and only visible when a human clicked the button.
    const github = { ...flow(), verifier: '', provider: 'github' as const };
    expect(openConnect(sealConnect(github))).toEqual(github);
  });

  it('refuses a provider it does not know', () => {
    const odd = { ...flow(), provider: 'gitlab' as unknown as 'github' };
    expect(openConnect(sealConnect(odd))).toBeNull();
  });

  it('refuses garbage', () => {
    expect(openConnect('')).toBeNull();
    expect(openConnect('nodot')).toBeNull();
    expect(openConnect('.mac')).toBeNull();
    expect(openConnect('bm90anNvbg.mac')).toBeNull();
  });
});
