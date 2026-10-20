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

/**
 * The drift that has now bitten twice.
 *
 * Both times the shape was identical: a provider was added to the *type* while
 * `openConnect` still refused anything outside a hardcoded pair. A widened type
 * is not a widened check — and the callback reports the refusal as "that
 * attempt timed out", so it reads as an expiry rather than a rejection and
 * costs a round trip with a real user to find.
 *
 * The existing tests above named Google and GitHub one at a time, which is why
 * they stayed green while Slack was broken. This one iterates the list, so it
 * fails the moment a fourth provider is added and something else is forgotten.
 */
describe('every provider the module admits to', () => {
  let providers: readonly string[];

  beforeAll(async () => {
    providers = (await import('../src/lib/connect-cookie.ts')).CONNECT_PROVIDERS;
  });

  /** The flows that run PKCE, and therefore must carry a verifier. */
  const PKCE = new Set(['google', 'microsoft']);

  it('survives a round trip', () => {
    for (const provider of providers) {
      const sealed = sealConnect({
        // Only a flow with a code challenge carries a verifier.
        verifier: PKCE.has(provider) ? 'v'.repeat(43) : '',
        state: 'state-abc',
        provider: provider as 'google',
        expiresAt: Date.now() + 60_000,
      });

      expect(openConnect(sealed), `${provider} was sealed and then refused`).not.toBeNull();
    }
  });

  /**
   * The other half of that: a PKCE flow whose verifier went missing must be
   * refused, not opened with an empty one.
   *
   * Without this, dropping a provider out of `NEEDS_VERIFIER` would pass both
   * other tests here — and the exchange would then fail at the provider, with a
   * message about a code verifier, on a round trip that cost a real user.
   */
  it('refuses a PKCE flow with no verifier', () => {
    for (const provider of providers) {
      const sealed = sealConnect({
        verifier: '',
        state: 'state-abc',
        provider: provider as 'google',
        expiresAt: Date.now() + 60_000,
      });

      const opened = openConnect(sealed);
      if (PKCE.has(provider)) {
        expect(opened, `${provider} runs PKCE and must not open without a verifier`).toBeNull();
      } else {
        expect(opened, `${provider} has no verifier to carry`).not.toBeNull();
      }
    }
  });

  it('is the set the connect routes actually mint', () => {
    // The other direction: a provider a start route seals but this list does
    // not admit would be refused on the way back, which is the exact bug.
    //
    // Hardcoded on purpose. It fails whenever a provider is added, which forces
    // whoever added it to come back here and confirm the rest of this file was
    // updated too — the check that caught Slack, and then Microsoft.
    expect([...providers].sort()).toEqual(['github', 'google', 'microsoft', 'slack']);
  });
});
