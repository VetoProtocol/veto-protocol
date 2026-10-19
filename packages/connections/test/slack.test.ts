/**
 * Slack's token exchange.
 *
 * `fetch` is stubbed, so nothing here talks to Slack. Two properties carry
 * most of the weight: Slack reports failure with HTTP 200 and an `ok: false`
 * body, and its refresh token rotates — so the two ways this integration can
 * quietly break are a refusal read as a success, and a replacement credential
 * dropped on the floor.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildSlackInstallUrl,
  createSlackExchange,
  exchangeSlackCode,
  isSlackService,
  SLACK_SERVICES,
  SLACK_SERVICE_NAMES,
} from '../src/slack.ts';

const CONFIG = {
  clientId: '123.456',
  clientSecret: 'not-a-real-secret',
  redirectUri: 'https://app.example/connections/slack/callback',
};

/** Slack always answers 200. The body says whether it worked. */
function stub(body: unknown, status = 200) {
  const seen: { url: string; body: string }[] = [];

  vi.stubGlobal('fetch', async (url: unknown, init: unknown) => {
    seen.push({ url: String(url), body: String((init as { body?: unknown }).body ?? '') });
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  });

  return seen;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('services', () => {
  it('asks for one service at a time, never a list', () => {
    // A connect flow cannot ask for everything by passing a list, because it
    // does not take a list.
    expect(SLACK_SERVICE_NAMES).toEqual(['channels', 'private_channels']);
    expect(isSlackService('channels')).toBe(true);
    expect(isSlackService('everything')).toBe(false);
  });

  it('keeps private channels a separate decision', () => {
    // Bundling them would make the second conversation with a customer
    // invisible.
    expect(SLACK_SERVICES.channels).not.toContain('groups:history');
  });

  it('builds an install URL with bot scopes and no user scope', () => {
    const url = new URL(buildSlackInstallUrl(CONFIG, { service: 'channels', state: 'abc123' }));

    expect(url.searchParams.get('scope')).toBe('channels:read,channels:history');
    expect(url.searchParams.get('state')).toBe('abc123');
    // This app never acts as the installing person.
    expect(url.searchParams.get('user_scope')).toBeNull();
    // And the secret never reaches a URL a browser follows.
    expect(url.href).not.toContain(CONFIG.clientSecret);
  });
});

describe('the install exchange', () => {
  it('reads a rotating credential out of a successful response', async () => {
    stub({
      ok: true,
      access_token: 'xoxb-fresh',
      refresh_token: 'xoxe-1-rotating',
      expires_in: 43200,
      scope: 'channels:read,channels:history',
      team: { id: 'T0123ABCD', name: 'Example' },
    });

    const installed = await exchangeSlackCode(CONFIG, 'code-from-callback');

    expect(installed.refreshToken).toBe('xoxe-1-rotating');
    expect(installed.scopes).toEqual(['channels:read', 'channels:history']);
    expect(installed.teamId).toBe('T0123ABCD');
    expect(installed.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it('treats ok:false as a failure even though the status is 200', async () => {
    // The trap. A status check alone would accept this and hand back an empty
    // token, which fails later and somewhere else.
    stub({ ok: false, error: 'invalid_code' });

    await expect(exchangeSlackCode(CONFIG, 'spent')).rejects.toThrow(/invalid_code/);
  });

  it('refuses an install with no refresh token, and names the setting', async () => {
    // Rotation is off on the app. The alternative — storing the non-expiring
    // bot token in the refresh column — would put a permanent bearer secret
    // where the system promises a rotating one.
    stub({ ok: true, access_token: 'xoxb-forever', scope: 'channels:read' });

    await expect(exchangeSlackCode(CONFIG, 'code')).rejects.toThrow(/token rotation/);
  });

  it('sends the secret to Slack and nowhere else', async () => {
    const seen = stub({
      ok: true,
      access_token: 'a',
      refresh_token: 'r',
      expires_in: 1,
      scope: 'channels:read',
      team: { id: 'T1', name: 'n' },
    });

    await exchangeSlackCode(CONFIG, 'code');

    expect(seen[0]?.url).toBe('https://slack.com/api/oauth.v2.access');
    expect(seen[0]?.body).toContain(encodeURIComponent(CONFIG.clientSecret));
  });
});

describe('refresh', () => {
  it('returns the rotated token for the broker to persist', async () => {
    // The failure this prevents does not happen now. It happens on the second
    // refresh, hours later, on a connection nobody touched.
    stub({
      ok: true,
      access_token: 'xoxb-second',
      refresh_token: 'xoxe-2-next',
      expires_in: 43200,
      scope: 'channels:read,channels:history',
    });

    const grant = await createSlackExchange(CONFIG).refresh('xoxe-1-current', ['channels:read']);

    expect(grant.accessToken).toBe('xoxb-second');
    expect(grant.rotatedRefreshToken).toBe('xoxe-2-next');
  });

  it('omits the rotation when the provider did not send one', async () => {
    // Absent means "unchanged", and the broker must not write an empty string
    // over a working credential.
    stub({ ok: true, access_token: 'xoxb-second', expires_in: 43200, scope: 'channels:read' });

    const grant = await createSlackExchange(CONFIG).refresh('xoxe-1', []);

    expect(grant.rotatedRefreshToken).toBeUndefined();
  });

  it('does not forward the requested scopes, because Slack ignores them', async () => {
    // Unlike GitHub, Slack issues whatever the installation holds. Pretending
    // otherwise would make `UPSTREAM_FOR_TOOL` read as narrowing when it is
    // not — the broker's own scope check is what narrows here.
    const seen = stub({ ok: true, access_token: 'a', expires_in: 1, scope: 'channels:read' });

    await createSlackExchange(CONFIG).refresh('xoxe-1', ['channels:history']);

    expect(seen[0]?.body).toContain('grant_type=refresh_token');
    expect(seen[0]?.body).not.toContain('channels%3Ahistory');
  });

  it('fails loudly when Slack refuses the refresh', async () => {
    stub({ ok: false, error: 'invalid_refresh_token' });

    await expect(createSlackExchange(CONFIG).refresh('spent', [])).rejects.toThrow(
      /invalid_refresh_token/,
    );
  });
});

describe('revoke', () => {
  it('does not let a provider refusal stop a local revocation', async () => {
    // The local credential is destroyed whatever Slack says.
    stub({ ok: false, error: 'token_revoked' });

    await expect(createSlackExchange(CONFIG).revoke('xoxe-1')).resolves.toBeUndefined();
  });
});
