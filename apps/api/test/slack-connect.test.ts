/**
 * The Slack connect flow over HTTP.
 *
 * The F-01 lesson, applied rather than repeated: the state is minted by the
 * server and never accepted from the caller. Slack needs no equivalent of
 * GitHub's ownership check, because an authorization code cannot be forged and
 * exchanging it with the client secret is itself the proof — which is exactly
 * why GitHub was the odd provider, not the normal one.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { createFakePolicyDecisions, createFakePolicyFacts } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let app: FastifyInstance;
let bare: FastifyInstance;

const s = suffix();
const WS = `ws_slk${s}`;
const OTHER_WS = `ws_slk2${s}`;
const ALICE = `usr_alice${s}`;
const CAROL = `usr_carol${s}`;

const SLACK = {
  clientId: '123.456',
  clientSecret: 'test-slack-secret',
  redirectUri: 'https://app.example/connections/slack/callback',
};

/** Slack always answers 200; the body says whether it worked. */
function stubSlack(body: unknown) {
  vi.stubGlobal('fetch', async () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  );
}

/**
 * Long enough to pass the schema.
 *
 * Shared, because a code that fails validation makes every assertion below
 * pass for the wrong reason — the request is refused before it reaches the
 * thing being tested. One of these started life as `'code'`, four characters
 * against a `minLength: 8`, and four assertions were green on a rejection that
 * had nothing to do with state, rotation or Slack's answer.
 */
const CODE = 'code-from-callback';

const good = {
  ok: true,
  access_token: 'xoxb-fresh',
  refresh_token: 'xoxe-1-rotating',
  expires_in: 43200,
  scope: 'channels:read,channels:history',
  team: { id: 'T0123ABCD', name: 'Example' },
};

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  await seed(pool, WS, [ALICE]);
  await seed(pool, OTHER_WS, [CAROL]);

  const common = {
    pool,
    redis,
    policy: createFakePolicyFacts(),
    decisions: createFakePolicyDecisions(),
    wrapper: createLocalKeyWrapper(randomBytes(32).toString('base64')),
    authenticate: headerAuthenticator(),
  };

  app = createApp({ ...common, slack: SLACK });
  bare = createApp({ ...common, slack: null });
  await Promise.all([app.ready(), bare.ready()]);
});

afterAll(async () => {
  await Promise.all([app.close(), bare.close()]);
  await pool.end();
  redis.disconnect();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const begin = (service = 'channels', instance = app, ws = WS, user = ALICE) =>
  instance.inject({
    method: 'GET',
    url: `/v1/connections/slack/install-url?service=${service}`,
    headers: as(ws, user),
  });

const finish = (body: Record<string, unknown>, instance = app, ws = WS, user = ALICE) =>
  instance.inject({
    method: 'POST',
    url: '/v1/connections/slack',
    headers: as(ws, user),
    payload: body,
  });

describe('beginning an install', () => {
  it('issues the state rather than accepting one', async () => {
    const res = await begin();

    expect(res.statusCode).toBe(200);
    expect(res.json().state.length).toBeGreaterThanOrEqual(16);
    expect(res.json().url).toContain(res.json().state);
  });

  it('refuses a caller that tries to choose its own state', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/v1/connections/slack/install-url?service=channels&state=${'z'.repeat(32)}`,
      headers: as(WS, ALICE),
    });

    // `additionalProperties: false`. CSRF protection the client mints is a
    // token the client can replay against itself.
    expect(res.statusCode).toBe(400);
  });

  it('asks for one service at a time', async () => {
    const pub = await begin('channels');
    const priv = await begin('private_channels');

    expect(pub.json().scopes).toEqual(['channels:read', 'channels:history']);
    expect(priv.json().scopes).toEqual(['groups:read', 'groups:history']);
    // Public consent must not quietly carry private channels.
    expect(pub.json().scopes).not.toContain('groups:history');
  });

  it('refuses a service nobody implements', async () => {
    expect((await begin('everything')).statusCode).toBe(400);
  });

  it('never puts the client secret in a URL a browser follows', async () => {
    expect((await begin()).json().url).not.toContain(SLACK.clientSecret);
  });

  it('refuses when Slack is not configured', async () => {
    expect((await begin('channels', bare)).statusCode).toBe(503);
  });
});

describe('finishing one', () => {
  it('stores what Slack actually granted', async () => {
    stubSlack(good);
    const state = (await begin()).json().state as string;

    const res = await finish({ code: CODE, state });

    expect(res.statusCode).toBe(201);
    expect(res.json().provider).toBe('slack');
    expect(res.json().scopes).toEqual(['channels:read', 'channels:history']);
  });

  it('refuses a state this server never issued', async () => {
    stubSlack(good);
    const res = await finish({ code: CODE, state: 'z'.repeat(32) });

    expect(res.statusCode).toBe(400);
  });

  it('refuses a state issued to another workspace', async () => {
    stubSlack(good);
    const state = (await begin('channels', app, OTHER_WS, CAROL)).json().state as string;

    // The key is workspace-scoped, so learning the value is not enough.
    expect((await finish({ code: CODE, state })).statusCode).toBe(400);
  });

  it('consumes the state, so a replayed callback is refused', async () => {
    stubSlack(good);
    const state = (await begin()).json().state as string;

    expect((await finish({ code: CODE, state })).statusCode).toBe(201);
    expect((await finish({ code: CODE, state })).statusCode).toBe(400);
  });

  it('refuses an install with rotation switched off', async () => {
    // No refresh token means a non-expiring bot token, and storing that in the
    // column that promises a rotating credential would be holding one kind of
    // secret while claiming another.
    stubSlack({ ok: true, access_token: 'xoxb-forever', scope: 'channels:read' });
    const state = (await begin()).json().state as string;

    expect((await finish({ code: CODE, state })).statusCode).toBe(400);
  });

  it('refuses when Slack says no, even though it answers 200', async () => {
    stubSlack({ ok: false, error: 'invalid_code' });
    const state = (await begin()).json().state as string;

    expect((await finish({ code: CODE, state })).statusCode).toBe(400);
  });

  it('refuses an unknown field rather than ignoring it', async () => {
    stubSlack(good);
    const state = (await begin()).json().state as string;

    const res = await finish({ code: CODE, state, provider: 'slack' });
    expect(res.statusCode).toBe(400);
  });

  it('never returns anything that could carry the credential', async () => {
    stubSlack(good);
    const state = (await begin()).json().state as string;

    const body = (await finish({ code: CODE, state })).json();

    expect(JSON.stringify(body)).not.toContain('xoxe-1-rotating');
    expect(JSON.stringify(body)).not.toContain('xoxb-fresh');
  });
});
