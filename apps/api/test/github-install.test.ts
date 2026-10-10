/**
 * F-01: a GitHub installation must be proved, not asserted.
 *
 * ## The hole
 *
 * `POST /v1/connections/github` took an `installation_id`, asked GitHub what
 * that installation *is*, and stored it against the caller's workspace. The
 * lookup uses the **App JWT**, which can read any installation of this App — so
 * it answers "does this exist" and never "is this yours".
 *
 * The install `state` did not close it either. It proves a flow began in this
 * workspace, as this user, recently. It says nothing about which installation
 * that flow ended at. So an authenticated caller could start a flow, never
 * visit GitHub, and post a stranger's installation id — they are small
 * sequential integers — attaching somebody else's repositories to their own
 * workspace, which this server would then mint real tokens for with the App
 * private key it holds.
 *
 * Two comments in the tree claimed this was already handled. It was not. That
 * is the third time in this codebase a comment has described a control that did
 * not exist, which is why the central assertion below is the attack itself
 * rather than the presence of a check.
 *
 * ## The proof
 *
 * With user authorization enabled on the App, the post-install redirect carries
 * a `code`. It exchanges for a *user* token, and `GET /user/installations` with
 * that token lists only what that person can reach. `fetch` is stubbed here, so
 * nothing talks to GitHub.
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
/** GitHub App and user authorization both configured. */
let app: FastifyInstance;
/** The App configured but user authorization absent — must refuse to begin. */
let halfConfigured: FastifyInstance;

const s = suffix();
const WS = `ws_ghi${s}`;
const ALICE = `usr_alice${s}`;

/** A throwaway RSA key, generated per run. Nothing real is involved. */
const { privateKey } = await import('node:crypto').then((c) =>
  c.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  }),
);

const GITHUB = { appId: '12345', appSlug: 'veto-test-app', privateKeyPem: privateKey };
const USER_AUTH = { clientId: 'Iv1.testclientid', clientSecret: 'test-client-secret' };

/** Installations the stubbed user token can reach. */
const MINE = '11111111';
/** A real installation belonging to somebody else entirely. */
const STRANGERS = '99887766';

const CODE = 'abcdefgh12345678';

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  await seed(pool, WS, [ALICE]);

  const common = {
    pool,
    redis,
    policy: createFakePolicyFacts(),
    decisions: createFakePolicyDecisions(),
    wrapper: createLocalKeyWrapper(randomBytes(32).toString('base64')),
    authenticate: headerAuthenticator(),
  };

  app = createApp({ ...common, github: GITHUB, githubUserAuth: USER_AUTH });
  halfConfigured = createApp({ ...common, github: GITHUB, githubUserAuth: null });
  await Promise.all([app.ready(), halfConfigured.ready()]);
});

afterAll(async () => {
  await Promise.all([app.close(), halfConfigured.close()]);
  await pool.end();
  redis.disconnect();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/**
 * GitHub, as far as this server is concerned.
 *
 * The user token reaches exactly one installation: `MINE`. `STRANGERS` exists
 * and the App can read it — which is precisely why the App-JWT lookup was never
 * a check on ownership.
 */
function stubGitHub(options: { reachable?: readonly string[]; codeValid?: boolean } = {}) {
  const reachable = options.reachable ?? [MINE];
  const codeValid = options.codeValid ?? true;

  vi.stubGlobal('fetch', async (url: unknown, init: unknown) => {
    const href = String(url);
    const json = (body: unknown, status = 200) =>
      new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

    if (href === 'https://github.com/login/oauth/access_token') {
      const sent = JSON.parse(String((init as { body?: unknown }).body)) as { client_secret?: string };
      // The secret must reach GitHub and nowhere else; asserting it here is how
      // a refactor that stopped sending it would be noticed.
      expect(sent.client_secret).toBe(USER_AUTH.clientSecret);
      // GitHub answers 200 with an `error` field for a bad code, not a 4xx.
      return codeValid
        ? json({ access_token: 'gho_stubbed', token_type: 'bearer' })
        : json({ error: 'bad_verification_code' });
    }

    if (href.startsWith('https://api.github.com/user/installations')) {
      return json({
        total_count: reachable.length,
        installations: reachable.map((id) => ({ id: Number(id) })),
      });
    }

    if (href.startsWith('https://api.github.com/app/installations/')) {
      const id = href.split('/').pop() ?? '';
      return json({
        id: Number(id),
        account: { login: 'someone' },
        permissions: { metadata: 'read', contents: 'read' },
      });
    }

    throw new Error(`unexpected fetch: ${href}`);
  });
}

/** Begin a flow properly and return the state the server issued. */
async function begin(instance: FastifyInstance = app): Promise<string> {
  const response = await instance.inject({
    method: 'GET',
    url: '/v1/connections/github/install-url',
    headers: as(WS, ALICE),
  });
  expect(response.statusCode).toBe(200);
  return response.json().state as string;
}

const connect = (body: Record<string, unknown>, instance: FastifyInstance = app) =>
  instance.inject({
    method: 'POST',
    url: '/v1/connections/github',
    headers: as(WS, ALICE),
    payload: body,
  });

describe('the attack itself', () => {
  it('refuses an installation the caller does not control', async () => {
    // Everything legitimate except the one thing that matters. The attacker
    // began the flow themselves, so the state is genuinely theirs and
    // genuinely unconsumed; only the installation id is somebody else's.
    stubGitHub({ reachable: [MINE] });
    const state = await begin();

    const response = await connect({ installation_id: STRANGERS, state, code: CODE });

    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('ARGUMENT_SCHEMA_INVALID');

    // And nothing was stored.
    const list = await app.inject({ method: 'GET', url: '/v1/connections', headers: as(WS, ALICE) });
    expect(list.json().connections).toEqual([]);
  });

  it('accepts the same request for an installation the caller does control', async () => {
    // The control: identical shape, different id. If this failed the test
    // above would prove nothing, because everything would be refused.
    stubGitHub({ reachable: [MINE, STRANGERS] });
    const state = await begin();

    const response = await connect({ installation_id: MINE, state, code: CODE });

    expect(response.statusCode).toBe(201);
    expect(response.json().provider).toBe('github');
  });

  it('tells a prober nothing about whether the installation exists', async () => {
    stubGitHub({ reachable: [MINE] });

    const notTheirs = await connect({
      installation_id: STRANGERS,
      state: await begin(),
      code: CODE,
    });
    const notReal = await connect({
      installation_id: '40404040',
      state: await begin(),
      code: CODE,
    });

    // Same status, same code, same message. Enumerating ids learns nothing.
    expect(notReal.statusCode).toBe(notTheirs.statusCode);
    expect(notReal.json()).toEqual(notTheirs.json());
  });
});

describe('the proof has to be present and real', () => {
  it('refuses a request with no code at all', async () => {
    stubGitHub();
    const state = await begin();

    const response = await connect({ installation_id: MINE, state });

    // The schema requires it, so an optional proof is not even representable.
    expect(response.statusCode).toBe(400);
  });

  it('refuses a code GitHub rejects', async () => {
    stubGitHub({ codeValid: false });
    const state = await begin();

    const response = await connect({ installation_id: MINE, state, code: CODE });

    expect(response.statusCode).toBe(400);
  });

  it('refuses when GitHub cannot be reached at all', async () => {
    // Fails closed. An outage at the provider must not become a way to skip
    // the check (invariant 1).
    vi.stubGlobal('fetch', async () => {
      throw new Error('network down');
    });
    const state = await begin();

    const response = await connect({ installation_id: MINE, state, code: CODE });

    expect(response.statusCode).toBe(400);
  });

  it('looks past the first page of installations', async () => {
    // Somebody in many organisations must not have a legitimate installation
    // judged not theirs because it sat on page two.
    const many = Array.from({ length: 100 }, (_, i) => String(200000 + i));
    stubGitHub({ reachable: [...many, MINE] });
    const state = await begin();

    const response = await connect({ installation_id: MINE, state, code: CODE });

    expect(response.statusCode).toBe(201);
  });
});

describe('the state is the server’s, not the caller’s', () => {
  it('issues one rather than accepting one', async () => {
    stubGitHub();
    const response = await app.inject({
      method: 'GET',
      url: '/v1/connections/github/install-url',
      headers: as(WS, ALICE),
    });

    expect(response.statusCode).toBe(200);
    expect(typeof response.json().state).toBe('string');
    expect(response.json().state.length).toBeGreaterThanOrEqual(16);
    // And it is in the URL the browser will follow.
    expect(response.json().url).toContain(response.json().state);
  });

  it('refuses a caller that tries to choose its own', async () => {
    stubGitHub();
    const response = await app.inject({
      method: 'GET',
      url: `/v1/connections/github/install-url?state=${'z'.repeat(32)}`,
      headers: as(WS, ALICE),
    });

    // `additionalProperties: false`. A value the caller picks is not CSRF
    // protection against the caller.
    expect(response.statusCode).toBe(400);
  });

  it('mints a different state every time', async () => {
    stubGitHub();
    expect(await begin()).not.toBe(await begin());
  });
});

describe('a server that cannot prove ownership does not begin', () => {
  it('refuses to issue an install URL without user authorization configured', async () => {
    stubGitHub();
    const response = await halfConfigured.inject({
      method: 'GET',
      url: '/v1/connections/github/install-url',
      headers: as(WS, ALICE),
    });

    // Refused at the start, not after somebody has picked repositories on
    // GitHub's screen and come back to find this server cannot finish.
    expect(response.statusCode).toBe(503);
  });

  it('refuses to complete one either', async () => {
    stubGitHub();
    const state = 'f'.repeat(32);
    await redis.set(`veto:${WS}:ghinst:${state}`, ALICE, 'EX', 900);

    const response = await connect(
      { installation_id: MINE, state, code: CODE },
      halfConfigured,
    );

    expect(response.statusCode).toBe(503);
  });
});
