/**
 * The connection routes (§9).
 *
 * Most of what matters here is refusal. The consent URL is built server-side so
 * that `redirect_uri` and the scope list cannot be proposed by a caller, and the
 * two values the caller *does* supply — `state` and `code_challenge` — are shape
 * checked before they reach a URL a browser will follow.
 *
 * The code exchange itself is not tested here: it talks to Google. What is
 * tested is that an unconfigured server refuses rather than half-works.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { createFakePolicyDecisions, createFakePolicyFacts } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
/** Google configured. */
let app: FastifyInstance;
/** Google absent — the deployment that must refuse rather than improvise. */
let bare: FastifyInstance;

const s = suffix();
const WS = `ws_cn${s}`;
const ALICE = `usr_alice${s}`;

const GOOGLE = {
  clientId: 'test-client-id.apps.googleusercontent.com',
  clientSecret: 'test-secret',
  redirectUri: 'http://localhost:3000/connections/google/callback',
};

const STATE = 'a'.repeat(32);
const CHALLENGE = 'b'.repeat(43);

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

  app = createApp({ ...common, google: GOOGLE });
  bare = createApp({ ...common, google: null });
  await Promise.all([app.ready(), bare.ready()]);
});

afterAll(async () => {
  await Promise.all([app.close(), bare.close()]);
  await pool.end();
  redis.disconnect();
});

const authorize = (
  query: Record<string, string>,
  instance: FastifyInstance = app,
  headers: Record<string, string> = as(WS, ALICE),
) =>
  instance.inject({
    method: 'GET',
    url: `/v1/connections/google/authorize-url?${new URLSearchParams(query).toString()}`,
    headers,
  });

describe('GET /v1/connections/google/authorize-url', () => {
  it('builds a consent URL the caller could not have influenced', async () => {
    const response = await authorize({ state: STATE, code_challenge: CHALLENGE });
    expect(response.statusCode).toBe(200);

    const body = response.json() as { url: string; scopes: string[] };
    const url = new URL(body.url);

    expect(url.origin + url.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth');
    // redirect_uri and client_id come from server configuration. There is no
    // request parameter that could have set either, which is how §12.1's exact
    // redirect URI requirement is met: there is nothing to validate.
    expect(url.searchParams.get('redirect_uri')).toBe(GOOGLE.redirectUri);
    expect(url.searchParams.get('client_id')).toBe(GOOGLE.clientId);
    expect(url.searchParams.get('state')).toBe(STATE);
    expect(url.searchParams.get('code_challenge')).toBe(CHALLENGE);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  });

  it('asks for Drive read-only and nothing else', async () => {
    // §9.1: scopes stay narrow. Gmail and Calendar are not requested before the
    // integrations that would enforce rules on them exist.
    const body = (await authorize({ state: STATE, code_challenge: CHALLENGE })).json() as {
      url: string;
      scopes: string[];
    };

    expect(body.scopes).toEqual(['https://www.googleapis.com/auth/drive.readonly']);
    expect(new URL(body.url).searchParams.get('scope')).toBe(
      'https://www.googleapis.com/auth/drive.readonly',
    );
  });

  it('asks for offline access, so the grant outlives the hour', async () => {
    const body = (await authorize({ state: STATE, code_challenge: CHALLENGE })).json() as {
      url: string;
    };
    const url = new URL(body.url);
    expect(url.searchParams.get('access_type')).toBe('offline');
    expect(url.searchParams.get('prompt')).toBe('consent');
  });

  it('refuses a code challenge that is not one', async () => {
    // Too short to be a PKCE challenge, and containing a character that would
    // let a caller append parameters to the URL a browser follows.
    for (const bad of ['short', `${CHALLENGE}&scope=mail.google.com`, `${CHALLENGE} `]) {
      const response = await authorize({ state: STATE, code_challenge: bad });
      expect(response.statusCode, bad).toBe(400);
    }
  });

  it('refuses a state that is too short to be unguessable', async () => {
    expect((await authorize({ state: 'abc', code_challenge: CHALLENGE })).statusCode).toBe(400);
  });

  it('refuses an unknown query parameter rather than dropping it', async () => {
    const response = await authorize({
      state: STATE,
      code_challenge: CHALLENGE,
      redirect_uri: 'https://attacker.example/callback',
    });
    expect(response.statusCode).toBe(400);
  });

  it('refuses a credential minted for sign-in', async () => {
    const response = await authorize({ state: STATE, code_challenge: CHALLENGE }, app, {
      ...as(WS, ALICE),
      'x-test-scope': 'identity-resolve',
    });
    expect(response.statusCode).toBe(403);
  });

  it('refuses when Google is not configured, rather than returning a broken URL', async () => {
    const response = await authorize({ state: STATE, code_challenge: CHALLENGE }, bare);
    expect(response.statusCode).toBe(503);
  });
});

describe('POST /v1/connections/google', () => {
  it('refuses when Google is not configured', async () => {
    const response = await bare.inject({
      method: 'POST',
      url: '/v1/connections/google',
      headers: as(WS, ALICE),
      payload: { code: 'x', code_verifier: 'v'.repeat(43) },
    });
    expect(response.statusCode).toBe(503);
  });

  it('refuses a verifier too short to be PKCE', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/connections/google',
      headers: as(WS, ALICE),
      payload: { code: 'x', code_verifier: 'short' },
    });
    expect(response.statusCode).toBe(400);
  });
});

describe('GET /v1/connections', () => {
  it('starts empty and never carries a token field', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/v1/connections',
      headers: as(WS, ALICE),
    });
    expect(response.statusCode).toBe(200);
    // The response schema has no property that could hold a credential, so this
    // asserts the shape rather than the absence of one particular field name.
    expect(response.json()).toEqual({ connections: [] });
  });
});

describe('the GitHub install state is CSRF protection, and only that', () => {
  // These check the state gate: a callback must belong to a flow this server
  // started, for this workspace, for this user, once.
  //
  // What they do **not** check is ownership, and an earlier version of this
  // comment claimed they did — it said the state closed F-01. It never could:
  // the state says a flow began, not which installation it ended at, so a
  // caller could start one, skip GitHub, and post a stranger's id. The proof is
  // the `code`, and it is tested in `github-install.test.ts`.
  //
  // Both gates matter and neither substitutes for the other, which is why they
  // are tested apart. Every payload here carries a `code` because the schema
  // now requires one; none of these requests gets far enough to use it.

  const INSTALLATION = '99887766';
  // Shape-valid, and never exchanged: every request below is refused earlier.
  const CODE = 'abcdefgh12345678';

  it('refuses an installation id with no state at all', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/connections/github',
      headers: as(WS, ALICE),
      payload: { installation_id: INSTALLATION },
    });

    // The schema requires it, so this never reaches GitHub.
    expect(response.statusCode).toBe(400);
  });

  it('refuses a state this server never issued', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/connections/github',
      headers: as(WS, ALICE),
      payload: { installation_id: INSTALLATION, code: CODE, state: 'z'.repeat(32) },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('ARGUMENT_SCHEMA_INVALID');
  });

  it('refuses a state issued to a different workspace', async () => {
    // The key is workspace-scoped, so learning the value is not enough. This
    // is the cross-tenant case the finding was really about.
    const other = `ws_cnx${suffix()}`;
    const stranger = `usr_x${suffix()}`;
    await seed(pool, other, [stranger]);

    const state = 'c'.repeat(32);
    await redis.set(`veto:${other}:ghinst:${state}`, stranger, 'EX', 900);

    const response = await app.inject({
      method: 'POST',
      url: '/v1/connections/github',
      headers: as(WS, ALICE),
      payload: { installation_id: INSTALLATION, code: CODE, state },
    });

    expect(response.statusCode).toBe(400);
    // And the victim's state is still there, unconsumed.
    expect(await redis.get(`veto:${other}:ghinst:${state}`)).toBe(stranger);
    await redis.del(`veto:${other}:ghinst:${state}`);
  });

  it('refuses a state issued to a different user in the same workspace', async () => {
    const state = 'd'.repeat(32);
    await redis.set(`veto:${WS}:ghinst:${state}`, `usr_someoneelse${s}`, 'EX', 900);

    const response = await app.inject({
      method: 'POST',
      url: '/v1/connections/github',
      headers: as(WS, ALICE),
      payload: { installation_id: INSTALLATION, code: CODE, state },
    });

    expect(response.statusCode).toBe(400);
  });

  it('consumes the state, so a replayed callback is refused', async () => {
    const state = 'e'.repeat(32);
    await redis.set(`veto:${WS}:ghinst:${state}`, ALICE, 'EX', 900);

    // The first attempt gets past the state gate and fails after it, because
    // this app has no GitHub configured. That is the point: the gate let it
    // through exactly once, and `getdel` burned the state on the way.
    await app.inject({
      method: 'POST',
      url: '/v1/connections/github',
      headers: as(WS, ALICE),
      payload: { installation_id: INSTALLATION, code: CODE, state },
    });

    expect(await redis.get(`veto:${WS}:ghinst:${state}`)).toBeNull();

    const replay = await app.inject({
      method: 'POST',
      url: '/v1/connections/github',
      headers: as(WS, ALICE),
      payload: { installation_id: INSTALLATION, code: CODE, state },
    });

    expect(replay.statusCode).toBe(400);
    expect(replay.json().error.code).toBe('ARGUMENT_SCHEMA_INVALID');
  });
});
