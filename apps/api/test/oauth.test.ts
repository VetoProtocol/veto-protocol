/**
 * /v1/oauth/clients — registration storage for the §8 authorization server.
 *
 * The route is reached only by the dashboard, with a credential minted for this
 * and nothing else. What is asserted here is the boundary: which credential
 * opens it, what it refuses to store, and that a registered client is a name
 * rather than an authority.
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
let app: FastifyInstance;

const s = suffix();
const WS = `ws_oa${s}`;
const USER = `usr_oa${s}`;

/** The scope the dashboard mints for this, and nothing else. */
const asOAuth = () => ({ ...as(WS, USER), 'x-test-scope': 'oauth-server' });

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  await seed(pool, WS, [USER]);

  app = createApp({
    pool,
    redis,
    policy: createFakePolicyFacts(),
    decisions: createFakePolicyDecisions(),
    wrapper: createLocalKeyWrapper(randomBytes(32).toString('base64')),
    authenticate: headerAuthenticator(),
  });
  // Registration is rate limited per address, and every injected request
  // reports the same one. A previous run's bucket has an hour to live, so a
  // suite that did not clear it would fail for an hour after one flood test.
  await redis.del('veto:oauth:register:127.0.0.1');

  await app.ready();
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

const register = (body: unknown, headers: Record<string, string> = asOAuth()) =>
  app.inject({ method: 'POST', url: '/v1/oauth/clients', headers, payload: body as object });

describe('registering a client', () => {
  it('issues a client id', async () => {
    const response = await register({
      client_name: 'Claude Desktop',
      redirect_uris: ['http://127.0.0.1:7777/cb'],
    });

    expect(response.statusCode).toBe(201);
    expect(String(response.json().client_id)).toMatch(/^oac_/);
  });

  it('issues no client secret', async () => {
    const body = (
      await register({ client_name: 'Cursor', redirect_uris: ['http://127.0.0.1:7777/cb'] })
    ).json();

    // A desktop application cannot keep a secret; issuing one would mean
    // shipping the same value inside every copy.
    expect(body).not.toHaveProperty('client_secret');
  });

  it('can be read back', async () => {
    const id = (
      await register({ client_name: 'Codex', redirect_uris: ['https://app.example.com/cb'] })
    ).json().client_id as string;

    const found = await app.inject({
      method: 'GET',
      url: `/v1/oauth/clients/${id}`,
      headers: asOAuth(),
    });
    expect(found.statusCode).toBe(200);
    expect(found.json().redirect_uris).toEqual(['https://app.example.com/cb']);
  });

  it('answers 404 for a client that does not exist', async () => {
    const found = await app.inject({
      method: 'GET',
      url: '/v1/oauth/clients/oac_nothing',
      headers: asOAuth(),
    });
    expect(found.statusCode).toBe(404);
  });
});

describe('what registration refuses', () => {
  it('refuses cleartext to a remote host', async () => {
    const response = await register({
      client_name: 'Sketchy',
      redirect_uris: ['http://evil.example/cb'],
    });
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('REDIRECT_URI_INVALID');
  });

  it('refuses a registration where only one URI is bad', async () => {
    // A client must not be able to smuggle a cleartext target in beside a
    // good one.
    const response = await register({
      client_name: 'Sketchy',
      redirect_uris: ['https://app.example.com/cb', 'http://evil.example/cb'],
    });
    expect(response.statusCode).toBe(400);
  });

  it('refuses no redirect URI at all', async () => {
    expect((await register({ client_name: 'Nowhere', redirect_uris: [] })).statusCode).toBe(400);
  });

  it('refuses an argument the schema does not name', async () => {
    const response = await register({
      client_name: 'Extra',
      redirect_uris: ['https://app.example.com/cb'],
      workspace_id: WS,
    });
    // A client does not get to nominate its own tenant.
    expect(response.statusCode).toBe(400);
  });
});

describe('the credential that opens it', () => {
  it('refuses an ordinary control-plane credential', async () => {
    const response = await register(
      { client_name: 'Wrong scope', redirect_uris: ['https://app.example.com/cb'] },
      as(WS, USER),
    );
    // A credential minted for the dashboard's own traffic must not reach the
    // authorization server's storage, and the reverse holds too.
    expect(response.statusCode).toBe(403);
  });

  it('refuses a sign-in credential', async () => {
    const response = await register(
      { client_name: 'Wrong scope', redirect_uris: ['https://app.example.com/cb'] },
      { ...as(WS, USER), 'x-test-scope': 'identity-resolve' },
    );
    expect(response.statusCode).toBe(403);
  });

  it('refuses no credential at all', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/oauth/clients',
      payload: { client_name: 'Anonymous', redirect_uris: ['https://app.example.com/cb'] },
    });
    expect(response.statusCode).toBe(401);
  });
});
