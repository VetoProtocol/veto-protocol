/**
 * The Microsoft 365 connect flow over HTTP.
 *
 * Google's shape, so most of what is asserted here is the same: one service per
 * consent screen, PKCE carried through, and a refusal when the app is not
 * configured. Three things are Microsoft's own and get their own tests:
 *
 *  1. **No refresh token is a refusal, not a connection.** It means
 *     `offline_access` was not granted, and the alternative is a connection
 *     that works for an hour and then dies unattended.
 *  2. **`offline_access` is recorded even when Microsoft omits it** from the
 *     response — which it usually does, because it names no resource. Without
 *     it on the connection, every refresh would ask for a scope the connection
 *     did not appear to hold.
 *  3. **Short-form scopes are normalised.** Microsoft answers with either
 *     `Mail.Read` or the full Graph URI, and the broker compares against the
 *     URI. A short-form answer stored verbatim would make every call fail
 *     `SCOPE_NOT_GRANTED` on a connection that is perfectly good — a refusal
 *     pointing at consent when the cause is a string format.
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
const WS = `ws_ms${s}`;
const ALICE = `usr_alice${s}`;

const MICROSOFT = {
  clientId: '11112222-bbbb-3333-cccc-4444dddd5555',
  clientSecret: 'test-ms-secret',
  redirectUri: 'https://app.example/connections/microsoft/callback',
};

/**
 * Long enough to pass the schema, for both fields.
 *
 * Shared, because a value that fails validation makes every assertion below
 * pass for the wrong reason — the request is refused before it reaches the
 * thing being tested. Slack's version of this file had four tests green on a
 * `minLength` rejection that had nothing to do with what they claimed to test.
 * The verifier must also be 43+ characters of the unreserved alphabet.
 */
const CODE = 'code-from-callback';
const VERIFIER = 'v'.repeat(43);

function stubToken(body: unknown, status = 200) {
  vi.stubGlobal('fetch', async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    }),
  );
}

const good = {
  access_token: 'eyJ-fresh',
  refresh_token: 'rt-first',
  expires_in: 3599,
  scope: 'https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read',
};

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

  app = createApp({ ...common, microsoft: MICROSOFT });
  bare = createApp({ ...common, microsoft: null });
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

const begin = (query: string, instance = app) =>
  instance.inject({
    method: 'GET',
    url: `/v1/connections/microsoft/authorize-url?${query}`,
    headers: as(WS, ALICE),
  });

const consent = (service?: string, instance = app) =>
  begin(
    `state=${'s'.repeat(32)}&code_challenge=${'c'.repeat(43)}${
      service === undefined ? '' : `&service=${service}`
    }`,
    instance,
  );

const finish = (body: Record<string, unknown>, instance = app) =>
  instance.inject({
    method: 'POST',
    url: '/v1/connections/microsoft',
    headers: as(WS, ALICE),
    payload: body,
  });

/**
 * The scopes on **one** connection, found by the id its own POST returned.
 *
 * Not "the newest Microsoft connection in the list": these tests each create
 * one, `listConnections` orders `created_at desc`, and an earlier version of
 * this file took `connections[length - 1]` — the *oldest*. The normalisation
 * assertion then read a row written by a different test and passed with the
 * normaliser deleted, which is the exact failure mode this whole file exists to
 * avoid. Verified by deleting the normaliser and watching it go red.
 */
async function storedScopes(id: string): Promise<readonly string[]> {
  const list = await app.inject({
    method: 'GET',
    url: '/v1/connections',
    headers: as(WS, ALICE),
  });
  const found = list.json().connections.find((c: { id: string }) => c.id === id);
  if (!found) throw new Error(`connection ${id} was not in the list`);
  return found.scopes;
}

describe('the consent URL', () => {
  it('carries PKCE and the work-and-school endpoint', async () => {
    const res = await consent('mail');

    expect(res.statusCode).toBe(200);
    const url = new URL(res.json().url);
    // `organizations`, not `common`: a personal Microsoft account has a
    // different Graph surface and is not a Microsoft 365 mailbox.
    expect(url.pathname).toContain('/organizations/');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    // The callback is a server-side route reading a query string. `fragment`
    // never reaches the server, which looks like a dead redirect.
    expect(url.searchParams.get('response_mode')).toBe('query');
  });

  it('asks for one service at a time, and never for both', async () => {
    const mail = (await consent('mail')).json();
    const cal = (await consent('calendar')).json();

    expect(mail.scopes).toContain('https://graph.microsoft.com/Mail.Read');
    expect(mail.scopes).not.toContain('https://graph.microsoft.com/Calendars.Read');
    expect(cal.scopes).toContain('https://graph.microsoft.com/Calendars.Read');
    expect(cal.scopes).not.toContain('https://graph.microsoft.com/Mail.Read');
  });

  it('always asks for offline access, or the connection dies in an hour', async () => {
    for (const service of ['mail', 'calendar']) {
      expect((await consent(service)).json().scopes).toContain('offline_access');
    }
  });

  it('refuses a service it does not know, rather than substituting one', async () => {
    // `additionalProperties: false` plus a closed enum. Substituting one
    // service for another is the one thing a consent screen must never do:
    // that is how "connect Calendar" once stored a Drive grant.
    expect((await consent('onedrive')).statusCode).toBe(400);
  });

  it('refuses when Microsoft is not configured, rather than half-working', async () => {
    expect((await consent('mail', bare)).statusCode).toBe(503);
  });
});

describe('finishing the connection', () => {
  it('stores what was granted and returns no credential', async () => {
    stubToken(good);
    const res = await finish({ code: CODE, code_verifier: VERIFIER });

    expect(res.statusCode).toBe(201);
    expect(res.json().provider).toBe('microsoft');
    // `Connection` has no field that could carry a refresh token. Asserted
    // against the serialized body, because a response schema is what actually
    // decides which fields leave the process.
    expect(JSON.stringify(res.json())).not.toContain('rt-first');
  });

  it('refuses an exchange that returned no refresh token', async () => {
    // No `refresh_token` means `offline_access` was not granted. Storing this
    // would produce a connection that works and then dies with nobody
    // watching, so it is refused at the one moment the message can say why.
    stubToken({ access_token: 'eyJ-fresh', expires_in: 3599, scope: good.scope });
    const res = await finish({ code: CODE, code_verifier: VERIFIER });

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('ARGUMENT_SCHEMA_INVALID');
  });

  it('records offline_access even though Microsoft omits it', async () => {
    // Microsoft usually leaves it out of `scope`, because it names no
    // resource. Reaching this line at all proves it was granted — a refresh
    // token is issued only when it was — and the scope has to be on the
    // connection because every refresh asks for it.
    stubToken(good);
    const created = await finish({ code: CODE, code_verifier: VERIFIER });

    expect((await storedScopes(created.json().id))).toContain('offline_access');
  });

  it('normalises a short-form scope to the one the broker compares against', async () => {
    // The failure this prevents is nasty: every call refused with
    // SCOPE_NOT_GRANTED on a connection that is perfectly good, pointing at
    // consent when the cause is which of two spellings Microsoft chose.
    stubToken({ ...good, scope: 'Mail.Read User.Read' });
    const created = await finish({ code: CODE, code_verifier: VERIFIER });
    const scopes = await storedScopes(created.json().id);

    expect(scopes).toContain('https://graph.microsoft.com/Mail.Read');
    expect(scopes).not.toContain('Mail.Read');
  });

  it('refuses a verifier too short to be a PKCE verifier', async () => {
    // RFC 7636: 43–128 characters. Checked by the schema, so nothing reaches
    // Microsoft and no fetch stub is needed.
    const res = await finish({ code: CODE, code_verifier: 'short' });
    expect(res.statusCode).toBe(400);
  });

  it('refuses when Microsoft is not configured', async () => {
    const res = await finish({ code: CODE, code_verifier: VERIFIER }, bare);
    expect(res.statusCode).toBe(503);
  });

  it('does not propagate Microsoft’s error text to the caller', async () => {
    // The body echoes the request, which carried the code, and is written for
    // a developer's console. The operator gets the cause from the server log.
    stubToken({ error: 'invalid_client', error_description: 'AADSTS7000215: bad secret' }, 401);
    const res = await finish({ code: CODE, code_verifier: VERIFIER });

    expect(res.statusCode).toBe(400);
    expect(JSON.stringify(res.json())).not.toContain('AADSTS7000215');
  });
});
