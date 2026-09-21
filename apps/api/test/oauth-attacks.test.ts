/**
 * The §12.1 list, applied to the authorization server.
 *
 * `packages/oauth` proves each mechanism alone and `tools/e2e/oauth-flow.ts`
 * proves the happy path through real services. What is left is the seam: the
 * things that are only wrong when two correct pieces are combined, and the
 * things that change *between* a human approving and a client exchanging.
 */

import { randomBytes, createHash } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, createFakePolicyFacts } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import { verifyCapability, GATEWAY_AUDIENCE } from '@veto/tokens';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_at${s}`;
const OTHER_WS = `ws_at2${s}`;
const ALICE = `usr_alice${s}`;
const CAROL = `usr_carol${s}`;
const SECRET = randomBytes(24).toString('hex');
const REDIRECT = 'http://127.0.0.1:7777/cb';
/**
 * Derived the same way the server derives it, not hardcoded.
 *
 * This constant was `http://127.0.0.1:4100/mcp` and the server now says
 * `http://localhost:4100/mcp`, so every test that minted a code started
 * failing — which is the bug being fixed, reappearing in the test that was
 * supposed to catch it. A test that pins the address cannot notice the address
 * changing.
 */
const RESOURCE = `${(process.env['GATEWAY_PUBLIC_URL'] ?? 'http://localhost:4100').replace(/\/$/, '')}/mcp`;

const verifier = randomBytes(32).toString('base64url');
const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');

let agentId = '';
let otherAgentId = '';
let clientId = '';
let rivalClientId = '';

const oauth = () => ({ ...as(WS, ALICE), 'x-test-scope': 'oauth-server' });

const post = (url: string, payload: unknown, headers: Record<string, string> = oauth()) =>
  app.inject({ method: 'POST', url, headers, payload: payload as object });

const registerAgent = async (ws: string, user: string, clientName: string): Promise<string> =>
  (
    await app.inject({
      method: 'POST',
      url: '/v1/agents',
      headers: as(ws, user),
      payload: { provider: 'mcp', client_id: clientName },
    })
  ).json().id as string;

const mintCode = async (over: Record<string, unknown> = {}) =>
  post('/v1/oauth/codes', {
    workspace_id: WS,
    user_id: ALICE,
    agent_id: agentId,
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: challenge,
    resource: RESOURCE,
    ...over,
  });

const exchange = (over: Record<string, unknown>) =>
  post('/v1/oauth/token', {
    grant_type: 'authorization_code',
    client_id: clientId,
    code_verifier: verifier,
    redirect_uri: REDIRECT,
    resource: RESOURCE,
    ...over,
  });

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  await seed(pool, WS, [ALICE]);
  await seed(pool, OTHER_WS, [CAROL]);

  app = createApp({
    pool,
    redis,
    policy: createFakePolicyFacts(),
    decisions: createFakePolicyDecisions(),
    wrapper: createLocalKeyWrapper(randomBytes(32).toString('base64')),
    capabilitySecret: SECRET,
    authenticate: headerAuthenticator(),
  });
  // Registration is rate limited per address, and every injected request
  // reports the same one. A previous run's bucket has an hour to live, so a
  // suite that did not clear it would fail for an hour after one flood test.
  await redis.del('veto:oauth:register:127.0.0.1');
  await redis.del('veto:oauth:token:127.0.0.1');

  await app.ready();

  agentId = await registerAgent(WS, ALICE, `alice-${s}`);
  otherAgentId = await registerAgent(OTHER_WS, CAROL, `carol-${s}`);

  clientId = (
    await post('/v1/oauth/clients', { client_name: 'Honest', redirect_uris: [REDIRECT] })
  ).json().client_id as string;
  rivalClientId = (
    await post('/v1/oauth/clients', {
      client_name: 'Rival',
      redirect_uris: ['http://127.0.0.1:9999/cb'],
    })
  ).json().client_id as string;
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

describe('a code belongs to the client that asked for it', () => {
  it('refuses redemption by a different client', async () => {
    const code = (await mintCode()).json().code as string;

    // The rival has a valid client id of its own. What it does not have is this
    // code's authorization.
    const stolen = await exchange({ code, client_id: rivalClientId });
    expect(stolen.statusCode).toBe(400);
    // The same answer an unknown code gets. "Issued to another client" would
    // confirm the code was real to whoever took it.
    expect(stolen.json().error.code).toBe('APPROVAL_EXPIRED');
  });

  it('spends the code even when the exchange then fails', async () => {
    const code = (await mintCode()).json().code as string;

    // Wrong verifier: the exchange fails after the code is spent.
    await exchange({ code, code_verifier: randomBytes(32).toString('base64url') });

    // A failed exchange must not leave a live code behind to grind against.
    const second = await exchange({ code });
    expect(second.json().error.code).toBe('APPROVAL_EXPIRED');
  });
});

describe('what the exchange must match', () => {
  it('refuses a redirect_uri that is not the approved one', async () => {
    const code = (await mintCode()).json().code as string;
    const response = await exchange({ code, redirect_uri: 'http://127.0.0.1:7777/cb/other' });
    expect(response.statusCode).toBe(400);
  });

  it('refuses a resource other than the approved one', async () => {
    const code = (await mintCode()).json().code as string;
    const response = await exchange({ code, resource: 'https://evil.example' });
    expect(response.json().error.code).toBe('RESOURCE_OUT_OF_SCOPE');
  });
});

describe('the consenting human owns the agent', () => {
  it('refuses a code for an agent belonging to another workspace', async () => {
    // §7.1: the delegator is the human the token acts for, and an agent from
    // another tenant is not theirs to delegate.
    const response = await mintCode({ agent_id: otherAgentId });
    expect([403, 404]).toContain(response.statusCode);
  });

  it('refuses a code for another human’s agent in the same workspace', async () => {
    const bob = `usr_bob${s}`;
    // A second user in the *same* workspace, so this tests ownership rather
    // than tenancy — `seed` would try to create the workspace again.
    await withWorkspace(pool, WS, (db) =>
      db.query(
        `insert into users (id, workspace_id, identity_subject) values ($1,$2,$3)
         on conflict do nothing`,
        [bob, WS, `oidc|${bob}`],
      ),
    );
    const bobsAgent = await registerAgent(WS, bob, `bob-${s}`);

    const response = await mintCode({ agent_id: bobsAgent });
    expect(response.statusCode).toBe(403);
    expect(response.json().error.code).toBe('IDENTITY_UNRESOLVED');
  });
});

describe('revocation between consent and exchange', () => {
  it('refuses to mint a code for an agent revoked first', async () => {
    const doomed = await registerAgent(WS, ALICE, `doomed-${s}`);
    await app.inject({ method: 'DELETE', url: `/v1/agents/${doomed}`, headers: as(WS, ALICE) });

    // Minting a code for a revoked agent would undo a revocation (FR-08).
    const response = await mintCode({ agent_id: doomed });
    expect(response.statusCode).toBe(409);
    expect(response.json().error.code).toBe('AGENT_REVOKED');
  });

  it('issues a token for an agent revoked after the code, which the gateway then refuses', async () => {
    const short = await registerAgent(WS, ALICE, `short-${s}`);
    const code = (await mintCode({ agent_id: short })).json().code as string;

    await app.inject({ method: 'DELETE', url: `/v1/agents/${short}`, headers: as(WS, ALICE) });

    const issued = await exchange({ code });
    // The token endpoint does not re-check: a capability token grants nothing
    // on its own, and the gateway reads the agent's row on every request. This
    // asserts where the line is rather than pretending it is somewhere else —
    // §11's "revocation effective on the next protected request".
    expect(issued.statusCode).toBe(200);

    const claims = verifyCapability(SECRET, issued.json().access_token as string, {
      audience: GATEWAY_AUDIENCE,
    });
    expect(claims?.agentId).toBe(short);

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ status: string }>(`select status from agents where id = $1`, [short]),
    );
    // The row the gateway will read says revoked, so the next request denies.
    expect(rows[0]?.status).toBe('revoked');
  });
});

describe('revoking an agent reaches its OAuth session', () => {
  it('kills the refresh chain, not just the access token', async () => {
    const short = await registerAgent(WS, ALICE, `revoke-${s}`);
    const code = (await mintCode({ agent_id: short })).json().code as string;
    const refresh = (await exchange({ code })).json().refresh_token as string;

    // It works while the agent is live.
    const before = await post('/v1/oauth/token', {
      grant_type: 'refresh_token',
      client_id: clientId,
      refresh_token: refresh,
    });
    expect(before.statusCode).toBe(200);
    const rotated = before.json().refresh_token as string;

    await app.inject({ method: 'DELETE', url: `/v1/agents/${short}`, headers: as(WS, ALICE) });

    // §13 stage 4's exit is revocation across all sessions, and a refresh chain
    // is a session: it outlives every access token it issued. The gateway would
    // refuse what it mints — the agent's row says revoked — so this is not an
    // access hole. It is authority outliving its withdrawal, which
    // "a grant must not outlive the authority it was granted under" forbids.
    const after = await post('/v1/oauth/token', {
      grant_type: 'refresh_token',
      client_id: clientId,
      refresh_token: rotated,
    });
    expect(after.statusCode).toBe(400);
  });
});

describe('an emergency lock reaches OAuth sessions too', () => {
  it('kills every refresh chain in the workspace', async () => {
    const code = (await mintCode()).json().code as string;
    const refresh = (await exchange({ code })).json().refresh_token as string;

    await app.inject({
      method: 'POST',
      url: '/v1/emergency-lock',
      headers: as(WS, ALICE),
      payload: { locked: true },
    });

    // A lock that leaves a way to keep minting credentials is not a lock. The
    // pipeline would deny every request while locked anyway — this is about
    // the chain not surviving the switch, the same way grants do not.
    const after = await post('/v1/oauth/token', {
      grant_type: 'refresh_token',
      client_id: clientId,
      refresh_token: refresh,
    });
    expect(after.statusCode).toBe(400);

    // Unlocking does not hand it back.
    await app.inject({
      method: 'POST',
      url: '/v1/emergency-lock',
      headers: as(WS, ALICE),
      payload: { locked: false },
    });
    const afterUnlock = await post('/v1/oauth/token', {
      grant_type: 'refresh_token',
      client_id: clientId,
      refresh_token: refresh,
    });
    expect(afterUnlock.statusCode).toBe(400);
  });
});

describe('the token it issues', () => {
  it('is audience-pinned to the gateway', async () => {
    const code = (await mintCode()).json().code as string;
    const token = (await exchange({ code })).json().access_token as string;

    expect(verifyCapability(SECRET, token, { audience: GATEWAY_AUDIENCE })).not.toBeNull();
    // A token for the gateway must not open the control plane, or the
    // authorization server would be a way around every scope check.
    expect(verifyCapability(SECRET, token, { audience: 'veto-control-plane' })).toBeNull();
  });

  it('carries the human and agent that were approved, not what the client asked for', async () => {
    const code = (await mintCode()).json().code as string;
    const token = (await exchange({ code })).json().access_token as string;
    const claims = verifyCapability(SECRET, token, { audience: GATEWAY_AUDIENCE });

    expect(claims?.workspaceId).toBe(WS);
    expect(claims?.humanId).toBe(ALICE);
    expect(claims?.agentId).toBe(agentId);
  });

  it('expires well inside the capability ceiling', async () => {
    const code = (await mintCode()).json().code as string;
    const body = (await exchange({ code })).json();
    expect(body.expires_in).toBeLessThanOrEqual(15 * 60);
    expect(body.expires_in).toBeGreaterThan(60);
  });
});

describe('refresh tokens across tenants', () => {
  it('refuses one whose prefix names a workspace it does not belong to', async () => {
    const code = (await mintCode()).json().code as string;
    const refresh = (await exchange({ code })).json().refresh_token as string;

    // Repointing the prefix at another tenant. The hash covers the prefix, so
    // the edited token hashes to something that exists nowhere.
    const repointed = `${OTHER_WS}.${refresh.slice(refresh.indexOf('.') + 1)}`;
    const response = await post('/v1/oauth/token', {
      grant_type: 'refresh_token',
      client_id: clientId,
      refresh_token: repointed,
    });
    expect(response.statusCode).toBe(400);
  });

  it('refuses a refresh token with no workspace prefix at all', async () => {
    const response = await post('/v1/oauth/token', {
      grant_type: 'refresh_token',
      client_id: clientId,
      refresh_token: randomBytes(32).toString('base64url'),
    });
    expect(response.statusCode).toBe(400);
  });
});

describe('the credential that opens the token endpoint', () => {
  it('refuses an ordinary control-plane credential', async () => {
    const code = (await mintCode()).json().code as string;
    const response = await post(
      '/v1/oauth/token',
      { grant_type: 'authorization_code', client_id: clientId, code, code_verifier: verifier,
        redirect_uri: REDIRECT, resource: RESOURCE },
      as(WS, ALICE),
    );
    expect(response.statusCode).toBe(403);
  });
});

describe('the code endpoint does not trust the consent screen', () => {
  it('refuses a redirect_uri the client never registered', async () => {
    // The page validates this before rendering the form, and the form carries
    // it in a hidden field. That is one check, in one place, on a value whose
    // whole purpose is to say where a code gets delivered — so the service that
    // mints the code checks it too.
    const response = await mintCode({ redirect_uri: 'http://127.0.0.1:9999/cb' });
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('REDIRECT_URI_MISMATCH');
  });

  it('refuses a redirect_uri registered by a different client', async () => {
    // `http://127.0.0.1:9999/cb` is the rival's registered URI. Being somebody's
    // does not make it this client's.
    const response = await mintCode({ redirect_uri: 'http://127.0.0.1:9999/cb' });
    expect(response.statusCode).toBe(400);
  });

  it('refuses a resource that is not the gateway', async () => {
    const response = await mintCode({ resource: 'https://evil.example/mcp' });
    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('RESOURCE_OUT_OF_SCOPE');
  });
});

describe('registration is open, and bounded', () => {
  it('rate limits a flood from one address', async () => {
    // The bound is an availability control, not authorization: a registered
    // client holds nothing, so the harm of a flood is storage and noise. The
    // endpoint must stay open, so this is what stops it being unbounded.
    let limited = false;
    for (let attempt = 0; attempt < 90 && !limited; attempt += 1) {
      const response = await post('/v1/oauth/clients', {
        client_name: `Flood ${attempt}`,
        redirect_uris: [REDIRECT],
      });
      if (response.statusCode === 429) limited = true;
    }
    expect(limited).toBe(true);

    // Every injected request reports the same address, so the bucket is shared
    // with every other test in the run. Filling it and walking away would fail
    // whichever file happens to go next — a test that breaks its neighbours is
    // worse than the gap it covers.
    await redis.del('veto:oauth:register:127.0.0.1');
  }, 60_000);

  it('still grants a rate-limited caller nothing, because registration never did', async () => {
    // Worth stating: the limit is not what makes registration safe. A client
    // that gets through it is still only a name and a redirect URI.
    const listed = await app.inject({
      method: 'GET',
      url: `/v1/oauth/clients/${clientId}`,
      headers: oauth(),
    });
    expect(listed.json()).not.toHaveProperty('workspace_id');
    expect(listed.json()).not.toHaveProperty('client_secret');
  });
});

describe('pruning what is finished with', () => {
  it('keeps a live refresh token', async () => {
    const code = (await mintCode()).json().code as string;
    const refresh = (await exchange({ code })).json().refresh_token as string;

    await app.inject({ method: 'POST', url: '/v1/oauth/prune', headers: as(WS, ALICE), payload: {} });

    const still = await post('/v1/oauth/token', {
      grant_type: 'refresh_token',
      client_id: clientId,
      refresh_token: refresh,
    });
    expect(still.statusCode).toBe(200);
  });

  it('keeps a spent token until the grace period is up', async () => {
    const code = (await mintCode()).json().code as string;
    const refresh = (await exchange({ code })).json().refresh_token as string;
    await post('/v1/oauth/token', {
      grant_type: 'refresh_token',
      client_id: clientId,
      refresh_token: refresh,
    });

    const pruneResponse = await app.inject({
      method: 'POST',
      url: '/v1/oauth/prune',
      headers: as(WS, ALICE),
      payload: {},
    });
    expect(pruneResponse.statusCode).toBe(200);
    const pruned = pruneResponse.json();
    // A rotated token is what makes a *reuse* detectable. Deleting it the
    // moment it is spent would turn the strongest signal in the flow into
    // "unknown token", which says nothing.
    const replay = await post('/v1/oauth/token', {
      grant_type: 'refresh_token',
      client_id: clientId,
      refresh_token: refresh,
    });
    expect(replay.json().error.code).toBe('APPROVAL_REPLAYED');
    expect(pruned.refresh_tokens).toBe(0);
  });

  it('deletes a spent token once it is old', async () => {
    const code = (await mintCode()).json().code as string;
    const refresh = (await exchange({ code })).json().refresh_token as string;
    await post('/v1/oauth/token', {
      grant_type: 'refresh_token',
      client_id: clientId,
      refresh_token: refresh,
    });

    await withWorkspace(pool, WS, (db) =>
      db.query(
        `update oauth_refresh_tokens set used_at = now() - interval '30 days'
          where workspace_id = $1 and status <> 'active'`,
        [WS],
      ),
    );

    const pruned = (
      await app.inject({ method: 'POST', url: '/v1/oauth/prune', headers: as(WS, ALICE), payload: {} })
    ).json();
    expect(pruned.refresh_tokens).toBeGreaterThan(0);
  });

  it('never deletes a client that was ever used', async () => {
    const code = (await mintCode()).json().code as string;
    await exchange({ code });

    await withWorkspace(pool, WS, (db) =>
      db.query(`update oauth_clients set created_at = now() - interval '90 days' where id = $1`, [
        clientId,
      ]),
    );

    await app.inject({ method: 'POST', url: '/v1/oauth/prune', headers: as(WS, ALICE), payload: {} });

    // Old, but something descended from it. Its name is part of what an audit
    // reads.
    const found = await app.inject({
      method: 'GET',
      url: `/v1/oauth/clients/${clientId}`,
      headers: oauth(),
    });
    expect(found.statusCode).toBe(200);
  });

  it('deletes an old registration nothing ever used', async () => {
    const orphan = (
      await post('/v1/oauth/clients', { client_name: 'Abandoned', redirect_uris: [REDIRECT] })
    ).json().client_id as string;

    await withWorkspace(pool, WS, (db) =>
      db.query(`update oauth_clients set created_at = now() - interval '90 days' where id = $1`, [
        orphan,
      ]),
    );

    await app.inject({ method: 'POST', url: '/v1/oauth/prune', headers: as(WS, ALICE), payload: {} });

    const gone = await app.inject({
      method: 'GET',
      url: `/v1/oauth/clients/${orphan}`,
      headers: oauth(),
    });
    expect(gone.statusCode).toBe(404);
  });
});
