/**
 * POST /v1/grants/sync over HTTP.
 *
 * The walk itself is tested in `hierarchy.test.ts`, where the bounds live.
 * What is asserted here is everything around it: that it needs a live Google
 * connection, that it mints a Drive-only credential, that one tenant cannot
 * walk another's Drive, and — the property the whole feature rests on — that
 * recording containment grants nobody anything.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import {
  createFakePolicyDecisions,
  createFakePolicyFacts,
  FILE_RESOURCE,
  FOLDER_RESOURCE,
  parentFact,
  type FakePolicyFacts,
} from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import {
  createConnection,
  DRIVE_READONLY_SCOPE,
  GMAIL_READONLY_SCOPE,
  type DriveEntry,
  type DriveFile,
  type DriveReader,
  type UpstreamTokenExchange,
} from '@veto/connections';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let policy: FakePolicyFacts;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_sy${s}`;
const BARE_WS = `ws_sy2${s}`;
const ALICE = `usr_alice${s}`;
const CAROL = `usr_carol${s}`;

const FOLDER_MIME = 'application/vnd.google-apps.folder';

const wrapper = createLocalKeyWrapper(randomBytes(32).toString('base64'));

const minted: string[][] = [];
const exchange: UpstreamTokenExchange = {
  async refresh(_token, scopes) {
    minted.push([...scopes]);
    return {
      accessToken: 'ya29.fake',
      expiresAt: new Date(Date.now() + 300_000),
      scopes: [...scopes],
    };
  },
  async revoke() {},
};

/** root holds one file and one folder; the folder holds one more file. */
const TREE: Record<string, readonly DriveEntry[]> = {
  root: [
    { id: 'loose', name: 'loose.txt', mimeType: 'text/plain', modifiedTime: null },
    { id: 'sub', name: 'Sub', mimeType: FOLDER_MIME, modifiedTime: null },
  ],
  sub: [{ id: 'nested', name: 'nested.txt', mimeType: 'text/plain', modifiedTime: null }],
};

const listed: string[] = [];

/**
 * The same shape of tree under any root, so each test can walk its own.
 *
 * Edges already sent to Permit are cached and skipped — that is the point of
 * the cache — so two tests sharing one tree would have the second observe no
 * writes at all. A private root per test is cheaper and clearer than forgetting
 * what was written between them.
 *
 * `root` keeps the original contents so the tests that name it read as before.
 */
function treeFor(root: string): Record<string, readonly DriveEntry[]> {
  if (root === 'root') return TREE;
  const sub = `${root}-sub`;
  return {
    [root]: [
      { id: `${root}-loose`, name: 'loose.txt', mimeType: 'text/plain', modifiedTime: null },
      { id: sub, name: 'Sub', mimeType: FOLDER_MIME, modifiedTime: null },
    ],
    [sub]: [
      { id: `${root}-nested`, name: 'nested.txt', mimeType: 'text/plain', modifiedTime: null },
    ],
  };
}

const drive: DriveReader = {
  async listFolder(_token, folderId): Promise<readonly DriveEntry[]> {
    listed.push(folderId);
    // The original fixture wins: `sub` is a folder inside `root`, not a root of
    // its own. Only ids it does not know are treated as a per-test tree, where
    // `r2` and `r2-sub` both belong to `r2`.
    if (folderId in TREE) return TREE[folderId] ?? [];
    return treeFor(folderId.replace(/-sub$/, ''))[folderId] ?? [];
  },
  async readFile(): Promise<DriveFile> {
    throw new Error('a walk never reads a file');
  },
};

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  policy = createFakePolicyFacts();
  await seed(pool, WS, [ALICE]);
  await seed(pool, BARE_WS, [CAROL]);

  // Only one workspace has a Google account attached. The other is the control.
  await withWorkspace(pool, WS, (db) =>
    createConnection(db, wrapper, {
      workspaceId: WS,
      userId: ALICE,
      provider: 'google',
      // Both scopes, so the "Drive-only token" assertion has something to fail on.
      scopes: [DRIVE_READONLY_SCOPE, GMAIL_READONLY_SCOPE],
      refreshToken: 'refresh-token-value',
    }),
  );

  app = createApp({
    pool,
    redis,
    policy,
    decisions: createFakePolicyDecisions(),
    wrapper,
    exchange,
    drive,
    authenticate: headerAuthenticator(),
  });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

const sync = (body: unknown, ws = WS, user = ALICE) =>
  app.inject({
    method: 'POST',
    url: '/v1/grants/sync',
    headers: as(ws, user),
    payload: body as object,
  });

/**
 * The walk is started by the request and outlives it, so a test has to wait for
 * the job rather than read a finished report out of the response. Polls the
 * status endpoint the same way a screen would.
 */
const settle = async (): Promise<Record<string, unknown>> => {
  for (let i = 0; i < 100; i += 1) {
    const job = (
      await app.inject({ method: 'GET', url: '/v1/grants/sync', headers: as(WS, ALICE) })
    ).json();
    if (job.status !== 'running') return job;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('the walk never settled');
};

describe('walking a folder over HTTP', () => {
  it('records the tree, to the bottom', async () => {
    const started = (await sync({ folder_id: 'root' })).json();
    // Answered immediately, with a job rather than a result.
    expect(started.status).toBe('running');

    const body = await settle();
    expect(body.status).toBe('done');
    expect(body.links).toBe(3);
    const held = await policy.factsFor(WS);
    expect(held).toContain(parentFact(FILE_RESOURCE, 'loose', 'root'));
    expect(held).toContain(parentFact(FOLDER_RESOURCE, 'sub', 'root'));
    // The one that matters: a file nobody named, two levels down.
    expect(held).toContain(parentFact(FILE_RESOURCE, 'nested', 'sub'));
  });

  it('mints a Drive-only token even though the account also holds Gmail', async () => {
    minted.length = 0;
    await sync({ folder_id: 'root' });
    await settle();
    expect(minted[0]).toEqual([DRIVE_READONLY_SCOPE]);
  });

  it('grants nobody anything', async () => {
    await sync({ folder_id: 'root' });
    await settle();
    // Containment says where a file is, not who may read it. An edge under a
    // folder nobody was granted reaches nobody — which is what makes this safe
    // to expose as an operation of its own.
    expect(await policy.listGrants(WS)).toHaveLength(0);
  });

  it('is idempotent', async () => {
    const before = (await policy.factsFor(WS)).length;
    await sync({ folder_id: 'root' });
    expect((await policy.factsFor(WS)).length).toBe(before);
  });
});

describe('what it refuses', () => {
  it('refuses a workspace with no Google connection', async () => {
    const response = await sync({ folder_id: 'root' }, BARE_WS, CAROL);
    expect(response.statusCode).toBe(409);
    expect(response.json().error.code).toBe('CONNECTION_UNKNOWN');
  });

  it('writes nothing for that workspace', async () => {
    // Fails closed: a refused sync leaves no half-built hierarchy behind.
    expect(await policy.factsFor(BARE_WS)).toHaveLength(0);
  });

  it('refuses a folder id that is not a Drive id', async () => {
    for (const folderId of ['/Work', '../root', 'a b', '']) {
      const response = await sync({ folder_id: folderId });
      expect(response.statusCode, folderId).toBe(400);
    }
  });

  it('refuses an argument the schema does not name', async () => {
    const response = await sync({ folder_id: 'root', depth: 99 });
    expect(response.statusCode).toBe(400);
  });

  it('refuses a credential minted for another scope', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/grants/sync',
      headers: { ...as(WS, ALICE), 'x-test-scope': 'gateway' },
      payload: { folder_id: 'root' },
    });
    expect(response.statusCode).toBe(403);
  });
});

describe('tenant isolation', () => {
  it('keeps one workspace’s hierarchy out of another', async () => {
    await sync({ folder_id: 'root' });
    expect(await policy.factsFor(BARE_WS)).toHaveLength(0);
  });

  it('never walks a folder using another tenant’s connection', async () => {
    // Carol names the same folder id Alice's Drive uses. Drive ids are unique
    // and unguessable, which is not the same as being a boundary — the refusal
    // has to come from the connection lookup being tenant-scoped.
    // A walk started by an earlier test outlives it now. Let it finish before
    // watching what gets listed, or its folders count as Carol's.
    await settle().catch(() => undefined);
    listed.length = 0;
    const response = await sync({ folder_id: 'root' }, BARE_WS, CAROL);
    expect(response.statusCode).toBe(409);
    expect(listed).toHaveLength(0);
  });
});

describe('the walk as a job', () => {
  it('answers a second request with the walk already running', async () => {
    // Two screens, or an impatient person. A rival walk would write the same
    // facts twice, more slowly, against the same rate limit.
    //
    // The fake writes instantly, so without a delay the first walk finishes
    // before the second request arrives and there is nothing to collide with —
    // which tests nothing. Slowed just enough to overlap.
    const slow = {
      async recordParent(): Promise<void> {
        await new Promise((r) => setTimeout(r, 60));
      },
    };
    const paced = createApp({
      pool, redis, policy: slow as never, decisions: createFakePolicyDecisions(),
      wrapper, exchange, drive, authenticate: headerAuthenticator(),
    });
    await paced.ready();
    const post = () =>
      paced.inject({
        method: 'POST', url: '/v1/grants/sync',
        headers: { ...as(WS, ALICE), 'content-type': 'application/json' },
        payload: { folder_id: 'root' },
      });

    const [a, b] = await Promise.all([post(), post()]);
    expect(a.json().id).toBe(b.json().id);

    for (let i = 0; i < 100; i += 1) {
      const job = (
        await paced.inject({ method: 'GET', url: '/v1/grants/sync', headers: as(WS, ALICE) })
      ).json();
      if (job.status !== 'running') break;
      await new Promise((r) => setTimeout(r, 20));
    }
    await paced.close();
  });

  it('reports counts only once it has finished', async () => {
    await settle().catch(() => undefined);
    // Its own tree: edges already sent are skipped, so a shared one would show
    // no writes here at all.
    const started = (await sync({ folder_id: 'r2' })).json();
    expect(started.links).toBe(0);
    expect(started.finished_at).toBeNull();

    const done = await settle();
    expect(done.links).toBe(3);
    expect(done.finished_at).not.toBeNull();
  });

  it('records a failure as a sentence rather than losing it', async () => {
    await settle().catch(() => undefined);
    const broken = {
      async recordParent(): Promise<void> {
        throw new Error('permit refused');
      },
    };
    const hobbled = createApp({
      pool,
      redis,
      policy: broken as never,
      decisions: createFakePolicyDecisions(),
      wrapper,
      exchange,
      drive,
      authenticate: headerAuthenticator(),
    });
    await hobbled.ready();

    await hobbled.inject({
      method: 'POST',
      url: '/v1/grants/sync',
      headers: { ...as(WS, ALICE), 'content-type': 'application/json' },
      // A tree nothing has walked, so there is a write available to fail.
      payload: { folder_id: 'r3' },
    });

    for (let i = 0; i < 100; i += 1) {
      const job = (
        await hobbled.inject({ method: 'GET', url: '/v1/grants/sync', headers: as(WS, ALICE) })
      ).json();
      if (job.status === 'failed') {
        // A sentence somebody can act on, and no upstream detail: an error
        // body can echo the request, which carried a token.
        expect(job.error).toMatch(/connected account/i);
        expect(job.error).not.toMatch(/permit refused/);
        await hobbled.close();
        return;
      }
      await new Promise((r) => setTimeout(r, 20));
    }
    await hobbled.close();
    throw new Error('the failure was never recorded');
  });

  it('404s before any walk has been run', async () => {
    const response = await app.inject({
      method: 'GET', url: '/v1/grants/sync', headers: as(BARE_WS, CAROL),
    });
    expect(response.statusCode).toBe(404);
  });
});

describe('a walk that does not finish', () => {
  it('keeps the edges it managed to write', async () => {
    await settle().catch(() => undefined);

    // Accepts three writes, then refuses. The walk fails, but what Permit
    // already took must not be forgotten — otherwise every retry pays for it
    // again and stops at the same place.
    let taken = 0;
    const flaky = {
      async recordParent(): Promise<void> {
        taken += 1;
        // Not a rate limit, so it fails immediately rather than backing off —
        // the property under test is that progress survives a failure, not how
        // long the walk waits before giving up.
        if (taken > 2) throw new Error('permit refused');
      },
    };
    const app2 = createApp({
      pool, redis, policy: flaky as never, decisions: createFakePolicyDecisions(),
      wrapper, exchange, drive, authenticate: headerAuthenticator(),
    });
    await app2.ready();

    await app2.inject({
      method: 'POST', url: '/v1/grants/sync',
      headers: { ...as(WS, ALICE), 'content-type': 'application/json' },
      payload: { folder_id: 'r4' },
    });

    for (let i = 0; i < 200; i += 1) {
      const job = (
        await app2.inject({ method: 'GET', url: '/v1/grants/sync', headers: as(WS, ALICE) })
      ).json();
      if (job.status === 'failed') break;
      await new Promise((r) => setTimeout(r, 20));
    }
    await app2.close();

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ n: number }>(
        `select count(*)::int as n from hierarchy_edges
          where workspace_id = $1 and child_key like 'r4%'`,
        [WS],
      ),
    );
    // The two Permit accepted, remembered despite the failure.
    expect(rows[0]?.n).toBe(2);
  });
});
