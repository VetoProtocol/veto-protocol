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
const drive: DriveReader = {
  async listFolder(_token, folderId): Promise<readonly DriveEntry[]> {
    listed.push(folderId);
    return TREE[folderId] ?? [];
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

describe('walking a folder over HTTP', () => {
  it('records the tree, to the bottom', async () => {
    const body = (await sync({ folder_id: 'root' })).json();

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
    expect(minted[0]).toEqual([DRIVE_READONLY_SCOPE]);
  });

  it('grants nobody anything', async () => {
    await sync({ folder_id: 'root' });
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
    listed.length = 0;
    const response = await sync({ folder_id: 'root' }, BARE_WS, CAROL);
    expect(response.statusCode).toBe(409);
    expect(listed).toHaveLength(0);
  });
});
