/**
 * `POST /v1/grants/github/sync` — where every repository actually lives.
 *
 * The GitHub counterpart of the folder walk, and the thing that makes a grant
 * on an account reach the repositories under it. Without these edges the
 * account resource exists, the `parent` relation is declared, and the
 * inheritance reaches nothing — which is how the dashboard came to offer
 * "GitHub account — and every repository under it" while meaning no such thing.
 *
 * What is worth asserting:
 *
 *  1. An edge per repository, pointing at the **account** and not at a folder.
 *  2. The account keyed by the Veto user id, so the edge lands where the
 *     decision will look for it.
 *  3. The token minted to list them carries metadata and nothing else.
 *  4. It grants nothing — containment only.
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
  FOLDER_RESOURCE,
  GITHUB_ACCOUNT_RESOURCE,
  GITHUB_REPO_RESOURCE,
  parentFact,
} from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import {
  createConnection,
  GITHUB_CONTENTS_READ,
  GITHUB_METADATA_READ,
  type RepoReader,
  type RepoSummary,
  type UpstreamTokenExchange,
} from '@veto/connections';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let policy: ReturnType<typeof createFakePolicyFacts>;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_ghs${s}`;
const ALICE = `usr_ghs${s}`;

const wrapper = createLocalKeyWrapper(randomBytes(32).toString('base64'));

/** Every scope set the exchange was asked for. */
const minted: string[][] = [];
const exchange: UpstreamTokenExchange = {
  async refresh(_credential, scopes) {
    minted.push([...scopes]);
    return {
      accessToken: 'ghs_fake',
      expiresAt: new Date(Date.now() + 3_600_000),
      scopes: [...scopes],
    };
  },
  async revoke() {
    /* not exercised */
  },
};

const REPOS: readonly RepoSummary[] = [
  {
    id: '524250555',
    fullName: 'acme/b1k1',
    isPrivate: true,
    defaultBranch: 'main',
    updatedAt: null,
  },
  {
    id: '999001',
    fullName: 'acme/other',
    isPrivate: false,
    defaultBranch: 'main',
    updatedAt: null,
  },
];

const repos: RepoReader = {
  async listRepos(): Promise<readonly RepoSummary[]> {
    return REPOS;
  },
  async listDirectory() {
    throw new Error('a sync never lists a directory');
  },
  async readFile() {
    throw new Error('a sync never reads a file');
  },
};

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  policy = createFakePolicyFacts();
  await seed(pool, WS, [ALICE]);

  await withWorkspace(pool, WS, (db) =>
    createConnection(db, wrapper, {
      workspaceId: WS,
      userId: ALICE,
      provider: 'github',
      // Both, so the "metadata-only token" assertion has something to fail on.
      scopes: [GITHUB_METADATA_READ, GITHUB_CONTENTS_READ],
      refreshToken: '4242',
    }),
  );

  app = createApp({
    pool,
    redis,
    policy,
    decisions: createFakePolicyDecisions(),
    wrapper,
    exchange,
    githubExchange: exchange,
    repos,
    authenticate: headerAuthenticator(),
  });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

const sync = () =>
  app.inject({
    method: 'POST',
    url: '/v1/grants/github/sync',
    headers: as(WS, ALICE),
    payload: {},
  });

describe('syncing where repositories live', () => {
  it('writes one edge per repository', async () => {
    const response = await sync();

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ repositories: 2, links: 2, truncated: false });
  });

  it('points each edge at the account, not at a folder', async () => {
    await sync();
    const held = await policy.factsFor(WS);

    // The key is the Veto user id — the same one `normalize` builds for
    // `list_repos`, so the edge lands where the decision looks for it.
    expect(held).toContain(
      parentFact(GITHUB_REPO_RESOURCE, '524250555', ALICE, GITHUB_ACCOUNT_RESOURCE),
    );
    expect(held).toContain(
      parentFact(GITHUB_REPO_RESOURCE, '999001', ALICE, GITHUB_ACCOUNT_RESOURCE),
    );

    // And never against the folder resource. A tuple written there would be the
    // wrong endpoint type, and a grant on a Drive folder would start reaching
    // repositories.
    expect(held).not.toContain(
      parentFact(GITHUB_REPO_RESOURCE, '524250555', ALICE, FOLDER_RESOURCE),
    );
  });

  it('lists them with a metadata-only token', async () => {
    minted.length = 0;
    await sync();

    // The installation can read code. Listing repositories does not need to,
    // so the token minted for it cannot.
    expect(minted[0]).toEqual([GITHUB_METADATA_READ]);
    expect(minted[0]).not.toContain(GITHUB_CONTENTS_READ);
  });

  it('grants nothing', async () => {
    // Containment only. Running this against an account nobody was granted
    // changes nobody's access, which is what makes it safe to expose.
    await sync();
    const held = await policy.factsFor(WS);

    expect(held.filter((fact) => fact.includes('#reader@'))).toEqual([]);
  });
});

describe('what it refuses', () => {
  it('refuses a workspace with no GitHub connection', async () => {
    const bare = `ws_ghx${suffix()}`;
    const carol = `usr_ghx${suffix()}`;
    await seed(pool, bare, [carol]);

    const response = await app.inject({
      method: 'POST',
      url: '/v1/grants/github/sync',
      headers: as(bare, carol),
      payload: {},
    });

    expect(response.statusCode).toBe(409);
    expect(response.json().error.code).toBe('CONNECTION_UNKNOWN');
  });

  it('refuses a body carrying anything at all', async () => {
    // There is nothing to name. An installation's list is what the installer
    // picked, so a parameter here could only be a way to ask about somebody
    // else's account.
    const response = await app.inject({
      method: 'POST',
      url: '/v1/grants/github/sync',
      headers: as(WS, ALICE),
      payload: { account: 'victim' },
    });

    expect(response.statusCode).toBe(400);
  });
});
