/**
 * GitHub through the gateway (spec §9.1, §3.3 step 8).
 *
 * The property worth testing here is the one GitHub makes possible and Google
 * does not: the token minted for a call carries **only** what that call needs.
 * An installation that can read code still gets an issues-only token for an
 * issue read, so a bug in a later layer cannot turn "look at the ticket" into
 * "read the source".
 *
 * Also here: that the repository being read comes from the authorised resource
 * and not from an argument, which is what stops a search reaching a repository
 * the decision never named.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, type FakePolicyDecisions } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import {
  createConnection,
  GITHUB_CONTENTS_READ,
  GITHUB_ISSUES_READ,
  GITHUB_METADATA_READ,
  GITHUB_PULL_REQUESTS_READ,
  type DriveFile,
  type DriveReader,
  type IssueDetail,
  type IssueReader,
  type IssueSummary,
  type PullRequestDetail,
  type PullRequestDiff,
  type RepoFile,
  type RepoReader,
  type RepoSummary,
  type TreeEntry,
  type UpstreamTokenExchange,
} from '@veto/connections';
import { createGateway } from '../src/app.ts';
import { RPC } from '../src/jsonrpc.ts';
import { SECRET, gatewayToken, rpc, seedAgent, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let policy: FakePolicyDecisions;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_gh${s}`;
const USER = `usr_gh${s}`;
const AGENT = `agt_gh${s}`;

/** GitHub's numeric id, which is what the policy layer sees. */
const REPO = '1296269';

const wrapper = createLocalKeyWrapper(randomBytes(32).toString('base64'));

/** Every scope set this exchange was asked for, in order. */
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
    /* not exercised here */
  },
};

/** Which repository each reader was actually asked about. */
const repoReads: string[] = [];
const searches: Array<{ repoId: string; query: string }> = [];

const repos: RepoReader = {
  async listRepos(): Promise<readonly RepoSummary[]> {
    return [
      { id: REPO, fullName: 'acme/api', isPrivate: true, defaultBranch: 'main', updatedAt: null },
    ];
  },
  async listDirectory(_token, repoId): Promise<readonly TreeEntry[]> {
    repoReads.push(repoId);
    return [{ name: 'README.md', path: 'README.md', type: 'file', size: 12 }];
  },
  async readFile(_token, repoId, path): Promise<RepoFile> {
    repoReads.push(repoId);
    return { repoId, path, ref: null, size: 12, content: 'hello world', omitted: null };
  },
};

const summary: IssueSummary = {
  number: 7,
  title: 'Login fails',
  state: 'open',
  author: 'someone',
  isPullRequest: false,
  labels: ['bug'],
  updatedAt: null,
};

const issues: IssueReader = {
  async search(_token, repoId, query): Promise<readonly IssueSummary[]> {
    searches.push({ repoId, query });
    return [summary];
  },
  async readIssue(_token, repoId): Promise<IssueDetail> {
    repoReads.push(repoId);
    return { ...summary, body: 'it fails', comments: [], truncated: false };
  },
  async readPullRequest(_token, repoId): Promise<PullRequestDetail> {
    repoReads.push(repoId);
    return {
      ...summary,
      isPullRequest: true,
      body: 'fixes it',
      baseRef: 'main',
      headRef: 'fix',
      merged: false,
      changedFiles: 1,
    };
  },
  async readDiff(_token, repoId): Promise<PullRequestDiff> {
    repoReads.push(repoId);
    return {
      number: 7,
      files: [{ path: 'a.ts', status: 'modified', additions: 1, deletions: 0, patch: '@@' }],
      truncated: false,
    };
  },
};

const drive: DriveReader = {
  async listFolder() {
    return [];
  },
  async readFile(_token, fileId): Promise<DriveFile> {
    return { id: fileId, name: fileId, mimeType: null, modifiedTime: null, content: null };
  },
};

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  policy = createFakePolicyDecisions();
  await seedAgent(pool, WS, USER, AGENT, 'claude-desktop');

  await withWorkspace(pool, WS, async (db) => {
    await db.query(
      `insert into presence (workspace_id,user_id,state,source) values ($1,$2,'active','test')`,
      [WS, USER],
    );

    for (const [action, type, id] of [
      ['read', 'github_repo', REPO],
      ['search', 'github_repo', REPO],
      ['search', 'github_account', USER],
    ] as const) {
      await db.query(
        `insert into policies (id,workspace_id,subject,action,resource_filter,conditions,effect,version)
         values ($1,$2,$3,$4,$5,'{}'::jsonb,'allow','polv_gh')`,
        [`pol_${suffix()}${suffix()}`, WS, AGENT, action, JSON.stringify({ type, ids: [id] })],
      );
    }

    // One installation holding everything, so a narrow token is a choice this
    // code made rather than the only thing available.
    await createConnection(db, wrapper, {
      workspaceId: WS,
      userId: USER,
      provider: 'github',
      scopes: [
        GITHUB_METADATA_READ,
        GITHUB_CONTENTS_READ,
        GITHUB_ISSUES_READ,
        GITHUB_PULL_REQUESTS_READ,
      ],
      refreshToken: '4242',
    });
  });

  policy.allow(WS, AGENT, 'read', 'github_repo', REPO);
  policy.allow(WS, AGENT, 'search', 'github_repo', REPO);
  policy.allow(WS, AGENT, 'search', 'github_account', USER);

  app = createGateway({
    pool,
    redis,
    policy,
    capabilitySecret: SECRET,
    publicUrl: 'https://gateway.veto.example',
    authorizationServer: 'https://app.veto.example',
    execute: { wrapper, exchange, drive, githubExchange: exchange, repos, issues },
  });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

const call = (name: string, args: Record<string, unknown>) =>
  app.inject({
    method: 'POST',
    url: '/mcp',
    headers: { authorization: `Bearer ${gatewayToken(WS, USER, AGENT)}` },
    payload: rpc('tools/call', { name, arguments: args }),
  });

const payload = (body: { result: { content: Array<{ text: string }> } }): unknown =>
  JSON.parse(body.result.content[0]?.text ?? '{}');

describe('the token is minted per tool', () => {
  it('gives an issue read no access to file contents', async () => {
    minted.length = 0;
    const body = (await call('github_issue.read', { repo_id: REPO, issue_number: 7 })).json();
    expect(body.error).toBeUndefined();

    // The installation holds contents:read. This call must not receive it.
    expect(minted[0]).toEqual([GITHUB_METADATA_READ, GITHUB_ISSUES_READ]);
    expect(minted[0]).not.toContain(GITHUB_CONTENTS_READ);
  });

  it('gives a file read contents, because that is what it needs', async () => {
    minted.length = 0;
    await call('github_repo.read_file', { repo_id: REPO, path: 'README.md' });

    expect(minted[0]).toEqual([GITHUB_METADATA_READ, GITHUB_CONTENTS_READ]);
    expect(minted[0]).not.toContain(GITHUB_ISSUES_READ);
  });

  it('gives a diff both, because a diff is file content on a review surface', async () => {
    minted.length = 0;
    await call('github_pull.read_diff', { repo_id: REPO, pull_number: 7 });

    expect(minted[0]).toContain(GITHUB_CONTENTS_READ);
    expect(minted[0]).toContain(GITHUB_PULL_REQUESTS_READ);
  });
});

describe('the repository comes from the decision', () => {
  it('reads the id the decision authorised, not one from the arguments', async () => {
    repoReads.length = 0;
    await call('github_repo.read_file', { repo_id: REPO, path: 'README.md' });

    expect(repoReads).toEqual([REPO]);
  });

  it('refuses a repository no policy allows', async () => {
    // Deny by default: a second repository nobody granted is simply refused,
    // and the agent learns nothing about whether it exists.
    const body = (
      await call('github_repo.read_file', { repo_id: '999', path: 'README.md' })
    ).json();

    expect(body.error.code).toBe(RPC.DENIED);
    expect(body.error.data.reason_code).not.toBe('ALLOWED_WITHIN_POLICY');
  });

  it('keeps a search inside the repository it named', async () => {
    searches.length = 0;
    // A query trying to name a different repository still arrives scoped to the
    // authorised one; the reader prepends its own qualifier.
    await call('github_issue.search', { repo_id: REPO, query: 'repo:victim/secrets password' });

    expect(searches[0]?.repoId).toBe(REPO);
  });
});

describe('what comes back', () => {
  it('returns the file content to the caller', async () => {
    const body = (await call('github_repo.read_file', { repo_id: REPO, path: 'README.md' })).json();
    expect(payload(body)).toMatchObject({ path: 'README.md', content: 'hello world' });
  });

  it('lists repositories without naming whose account it is', async () => {
    // The resource is the account, taken from the session. There is no argument
    // here an agent could put somebody else's organisation in.
    const body = (await call('github_repo.list_repos', {})).json();
    expect(body.error).toBeUndefined();
    expect(payload(body)).toMatchObject({ repositories: [{ id: REPO }] });
  });

  it('rejects an argument the schema does not allow', async () => {
    const body = (
      await call('github_repo.read_file', { repo_id: REPO, path: 'README.md', owner: 'victim' })
    ).json();

    // additionalProperties: false. An unknown argument is a malformed call, not
    // one that quietly ignores the extra field.
    expect(body.error.code).toBe(RPC.INVALID_PARAMS);
  });
});
