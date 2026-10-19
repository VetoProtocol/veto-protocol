/**
 * Starter rules over HTTP.
 *
 * Deny-by-default means a workspace with no rules refuses everything, which
 * looks identical to a broken one. These check the shortcut out of that: what
 * it creates, what it refuses to create, and that it creates nothing twice.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, createFakePolicyFacts } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import { loadPolicies, POLICY_TEMPLATES } from '@veto/decisions';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_tpl${s}`;
const OTHER_WS = `ws_tpl2${s}`;
const ALICE = `usr_alice${s}`;
const CAROL = `usr_carol${s}`;

let agentId: string;

const register = async (ws: string, user: string, clientId: string): Promise<string> => {
  const res = await app.inject({
    method: 'POST',
    url: '/v1/agents',
    headers: as(ws, user),
    payload: { provider: 'mcp', client_id: clientId },
  });
  return res.json().id as string;
};

const apply = (body: Record<string, unknown>, ws = WS, user = ALICE) =>
  app.inject({
    method: 'POST',
    url: '/v1/policies/templates',
    headers: as(ws, user),
    payload: body,
  });

const rulesFor = (ws: string) => withWorkspace(pool, ws, (db) => loadPolicies(db, ws));

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
    authenticate: headerAuthenticator(),
  });
  await app.ready();

  agentId = await register(WS, ALICE, `client-${s}`);
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

describe('the catalogue', () => {
  it('lists the templates, with what each rule does', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/policies/templates',
      headers: as(WS, ALICE),
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().templates).toHaveLength(POLICY_TEMPLATES.length);

    const drive = res.json().templates.find((t: { id: string }) => t.id === 'drive-read');
    expect(drive.requires).toBe('google');
    // Every rule explains itself, because a list of (action, type) pairs is
    // not something somebody can consent to.
    expect(drive.rules.every((r: { explains: string }) => r.explains.length > 0)).toBe(true);
  });

  it('is the same for every workspace, and reads nothing', async () => {
    const mine = await app.inject({
      method: 'GET',
      url: '/v1/policies/templates',
      headers: as(WS, ALICE),
    });
    const theirs = await app.inject({
      method: 'GET',
      url: '/v1/policies/templates',
      headers: as(OTHER_WS, CAROL),
    });

    expect(theirs.json()).toEqual(mine.json());
  });
});

describe('applying one', () => {
  it('creates the template’s rules against the named agent', async () => {
    const res = await apply({ template_id: 'drive-read', subject: agentId });

    expect(res.statusCode).toBe(201);
    expect(res.json().created).toHaveLength(2);
    expect(res.json().skipped).toBe(0);

    const rules = await rulesFor(WS);
    const mine = rules.filter((r) => r.subject === agentId);

    expect(mine.map((r) => r.resourceFilter.type).sort()).toEqual(['google_file', 'google_folder']);
    // Presence narrows: away raises a challenge rather than proceeding.
    expect(mine.every((r) => r.conditions.presence?.includes('active'))).toBe(true);
  });

  it('gives every rule its own version', async () => {
    // Rules are created and deleted, never edited, and each decision records
    // the version that produced it. Two rules sharing a version would make an
    // old decision ambiguous about which text it meant.
    const rules = (await rulesFor(WS)).filter((r) => r.subject === agentId);
    const versions = rules.map((r) => r.version);

    expect(new Set(versions).size).toBe(versions.length);
  });

  it('creates nothing the second time', async () => {
    const again = await apply({ template_id: 'drive-read', subject: agentId });

    expect(again.json().created).toHaveLength(0);
    expect(again.json().skipped).toBe(2);
  });

  it('applies the same template to a different agent independently', async () => {
    const other = await register(WS, ALICE, `client-two-${s}`);
    const res = await apply({ template_id: 'drive-read', subject: other });

    // A rule for one agent is not a rule for another, so nothing is skipped.
    expect(res.json().created).toHaveLength(2);
    expect(res.json().skipped).toBe(0);
  });

  it('writes a deny for writes that nothing can currently perform', async () => {
    const res = await apply({ template_id: 'no-writes', subject: agentId });

    expect(res.json().created.length).toBeGreaterThan(0);

    const denies = (await rulesFor(WS)).filter(
      (r) => r.subject === agentId && r.action === 'write',
    );
    expect(denies.every((r) => r.effect === 'deny')).toBe(true);
  });
});

describe('what it refuses', () => {
  it('404s an unknown template rather than creating nothing quietly', async () => {
    const res = await apply({ template_id: 'does-not-exist', subject: agentId });
    expect(res.statusCode).toBe(404);
  });

  it('requires a subject — there is no default', async () => {
    // A template that quietly applied to every agent would hand the whole
    // workspace the same access on one click.
    const res = await apply({ template_id: 'drive-read' });
    expect(res.statusCode).toBe(400);
  });

  it('refuses a subject that is not an agent id or the wildcard', async () => {
    for (const subject of ['usr_someone', 'everyone', 'agt_'.padEnd(200, 'x')]) {
      const res = await apply({ template_id: 'drive-read', subject });
      expect(res.statusCode).toBe(400);
    }
  });

  it('refuses an unknown field rather than ignoring it', async () => {
    const res = await apply({
      template_id: 'drive-read',
      subject: agentId,
      effect: 'allow',
    });
    expect(res.statusCode).toBe(400);
  });

  it('does not reach into another workspace', async () => {
    // Carol applies to Alice's agent id. The rule lands in Carol's own
    // workspace — subjects are not resolved across tenants — and Alice's rule
    // list is untouched.
    const before = (await rulesFor(WS)).length;

    await apply({ template_id: 'calendar-read', subject: agentId }, OTHER_WS, CAROL);

    expect((await rulesFor(WS)).length).toBe(before);
    expect((await rulesFor(OTHER_WS)).length).toBeGreaterThan(0);
  });
});
