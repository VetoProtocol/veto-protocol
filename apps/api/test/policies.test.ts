/**
 * /v1/policies over HTTP.
 *
 * The rules that decide, and until now the only part of §5 with no way to reach
 * it except SQL. The assertions that matter are about what the endpoint
 * *refuses* to let somebody write, because a rule that looks right and matches
 * nothing is worse than an error: it reads as "the system is broken" rather
 * than "your rule is wrong".
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, createFakePolicyFacts } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import { loadPolicies, matchPolicies } from '@veto/decisions';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_pol${s}`;
const OTHER_WS = `ws_pol2${s}`;
const ALICE = `usr_alice${s}`;
const CAROL = `usr_carol${s}`;
const AGENT = `agt_reader${s}`;

const rule = (over: Record<string, unknown> = {}) => ({
  subject: AGENT,
  action: 'read',
  effect: 'allow',
  resource_filter: { type: 'google_file', prefix: '/Work' },
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
    authenticate: headerAuthenticator(),
  });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

const post = (body: unknown, ws = WS, user = ALICE) =>
  app.inject({
    method: 'POST',
    url: '/v1/policies',
    headers: as(ws, user),
    payload: body as object,
  });

const list = (ws = WS, user = ALICE) =>
  app.inject({ method: 'GET', url: '/v1/policies', headers: as(ws, user) });

describe('writing a rule', () => {
  it('creates one and gives it its own version', async () => {
    const response = await post(rule());
    expect(response.statusCode).toBe(201);

    const body = response.json();
    expect(body.id).toMatch(/^pol_/);
    // Per rule, not per workspace. A decision records the version that produced
    // it, so two rules must never share one.
    expect(body.version).toMatch(/^polv_/);
    expect(body.effect).toBe('allow');

    const second = (
      await post(rule({ resource_filter: { type: 'google_file', prefix: '/Other' } }))
    ).json();
    expect(second.version).not.toBe(body.version);
  });

  it('round trips through the matcher that actually reads it', async () => {
    // The endpoint and the pipeline have to agree about the shape stored in
    // jsonb. Writing through HTTP and matching through the real matcher is the
    // only assertion that catches a mismatch.
    const created = (
      await post(rule({ resource_filter: { type: 'google_file', ids: ['/Work/a.txt'] } }))
    ).json();

    const rules = await withWorkspace(pool, WS, (db) => loadPolicies(db, WS));
    const mine = rules.find((r) => r.id === created.id);
    expect(mine?.resourceFilter).toEqual({ type: 'google_file', ids: ['/Work/a.txt'] });

    const verdict = matchPolicies(mine ? [mine] : [], {
      workspaceId: WS,
      humanId: ALICE,
      agentId: AGENT,
      clientId: 'claude-desktop',
      requestId: 'req_x',
      tool: 'google_drive.read_file',
      action: 'read',
      resource: { type: 'google_file', id: '/Work/a.txt' },
      arguments: {},
      declaredIntent: null,
      destination: null,
      occurredAt: new Date().toISOString(),
    });
    expect(verdict.effect).toBe('allow');
  });

  it('accepts conditions and stores them intact', async () => {
    const created = (
      await post(rule({ conditions: { presence: ['active'], maxPerDay: 25, requireIntent: true } }))
    ).json();

    expect(created.conditions).toEqual({
      presence: ['active'],
      maxPerDay: 25,
      requireIntent: true,
    });
  });
});

describe('what it refuses to write', () => {
  it('refuses a subject that is not an agent id', async () => {
    // A typo'd id produces a rule that matches nothing and looks like a policy
    // engine bug rather than a typo.
    for (const subject of ['agent-1', 'usr_someone', 'AGT_X', '']) {
      expect((await post(rule({ subject }))).statusCode, subject).toBe(400);
    }
  });

  it('accepts the wildcard subject, because it is a real rule', async () => {
    expect((await post(rule({ subject: '*' }))).statusCode).toBe(201);
  });

  it('refuses an action no tool declares', async () => {
    expect((await post(rule({ action: 'delete' }))).statusCode).toBe(400);
    expect((await post(rule({ action: 'READ' }))).statusCode).toBe(400);
  });

  it('refuses an effect outside the three', async () => {
    // §5.3: allow, deny, challenge. Not "warn", not "audit".
    expect((await post(rule({ effect: 'warn' }))).statusCode).toBe(400);
  });

  it('refuses a filter with no resource type', async () => {
    // Would match a resource type invented later — the one rule nobody can
    // review today.
    expect((await post(rule({ resource_filter: { prefix: '/Work' } }))).statusCode).toBe(400);
  });

  it('refuses ids and prefix together rather than silently intersecting them', async () => {
    const response = await post(
      rule({ resource_filter: { type: 'google_file', ids: ['/a'], prefix: '/b' } }),
    );
    expect(response.statusCode).toBe(400);
    expect(response.json().error.message).toMatch(/either/i);
  });

  it('refuses an unknown presence state', async () => {
    expect((await post(rule({ conditions: { presence: ['asleep'] } }))).statusCode).toBe(400);
  });

  it('refuses an unknown condition rather than dropping it', async () => {
    // `removeAdditional` is off app-wide. A condition silently discarded is a
    // rule weaker than the one somebody wrote.
    expect((await post(rule({ conditions: { ipAllowlist: ['10.0.0.1'] } }))).statusCode).toBe(400);
  });

  it('refuses a maxPerDay of zero', async () => {
    // Zero is not a limit, it is a deny — and it should be written as one, so
    // the rule says what it means.
    expect((await post(rule({ conditions: { maxPerDay: 0 } }))).statusCode).toBe(400);
  });

  it('refuses an unknown top-level field', async () => {
    expect((await post(rule({ priority: 10 }))).statusCode).toBe(400);
  });
});

describe('reading and removing', () => {
  it('lists only this workspace’s rules', async () => {
    await post(rule(), OTHER_WS, CAROL);

    const mine = (await list().then((r) => r.json())).policies as Array<{ id: string }>;
    const theirs = (await list(OTHER_WS, CAROL).then((r) => r.json())).policies as Array<{
      id: string;
    }>;

    const ids = new Set(mine.map((p) => p.id));
    for (const p of theirs) expect(ids.has(p.id)).toBe(false);
  });

  it('removes one, and refuses to remove it twice', async () => {
    const created = (await post(rule())).json();

    const first = await app.inject({
      method: 'DELETE',
      url: `/v1/policies/${created.id}`,
      headers: as(WS, ALICE),
    });
    expect(first.statusCode).toBe(200);

    const second = await app.inject({
      method: 'DELETE',
      url: `/v1/policies/${created.id}`,
      headers: as(WS, ALICE),
    });
    expect(second.statusCode).toBe(404);
  });

  it('cannot remove another workspace’s rule', async () => {
    const theirs = (await post(rule(), OTHER_WS, CAROL)).json();

    const response = await app.inject({
      method: 'DELETE',
      url: `/v1/policies/${theirs.id}`,
      headers: as(WS, ALICE),
    });
    // Not found, not forbidden: a caller must not learn that an id exists
    // somewhere else (invariant 4).
    expect(response.statusCode).toBe(404);

    const still = await withWorkspace(pool, OTHER_WS, (db) => loadPolicies(db, OTHER_WS));
    expect(still.map((p) => p.id)).toContain(theirs.id);
  });

  it('records both writing and removing in the audit trail', async () => {
    const created = (await post(rule())).json();
    await app.inject({
      method: 'DELETE',
      url: `/v1/policies/${created.id}`,
      headers: as(WS, ALICE),
    });

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ event_type: string; resource_ref: string }>(
        `select event_type, resource_ref from audit_events
          where workspace_id = $1 and resource_ref like $2 order by seq`,
        [WS, `policy:${created.id}%`],
      ),
    );

    expect(rows.map((r) => r.event_type)).toEqual(['policy.created', 'policy.removed']);
    // The effect is on the row, because removing a deny widens what is possible
    // and that is the direction an auditor cares about.
    expect(rows[1]?.resource_ref).toContain(':allow');
  });

  it('refuses a sign-in credential', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/v1/policies',
      headers: { ...as(WS, ALICE), 'x-test-scope': 'identity-resolve' },
    });
    expect(response.statusCode).toBe(403);
  });
});

describe('a rule with a time window (FR-06)', () => {
  it('accepts working hours', async () => {
    const response = await post({
      subject: AGENT,
      action: 'read',
      effect: 'allow',
      resource_filter: { type: 'google_folder' },
      conditions: { schedule: { from: '09:00', to: '17:00', days: [1, 2, 3, 4, 5] } },
    });
    expect(response.statusCode).toBe(201);
    expect(response.json().conditions.schedule.from).toBe('09:00');
  });

  it('accepts a window that crosses midnight', async () => {
    // A night shift is not a mistake.
    const response = await post({
      subject: AGENT,
      action: 'read',
      effect: 'allow',
      resource_filter: { type: 'google_folder' },
      conditions: { schedule: { from: '22:00', to: '06:00' } },
    });
    expect(response.statusCode).toBe(201);
  });

  it('refuses a window that starts when it ends', async () => {
    // Passes every pattern in the schema and matches nothing, ever. Storing it
    // would mean an operator wrote a rule that silently does nothing.
    const response = await post({
      subject: AGENT,
      action: 'read',
      effect: 'allow',
      resource_filter: { type: 'google_folder' },
      conditions: { schedule: { from: '09:00', to: '09:00' } },
    });
    expect(response.statusCode).toBe(400);
  });

  it('refuses a time that is not a time', async () => {
    for (const bad of ['25:00', '9:00', 'morning', '']) {
      const response = await post({
        subject: AGENT,
        action: 'read',
        effect: 'allow',
        resource_filter: { type: 'google_folder' },
        conditions: { schedule: { from: bad, to: '17:00' } },
      });
      expect(response.statusCode, bad).toBe(400);
    }
  });

  it('refuses a day outside the week', async () => {
    const response = await post({
      subject: AGENT,
      action: 'read',
      effect: 'allow',
      resource_filter: { type: 'google_folder' },
      conditions: { schedule: { from: '09:00', to: '17:00', days: [7] } },
    });
    expect(response.statusCode).toBe(400);
  });
});
