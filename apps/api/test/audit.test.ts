/**
 * The audit timeline over HTTP.
 *
 * Two properties beyond "it returns rows": the timeline is tenant-scoped like
 * everything else, and paging on `seq` cannot skip or repeat an event. An audit
 * trail that quietly drops one is worse than no audit trail, because it is
 * believed.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { writeAuditEvent } from '@veto/identity';
import { createFakePolicyDecisions, createFakePolicyFacts } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_au${s}`;
const OTHER = `ws_ot${s}`;
const ALICE = `usr_alice${s}`;
const CAROL = `usr_carol${s}`;

const TOTAL = 25;

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  await seed(pool, WS, [ALICE]);
  await seed(pool, OTHER, [CAROL]);

  await withWorkspace(pool, WS, async (db) => {
    for (let i = 0; i < TOTAL; i += 1) {
      await writeAuditEvent(db, {
        workspaceId: WS,
        actor: ALICE,
        eventType: i % 5 === 0 ? 'decision.deny' : 'decision.allow',
        resourceRef: `google_file:/doc-${i}.md`,
        outcome: i % 5 === 0 ? 'deny' : 'allow',
        correlationId: `req_run${s}`,
      });
    }
  });

  await withWorkspace(pool, OTHER, (db) =>
    writeAuditEvent(db, {
      workspaceId: OTHER,
      actor: CAROL,
      eventType: 'decision.allow',
      resourceRef: 'google_file:/carols-secret.md',
      outcome: 'allow',
      correlationId: null,
    }),
  );

  app = createApp({
    pool, redis,
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

const list = (query = '', ws = WS, user = ALICE) =>
  app.inject({ method: 'GET', url: `/v1/audit-events${query}`, headers: as(ws, user) });

describe('reading the timeline', () => {
  it('returns newest first, with the chain links', async () => {
    const body = (await list('?limit=5')).json();

    expect(body.events).toHaveLength(5);
    expect(body.events[0].seq).toBeGreaterThan(body.events[4].seq);
    // Hashes are returned so a customer can verify the chain themselves.
    expect(body.events[0].hash).toMatch(/^[0-9a-f]{64}$/);
    expect(body.events[0].prev_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('pages without skipping or repeating an event', async () => {
    // seq is unique and monotonic; occurred_at is neither, and paging on it
    // would drop events that share a timestamp.
    const seen: number[] = [];
    let cursor: number | null = null;

    for (let page = 0; page < 10; page += 1) {
      const query: string = `?limit=4${cursor === null ? '' : `&before=${cursor}`}`;
      const body = (await list(query)).json();
      seen.push(...body.events.map((e: { seq: number }) => e.seq));
      cursor = body.next_cursor;
      if (cursor === null) break;
    }

    const ours = seen.length;
    expect(new Set(seen).size).toBe(ours);
    expect(ours).toBeGreaterThanOrEqual(TOTAL);
    // Strictly descending across page boundaries.
    expect([...seen].sort((a, b) => b - a)).toEqual(seen);
  });

  it('filters without letting a filter reach the query', async () => {
    const denied = (await list('?outcome=deny&limit=100')).json();
    expect(denied.events.length).toBeGreaterThan(0);
    expect(denied.events.every((e: { outcome: string }) => e.outcome === 'deny')).toBe(true);

    // Filters are bound parameters. An injection attempt is just a string that
    // matches nothing.
    const injected = (await list(`?actor=${encodeURIComponent("' or '1'='1")}`)).json();
    expect(injected.events).toEqual([]);
  });

  it('refuses a filter that is not a real outcome, and an oversized page', async () => {
    expect((await list('?outcome=maybe')).statusCode).toBe(400);
    expect((await list('?limit=10000')).statusCode).toBe(400);
    expect((await list('?unknown=1')).statusCode).toBe(400);
  });
});

describe('tenant isolation', () => {
  it('never shows another workspace’s timeline', async () => {
    const mine = (await list('?limit=200')).json();

    expect(mine.events.every((e: { actor: string }) => e.actor === ALICE)).toBe(true);
    expect(JSON.stringify(mine)).not.toContain('carols-secret');
  });

  it('gives each workspace its own chain', async () => {
    const theirs = (await list('?limit=5', OTHER, CAROL)).json();

    expect(theirs.events).toHaveLength(1);
    // First event in its own chain: nothing before it.
    expect(theirs.events[0].prev_hash).toBeNull();
  });
});

describe('verification', () => {
  it('reports an intact chain', async () => {
    const body = (await app.inject({
      method: 'GET', url: '/v1/audit-events/verify', headers: as(WS, ALICE),
    })).json();

    expect(body).toEqual({ verified: true, broken_at: null, event_id: null });
  });

  it('is scoped to the caller’s workspace', async () => {
    const body = (await app.inject({
      method: 'GET', url: '/v1/audit-events/verify', headers: as(OTHER, CAROL),
    })).json();
    expect(body.verified).toBe(true);
  });
});

describe('what the timeline cannot carry', () => {
  it('has no route that could change it', async () => {
    // Append-only is enforced by triggers; there must also be no HTTP surface
    // that looks like a way around them.
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE'] as const) {
      const res = await app.inject({ method, url: '/v1/audit-events', headers: as(WS, ALICE), payload: {} });
      expect(res.statusCode, method).toBe(404);
    }
  });

  it('returns references, never content', async () => {
    const body = (await list('?limit=200')).json();

    for (const event of body.events) {
      // resource_ref is 'type:id'. There is no column that could hold a
      // document body, a token, or a passkey challenge (invariant 5).
      expect(Object.keys(event).sort()).toEqual([
        'actor', 'correlation_id', 'event_type', 'hash', 'id',
        'occurred_at', 'outcome', 'prev_hash', 'resource_ref', 'seq',
      ]);
    }
  });
});
