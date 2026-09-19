/**
 * Presence and the emergency lock over HTTP.
 *
 * The rules that matter here are about what the API *cannot* be asked to do:
 * set somebody else's presence, accept a location, or let a background signal
 * lift a lock.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, createFakePolicyFacts } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_pr${s}`;
const ALICE = `usr_alice${s}`;
const BOB = `usr_bob${s}`;

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  await seed(pool, WS, [ALICE, BOB]);
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

const put = (body: unknown, user = ALICE) =>
  app.inject({ method: 'PUT', url: '/v1/presence', headers: as(WS, user), payload: body as object });

const get = (user = ALICE) =>
  app.inject({ method: 'GET', url: '/v1/presence', headers: as(WS, user) });

describe('reading presence', () => {
  it('reports away before anything has been set', async () => {
    // Absence of a signal is not evidence of presence (§7.2).
    const body = (await get(BOB)).json();
    expect(body.state).toBe('away');
    expect(body.assurance).toBe('low');
  });
});

describe('setting presence', () => {
  it('sets the caller’s own state', async () => {
    const res = await put({ state: 'active', source: 'passkey', assurance: 'high' });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ state: 'active', assurance: 'high', source: 'passkey' });
    expect((await get()).json().state).toBe('active');
  });

  it('has no way to name another user', async () => {
    // The body schema is closed, so a user_id field is a rejected request
    // rather than a quietly ignored one.
    const res = await put({ state: 'active', source: 'passkey', assurance: 'high', user_id: BOB });
    expect(res.statusCode).toBe(400);

    // Bob is untouched.
    expect((await get(BOB)).json().state).toBe('away');
  });

  it('has no way to supply a location', async () => {
    for (const extra of [{ ip: '203.0.113.4' }, { country: 'GB' }, { coordinates: [51.5, -0.1] }]) {
      const res = await put({ state: 'active', source: 'device_activity', assurance: 'low', ...extra });
      expect(res.statusCode, JSON.stringify(extra)).toBe(400);
    }
  });

  it('refuses a source claiming more assurance than it can witness', async () => {
    const res = await put({ state: 'active', source: 'device_activity', assurance: 'high' });
    expect(res.statusCode).toBe(409);
    expect(res.json().error.message).toMatch(/cannot assert high/);
  });

  it('refuses an unknown state or source', async () => {
    expect((await put({ state: 'online', source: 'passkey', assurance: 'high' })).statusCode).toBe(400);
    expect((await put({ state: 'active', source: 'wifi', assurance: 'low' })).statusCode).toBe(400);
  });

  it('requires automation to name a window', async () => {
    expect((await put({ state: 'automation', source: 'operator', assurance: 'medium' })).statusCode).toBe(409);
    expect(
      (await put({ state: 'automation', source: 'operator', assurance: 'medium', ttl_ms: 60_000 })).statusCode,
    ).toBe(200);
  });

  it('bounds how long a window can be', async () => {
    const res = await put({
      state: 'active', source: 'passkey', assurance: 'high', ttl_ms: 7 * 24 * 60 * 60 * 1000,
    });
    expect(res.statusCode).toBe(400);
  });
});

describe('locks', () => {
  it('will not let background activity clear a user lock', async () => {
    await put({ state: 'locked', source: 'operator', assurance: 'medium' }, BOB);

    const sneak = await put({ state: 'active', source: 'device_activity', assurance: 'low' }, BOB);
    expect(sneak.statusCode).toBe(409);
    expect((await get(BOB)).json().state).toBe('locked');

    // An operator can.
    expect((await put({ state: 'active', source: 'operator', assurance: 'medium' }, BOB)).statusCode).toBe(200);
  });

  it('sets and clears the workspace emergency lock', async () => {
    const lock = (locked: boolean) =>
      app.inject({
        method: 'POST', url: '/v1/emergency-lock', headers: as(WS, ALICE), payload: { locked },
      });

    // The counts are part of the answer, not decoration: locking is supposed to
    // stop work already in flight, and a caller who sees zero where they
    // expected more knows to look further. This workspace is quiet, so zero is
    // the correct report rather than an absence of one.
    expect((await lock(true)).json()).toEqual({
      locked: true,
      grants_revoked: 0,
      sessions_dropped: 0,
    });

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ emergency_lock: boolean; locked_at: Date | null }>(
        `select emergency_lock, locked_at from workspaces where id=$1`, [WS],
      ),
    );
    expect(rows[0]?.emergency_lock).toBe(true);
    expect(rows[0]?.locked_at).not.toBeNull();

    // Releasing tears nothing down and restores nothing, so both counts are
    // zero by construction rather than by coincidence.
    expect((await lock(false)).json()).toEqual({
      locked: false,
      grants_revoked: 0,
      sessions_dropped: 0,
    });
  });

  it('records every presence change in the audit trail, without a location', async () => {
    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ event_type: string; resource_ref: string }>(
        `select event_type, resource_ref from audit_events
          where workspace_id=$1 and event_type like 'presence.%'`,
        [WS],
      ),
    );

    expect(rows.length).toBeGreaterThan(0);
    // The source is a classification, never a device fingerprint or an address.
    expect(JSON.stringify(rows)).not.toMatch(/\d+\.\d+\.\d+\.\d+/);
  });
});
