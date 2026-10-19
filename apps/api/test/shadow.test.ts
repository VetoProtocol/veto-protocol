/**
 * Shadow Agents over HTTP.
 *
 * Almost every assertion here is about one distinction: **"I could not look"
 * is not "I looked and found nothing."** A screen that collapses the two says
 * *no shadow agents found* to somebody whose account it was never allowed to
 * read — which is the reassurance they would act on, and stop checking.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, createFakePolicyFacts } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import {
  createFakeInventorySource,
  reachesProtectedData,
  type AppInventorySource,
  type AuthorizedApp,
} from '@veto/connections';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;

const s = suffix();
const WS = `ws_sh${s}`;
const ALICE = `usr_alice${s}`;

const app = (inventory: readonly AppInventorySource[] | null): FastifyInstance =>
  createApp({
    pool,
    redis,
    policy: createFakePolicyFacts(),
    decisions: createFakePolicyDecisions(),
    wrapper: createLocalKeyWrapper(randomBytes(32).toString('base64')),
    authenticate: headerAuthenticator(),
    inventory,
  });

const appOf = (
  over: Partial<AuthorizedApp> & Pick<AuthorizedApp, 'appId' | 'displayName' | 'scopes'>,
): AuthorizedApp => ({
  provider: 'google',
  accountRef: ALICE,
  isVeto: false,
  ...over,
});

const VETO = appOf({
  appId: 'veto.apps.googleusercontent.com',
  displayName: 'Veto Protocol',
  scopes: ['https://www.googleapis.com/auth/drive.readonly'],
  isVeto: true,
});

const STRANGER = appOf({
  appId: 'other.apps.googleusercontent.com',
  displayName: 'Some Assistant',
  scopes: ['https://www.googleapis.com/auth/drive', 'https://www.googleapis.com/auth/gmail.readonly'],
});

const HARMLESS = appOf({
  appId: 'signin.apps.googleusercontent.com',
  displayName: 'A Sign-in Button',
  scopes: ['openid', 'profile'],
});

const get = (instance: FastifyInstance) =>
  instance.inject({ method: 'GET', url: '/v1/shadow', headers: as(WS, ALICE) });

const plan = (value: 'free' | 'pro') =>
  withWorkspace(pool, WS, (db) =>
    db.query(`update workspaces set plan = $2 where id = $1`, [WS, value]),
  );

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  await seed(pool, WS, [ALICE]);
  await plan('pro');
});

afterAll(async () => {
  await pool.end();
  redis.disconnect();
});

describe('could not look is not found nothing', () => {
  it('says unavailable, with a reason, when no source is wired up', async () => {
    const instance = app(null);
    await instance.ready();
    const res = await get(instance);
    await instance.close();

    expect(res.statusCode).toBe(200);
    for (const provider of res.json().providers) {
      expect(provider.state).toBe('unavailable');
      expect(provider.reason).toBe('not_configured');
    }
  });

  it('refuses to put a number on an estate it could not fully read', async () => {
    // Zero would be a claim, and a claim made over a question nobody
    // answered. Null forces the screen to say something else.
    const instance = app([
      createFakeInventorySource('google', { kind: 'read', apps: [VETO] }),
      // github absent, so the picture is incomplete
    ]);
    await instance.ready();
    const res = await get(instance);
    await instance.close();

    expect(res.json().shadow_count).toBeNull();
  });

  it('counts only when every provider actually answered', async () => {
    const instance = app([
      createFakeInventorySource('google', { kind: 'read', apps: [VETO, STRANGER] }),
      createFakeInventorySource('github', { kind: 'read', apps: [] }),
    ]);
    await instance.ready();
    const res = await get(instance);
    await instance.close();

    expect(res.json().shadow_count).toBe(1);
  });

  it('carries the specific reason, because each one is a different conversation', async () => {
    const instance = app([
      createFakeInventorySource('google', {
        kind: 'unavailable',
        reason: 'not_a_workspace_account',
      }),
      createFakeInventorySource('github', { kind: 'unavailable', reason: 'not_an_organization' }),
    ]);
    await instance.ready();
    const res = await get(instance);
    await instance.close();

    const reasons = Object.fromEntries(
      res.json().providers.map((p: { provider: string; reason: string }) => [p.provider, p.reason]),
    );

    expect(reasons['google']).toBe('not_a_workspace_account');
    expect(reasons['github']).toBe('not_an_organization');
  });

  it('turns a thrown source into unavailable, never into all-clear', async () => {
    const exploding: AppInventorySource = {
      provider: 'google',
      read: () => Promise.reject(new Error('token expired')),
    };

    const instance = app([exploding]);
    await instance.ready();
    const res = await get(instance);
    await instance.close();

    const google = res.json().providers.find((p: { provider: string }) => p.provider === 'google');
    expect(google.state).toBe('unavailable');
    expect(google.reason).toBe('provider_unavailable');
    expect(res.json().shadow_count).toBeNull();
  });

  it('an empty read is a real answer, distinct from unavailable', async () => {
    const instance = app([
      createFakeInventorySource('google', { kind: 'read', apps: [VETO] }),
      createFakeInventorySource('github', { kind: 'read', apps: [] }),
    ]);
    await instance.ready();
    const res = await get(instance);
    await instance.close();

    for (const provider of res.json().providers) {
      expect(provider.state).toBe('read');
      expect(provider.reason).toBeNull();
    }
    expect(res.json().shadow_count).toBe(0);
  });
});

describe('what counts as a shadow agent', () => {
  it('does not count us', async () => {
    const instance = app([
      createFakeInventorySource('google', { kind: 'read', apps: [VETO] }),
      createFakeInventorySource('github', { kind: 'read', apps: [] }),
    ]);
    await instance.ready();
    const res = await get(instance);
    await instance.close();

    expect(res.json().shadow_count).toBe(0);
  });

  it('does not count an app that cannot reach anything protected', async () => {
    // A sign-in button is not a shadow agent. Listing it would bury the three
    // that matter under thirty that do not.
    const instance = app([
      createFakeInventorySource('google', { kind: 'read', apps: [VETO, HARMLESS] }),
      createFakeInventorySource('github', { kind: 'read', apps: [] }),
    ]);
    await instance.ready();
    const res = await get(instance);
    await instance.close();

    expect(res.json().shadow_count).toBe(0);
    // Still listed, with the judgement shown, rather than hidden.
    const google = res.json().providers.find((p: { provider: string }) => p.provider === 'google');
    expect(google.apps).toHaveLength(2);
    expect(
      google.apps.find((a: { app_id: string }) => a.app_id === HARMLESS.appId)
        .reaches_protected_data,
    ).toBe(false);
  });

  it('is decided by client id, never by what an app calls itself', async () => {
    // An app calling itself "Veto Protocol" is exactly what somebody hiding
    // would do. `isVeto` comes from the reader comparing client ids.
    const impostor = appOf({
      appId: 'definitely-not-us.apps.googleusercontent.com',
      displayName: 'Veto Protocol',
      scopes: ['https://www.googleapis.com/auth/drive'],
    });

    const instance = app([
      createFakeInventorySource('google', { kind: 'read', apps: [impostor] }),
      createFakeInventorySource('github', { kind: 'read', apps: [] }),
    ]);
    await instance.ready();
    const res = await get(instance);
    await instance.close();

    expect(res.json().shadow_count).toBe(1);
  });
});

describe('the plan gate', () => {
  it('refuses a free workspace before asking any provider', async () => {
    let asked = false;
    const counting: AppInventorySource = {
      provider: 'google',
      read: () => {
        asked = true;
        return Promise.resolve({ kind: 'read' as const, apps: [] });
      },
    };

    await plan('free');
    const instance = app([counting]);
    await instance.ready();
    const res = await get(instance);
    await instance.close();
    await plan('pro');

    expect(res.statusCode).toBe(402);
    expect(res.json().error.code).toBe('PLAN_REQUIRED');
    // The gate runs before the work, not after it.
    expect(asked).toBe(false);
  });
});

describe('reachesProtectedData', () => {
  it('recognises the scopes that matter on both providers', () => {
    expect(reachesProtectedData(STRANGER)).toBe(true);
    expect(reachesProtectedData(HARMLESS)).toBe(false);
    expect(
      reachesProtectedData(appOf({ appId: 'x', displayName: 'x', scopes: ['contents:read'] })),
    ).toBe(true);
  });

  it('errs towards listing, because a miss is the whole feature failing', () => {
    // A false positive costs one row on a screen. A false negative is an
    // agent nobody was told about.
    expect(
      reachesProtectedData(
        appOf({ appId: 'x', displayName: 'x', scopes: ['https://example.com/auth/DRIVE.file'] }),
      ),
    ).toBe(true);
  });
});
