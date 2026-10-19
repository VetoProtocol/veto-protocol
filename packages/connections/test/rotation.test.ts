/**
 * The broker persisting a rotated credential.
 *
 * Google's refresh token does not rotate and GitHub's durable value is an
 * installation id, so for the whole life of this codebase the credential
 * column has been write-once and nothing noticed it had no writer. Slack
 * rotates on every refresh.
 *
 * The failure this guards against is quiet: dropping the replacement does not
 * break the call that dropped it. It breaks the *next* one, hours later, as
 * `CONNECTION_EXPIRED` on a connection nobody touched.
 */

import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { createPool, withWorkspace } from '@veto/db';
import { createLocalKeyWrapper } from '@veto/vault';
import {
  createConnection,
  mintUpstreamToken,
  revealRefreshTokenForBroker,
  type UpstreamTokenExchange,
} from '../src/index.ts';

const here = path.dirname(fileURLToPath(import.meta.url));
const wrapper = createLocalKeyWrapper(randomBytes(32).toString('base64'));

let pool: Pool;
const s = Math.random().toString(36).slice(2, 10);
const WS = `ws_rot${s}`;
const USER = `usr_rot${s}`;

/** Hands back a new refresh token every time, as a rotating provider does. */
function rotating(): UpstreamTokenExchange & { calls: number } {
  const state = {
    calls: 0,
    refresh(current: string) {
      state.calls += 1;
      return Promise.resolve({
        accessToken: `access-${String(state.calls)}`,
        expiresAt: new Date(Date.now() + 3_600_000),
        scopes: ['channels:read'],
        rotatedRefreshToken: `${current}-next`,
      });
    },
    revoke: () => Promise.resolve(),
  };
  return state as UpstreamTokenExchange & { calls: number };
}

/** A provider whose credential is stable, as Google's is. */
const stable: UpstreamTokenExchange = {
  refresh: () =>
    Promise.resolve({
      accessToken: 'access',
      expiresAt: new Date(Date.now() + 3_600_000),
      scopes: ['channels:read'],
    }),
  revoke: () => Promise.resolve(),
};

async function connect(): Promise<string> {
  const made = await withWorkspace(pool, WS, (db) =>
    createConnection(db, wrapper, {
      workspaceId: WS,
      userId: USER,
      provider: 'slack',
      scopes: ['channels:read'],
      refreshToken: 'xoxe-original',
    }),
  );
  return made.id;
}

const storedToken = (connectionId: string) =>
  withWorkspace(pool, WS, (db) => revealRefreshTokenForBroker(db, wrapper, WS, connectionId));

beforeAll(async () => {
  // The app `.env` sets NODE_ENV=development; letting it overwrite vitest's
  // `test` would disable the guards that refuse to construct outside one.
  const runner = process.env['NODE_ENV'];
  try {
    process.loadEnvFile(path.join(here, '..', '..', '..', '.env'));
  } catch {
    /* already present */
  }
  if (runner !== undefined) process.env['NODE_ENV'] = runner;

  pool = createPool(process.env['DATABASE_URL'] ?? '');
  const c = await pool.connect();
  try {
    await c.query('begin');
    await c.query('select set_config($1,$2,true)', ['veto.workspace_id', WS]);
    await c.query(`insert into workspaces (id,name,type) values ($1,$1,'organization')`, [WS]);
    await c.query(`insert into users (id,workspace_id,identity_subject) values ($1,$2,$3)`, [
      USER,
      WS,
      `oidc|${USER}`,
    ]);
    await c.query('commit');
  } catch (e) {
    await c.query('rollback').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
});

afterAll(async () => {
  await pool.end();
});

describe('a rotating provider', () => {
  it('stores the replacement, so the next refresh has a live credential', async () => {
    const id = await connect();
    const exchange = rotating();

    await withWorkspace(pool, WS, (db) =>
      mintUpstreamToken(db, wrapper, exchange, {
        workspaceId: WS,
        connectionId: id,
        requiredScopes: ['channels:read'],
      }),
    );

    expect(await storedToken(id)).toBe('xoxe-original-next');
  });

  it('keeps working across repeated refreshes', async () => {
    // The real assertion. One refresh succeeding proves nothing — a dropped
    // rotation fails on the second.
    const id = await connect();
    const exchange = rotating();

    for (let i = 0; i < 3; i += 1) {
      await withWorkspace(pool, WS, (db) =>
        mintUpstreamToken(db, wrapper, exchange, {
          workspaceId: WS,
          connectionId: id,
          requiredScopes: ['channels:read'],
        }),
      );
    }

    expect(exchange.calls).toBe(3);
    expect(await storedToken(id)).toBe('xoxe-original-next-next-next');
  });

  it('hands the grant back only after the replacement is stored', async () => {
    // Persisted before the token is returned, so a caller can never act on a
    // grant whose replacement was lost.
    const id = await connect();

    const grant = await withWorkspace(pool, WS, (db) =>
      mintUpstreamToken(db, wrapper, rotating(), {
        workspaceId: WS,
        connectionId: id,
        requiredScopes: ['channels:read'],
      }),
    );

    expect(grant.accessToken).toBe('access-1');
    expect(await storedToken(id)).toBe('xoxe-original-next');
  });
});

describe('a provider that does not rotate', () => {
  it('leaves the stored credential exactly as it was', async () => {
    // Google and GitHub go through this same path. Nothing about rotation may
    // touch a connection whose provider never rotates.
    const id = await connect();

    await withWorkspace(pool, WS, (db) =>
      mintUpstreamToken(db, wrapper, stable, {
        workspaceId: WS,
        connectionId: id,
        requiredScopes: ['channels:read'],
      }),
    );

    expect(await storedToken(id)).toBe('xoxe-original');
  });

  it('does not rewrite when the provider echoes the same token back', async () => {
    const id = await connect();
    const echoing: UpstreamTokenExchange = {
      refresh: (current) =>
        Promise.resolve({
          accessToken: 'access',
          expiresAt: new Date(Date.now() + 3_600_000),
          scopes: ['channels:read'],
          rotatedRefreshToken: current,
        }),
      revoke: () => Promise.resolve(),
    };

    await withWorkspace(pool, WS, (db) =>
      mintUpstreamToken(db, wrapper, echoing, {
        workspaceId: WS,
        connectionId: id,
        requiredScopes: ['channels:read'],
      }),
    );

    expect(await storedToken(id)).toBe('xoxe-original');
  });
});
