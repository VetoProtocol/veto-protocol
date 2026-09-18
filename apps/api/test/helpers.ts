import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Redis from 'ioredis';
import type { Pool } from 'pg';
import { createPool } from '@veto/db';
import type { FastifyRequest } from 'fastify';
import type { Principal } from '../src/principal.ts';

const here = path.dirname(fileURLToPath(import.meta.url));

export function loadEnv(): void {
  const runnerEnv = process.env['NODE_ENV'];
  try {
    process.loadEnvFile(path.join(here, '..', '..', '..', '.env'));
  } catch {
    /* already in the environment */
  }
  if (runnerEnv !== undefined) process.env['NODE_ENV'] = runnerEnv;
}

export function testPool(): Pool {
  loadEnv();
  return createPool(process.env['DATABASE_URL'] ?? '');
}

export function testRedis(): Redis {
  loadEnv();
  return new Redis(process.env['REDIS_URL'] ?? 'redis://localhost:6379');
}

export const suffix = (): string => Math.random().toString(36).slice(2, 10);

export async function seed(pool: Pool, ws: string, users: string[]): Promise<void> {
  const c = await pool.connect();
  try {
    await c.query('begin');
    await c.query('select set_config($1,$2,true)', ['veto.workspace_id', ws]);
    await c.query(`insert into workspaces (id, name, type) values ($1,$1,'organization')`, [ws]);
    for (const u of users) {
      await c.query(`insert into users (id, workspace_id, identity_subject) values ($1,$2,$3)`, [
        u,
        ws,
        `oidc|${u}`,
      ]);
    }
    await c.query('commit');
  } catch (e) {
    await c.query('rollback').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
}

export async function setEmergencyLock(pool: Pool, ws: string, locked: boolean): Promise<void> {
  const c = await pool.connect();
  try {
    await c.query('begin');
    await c.query('select set_config($1,$2,true)', ['veto.workspace_id', ws]);
    await c.query(
      `update workspaces set emergency_lock = $2, locked_at = case when $2 then now() else null end
        where id = $1`,
      [ws, locked],
    );
    await c.query('commit');
  } finally {
    c.release();
  }
}

/**
 * Test authenticator.
 *
 * Reads the principal from two headers. This exists only so the route tests can
 * vary the caller; it is not a shipped auth scheme, and the real OIDC
 * authenticator replaces it wholesale in phase 6. The app takes the
 * authenticator as an argument precisely so this stub cannot be reached from
 * production code — it lives in the test tree and nothing in src imports it.
 */
export function headerAuthenticator(): (r: FastifyRequest) => Promise<Principal | null> {
  return async (request: FastifyRequest) => {
    const workspaceId = request.headers['x-test-workspace'];
    const userId = request.headers['x-test-user'];
    if (typeof workspaceId !== 'string' || typeof userId !== 'string') return null;
    return { workspaceId, userId };
  };
}

export const as = (ws: string, user: string): Record<string, string> => ({
  'x-test-workspace': ws,
  'x-test-user': user,
});
