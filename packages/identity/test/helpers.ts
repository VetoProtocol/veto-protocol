import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Redis from 'ioredis';
import type { Pool } from 'pg';
import { createPool } from '@veto/db';

const here = path.dirname(fileURLToPath(import.meta.url));

export function loadEnv(): void {
  // The app .env sets NODE_ENV=development. Letting it overwrite vitest's
  // NODE_ENV=test would disable the test-only guard in the Permit fake, so
  // preserve whatever the runner chose.
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
