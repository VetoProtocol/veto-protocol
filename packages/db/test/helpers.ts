import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Pool } from 'pg';
import { createPool, type Db } from '../src/client.ts';

export const MIGRATIONS_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'migrations',
);

export function loadEnv(): void {
  // The app .env sets NODE_ENV=development. Letting it overwrite vitest's
  // NODE_ENV=test would disable the test-only guard in the Permit fake, so
  // preserve whatever the runner chose.
  const runnerEnv = process.env['NODE_ENV'];
  try {
    process.loadEnvFile(path.join(MIGRATIONS_DIR, '..', '..', '..', '.env'));
  } catch {
    /* already present in the environment */
  }
  if (runnerEnv !== undefined) process.env['NODE_ENV'] = runnerEnv;
}

export function testPool(): Pool {
  loadEnv();
  return createPool(process.env['DATABASE_URL'] ?? '');
}

/** Unique per run so concurrent runs never collide on a workspace id. */
export function uniqueSuffix(): string {
  return Math.random().toString(36).slice(2, 10);
}

/** Transaction bound to a workspace that is always rolled back. */
export async function inRolledBackTenant<T>(
  pool: Pool,
  workspaceId: string,
  fn: (db: Db) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('select set_config($1, $2, true)', ['veto.workspace_id', workspaceId]);
    return await fn(client);
  } finally {
    await client.query('rollback').catch(() => {});
    client.release();
  }
}

/** Transaction with no tenant bound, always rolled back. */
export async function inRolledBackUntenanted<T>(pool: Pool, fn: (db: Db) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('begin');
    return await fn(client);
  } finally {
    await client.query('rollback').catch(() => {});
    client.release();
  }
}

/** Minimal committed fixture: one workspace with one user. */
export async function seedWorkspace(pool: Pool, ws: string, usr: string): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('select set_config($1, $2, true)', ['veto.workspace_id', ws]);
    await client.query(
      `insert into workspaces (id, name, type) values ($1, $2, 'personal')`,
      [ws, `fixture ${ws}`],
    );
    await client.query(
      `insert into users (id, workspace_id, identity_subject) values ($1, $2, $3)`,
      [usr, ws, `oidc|${usr}`],
    );
    await client.query('commit');
  } catch (e) {
    await client.query('rollback').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}
