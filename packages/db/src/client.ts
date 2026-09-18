/**
 * Database access. The tenant boundary is enforced here, not by convention.
 *
 * `withWorkspace` is the only sanctioned way to touch tenant data: it opens a
 * transaction, binds `veto.workspace_id` for that transaction only, and hands
 * back a client. Row-level security (migration 0005) reads that setting, so a
 * query that forgets its `where workspace_id = ...` returns nothing rather than
 * another tenant's rows (CLAUDE.md invariant 4).
 *
 * The binding is transaction-local on purpose. A session-level `set` would
 * survive the connection's return to the pool and leak the tenant into whatever
 * checked it out next.
 */

// `pg` is CommonJS and builds its exports dynamically, so named ESM imports
// are not statically detectable. Import the default and destructure.
import pg from 'pg';
import type { Pool, PoolClient } from 'pg';

const { Pool: PgPool } = pg;

export type Db = Pick<PoolClient, 'query'>;

export function createPool(connectionString: string): Pool {
  if (!connectionString) {
    // Fail closed rather than silently falling back to libpq defaults, which
    // would connect somewhere unintended.
    throw new Error('DATABASE_URL is required');
  }
  return new PgPool({ connectionString, max: 10, idleTimeoutMillis: 30_000 });
}

/**
 * Run `fn` inside a transaction scoped to one workspace.
 * Commits on success, rolls back on any throw.
 */
export async function withWorkspace<T>(
  pool: Pool,
  workspaceId: string,
  fn: (db: Db) => Promise<T>,
): Promise<T> {
  if (!/^ws_[A-Za-z0-9_-]{1,64}$/.test(workspaceId)) {
    throw new Error(`Refusing to open a transaction for a malformed workspace id`);
  }

  const client = await pool.connect();
  try {
    await client.query('begin');
    // Third argument `true` makes this transaction-local (SET LOCAL).
    await client.query('select set_config($1, $2, true)', ['veto.workspace_id', workspaceId]);
    const result = await fn(client);
    await client.query('commit');
    return result;
  } catch (error) {
    await client.query('rollback').catch(() => {
      /* the original error is the one worth surfacing */
    });
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Untenanted transaction, for migrations and operator tooling only.
 *
 * Nothing here bypasses RLS — the policies still apply with an unset tenant,
 * which means tenant tables appear empty. That is the intended blast radius.
 */
export async function withoutTenant<T>(pool: Pool, fn: (db: Db) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    return await fn(client);
  } finally {
    client.release();
  }
}
