import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { migrate, readMigrations } from '../src/migrate.ts';
import { MIGRATIONS_DIR, inRolledBackUntenanted, testPool } from './helpers.ts';

let pool: Pool;

beforeAll(() => {
  pool = testPool();
});
afterAll(async () => {
  await pool.end();
});

const EXPECTED_TABLES = [
  'agents', 'approvals', 'audit_events', 'connections', 'decisions',
  'policies', 'presence', 'schema_migrations', 'sessions', 'users', 'workspaces',
];

describe('migrations', () => {
  it('creates every entity in spec §6', async () => {
    const { rows } = await inRolledBackUntenanted(pool, (db) =>
      db.query<{ tablename: string }>(
        `select tablename from pg_tables where schemaname = 'public' order by tablename`,
      ),
    );
    expect(rows.map((r) => r.tablename)).toEqual(EXPECTED_TABLES);
  });

  it('is idempotent — a second run applies nothing', async () => {
    const { applied, skipped } = await migrate(pool, MIGRATIONS_DIR);
    expect(applied).toEqual([]);
    expect(skipped.length).toBeGreaterThanOrEqual(5);
  });

  it('refuses to run when an applied migration was edited on disk', async () => {
    // Editing an applied migration means the live schema no longer matches the
    // file describing it. For authorization tables that divergence is a security
    // problem, so the runner refuses rather than guessing.
    //
    // The tamper must be committed: migrate() runs on its own pooled connection
    // and would not see an open transaction's uncommitted write.
    const name = '0001_workspaces.sql';
    const original = await inRolledBackUntenanted(pool, (db) =>
      db.query<{ checksum: string }>('select checksum from schema_migrations where name = $1', [name]),
    );
    const restore = original.rows[0]!.checksum;

    await pool.query(`update schema_migrations set checksum = 'tampered' where name = $1`, [name]);
    try {
      await expect(migrate(pool, MIGRATIONS_DIR)).rejects.toThrow(/modified after it was applied/);
    } finally {
      await pool.query('update schema_migrations set checksum = $2 where name = $1', [name, restore]);
    }

    // And the ledger is back to a state where migrate() is happy again.
    await expect(migrate(pool, MIGRATIONS_DIR)).resolves.toMatchObject({ applied: [] });
  });

  it('applies migrations in lexical order', async () => {
    const names = (await readMigrations(MIGRATIONS_DIR)).map((m) => m.name);
    expect(names).toEqual([...names].sort());
    expect(names[0]).toMatch(/^0001_/);
  });

  it('enforces id shape at the database boundary, not only in TypeScript', async () => {
    await expect(
      inRolledBackUntenanted(pool, (db) =>
        db.query(`insert into workspaces (id, name, type) values ('nope','x','personal')`),
      ),
    ).rejects.toThrow(/check constraint|row-level security/i);
  });
});
