/**
 * Migration runner.
 *
 * Plain SQL files applied in lexical order, each in its own transaction, each
 * recorded with a checksum. The checksum matters: an already-applied migration
 * that changes on disk means the schema in front of you is not the schema the
 * file describes, and for authorization tables that divergence is a security
 * problem, not a inconvenience. The runner refuses rather than guessing.
 */

import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Pool } from 'pg';
import { withoutTenant } from './client.ts';

export interface AppliedMigration {
  name: string;
  checksum: string;
}

const LEDGER = `
  create table if not exists schema_migrations (
    name        text        primary key,
    checksum    text        not null,
    applied_at  timestamptz not null default now()
  )
`;

function checksum(sql: string): string {
  return createHash('sha256').update(sql, 'utf8').digest('hex');
}

export async function readMigrations(dir: string): Promise<{ name: string; sql: string }[]> {
  const names = (await readdir(dir)).filter((n) => n.endsWith('.sql')).sort();
  return Promise.all(
    names.map(async (name) => ({ name, sql: await readFile(path.join(dir, name), 'utf8') })),
  );
}

export async function migrate(
  pool: Pool,
  dir: string,
): Promise<{ applied: string[]; skipped: string[] }> {
  const migrations = await readMigrations(dir);
  const applied: string[] = [];
  const skipped: string[] = [];

  await withoutTenant(pool, async (db) => {
    await db.query(LEDGER);
  });

  const { rows } = await withoutTenant(pool, (db) =>
    db.query<AppliedMigration>('select name, checksum from schema_migrations'),
  );
  const ledger = new Map(rows.map((r) => [r.name, r.checksum]));

  for (const { name, sql } of migrations) {
    const sum = checksum(sql);
    const recorded = ledger.get(name);

    if (recorded !== undefined) {
      if (recorded !== sum) {
        throw new Error(
          `Migration ${name} was modified after it was applied. ` +
            `Applied checksum ${recorded.slice(0, 12)}…, file is ${sum.slice(0, 12)}…. ` +
            `Add a new migration instead of editing an applied one.`,
        );
      }
      skipped.push(name);
      continue;
    }

    const client = await pool.connect();
    try {
      await client.query('begin');
      await client.query(sql);
      await client.query('insert into schema_migrations (name, checksum) values ($1, $2)', [
        name,
        sum,
      ]);
      await client.query('commit');
      applied.push(name);
    } catch (error) {
      await client.query('rollback').catch(() => {});
      throw new Error(`Migration ${name} failed: ${(error as Error).message}`, { cause: error });
    } finally {
      client.release();
    }
  }

  return { applied, skipped };
}
