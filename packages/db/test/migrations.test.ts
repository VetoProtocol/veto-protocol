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

/** The ten entities spec §6 names. Every one must exist. */
const SPEC_TABLES = [
  'agents', 'approvals', 'audit_events', 'connections', 'decisions',
  'policies', 'presence', 'sessions', 'users', 'workspaces',
];

/**
 * Tables beyond §6, each with a reason.
 *
 * §6 gives required fields, not an exhaustive schema — but an unexplained table
 * in an authorization database is exactly the thing nobody should be able to
 * add quietly. Anything not listed here fails the test, so a new table arrives
 * with a justification or not at all.
 */
const JUSTIFIED_EXTRAS: Readonly<Record<string, string>> = {
  schema_migrations: 'the migration ledger itself',
  agent_fingerprints:
    'which software has been connecting as each agent, parsed from the request User-Agent — the one identifier an MCP client sends on every request rather than only at the handshake. Change detection and never authentication, because every value in it is one the client chose to send; read by nothing in the §3.3 pipeline',
  passkeys: 'WebAuthn credentials (§15, §7.1); §6 stores only passkey_enrolled on users',
  resource_labels: 'the §4.2 sensitivity attribute, attached to resources rather than repeated in every rule',
  webhook_endpoints: 'where §5.4 alerts are sent, and the per-endpoint signing secret',
  webhook_deliveries:
    'the §5.4 delivery queue. A table rather than a fetch, so a receiver outage cannot become an authorization outage',
  oauth_clients:
    'dynamically registered MCP clients (§8, RFC 7591). Deliberately not tenant-scoped — a client registers before any human is involved and holds no authority; the migration argues why that is safe',
  oauth_refresh_tokens:
    'the §8 authorization server\u2019s refresh tokens, stored as hashes and rotated on use. Needed because the access token is the capability token, which MAX_TTL_MS caps at fifteen minutes',
  hierarchy_edges:
    'containment edges already sent to Permit, so a repeat walk does not re-state them. On a real deployment 648 of 676 upstream calls were duplicates and the rest were rate limits; a cache of what was written, never consulted at decision time',
  hierarchy_syncs:
    'one folder walk, and what it found. The walk writes a parent fact per entry to Permit\u2019s cloud API and outlives the request that started it, so its outcome needs somewhere to live; counts only, never file names (invariant 5)',
  legal_acceptances:
    'which published version of the terms and the privacy policy each user agreed to. Append-only, because acceptance is an event and the question asked later is what somebody agreed to at the time. Read at §3.3 step 3 — an agent acting for a human who has not agreed is denied CONSENT_REQUIRED',
};

describe('migrations', () => {
  it('creates every entity in spec §6, and nothing unexplained', async () => {
    const { rows } = await inRolledBackUntenanted(pool, (db) =>
      db.query<{ tablename: string }>(
        `select tablename from pg_tables where schemaname = 'public' order by tablename`,
      ),
    );
    const present = rows.map((r) => r.tablename);

    for (const table of SPEC_TABLES) {
      expect(present, `§6 requires ${table}`).toContain(table);
    }

    const unexplained = present.filter(
      (t) => !SPEC_TABLES.includes(t) && JUSTIFIED_EXTRAS[t] === undefined,
    );
    expect(unexplained, 'a table beyond §6 needs a reason in JUSTIFIED_EXTRAS').toEqual([]);
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
