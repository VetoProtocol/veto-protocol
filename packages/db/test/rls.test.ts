import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { inRolledBackTenant, inRolledBackUntenanted, seedWorkspace, testPool, uniqueSuffix } from './helpers.ts';

const s = uniqueSuffix();
const WS_A = `ws_a${s}`;
const WS_B = `ws_b${s}`;
const USR_A = `usr_a${s}`;
const USR_B = `usr_b${s}`;

let pool: Pool;

beforeAll(async () => {
  pool = testPool();
  await seedWorkspace(pool, WS_A, USR_A);
  await seedWorkspace(pool, WS_B, USR_B);
});

afterAll(async () => {
  for (const [ws, usr] of [[WS_A, USR_A], [WS_B, USR_B]] as const) {
    const c = await pool.connect();
    try {
      await c.query('begin');
      await c.query('select set_config($1,$2,true)', ['veto.workspace_id', ws]);
      await c.query('delete from users where id = $1', [usr]);
      await c.query('delete from workspaces where id = $1', [ws]);
      await c.query('commit');
    } catch {
      await c.query('rollback').catch(() => {});
    } finally {
      c.release();
    }
  }
  await pool.end();
});

describe('tenant isolation (invariant 4)', () => {
  it('shows a workspace only its own users', async () => {
    const a = await inRolledBackTenant(pool, WS_A, (db) =>
      db.query<{ id: string }>('select id from users'),
    );
    expect(a.rows.map((r) => r.id)).toEqual([USR_A]);

    const b = await inRolledBackTenant(pool, WS_B, (db) =>
      db.query<{ id: string }>('select id from users'),
    );
    expect(b.rows.map((r) => r.id)).toEqual([USR_B]);
  });

  it("hides another tenant's row even when queried by primary key", async () => {
    const res = await inRolledBackTenant(pool, WS_A, (db) =>
      db.query('select id from users where id = $1', [USR_B]),
    );
    expect(res.rowCount).toBe(0);
  });

  it('returns nothing when no tenant is bound — unset fails closed (invariant 1)', async () => {
    const res = await inRolledBackUntenanted(pool, (db) => db.query('select id from users'));
    expect(res.rowCount).toBe(0);

    const ws = await inRolledBackUntenanted(pool, (db) => db.query('select id from workspaces'));
    expect(ws.rowCount).toBe(0);
  });

  it('refuses to insert a row belonging to another tenant', async () => {
    await expect(
      inRolledBackTenant(pool, WS_A, (db) =>
        db.query('insert into users (id, workspace_id, identity_subject) values ($1,$2,$3)', [
          `usr_x${s}`,
          WS_B,
          'oidc|x',
        ]),
    ),
    ).rejects.toThrow(/row-level security/i);
  });

  it('refuses an insert when no tenant is bound', async () => {
    await expect(
      inRolledBackUntenanted(pool, (db) =>
        db.query(`insert into workspaces (id, name, type) values ($1,'x','personal')`, [
          `ws_z${s}`,
        ]),
      ),
    ).rejects.toThrow(/row-level security/i);
  });

  it('cannot cross tenants through a foreign key', async () => {
    // An agent in A owned by a user in B is unrepresentable: the composite FK
    // targets users (workspace_id, id), so the parent must be in the same tenant.
    await expect(
      inRolledBackTenant(pool, WS_A, (db) =>
        db.query(
          `insert into agents (id, workspace_id, provider, client_id, owner_user_id)
           values ($1,$2,'anthropic','claude-desktop',$3)`,
          [`agt_x${s}`, WS_A, USR_B],
        ),
      ),
    ).rejects.toThrow(/foreign key|violates/i);
  });

  it('applies RLS to the owner role — FORCE is in effect, not decorative', async () => {
    const res = await inRolledBackUntenanted(pool, (db) =>
      db.query<{ relrowsecurity: boolean; relforcerowsecurity: boolean }>(
        `select relrowsecurity, relforcerowsecurity from pg_class
          where relname = any($1::text[]) and relkind = 'r'`,
        [['workspaces', 'users', 'agents', 'connections', 'sessions', 'presence', 'policies', 'decisions', 'approvals', 'audit_events']],
      ),
    );
    expect(res.rowCount).toBe(10);
    for (const row of res.rows) {
      expect(row.relrowsecurity).toBe(true);
      expect(row.relforcerowsecurity).toBe(true);
    }
  });
});
