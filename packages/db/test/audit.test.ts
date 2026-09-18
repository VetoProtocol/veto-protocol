import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { inRolledBackTenant, seedWorkspace, testPool, uniqueSuffix } from './helpers.ts';

const s = uniqueSuffix();
const WS = `ws_aud${s}`;
const USR = `usr_aud${s}`;

let pool: Pool;

beforeAll(async () => {
  pool = testPool();
  await seedWorkspace(pool, WS, USR);
});

afterAll(async () => {
  await pool.end();
});

const insert = (db: Parameters<Parameters<typeof inRolledBackTenant>[2]>[0], id: string, type: string) =>
  db.query(
    `insert into audit_events (id, workspace_id, actor, event_type, resource_ref, outcome)
     values ($1, $2, $3, $4, 'google_file:1abc', 'lifecycle')`,
    [id, WS, USR, type],
  );

describe('audit append-only + hash chain (spec §7.3)', () => {
  it('chains each event to its predecessor', async () => {
    await inRolledBackTenant(pool, WS, async (db) => {
      await insert(db, `aud_1${s}`, 'agent.registered');
      await insert(db, `aud_2${s}`, 'agent.revoked');
      await insert(db, `aud_3${s}`, 'workspace.locked');

      const { rows } = await db.query<{ id: string; prev_hash: Buffer | null; hash: Buffer }>(
        'select id, prev_hash, hash from audit_events where workspace_id = $1 order by seq',
        [WS],
      );

      expect(rows).toHaveLength(3);
      expect(rows[0]!.prev_hash).toBeNull();
      expect(rows[1]!.prev_hash).toEqual(rows[0]!.hash);
      expect(rows[2]!.prev_hash).toEqual(rows[1]!.hash);
      for (const r of rows) expect(r.hash).toHaveLength(32);
    });
  });

  it('verifies an intact chain', async () => {
    await inRolledBackTenant(pool, WS, async (db) => {
      await insert(db, `aud_v1${s}`, 'agent.registered');
      await insert(db, `aud_v2${s}`, 'agent.revoked');
      const { rows } = await db.query('select * from audit_chain_verify($1)', [WS]);
      expect(rows).toHaveLength(0);
    });
  });

  it('refuses updates', async () => {
    await inRolledBackTenant(pool, WS, async (db) => {
      await insert(db, `aud_u${s}`, 'agent.registered');
      await expect(
        db.query(`update audit_events set outcome = 'allow' where id = $1`, [`aud_u${s}`]),
      ).rejects.toThrow(/append-only/);
    });
  });

  it('refuses deletes', async () => {
    await inRolledBackTenant(pool, WS, async (db) => {
      await insert(db, `aud_d${s}`, 'agent.registered');
      await expect(
        db.query('delete from audit_events where id = $1', [`aud_d${s}`]),
      ).rejects.toThrow(/append-only/);
    });
  });

  it('keeps chains independent per workspace', async () => {
    const other = `ws_aud2${s}`;
    await seedWorkspace(pool, other, `usr_aud2${s}`);
    await inRolledBackTenant(pool, other, async (db) => {
      await db.query(
        `insert into audit_events (id, workspace_id, actor, event_type, outcome)
         values ($1, $2, $3, 'agent.registered', 'lifecycle')`,
        [`aud_o${s}`, other, `usr_aud2${s}`],
      );
      const { rows } = await db.query<{ prev_hash: Buffer | null }>(
        'select prev_hash from audit_events where workspace_id = $1 order by seq',
        [other],
      );
      // First event in its own workspace, regardless of what WS already holds.
      expect(rows[0]!.prev_hash).toBeNull();
    });
  });

  it('rejects an audit id that does not match the expected shape', async () => {
    await inRolledBackTenant(pool, WS, async (db) => {
      await expect(insert(db, 'not_an_audit_id', 'agent.registered')).rejects.toThrow(/check constraint/i);
    });
  });
});

describe('decision integrity constraints', () => {
  it('refuses to record an allow when Permit was unavailable (invariant 1)', async () => {
    await inRolledBackTenant(pool, WS, async (db) => {
      await expect(
        db.query(
          `insert into decisions (id, workspace_id, request_id, human_id, agent_id, tool, action,
                                  permit_result, veto_result, reason_code)
           values ($1,$2,$3,$4,$4,'google_drive.read_file','read','unavailable','allow','X')`,
          [`dec_x${s}`, WS, `req_x${s}`, USR],
        ),
      ).rejects.toThrow(/unavailable_policy_never_allows/);
    });
  });
});
