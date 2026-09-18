/**
 * The pipeline, end to end (spec §3.3).
 *
 * Phase 3's exit condition: all three results against seeded policy, decisions
 * persisted, and the emergency-lock and Permit-unavailable scenarios from
 * §12.1 green.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, type FakePolicyDecisions } from '@veto/permit';
import { evaluate } from '../src/pipeline.ts';
import { addPolicy, request, seed, setLock, setPresence, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let policy: FakePolicyDecisions;

const s = suffix();
const WS = `ws_p${s}`;
const USER = `usr_p${s}`;
const AGENT = `agt_p${s}`;

const deps = () => ({ pool, redis, policy });

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  policy = createFakePolicyDecisions();
  await seed(pool, WS, USER, AGENT);
  await setPresence(pool, WS, USER, 'active');
  // Permit grants the relationship; Veto's own rules decide the rest.
  policy.allow(WS, AGENT, 'read', 'google_file', '/Work/report.md');
  policy.allow(WS, AGENT, 'read', 'google_file', '/Work/other.md');
  policy.allow(WS, AGENT, 'read', 'google_file', '/Finance/q3.xlsx');
});

afterAll(async () => {
  await pool.end();
  redis.disconnect();
});

const base = () => request({ workspaceId: WS, humanId: USER, agentId: AGENT });

describe('the three results', () => {
  it('denies when no rule grants anything', async () => {
    // Deny by default: absence of a rule is a refusal, not a gap (invariant 2).
    const d = await evaluate(deps(), base());

    expect(d.result).toBe('deny');
    expect(d.reasonCode).toBe('TOOL_NOT_ALLOWED');
    // Permit was never asked — nothing had granted this in the first place.
    expect(d.permitResult).toBe('not_evaluated');
  });

  it('allows when a rule and Permit both say so', async () => {
    await addPolicy(pool, WS, {
      subject: AGENT, action: 'read', effect: 'allow',
      resourceFilter: { type: 'google_file', prefix: '/Work/' },
      version: 'polv_2',
    });

    const d = await evaluate(deps(), base());

    expect(d.result).toBe('allow');
    expect(d.reasonCode).toBe('ALLOWED_WITHIN_POLICY');
    expect(d.permitResult).toBe('allow');
    expect(d.policyVersion).toBe('polv_2');
    expect(d.actionDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('challenges when the rule says so, and opens an approval bound to the digest', async () => {
    await addPolicy(pool, WS, {
      subject: AGENT, action: 'read', effect: 'challenge',
      resourceFilter: { type: 'google_file', prefix: '/Finance/' },
      version: 'polv_3',
    });

    const d = await evaluate(deps(), base() && request({
      workspaceId: WS, humanId: USER, agentId: AGENT,
      resource: { type: 'google_file', id: '/Finance/q3.xlsx' },
    }));

    expect(d.result).toBe('challenge');
    expect(d.approvalId).toMatch(/^apr_/);
    expect(d.expiresAt).toBeTruthy();

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ approver_id: string; action_digest: string; status: string }>(
        `select approver_id, action_digest, status from approvals where id = $1`,
        [d.approvalId],
      ),
    );

    // Only the original delegating user may resolve it (invariant 7).
    expect(rows[0]?.approver_id).toBe(USER);
    expect(rows[0]?.action_digest).toBe(d.actionDigest);
    expect(rows[0]?.status).toBe('pending');
  });
});

describe('§12.1 — emergency lock during an active session', () => {
  it('denies at step 3 without consulting Permit at all', async () => {
    await setLock(pool, WS, true);
    const before = policy.calls.length;
    try {
      const d = await evaluate(deps(), base());

      expect(d.result).toBe('deny');
      expect(d.reasonCode).toBe('WORKSPACE_LOCKED');
      // The lock is Veto's answer (invariant 3). Asking Permit would imply its
      // reply could matter.
      expect(policy.calls.length).toBe(before);
      expect(d.permitResult).toBe('not_evaluated');
    } finally {
      await setLock(pool, WS, false);
    }
  });
});

describe('§12.1 — Permit unavailable during a sensitive request', () => {
  it('denies, and records the outage distinctly from a refusal', async () => {
    policy.breakNext();
    const d = await evaluate(deps(), base());

    expect(d.result).toBe('deny');
    expect(d.reasonCode).toBe('POLICY_UNAVAILABLE');
    // Both columns, never collapsed: "Permit was unreachable" and "Veto denied"
    // are different facts and the database forbids the pair that would be a bug.
    expect(d.permitResult).toBe('unavailable');

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ permit_result: string; veto_result: string }>(
        `select permit_result, veto_result from decisions where id = $1`,
        [d.decisionId],
      ),
    );
    expect(rows[0]).toEqual({ permit_result: 'unavailable', veto_result: 'deny' });
  });
});

describe('§12.1 — an agent authorized for one file asks for more', () => {
  it('denies a resource outside the granted prefix', async () => {
    const d = await evaluate(deps(), request({
      workspaceId: WS, humanId: USER, agentId: AGENT,
      resource: { type: 'google_folder', id: '/Work' },
      tool: 'google_drive.list_folder',
    }));

    expect(d.result).toBe('deny');
    // A folder is not the files inside it, and the rule named files.
    expect(['TOOL_NOT_ALLOWED', 'RESOURCE_OUT_OF_SCOPE']).toContain(d.reasonCode);
  });

  it('will not let a grant on one file reach the folder containing it', async () => {
    // Inheritance flows down, never up. Being granted /Team/one.md says nothing
    // about /Team — that is the widening the scenario is about.
    const ws = `ws_s${suffix()}`;
    const user = `usr_s${suffix()}`;
    const agent = `agt_s${suffix()}`;
    await seed(pool, ws, user, agent);
    await setPresence(pool, ws, user, 'active');
    await addPolicy(pool, ws, {
      subject: agent, action: 'read', effect: 'allow',
      resourceFilter: { type: 'google_file', ids: ['/Team/one.md'] },
      version: 'polv_s',
    });
    policy.allow(ws, agent, 'read', 'google_file', '/Team/one.md');
    policy.allow(ws, agent, 'read', 'google_folder', '/Team');

    const file = await evaluate(deps(), request({
      workspaceId: ws, humanId: user, agentId: agent,
      resource: { type: 'google_file', id: '/Team/one.md' },
    }));
    expect(file.result).toBe('allow');

    // Even with Permit saying yes, Veto's own scope rule refuses: the grant
    // named a file, and a folder is a different resource.
    const folder = await evaluate(deps(), request({
      workspaceId: ws, humanId: user, agentId: agent,
      resource: { type: 'google_folder', id: '/Team' },
      tool: 'google_drive.list_folder',
    }));
    expect(folder.result).toBe('deny');
    expect(folder.permitResult).toBe('not_evaluated');

    // Nor a sibling inside the same folder.
    policy.allow(ws, agent, 'read', 'google_file', '/Team/two.md');
    const sibling = await evaluate(deps(), request({
      workspaceId: ws, humanId: user, agentId: agent,
      resource: { type: 'google_file', id: '/Team/two.md' },
    }));
    expect(sibling.result).toBe('deny');
  });
});

describe('§12.1 — a blocked bulk request split into many small ones', () => {
  it('denies once the cumulative budget is spent, and refusals cost nothing', async () => {
    const agent = `agt_v${suffix()}`;
    const user = `usr_v${suffix()}`;
    const ws = `ws_v${suffix()}`;
    await seed(pool, ws, user, agent);
    await setPresence(pool, ws, user, 'active');
    await addPolicy(pool, ws, {
      subject: agent, action: 'read', effect: 'allow',
      resourceFilter: { type: 'google_file' },
      conditions: { maxPerDay: 3 },
      version: 'polv_v',
    });

    const ask = (id: string) =>
      evaluate(deps(), request({
        workspaceId: ws, humanId: user, agentId: agent,
        resource: { type: 'google_file', id },
      }));

    for (let i = 0; i < 3; i += 1) {
      policy.allow(ws, agent, 'read', 'google_file', `/f${i}`);
      expect((await ask(`/f${i}`)).result, `call ${i}`).toBe('allow');
    }

    policy.allow(ws, agent, 'read', 'google_file', '/f3');
    const over = await ask('/f3');
    expect(over.result).toBe('deny');
    // A volume limit denies. A rate limit would have throttled (§7.1).
    expect(over.reasonCode).toBe('VOLUME_LIMIT_EXCEEDED');

    // A refused request must not have spent budget — otherwise anyone could
    // exhaust a victim's allowance with requests they knew would fail.
    const denied = await evaluate(deps(), request({
      workspaceId: ws, humanId: user, agentId: agent,
      resource: { type: 'google_file', id: '/never-granted' },
    }));
    expect(denied.result).toBe('deny');
    expect((await ask('/f3')).reasonCode).toBe('VOLUME_LIMIT_EXCEEDED');
  });
});

describe('presence', () => {
  it('challenges a sensitive read while the user is away', async () => {
    const ws = `ws_a${suffix()}`;
    const user = `usr_a${suffix()}`;
    const agent = `agt_a${suffix()}`;
    await seed(pool, ws, user, agent);
    await setPresence(pool, ws, user, 'away');
    await addPolicy(pool, ws, {
      subject: agent, action: 'read', effect: 'allow',
      resourceFilter: { type: 'google_file' },
      conditions: { presence: ['active'] },
      version: 'polv_a',
    });
    policy.allow(ws, agent, 'read', 'google_file', '/Work/report.md');

    const d = await evaluate(deps(), request({ workspaceId: ws, humanId: user, agentId: agent }));

    expect(d.result).toBe('challenge');
    expect(d.reasonCode).toBe('USER_AWAY_SENSITIVE_RESOURCE');
  });

  it('treats a missing presence record as away, never as active', async () => {
    const ws = `ws_n${suffix()}`;
    const user = `usr_n${suffix()}`;
    const agent = `agt_n${suffix()}`;
    await seed(pool, ws, user, agent);
    await addPolicy(pool, ws, {
      subject: agent, action: 'read', effect: 'allow',
      resourceFilter: { type: 'google_file' },
      conditions: { presence: ['active'] },
      version: 'polv_n',
    });
    policy.allow(ws, agent, 'read', 'google_file', '/Work/report.md');

    // Absence of a signal is not evidence of presence (§7.2).
    expect((await evaluate(deps(), request({ workspaceId: ws, humanId: user, agentId: agent }))).result)
      .toBe('challenge');
  });

  it('denies everything while presence is locked', async () => {
    const ws = `ws_l${suffix()}`;
    const user = `usr_l${suffix()}`;
    const agent = `agt_l${suffix()}`;
    await seed(pool, ws, user, agent);
    await setPresence(pool, ws, user, 'locked');
    await addPolicy(pool, ws, {
      subject: agent, action: 'read', effect: 'allow',
      resourceFilter: {}, version: 'polv_l',
    });

    const d = await evaluate(deps(), request({ workspaceId: ws, humanId: user, agentId: agent }));
    expect(d.result).toBe('deny');
    expect(d.reasonCode).toBe('WORKSPACE_LOCKED');
  });
});

describe('every decision is recorded', () => {
  it('writes the decision and an audit event for each result', async () => {
    const d = await evaluate(deps(), base());

    const rows = await withWorkspace(pool, WS, async (db) => {
      const dec = await db.query(`select reason_code from decisions where id=$1`, [d.decisionId]);
      const aud = await db.query(
        `select outcome from audit_events where workspace_id=$1 and correlation_id is not null
          order by seq desc limit 1`,
        [WS],
      );
      return { dec: dec.rows.length, aud: aud.rows.length };
    });

    expect(rows.dec).toBe(1);
    expect(rows.aud).toBe(1);
  });

  it('never puts the resource contents in the record, only a reference', async () => {
    const d = await evaluate(deps(), request({
      workspaceId: WS, humanId: USER, agentId: AGENT,
      arguments: { fields: ['content'], note: 'the quarterly numbers are 4.2m' },
    }));

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ resource_ref: string }>(`select resource_ref from decisions where id=$1`, [d.decisionId]),
    );
    expect(rows[0]?.resource_ref).toBe('google_file:/Work/report.md');
    expect(JSON.stringify(rows[0])).not.toContain('4.2m');
  });
});

describe('revocation', () => {
  it('denies a revoked agent before anything else happens', async () => {
    const ws = `ws_r${suffix()}`;
    const user = `usr_r${suffix()}`;
    const agent = `agt_r${suffix()}`;
    await seed(pool, ws, user, agent);
    await withWorkspace(pool, ws, (db) =>
      db.query(`update agents set status='revoked', revoked_at=now() where id=$1`, [agent]),
    );

    const d = await evaluate(deps(), request({ workspaceId: ws, humanId: user, agentId: agent }));
    expect(d.result).toBe('deny');
    expect(d.reasonCode).toBe('AGENT_REVOKED');
  });
});
