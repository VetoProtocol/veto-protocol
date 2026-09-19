/**
 * Sensitivity labels.
 *
 * The property under test throughout: a label can only ever *add* a
 * requirement. Nothing a label says grants access, so mislabelling something
 * `public` cannot open it.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, type FakePolicyDecisions } from '@veto/permit';
import { evaluate } from '../src/pipeline.ts';
import { matchLabel, requirementFor, type ResourceLabel } from '../src/labels.ts';
import { addPolicy, request, seed, setPresence, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let policy: FakePolicyDecisions;

const s = suffix();
const WS = `ws_lb${s}`;
const USER = `usr_lb${s}`;
const AGENT = `agt_lb${s}`;

const deps = () => ({ pool, redis, policy });

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  policy = createFakePolicyDecisions();
  await seed(pool, WS, USER, AGENT);
  await setPresence(pool, WS, USER, 'away');
  // One broad rule with no presence condition of its own. Everything below is
  // the label doing the work.
  await addPolicy(pool, WS, {
    subject: AGENT, action: 'read', effect: 'allow',
    resourceFilter: { type: 'google_file' }, version: 'polv_lb',
  });
});

afterAll(async () => {
  await pool.end();
  redis.disconnect();
});

async function label(pattern: string, sensitivity: string, exact = false): Promise<void> {
  await withWorkspace(pool, WS, (db) =>
    db.query(
      `insert into resource_labels (id,workspace_id,resource_type,pattern,exact,sensitivity,created_by)
       values ($1,$2,'google_file',$3,$4,$5,$6)`,
      [`lbl_${suffix()}${suffix()}`, WS, pattern, exact, sensitivity, USER],
    ),
  );
}

const ask = (id: string, intent: string | null = 'Summarize it') => {
  policy.allow(WS, AGENT, 'read', 'google_file', id);
  return evaluate(deps(), request({
    workspaceId: WS, humanId: USER, agentId: AGENT,
    resource: { type: 'google_file', id },
    declaredIntent: intent,
  }));
};

describe('matching', () => {
  const labels: ResourceLabel[] = [
    { id: 'l1', resourceType: 'google_file', pattern: '/Finance', exact: false, sensitivity: 'confidential', note: null },
    { id: 'l2', resourceType: 'google_file', pattern: '/Finance/Public', exact: false, sensitivity: 'public', note: null },
    { id: 'l3', resourceType: 'google_file', pattern: '/Finance/payroll.csv', exact: true, sensitivity: 'restricted', note: null },
    { id: 'l4', resourceType: 'google_folder', pattern: '/Finance', exact: false, sensitivity: 'restricted', note: null },
  ];

  it('picks the longest matching prefix', () => {
    // /Finance/Public is less restricted than /Finance, and says so without the
    // answer depending on row order.
    expect(matchLabel(labels, 'google_file', '/Finance/q3.xlsx')?.id).toBe('l1');
    expect(matchLabel(labels, 'google_file', '/Finance/Public/menu.md')?.id).toBe('l2');
  });

  it('lets an exact id beat any prefix', () => {
    expect(matchLabel(labels, 'google_file', '/Finance/payroll.csv')?.id).toBe('l3');
  });

  it('does not cross resource types', () => {
    // A folder labelled restricted says nothing about a file with the same path.
    expect(matchLabel(labels, 'google_folder', '/Finance/x')?.id).toBe('l4');
  });

  it('returns nothing when nothing matches', () => {
    expect(matchLabel(labels, 'google_file', '/Work/notes.md')).toBeNull();
  });
});

describe('what each level requires', () => {
  it('adds nothing below confidential', () => {
    expect(requirementFor('public')).toEqual({ presence: [], requireIntent: false });
    expect(requirementFor('internal')).toEqual({ presence: [], requireIntent: false });
  });

  it('requires presence at confidential, and intent too at restricted', () => {
    expect(requirementFor('confidential')).toEqual({ presence: ['active'], requireIntent: false });
    expect(requirementFor('restricted')).toEqual({ presence: ['active'], requireIntent: true });
  });
});

describe('labels in the pipeline', () => {
  it('leaves an unlabelled resource alone', async () => {
    // The rule allows it and nothing adds a requirement, even though the user
    // is away.
    expect((await ask('/Work/notes.md')).result).toBe('allow');
  });

  it('challenges a confidential resource while the user is away', async () => {
    await label('/Finance', 'confidential');

    const d = await ask('/Finance/q3.xlsx');
    expect(d.result).toBe('challenge');
    expect(d.reasonCode).toBe('USER_AWAY_SENSITIVE_RESOURCE');
  });

  it('lets a more specific label relax a broader one', async () => {
    await label('/Finance/Public', 'public');
    expect((await ask('/Finance/Public/menu.md')).result).toBe('allow');
  });

  it('requires a stated intent at restricted, even when present', async () => {
    await label('/Finance/payroll.csv', 'restricted', true);
    await setPresence(pool, WS, USER, 'active');

    const without = await ask('/Finance/payroll.csv', null);
    expect(without.result).toBe('challenge');
    expect(without.reasonCode).toBe('INTENT_MISMATCH');

    const withIntent = await ask('/Finance/payroll.csv', 'Prepare the quarterly summary');
    expect(withIntent.result).toBe('allow');
  });

  it('never grants: a label cannot open what no rule allows', async () => {
    // The whole safety property. `public` is not permission.
    await label('/Personal', 'public');

    const d = await evaluate(deps(), request({
      workspaceId: WS, humanId: USER, agentId: AGENT,
      // A type no rule mentions.
      resource: { type: 'google_folder', id: '/Personal' },
    }));

    expect(d.result).toBe('deny');
  });

  it('keeps the rule’s own condition when the label is looser', async () => {
    // A label that asks for less must not undo a rule that asks for more.
    const ws = `ws_lx${suffix()}`;
    const user = `usr_lx${suffix()}`;
    const agent = `agt_lx${suffix()}`;
    await seed(pool, ws, user, agent);
    await setPresence(pool, ws, user, 'away');
    await addPolicy(pool, ws, {
      subject: agent, action: 'read', effect: 'allow',
      resourceFilter: { type: 'google_file' },
      conditions: { presence: ['active'] },
      version: 'polv_lx',
    });
    await withWorkspace(pool, ws, (db) =>
      db.query(
        `insert into resource_labels (id,workspace_id,resource_type,pattern,exact,sensitivity,created_by)
         values ($1,$2,'google_file','/',false,'public',$3)`,
        [`lbl_${suffix()}${suffix()}`, ws, user],
      ),
    );

    policy.allow(ws, agent, 'read', 'google_file', '/anything.md');
    const d = await evaluate(deps(), request({
      workspaceId: ws, humanId: user, agentId: agent,
      resource: { type: 'google_file', id: '/anything.md' },
    }));

    expect(d.result).toBe('challenge');
  });
});
