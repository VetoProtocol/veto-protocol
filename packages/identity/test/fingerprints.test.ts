/**
 * Agent fingerprints: what the parser makes of a `User-Agent`, and what the
 * writer does with it.
 *
 * The adversarial cases come first, because the input is attacker-controlled
 * and the header is the only material this feature has.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import { createFakePolicyFacts } from '@veto/permit';
import {
  FINGERPRINT_VERSION,
  MAX_FINGERPRINTS_PER_AGENT,
  fingerprintModeOf,
  PRODUCT_ABSENT,
  PRODUCT_UNPARSABLE,
  listFingerprints,
  observeClient,
  recordSighting,
  registerAgent,
} from '../src/index.ts';
import { seed, suffix, testPool } from './helpers.ts';

/** Exactly what Claude Code 2.1.293 sent, measured on 2026-10-09. */
const CLAUDE_CODE = 'claude-code/2.1.293 (sdk-cli)';

describe('observeClient', () => {
  it('splits the measured header into a stable half and a moving half', () => {
    const seen = observeClient(CLAUDE_CODE);

    expect(seen.product).toBe('claude-code');
    expect(seen.channel).toBe('sdk-cli');
    expect(seen.version).toBe('2.1.293');
    expect(seen.fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('survives a version bump, which is the whole point', () => {
    // The case that decides whether anybody leaves this switched on. If a
    // routine update changed the fingerprint, every Claude Code release would
    // look like a different program arriving on the same credential.
    const before = observeClient('claude-code/2.1.293 (sdk-cli)');
    const after = observeClient('claude-code/9.9.9 (sdk-cli)');

    expect(after.fingerprint).toBe(before.fingerprint);
    expect(after.version).not.toBe(before.version);
  });

  it('distinguishes a different program on the same credential', () => {
    const claude = observeClient(CLAUDE_CODE);
    const other = observeClient('mcp-remote/1.0.0');

    expect(other.fingerprint).not.toBe(claude.fingerprint);
  });

  it('treats one install reaching us two ways as one client', () => {
    // Measured, not assumed. The same Claude Code install sent both of these:
    //
    //   claude-code/2.1.293 (sdk-cli)   its own server health check
    //   claude-code/2.1.289 (cli)       an actual tool call
    //
    // Hashing the channel gave every user two fingerprints for one program,
    // pinned whichever connected first, and would have challenged the other
    // the moment enforcement went on. Found by deploying and making one real
    // call, which no amount of unit testing was going to turn up.
    const health = observeClient('claude-code/2.1.293 (sdk-cli)');
    const toolCall = observeClient('claude-code/2.1.289 (cli)');

    expect(toolCall.fingerprint).toBe(health.fingerprint);
    // Both halves are still recorded; they simply do not decide anything.
    expect(health.channel).toBe('sdk-cli');
    expect(toolCall.channel).toBe('cli');
  });

  it('gives a missing header its own bucket rather than failing', () => {
    for (const nothing of [undefined, null, '', '   ']) {
      const seen = observeClient(nothing);
      expect(seen.product).toBe(PRODUCT_ABSENT);
      expect(seen.version).toBeNull();
      expect(seen.fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/);
    }

    // And absent is not the same thing as unrecognised.
    expect(observeClient(undefined).fingerprint).not.toBe(observeClient('((((').fingerprint);
  });

  it('collapses unparsable junk into one bucket', () => {
    // Otherwise a caller varying garbage would spend the agent's whole
    // allowance of rows without ever naming a product.
    const a = observeClient('((((');
    const b = observeClient(')))) nonsense ((((');

    expect(a.product).toBe(PRODUCT_UNPARSABLE);
    expect(b.product).toBe(PRODUCT_UNPARSABLE);
    expect(a.fingerprint).toBe(b.fingerprint);
  });

  it('strips control characters, so a header cannot forge a log line', () => {
    const seen = observeClient('claude-code/2.1.293 (sdk-cli)\n2026-01-01 FAKE LOG ENTRY');

    expect(seen.product).toBe('claude-code');
    expect(seen.channel).toBe('sdk-cli');
    expect(JSON.stringify(seen)).not.toContain('\n');
    expect(JSON.stringify(seen)).not.toContain('FAKE LOG ENTRY');
  });

  it('bounds an over-long header instead of refusing it', () => {
    const seen = observeClient(`${'a'.repeat(5000)}/1.0 (${'b'.repeat(5000)})`);

    expect(seen.product.length).toBeLessThanOrEqual(200);
    expect(seen.channel?.length ?? 0).toBeLessThanOrEqual(200);
  });

  it('reads the first product, so an added proxy token is not a new client', () => {
    const seen = observeClient('claude-code/2.1.293 (sdk-cli) some-proxy/4.0');
    expect(seen.product).toBe('claude-code');
  });

  it('is stable across calls — the digest is not salted per process', () => {
    expect(observeClient(CLAUDE_CODE).fingerprint).toBe(observeClient(CLAUDE_CODE).fingerprint);
  });

  it('names the version that produced the digest', () => {
    expect(FINGERPRINT_VERSION).toBe(2);
  });
});

describe('recordSighting', () => {
  const s = suffix();
  const WS = `ws_f${s}`;
  const OTHER = `ws_g${s}`;
  const ALICE = `usr_fa${s}`;
  const BOB = `usr_fb${s}`;

  let pool: Pool;
  let agentId: string;
  let otherAgentId: string;

  beforeAll(async () => {
    pool = testPool();
    await seed(pool, WS, [ALICE]);
    await seed(pool, OTHER, [BOB]);

    const policy = createFakePolicyFacts();

    agentId = (
      await withWorkspace(pool, WS, (db) =>
        registerAgent(db, policy, {
          workspaceId: WS,
          ownerUserId: ALICE,
          provider: 'mcp',
          clientId: `cli-${s}`,
        }),
      )
    ).id;

    otherAgentId = (
      await withWorkspace(pool, OTHER, (db) =>
        registerAgent(db, policy, {
          workspaceId: OTHER,
          ownerUserId: BOB,
          provider: 'mcp',
          clientId: `cli-other-${s}`,
        }),
      )
    ).id;
  });

  afterAll(async () => {
    await pool.end();
  });

  const note = (
    workspaceId: string,
    agent: string,
    userAgent: string | undefined,
    handshake?: Parameters<typeof recordSighting>[1]['handshake'],
  ) =>
    withWorkspace(pool, workspaceId, (db) =>
      recordSighting(db, {
        workspaceId,
        agentId: agent,
        observation: observeClient(userAgent),
        handshake: handshake ?? null,
      }),
    );

  const noteOutcome = (workspaceId: string, agent: string, userAgent: string) =>
    withWorkspace(pool, workspaceId, (db) =>
      recordSighting(db, {
        workspaceId,
        agentId: agent,
        observation: observeClient(userAgent),
        handshake: null,
      }),
    );

  const read = (workspaceId: string, agent: string) =>
    withWorkspace(pool, workspaceId, (db) => listFingerprints(db, workspaceId, agent));

  it('records a first sighting and then counts repeats', async () => {
    await note(WS, agentId, CLAUDE_CODE);
    await note(WS, agentId, CLAUDE_CODE);
    await note(WS, agentId, CLAUDE_CODE);

    const rows = await read(WS, agentId);
    const row = rows.find((r) => r.product === 'claude-code');

    expect(row).toBeDefined();
    expect(Number(row?.sightings)).toBe(3);
    expect(row?.channel).toBe('sdk-cli');
    // Trust on first use: the first software an agent ever used is pinned, so
    // raising the mode later does not challenge the client the operator is
    // sitting in front of.
    expect(row?.status).toBe('pinned');
  });

  it('pins only the first, and reports which is which', async () => {
    const fresh = `agt_tofu${suffix()}`;
    await withWorkspace(pool, WS, (db) =>
      db.query(
        `insert into agents (id, workspace_id, provider, client_id, owner_user_id)
         values ($1, $2, 'mcp', $3, $4)`,
        [fresh, WS, `cli-tofu-${suffix()}`, ALICE],
      ),
    );

    const first = await noteOutcome(WS, fresh, CLAUDE_CODE);
    const again = await noteOutcome(WS, fresh, CLAUDE_CODE);
    const second = await noteOutcome(WS, fresh, 'other-client/1.0');

    expect(first).toEqual({ kind: 'first' });
    expect(again).toEqual({ kind: 'repeat' });
    expect(second).toEqual({ kind: 'new' });

    const rows = await read(WS, fresh);
    expect(rows.find((r) => r.product === 'claude-code')?.status).toBe('pinned');
    // Everything after the first arrives unendorsed. This is the row an
    // operator is being asked to decide about.
    expect(rows.find((r) => r.product === 'other-client')?.status).toBe('seen');
  });

  it('reports a dropped sighting once the ceiling is reached', async () => {
    const fresh = `agt_cap${suffix()}`;
    await withWorkspace(pool, WS, (db) =>
      db.query(
        `insert into agents (id, workspace_id, provider, client_id, owner_user_id)
         values ($1, $2, 'mcp', $3, $4)`,
        [fresh, WS, `cli-cap-${suffix()}`, ALICE],
      ),
    );

    for (let i = 0; i < MAX_FINGERPRINTS_PER_AGENT; i += 1) {
      expect(await noteOutcome(WS, fresh, `c${i}/1.0`)).not.toEqual({ kind: 'dropped' });
    }

    // One past the ceiling: nothing is written, and the caller is told so
    // rather than being handed a silent success.
    expect(await noteOutcome(WS, fresh, 'one-too-many/1.0')).toEqual({ kind: 'dropped' });
  });

  it('is told apart from a repeat, so only new software raises an alarm', async () => {
    // The gateway alerts on `new` and stays quiet for `first` and `repeat`.
    // An alert on every agent's very first request would fire once per agent
    // forever and teach an operator to ignore the channel.
    const fresh = `agt_alarm${suffix()}`;
    await withWorkspace(pool, WS, (db) =>
      db.query(
        `insert into agents (id, workspace_id, provider, client_id, owner_user_id)
         values ($1, $2, 'mcp', $3, $4)`,
        [fresh, WS, `cli-alarm-${suffix()}`, ALICE],
      ),
    );

    expect((await noteOutcome(WS, fresh, CLAUDE_CODE)).kind).toBe('first');
    // A version bump is the same software and must not alarm.
    expect((await noteOutcome(WS, fresh, 'claude-code/9.9.9 (sdk-cli)')).kind).toBe('repeat');
  });

  it('keeps the first version and moves the last one', async () => {
    await note(WS, agentId, 'claude-code/9.9.9 (sdk-cli)');

    const row = (await read(WS, agentId)).find((r) => r.product === 'claude-code');

    // Same row: an update is not a new client.
    expect(row?.first_version).toBe('2.1.293');
    expect(row?.last_version).toBe('9.9.9');
  });

  it('fills handshake detail in and never blanks it out again', async () => {
    await note(WS, agentId, CLAUDE_CODE, {
      clientName: 'claude-code',
      clientTitle: 'Claude Code',
      clientVersion: '2.1.293',
      protocolVersion: '2025-11-25',
    });

    // Most requests carry no handshake. Those must not erase what the one
    // handshake told us.
    await note(WS, agentId, CLAUDE_CODE, null);

    const row = (await read(WS, agentId)).find((r) => r.product === 'claude-code');
    expect(row?.client_title).toBe('Claude Code');
    expect(row?.protocol_version).toBe('2025-11-25');
  });

  it('records a different program as a separate row', async () => {
    await note(WS, agentId, 'mcp-remote/1.0.0');

    const products = (await read(WS, agentId)).map((r) => r.product);
    expect(products).toContain('claude-code');
    expect(products).toContain('mcp-remote');
  });

  it('stops new rows at the ceiling but keeps counting the ones on file', async () => {
    // A caller varying the header cannot grow this table without bound.
    for (let i = 0; i < MAX_FINGERPRINTS_PER_AGENT + 15; i += 1) {
      await note(WS, agentId, `flood-${i}/1.0`);
    }

    const rows = await read(WS, agentId);
    expect(rows.length).toBeLessThanOrEqual(MAX_FINGERPRINTS_PER_AGENT);

    // The important half: a fingerprint already on file is still updated once
    // the ceiling is reached. A count-then-insert would have frozen these too.
    const before = rows.find((r) => r.product === 'claude-code');
    await note(WS, agentId, CLAUDE_CODE);
    const after = (await read(WS, agentId)).find((r) => r.product === 'claude-code');

    expect(Number(after?.sightings)).toBe(Number(before?.sightings) + 1);
  });

  it('does not leak a fingerprint across workspaces', async () => {
    await note(OTHER, otherAgentId, 'other-tenant-client/1.0');

    const mine = (await read(WS, agentId)).map((r) => r.product);
    expect(mine).not.toContain('other-tenant-client');

    // And the other tenant sees only its own.
    const theirs = (await read(OTHER, otherAgentId)).map((r) => r.product);
    expect(theirs).toEqual(['other-tenant-client']);
  });

  it('refuses to record against an agent in another workspace', async () => {
    // The composite foreign key is the control: workspace WS cannot acquire a
    // row pointing at an agent that belongs to OTHER.
    await expect(note(WS, otherAgentId, CLAUDE_CODE)).rejects.toThrow();
  });
});

describe('fingerprintModeOf', () => {
  it('reads the three real modes', () => {
    expect(fingerprintModeOf({ fingerprint_mode: 'observe' })).toBe('observe');
    expect(fingerprintModeOf({ fingerprint_mode: 'challenge' })).toBe('challenge');
    expect(fingerprintModeOf({ fingerprint_mode: 'deny' })).toBe('deny');
  });

  it('treats an absent column as observe, not as enforcement', () => {
    // The deployment hazard this exists for. `findAgent` does `select *`, so on
    // a database where migration 0027 has not run the field is absent — and a
    // bare `!== 'observe'` would be true, sending step 3 into the enforcing
    // branch to query a table that does not exist either. Every request in the
    // workspace would be denied because the services restarted before the
    // migrations ran.
    expect(fingerprintModeOf({})).toBe('observe');
    expect(fingerprintModeOf({ fingerprint_mode: undefined })).toBe('observe');
    expect(fingerprintModeOf({ fingerprint_mode: null })).toBe('observe');
  });

  it('treats a value outside the three as observe', () => {
    // Unreachable while the CHECK constraint holds. If it is ever reached, the
    // cause is a broken deployment rather than an attack, and denying every
    // request is not a safer answer to that.
    expect(fingerprintModeOf({ fingerprint_mode: 'paranoid' })).toBe('observe');
    expect(fingerprintModeOf({ fingerprint_mode: 7 })).toBe('observe');
  });
});
