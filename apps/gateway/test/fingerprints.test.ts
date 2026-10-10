/**
 * Agent fingerprints through the real gateway.
 *
 * The unit tests in `@veto/identity` prove the parser and the writer. These
 * prove the wiring: that a request arriving over HTTP leaves a row behind, and
 * — the part that matters more — that nothing about this record can change
 * whether a request is allowed.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, type FakePolicyDecisions } from '@veto/permit';
import {
  listFingerprints,
  observeClient,
  setFingerprintMode,
  setFingerprintStatus,
} from '@veto/identity';
import { createGateway } from '../src/app.ts';
import { SECRET, gatewayToken, rpc, seedAgent, suffix, testPool, testRedis } from './helpers.ts';

/** Exactly what Claude Code 2.1.293 sent, measured on 2026-10-09. */
const CLAUDE_CODE = 'claude-code/2.1.293 (sdk-cli)';

let pool: Pool;
let redis: Redis;
let policy: FakePolicyDecisions;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_fp${s}`;
const ALICE = `usr_fp${s}`;
const AGENT = `agt_fp${s}`;

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  policy = createFakePolicyDecisions();
  await seedAgent(pool, WS, ALICE, AGENT, `cli-fp-${s}`);

  app = createGateway({
    pool,
    redis,
    policy,
    capabilitySecret: SECRET,
    publicUrl: 'https://gateway.veto.example',
    authorizationServer: 'https://app.veto.example',
  });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

// `app.inject` supplies a `user-agent` of its own when none is given, so an
// absent header is simulated with an empty one rather than by omission — which
// is itself a small confirmation that the recorder reads the real header and
// not something the gateway invented.
const post = (body: unknown, userAgent: string) =>
  app.inject({
    method: 'POST',
    url: '/mcp',
    headers: {
      authorization: `Bearer ${gatewayToken(WS, ALICE, AGENT)}`,
      'user-agent': userAgent,
    },
    payload: body as object,
  });

const recorded = () => withWorkspace(pool, WS, (db) => listFingerprints(db, WS, AGENT));

describe('fingerprints through the gateway', () => {
  it('records the handshake, with the detail only initialize carries', async () => {
    const res = await post(
      rpc('initialize', {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'claude-code', title: 'Claude Code', version: '2.1.293' },
      }),
      CLAUDE_CODE,
    );
    expect(res.statusCode).toBe(200);

    const row = (await recorded()).find((r) => r.product === 'claude-code');
    expect(row?.channel).toBe('sdk-cli');
    expect(row?.client_title).toBe('Claude Code');
    expect(row?.protocol_version).toBe('2025-11-25');
  });

  it('records the tool call too — the request that actually matters', async () => {
    // This is the finding phase 0 turned up: the User-Agent rides on every
    // request, so the protected action identifies its own client without
    // depending on a handshake happening first, or at all.
    const before = Number((await recorded()).find((r) => r.product === 'claude-code')?.sightings ?? 0);

    await post(rpc('tools/call', { name: 'google_drive.read_file', arguments: { file_id: 'f1' } }), CLAUDE_CODE);

    const after = Number((await recorded()).find((r) => r.product === 'claude-code')?.sightings ?? 0);
    expect(after).toBe(before + 1);
  });

  it('does not change the answer — a stranger gets the same denial', async () => {
    // The whole safety claim for this phase. Two tool calls, wildly different
    // clients, identical outcome.
    const call = rpc('tools/call', { name: 'google_drive.read_file', arguments: { file_id: 'f1' } });

    const known = await post(call, CLAUDE_CODE);
    const unknown = await post(call, 'definitely-not-claude/0.0.1 (stolen)');
    const headless = await post(call, '');

    const reason = (r: { json: () => { error?: { data?: { reason_code?: string } } } }) =>
      r.json().error?.data?.reason_code;

    expect(reason(unknown)).toBe(reason(known));
    expect(reason(headless)).toBe(reason(known));
    expect(known.statusCode).toBe(unknown.statusCode);
  });

  it('records an unrecognised client beside the known one, not instead of it', async () => {
    const products = (await recorded()).map((r) => r.product);

    expect(products).toContain('claude-code');
    expect(products).toContain('definitely-not-claude');
    // A request with no User-Agent is a bucket of its own, never silently
    // folded into whatever was seen last.
    expect(products).toContain(observeClient(undefined).product);
  });

  it('a tool call with no agent on the token still refuses before recording anything', async () => {
    // Ordering: identity is resolved first, and `resolveSession` throws before
    // any sighting is written. An unauthenticated caller must not be able to
    // put a row in this table.
    const res = await app.inject({
      method: 'POST',
      url: '/mcp',
      headers: {
        authorization: `Bearer ${gatewayToken(WS, ALICE, null)}`,
        'user-agent': 'ghost/1.0',
      },
      payload: rpc('tools/call', { name: 'google_drive.read_file', arguments: { file_id: 'f1' } }),
    });

    expect(res.statusCode).toBe(401);
    expect((await recorded()).map((r) => r.product)).not.toContain('ghost');
  });
});

/**
 * Enforcement. The §12.1 shape for this feature is "a stolen credential used
 * from somewhere else", and the tests that matter most are the two that say
 * what it cannot do.
 */
describe('fingerprint enforcement at step 3', () => {
  const mode = (m: 'observe' | 'challenge' | 'deny') =>
    withWorkspace(pool, WS, (db) => setFingerprintMode(db, WS, AGENT, m));

  const status = (userAgent: string, s: 'pinned' | 'seen' | 'refused') =>
    withWorkspace(pool, WS, (db) =>
      setFingerprintStatus(db, {
        workspaceId: WS,
        agentId: AGENT,
        fingerprint: observeClient(userAgent).fingerprint,
        status: s,
      }),
    );

  // A file this agent is genuinely allowed to read.
  //
  // Needed because a deny always beats a held challenge: with no rule, step 4
  // answers TOOL_NOT_ALLOWED and the fingerprint check never shows. So the
  // only place `challenge` is observable is on an action that would otherwise
  // succeed — which is the right precedence and worth being explicit about.
  const ALLOWED_FILE = `/Work/fp-${suffix()}.md`;

  const call = () =>
    rpc('tools/call', { name: 'google_drive.read_file', arguments: { file_id: ALLOWED_FILE } });

  const reasonOf = async (userAgent: string): Promise<string | undefined> => {
    const res = await post(call(), userAgent);
    return res.json().error?.data?.reason_code;
  };

  beforeAll(async () => {
    await withWorkspace(pool, WS, (db) =>
      db.query(
        `insert into policies (id,workspace_id,subject,action,resource_filter,conditions,effect,version)
         values ($1,$2,$3,'read',$4,'{}'::jsonb,'allow','polv_fp')`,
        [
          `pol_${suffix()}${suffix()}`,
          WS,
          AGENT,
          JSON.stringify({ type: 'google_file', ids: [ALLOWED_FILE] }),
        ],
      ),
    );
    policy.allow(WS, AGENT, 'read', 'google_file', ALLOWED_FILE);

    // Everything this suite needs on file, pinned or otherwise, before any
    // mode is raised.
    await post(call(), CLAUDE_CODE);
    await status(CLAUDE_CODE, 'pinned');
  });

  afterAll(async () => {
    // Never leave an enforcing mode behind for another suite to trip over.
    await mode('observe');
  });

  it('observe changes nothing at all, for any client', async () => {
    await mode('observe');

    const pinned = await reasonOf(CLAUDE_CODE);
    const stranger = await reasonOf('stolen-token-client/1.0');

    // The promise the default rests on. A workspace that has not turned this
    // on cannot be affected by it, and that includes a client somebody has
    // explicitly refused.
    await status('refused-in-observe/1.0', 'seen');
    await post(call(), 'refused-in-observe/1.0');
    await status('refused-in-observe/1.0', 'refused');

    expect(stranger).toBe(pinned);
    expect(await reasonOf('refused-in-observe/1.0')).toBe(pinned);
  });

  it('challenge lets a pinned client through and stops an unknown one', async () => {
    await mode('challenge');

    // The pinned client is not merely spared this code — it is allowed.
    const allowed = await post(call(), CLAUDE_CODE);
    expect(allowed.json().error).toBeUndefined();

    expect(await reasonOf('brand-new-thing/1.0')).toBe('AGENT_FINGERPRINT_UNRECOGNISED');
  });

  it('challenge does not become an allow — a denial later still wins', async () => {
    await mode('challenge');

    // A file no rule grants. The fingerprint held a challenge, and step 4's
    // denial has to win: challenge is the least permissive answer that is not
    // a refusal, and anything stricter replaces it.
    const res = await post(
      rpc('tools/call', { name: 'google_drive.read_file', arguments: { file_id: '/nothing-grants-this' } }),
      'brand-new-thing/1.0',
    );

    expect(res.json().error?.data?.reason_code).toBe('TOOL_NOT_ALLOWED');
    expect(res.json().result).toBeUndefined();
  });

  it('deny refuses an unknown client outright', async () => {
    await mode('deny');

    expect(await reasonOf('brand-new-thing/1.0')).toBe('AGENT_FINGERPRINT_REJECTED');
    expect(await reasonOf(CLAUDE_CODE)).not.toBe('AGENT_FINGERPRINT_REJECTED');
  });

  it('refuses a client an operator refused, even while others pass', async () => {
    await mode('challenge');
    await post(call(), 'banned-client/2.0');
    await status('banned-client/2.0', 'refused');

    expect(await reasonOf('banned-client/2.0')).toBe('AGENT_FINGERPRINT_REJECTED');
  });

  it('refuses a request that named no client while enforcing', async () => {
    await mode('deny');
    // Absence narrows, as it does for presence and for an unreadable schedule.
    expect(await reasonOf('')).toBe('AGENT_FINGERPRINT_REJECTED');
  });

  it('CANNOT stop a thief who copies the header — stated, not hidden', async () => {
    // The honest limit, as a test so nobody can quietly start claiming more.
    // A `User-Agent` is a string the client chooses. Someone holding a stolen
    // token who sends the pinned client's header is indistinguishable from the
    // real one, and this feature is change detection rather than
    // authentication precisely because of this case.
    await mode('deny');

    const thiefWhoCopied = await post(call(), CLAUDE_CODE);

    // Allowed. Not "not rejected" — allowed, in the strictest mode there is.
    expect(thiefWhoCopied.json().error).toBeUndefined();
    expect(thiefWhoCopied.json().result.isError).toBe(false);
  });

  it('does not leak enforcement across agents in the same workspace', async () => {
    await mode('deny');

    const sibling = `agt_sib${suffix()}`;
    await withWorkspace(pool, WS, (db) =>
      db.query(
        `insert into agents (id, workspace_id, provider, client_id, owner_user_id)
         values ($1, $2, 'mcp', $3, $4)`,
        [sibling, WS, `cli-sib-${suffix()}`, ALICE],
      ),
    );

    // The mode is per agent. A sibling left on `observe` is unaffected by this
    // one being set to `deny`.
    const res = await app.inject({
      method: 'POST',
      url: '/mcp',
      headers: {
        authorization: `Bearer ${gatewayToken(WS, ALICE, sibling)}`,
        'user-agent': 'anything-at-all/1.0',
      },
      payload: call(),
    });

    expect(res.json().error?.data?.reason_code).not.toBe('AGENT_FINGERPRINT_REJECTED');
  });
});

/**
 * The alert path, with a receiver actually subscribed.
 *
 * `enqueue` returns early when no endpoint wants the event, so every other
 * test in this file exercises the call and none of them exercises the write.
 * On a workspace that *has* a receiver subscribed to `risk.anomaly_detected`,
 * a new client creates delivery rows — and this is the only test that proves
 * the gateway can do that at all, since until now `@veto/webhooks` was only
 * ever called from the API and the pipeline.
 */
describe('alerting a subscribed receiver', () => {
  const ENDPOINT = `whe_fp${suffix()}`;

  beforeAll(async () => {
    await withWorkspace(pool, WS, (db) =>
      db.query(
        `insert into webhook_endpoints
           (id, workspace_id, url, secret_sealed, secret_key_id, events, created_by)
         values ($1, $2, $3, $4, 'test-key', $5, $6)`,
        [
          ENDPOINT,
          WS,
          `https://receiver.example/fp-${suffix()}`,
          Buffer.from('not-a-real-sealed-secret'),
          ['risk.anomaly_detected'],
          ALICE,
        ],
      ),
    );
  });

  const deliveries = async (): Promise<string[]> => {
    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ event_type: string }>(
        `select event_type from webhook_deliveries
          where workspace_id = $1 and endpoint_id = $2`,
        [WS, ENDPOINT],
      ),
    );
    return rows.map((r) => r.event_type);
  };

  it('queues an anomaly when new software appears, in observe mode', async () => {
    // Observe must not change an *answer*. It would be a strange kind of
    // observation that declined to mention what it saw.
    await withWorkspace(pool, WS, (db) => setFingerprintMode(db, WS, AGENT, 'observe'));

    expect(await deliveries()).toEqual([]);

    await post(
      rpc('tools/call', { name: 'google_drive.read_file', arguments: { file_id: '/x' } }),
      `first-sighting-of-this/1.0`,
    );

    expect(await deliveries()).toEqual(['risk.anomaly_detected']);
  });

  it('stays quiet for a repeat, and for a version bump', async () => {
    const before = (await deliveries()).length;

    await post(
      rpc('tools/call', { name: 'google_drive.read_file', arguments: { file_id: '/x' } }),
      `first-sighting-of-this/1.0`,
    );
    // Same product and channel, new version: the same fingerprint, so nothing
    // changed and nobody is told anything.
    await post(
      rpc('tools/call', { name: 'google_drive.read_file', arguments: { file_id: '/x' } }),
      `first-sighting-of-this/9.9.9`,
    );

    expect((await deliveries()).length).toBe(before);
  });

  it('queues nothing a receiver did not subscribe to', async () => {
    // The endpoint wants anomalies only. A denial is not an anomaly, and the
    // closed event set is what keeps the two apart.
    expect((await deliveries()).every((t) => t === 'risk.anomaly_detected')).toBe(true);
  });
});
