/**
 * Phase 2's exit condition, stated as tests.
 *
 * A real MCP client connects, lists tools, and **every** tools/call is denied.
 * The interesting assertions are the ones about who gets refused: a revoked
 * agent, a suspended one, a token with no agent claim, and a token naming
 * another workspace's agent all get the same answer as a stranger.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, type FakePolicyDecisions } from '@veto/permit';
import { POLICY_ACTIONS } from '@veto/decisions';
import { createGateway, PROTOCOL_VERSION } from '../src/app.ts';
import { TOOLS } from '../src/tools.ts';
import { RPC } from '../src/jsonrpc.ts';
import { SECRET, gatewayToken, rpc, seedAgent, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let policy: FakePolicyDecisions;
let app: FastifyInstance;

const s = suffix();
const WS_A = `ws_a${s}`;
const WS_B = `ws_b${s}`;
const ALICE = `usr_alice${s}`;
const BOB = `usr_bob${s}`;
const CAROL = `usr_carol${s}`;
const LIVE = `agt_live${s}`;
const REVOKED = `agt_rev${s}`;
const SUSPENDED = `agt_susp${s}`;
const OTHER_WS_AGENT = `agt_other${s}`;

const PUBLIC_URL = 'https://gateway.veto.example';

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  policy = createFakePolicyDecisions();
  await seedAgent(pool, WS_A, ALICE, LIVE, 'claude-desktop');
  await seedAgent(pool, WS_A, ALICE, REVOKED, 'cursor', 'revoked');
  await seedAgent(pool, WS_A, BOB, SUSPENDED, 'zed', 'suspended');
  await seedAgent(pool, WS_B, CAROL, OTHER_WS_AGENT, 'claude-desktop');

  app = createGateway({
    pool,
    redis,
    policy,
    capabilitySecret: SECRET,
    publicUrl: PUBLIC_URL,
    authorizationServer: 'https://app.veto.example',
  });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

const post = (payload: unknown, token?: string) =>
  app.inject({
    method: 'POST',
    url: '/mcp',
    ...(token === undefined ? {} : { headers: { authorization: `Bearer ${token}` } }),
    payload: payload as object,
  });

const live = () => gatewayToken(WS_A, ALICE, LIVE);

describe('discovery', () => {
  it('serves protected resource metadata without authentication', async () => {
    const res = await app.inject({ method: 'GET', url: '/.well-known/oauth-protected-resource' });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      resource: `${PUBLIC_URL}/mcp`,
      authorization_servers: ['https://app.veto.example'],
    });
  });

  it('returns only Veto-controlled URLs', async () => {
    // Invariant 8: the gateway must never hand a client a URL that bypasses it.
    const body = (await app.inject({ method: 'GET', url: '/.well-known/oauth-protected-resource' })).json();

    for (const url of [body.resource, ...body.authorization_servers, body.resource_documentation]) {
      expect(String(url)).toMatch(/^https:\/\/(gateway|app)\.veto\.example/);
    }
  });
});

describe('authentication', () => {
  it('refuses an unauthenticated call and says where to authenticate', async () => {
    const res = await post(rpc('tools/list'));

    expect(res.statusCode).toBe(401);
    expect(res.headers['www-authenticate']).toContain(
      `${PUBLIC_URL}/.well-known/oauth-protected-resource`,
    );
    expect(res.json().error.code).toBe(RPC.UNAUTHENTICATED);
  });

  it('gives every kind of bad credential the same answer', async () => {
    // A revoked agent must learn exactly as much as a stranger.
    const cases: Array<[string, string | undefined]> = [
      ['no token', undefined],
      ['garbage', 'not-a-token'],
      ['no agent claim', gatewayToken(WS_A, ALICE, null)],
      ['control-plane audience', gatewayToken(WS_A, ALICE, LIVE, { aud: 'veto-control-plane' })],
      ['wrong scope', gatewayToken(WS_A, ALICE, LIVE, { action: 'control-plane' })],
      ['revoked agent', gatewayToken(WS_A, ALICE, REVOKED)],
      ['suspended agent', gatewayToken(WS_A, BOB, SUSPENDED)],
      ['another workspace agent', gatewayToken(WS_A, ALICE, OTHER_WS_AGENT)],
      ['owner mismatch', gatewayToken(WS_A, BOB, LIVE)],
    ];

    const answers = new Set<string>();
    for (const [label, token] of cases) {
      const res = await post(rpc('tools/list'), token);
      expect(res.statusCode, label).toBe(401);
      answers.add(JSON.stringify(res.json().error));
    }

    // One distinct body across every failure mode: nothing is learned from
    // which one you hit.
    expect(answers.size).toBe(1);
  });

  it('reads the agent status on every request, not just at connect', async () => {
    // §11: revocation effective on the next protected request. The token stays
    // cryptographically valid, so only the database read can enforce this.
    const agentId = `agt_flip${suffix()}`;
    await seedAgent(pool, WS_A, ALICE, agentId, `flip-${suffix()}`);
    const token = gatewayToken(WS_A, ALICE, agentId);

    expect((await post(rpc('tools/list'), token)).statusCode).toBe(200);

    const c = await pool.connect();
    try {
      await c.query('begin');
      await c.query('select set_config($1,$2,true)', ['veto.workspace_id', WS_A]);
      await c.query(`update agents set status='revoked', revoked_at=now() where id=$1`, [agentId]);
      await c.query('commit');
    } finally {
      c.release();
    }

    expect((await post(rpc('tools/list'), token)).statusCode).toBe(401);
  });
});

describe('JSON-RPC validation', () => {
  it('rejects malformed and non-conforming requests', async () => {
    const cases: Array<[string, unknown, number]> = [
      ['batch', [rpc('ping'), rpc('ping')], RPC.INVALID_REQUEST],
      ['wrong version', { jsonrpc: '1.0', id: 1, method: 'ping' }, RPC.INVALID_REQUEST],
      ['missing method', { jsonrpc: '2.0', id: 1 }, RPC.INVALID_REQUEST],
      ['empty method', { jsonrpc: '2.0', id: 1, method: '' }, RPC.INVALID_REQUEST],
      ['positional params', { jsonrpc: '2.0', id: 1, method: 'ping', params: [1] }, RPC.INVALID_PARAMS],
      ['object id', { jsonrpc: '2.0', id: {}, method: 'ping' }, RPC.INVALID_REQUEST],
    ];

    for (const [label, payload, code] of cases) {
      const res = await post(payload, live());
      expect(res.statusCode, label).toBe(400);
      expect(res.json().error.code, label).toBe(code);
    }
  });

  it('rejects a JSON body that is not an object', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/mcp',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${live()}` },
      payload: '"hello"',
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe(RPC.INVALID_REQUEST);
  });

  it('refuses a content type that is not JSON', async () => {
    // MCP is JSON over HTTP. Sniffing a body whose type says otherwise would be
    // guessing at the caller's intent on the wrong side of the boundary.
    const res = await app.inject({
      method: 'POST',
      url: '/mcp',
      headers: { 'content-type': 'text/plain', authorization: `Bearer ${live()}` },
      payload: 'hello',
    });

    expect(res.statusCode).toBe(415);
  });

  it('turns unparsable JSON into a parse error, not a framework 400', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/mcp',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${live()}` },
      payload: '{ not json',
    });

    expect(res.json().error.code).toBe(RPC.PARSE_ERROR);
  });

  it('rejects an unknown method', async () => {
    const res = await post(rpc('tools/destroy'), live());
    expect(res.json().error.code).toBe(RPC.METHOD_NOT_FOUND);
  });

  it('answers a notification with no body', async () => {
    const res = await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, live());
    expect(res.statusCode).toBe(202);
    expect(res.body).toBe('');
  });
});

describe('a client can connect and list', () => {
  it('initializes', async () => {
    const res = await post(rpc('initialize'), live());
    const result = res.json().result;

    expect(result.protocolVersion).toBe(PROTOCOL_VERSION);
    expect(result.serverInfo.name).toBe('veto-gateway');
    // The instructions tell the model the rule it most needs to know.
    expect(result.instructions).toContain('authorized individually');
  });

  it('lists tools', async () => {
    const tools = (await post(rpc('tools/list'), live())).json().result.tools;

    // The whole catalogue, asserted exactly. A tool appearing here without
    // anybody noticing is a new thing an agent can ask for.
    expect(tools.map((t: { name: string }) => t.name)).toEqual([
      'google_drive.read_file',
      'google_drive.list_folder',
      'google_gmail.search_messages',
      'google_gmail.read_message',
    ]);
  });

  it('lists the same catalogue to every agent, because listing is not granting', async () => {
    const a = (await post(rpc('tools/list'), live())).json().result;
    const b = (await post(rpc('tools/list'), gatewayToken(WS_B, CAROL, OTHER_WS_AGENT))).json().result;

    expect(a).toEqual(b);
  });

  it('declares an action a policy rule is allowed to name', async () => {
    // The drift guard. A tool whose action is not in POLICY_ACTIONS can never
    // be allowed by any rule, because /v1/policies refuses to write one naming
    // it — so the tool would be listed, called, and denied forever with nothing
    // pointing at the cause.
    for (const tool of TOOLS) {
      expect(POLICY_ACTIONS as readonly string[], tool.name).toContain(tool.action);
    }
  });

  it('declares strict, closed argument schemas', async () => {
    // Arguments are validated before policy evaluation (invariant 9), which
    // requires a schema that cannot be widened by the caller.
    const tools = (await post(rpc('tools/list'), live())).json().result.tools;

    for (const tool of tools) {
      expect(tool.inputSchema.additionalProperties, tool.name).toBe(false);
      expect(Array.isArray(tool.inputSchema.required), tool.name).toBe(true);
    }
  });
});

describe('tool calls go through the pipeline', () => {
  const call = (name: string, args: unknown) =>
    post(rpc('tools/call', { name, arguments: args }), live());

  it('denies by default — nothing is granted until a policy says so', async () => {
    for (const [name, args] of [
      ['google_drive.read_file', { file_id: '/Work/report.md' }],
      ['google_drive.list_folder', { folder_id: '/Work' }],
      ['not_a_real_tool', { anything: true }],
    ] as const) {
      const res = await call(name, args);

      // 200 with a JSON-RPC error: a denial is a normal outcome, not a
      // transport failure.
      expect(res.statusCode, name).toBe(200);
      const error = res.json().error;
      expect(error.code, name).toBe(RPC.DENIED);
      expect(error.data.result, name).toBe('deny');
      expect(error.data.reason_code, name).toBe('TOOL_NOT_ALLOWED');
      expect(error.data.correlation_id, name).toBeTruthy();
    }
  });

  it('rejects arguments before deciding anything', async () => {
    // Invariant 9: validation runs before policy evaluation, so a malformed
    // call never reaches a decision and never produces a digest.
    for (const args of [{}, { file_id: '' }, { file_id: 'x', nope: 1 }, { file_id: 12 }]) {
      const res = await call('google_drive.read_file', args);
      expect(res.json().error.code, JSON.stringify(args)).toBe(RPC.INVALID_PARAMS);
      expect(res.json().error.data.reason_code).toBe('ARGUMENT_SCHEMA_INVALID');
    }
  });

  it('allows once a policy and Permit agree, and says nothing was fetched', async () => {
    const file = `/Work/ok-${suffix()}.md`;
    await withWorkspace(pool, WS_A, (db) =>
      db.query(
        `insert into policies (id,workspace_id,subject,action,resource_filter,conditions,effect,version)
         values ($1,$2,$3,'read',$4,'{}'::jsonb,'allow','polv_g')`,
        [`pol_${suffix()}${suffix()}`, WS_A, LIVE, JSON.stringify({ type: 'google_file', ids: [file] })],
      ),
    );
    policy.allow(WS_A, LIVE, 'read', 'google_file', file);

    const res = await call('google_drive.read_file', { file_id: file });
    const result = res.json().result;

    expect(res.json().error).toBeUndefined();
    expect(result.isError).toBe(false);
    // An allow is not an execution. Phase 5 makes the upstream call; pretending
    // otherwise would hand the model a result it would act on.
    expect(result.content[0].text).toContain('not configured');
  });

  it('challenges, and names the approval the human must resolve', async () => {
    const file = `/Finance/q-${suffix()}.xlsx`;
    await withWorkspace(pool, WS_A, (db) =>
      db.query(
        `insert into policies (id,workspace_id,subject,action,resource_filter,conditions,effect,version)
         values ($1,$2,$3,'read',$4,'{}'::jsonb,'challenge','polv_g')`,
        [`pol_${suffix()}${suffix()}`, WS_A, LIVE, JSON.stringify({ type: 'google_file', ids: [file] })],
      ),
    );
    policy.allow(WS_A, LIVE, 'read', 'google_file', file);

    const error = (await call('google_drive.read_file', { file_id: file })).json().error;

    expect(error.data.result).toBe('challenge');
    expect(error.data.reason_code).toBe('APPROVAL_REQUIRED');
    expect(error.data.approval_id).toMatch(/^apr_/);
    expect(error.data.expires_at).toBeTruthy();
  });

  it('resumes a challenge only with the grant, and only once', async () => {
    const file = `/Finance/resume-${suffix()}.xlsx`;
    await withWorkspace(pool, WS_A, (db) =>
      db.query(
        `insert into policies (id,workspace_id,subject,action,resource_filter,conditions,effect,version)
         values ($1,$2,$3,'read',$4,'{}'::jsonb,'challenge','polv_g')`,
        [`pol_${suffix()}${suffix()}`, WS_A, LIVE, JSON.stringify({ type: 'google_file', ids: [file] })],
      ),
    );
    policy.allow(WS_A, LIVE, 'read', 'google_file', file);

    const challenged = (await call('google_drive.read_file', { file_id: file })).json().error;
    const approvalId: string = challenged.data.approval_id;

    // The human says yes.
    await withWorkspace(pool, WS_A, (db) =>
      db.query(
        `update approvals set status='approved', resolved_at=now() where workspace_id=$1 and id=$2`,
        [WS_A, approvalId],
      ),
    );

    const withGrant = (id: string, args: Record<string, unknown> = { file_id: file }) =>
      post(rpc('tools/call', { name: 'google_drive.read_file', arguments: args, approval_id: id }), live());

    const allowed = (await withGrant(approvalId)).json();
    expect(allowed.error).toBeUndefined();
    expect(allowed.result.isError).toBe(false);

    // Single use.
    expect((await withGrant(approvalId)).json().error.data.reason_code).toBe('APPROVAL_REPLAYED');
  });

  it('rejects a non-string approval_id before deciding', async () => {
    const res = await post(
      rpc('tools/call', { name: 'google_drive.read_file', arguments: { file_id: '/x' }, approval_id: 7 }),
      live(),
    );
    expect(res.json().error.code).toBe(RPC.INVALID_PARAMS);
  });

  it('never dresses a refusal up as a tool result', async () => {
    // A denial arriving as content is a denial the model can try to work with.
    const body = (await call('google_drive.read_file', { file_id: '/nothing-granted' })).json();

    expect(body.result).toBeUndefined();
    expect(body.error.code).toBe(RPC.DENIED);
  });
});

describe('construction', () => {
  it('refuses a weak signing key', () => {
    expect(() =>
      createGateway({
        pool,
        redis,
        policy,
        capabilitySecret: 'short',
        publicUrl: PUBLIC_URL,
        authorizationServer: 'https://app.veto.example',
      }),
    ).toThrow(/at least 32/);
  });
});
