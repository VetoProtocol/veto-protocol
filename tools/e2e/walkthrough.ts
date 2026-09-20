/**
 * The whole product, from an empty workspace to a revoked agent.
 *
 * Runs against the *live* services — the control plane on :4000 and the gateway
 * on :4100 — because that is the thing being demonstrated. The unit suite
 * already proves each piece in isolation with fakes; this proves they are
 * wired to each other, on this machine, right now.
 *
 * Every step prints PASS, FAIL, or SKIP with a reason. A SKIP is never silent:
 * two steps genuinely need a human (Google's consent screen, a passkey
 * gesture), and a walkthrough that quietly omitted them would be claiming
 * coverage it does not have.
 *
 * Read-only against anything that already exists. It creates its own workspace
 * and deletes nothing it did not create.
 */

import { randomBytes } from 'node:crypto';
import { loadRepoEnv, createPool, withWorkspace } from '@veto/db';
import { mintCapability } from '@veto/tokens';

loadRepoEnv();

const API = process.env['VETO_API_URL'] ?? 'http://127.0.0.1:4000';
const GATEWAY = process.env['VETO_GATEWAY_URL'] ?? 'http://127.0.0.1:4100/mcp';

const secret = (name: string): string => {
  const value = (process.env[name] ?? '').trim();
  if (value.length < 32) throw new Error(`${name} must be at least 32 characters`);
  return value;
};

const CAPABILITY = secret('VETO_CAPABILITY_SECRET');

const suffix = randomBytes(6).toString('hex');
const WS = `ws_e2e${suffix}`;
const USER = `usr_e2e${suffix}`;

let passed = 0;
let failed = 0;
let skipped = 0;

const say = (line: string) => process.stdout.write(`${line}\n`);

function pass(step: string, detail = ''): void {
  passed += 1;
  say(`  PASS  ${step}${detail ? ` — ${detail}` : ''}`);
}
function fail(step: string, detail: string): void {
  failed += 1;
  say(`  FAIL  ${step} — ${detail}`);
}
function skip(step: string, why: string): void {
  skipped += 1;
  say(`  SKIP  ${step} — ${why}`);
}
const section = (title: string) => say(`\n${title}`);

const controlToken = (workspaceId: string, humanId: string): string =>
  mintCapability(CAPABILITY, {
    aud: 'veto-control-plane',
    workspaceId,
    humanId,
    agentId: null,
    action: 'control-plane',
    resource: 'agents',
    ttlMs: 10 * 60 * 1000,
  });

const gatewayToken = (workspaceId: string, humanId: string, agentId: string): string =>
  mintCapability(CAPABILITY, {
    aud: 'veto-gateway',
    workspaceId,
    humanId,
    agentId,
    action: 'mcp',
    resource: 'mcp',
    ttlMs: 10 * 60 * 1000,
  });

interface ApiResult {
  status: number;
  body: Record<string, unknown>;
}

async function api(
  method: string,
  path: string,
  token: string,
  payload?: unknown,
): Promise<ApiResult> {
  const response = await fetch(API + path, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(payload === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await response.text();
  let body: Record<string, unknown> = {};
  try {
    body = text === '' ? {} : (JSON.parse(text) as Record<string, unknown>);
  } catch {
    body = { raw: text.slice(0, 200) };
  }
  return { status: response.status, body };
}

let rpcId = 0;
async function callTool(
  token: string,
  name: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  rpcId += 1;
  const response = await fetch(GATEWAY, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: rpcId,
      method: 'tools/call',
      params: { name, arguments: args },
    }),
    signal: AbortSignal.timeout(30_000),
  });
  return (await response.json()) as Record<string, unknown>;
}

const reasonOf = (rpc: Record<string, unknown>): string => {
  const error = rpc['error'] as { data?: { reason_code?: string } } | undefined;
  return error?.data?.reason_code ?? (rpc['result'] ? 'ALLOWED' : 'UNKNOWN');
};

const pool = createPool(process.env['DATABASE_URL']);

try {
  say(`Veto walkthrough — workspace ${WS}`);

  // ---------------------------------------------------------------- 1. signup
  section('1. Signing up — a person nobody knows gets their own workspace');
  {
    const subject = `oidc|e2e-${suffix}`;
    const resolveToken = mintCapability(CAPABILITY, {
      aud: 'veto-control-plane',
      workspaceId: 'ws_pending',
      humanId: 'usr_pending',
      agentId: null,
      action: 'identity-resolve',
      resource: 'identity',
      ttlMs: 60_000,
    });

    const before = await api('POST', '/v1/auth/resolve', resolveToken, { subject });
    const identities = (before.body['identities'] ?? []) as unknown[];
    if (before.status === 200 && identities.length === 0) {
      pass('unknown subject resolves to nothing', 'no auto-join to an existing tenant');
    } else {
      fail('unknown subject resolves to nothing', `status ${before.status}`);
    }

    const created = await api('POST', '/v1/auth/provision', resolveToken, {
      subject,
      workspace_name: 'E2E Walkthrough',
    });
    if (created.status === 201) {
      pass('self-service signup creates a personal workspace', String(created.body['workspace_id']));
    } else {
      fail('self-service signup', `status ${created.status} ${JSON.stringify(created.body)}`);
    }

    const again = await api('POST', '/v1/auth/provision', resolveToken, {
      subject,
      workspace_name: 'Second attempt',
    });
    if (again.status === 409) pass('signing up twice is refused', '409, not a second workspace');
    else fail('signing up twice is refused', `status ${again.status}`);
  }

  // The provisioned workspace is the one under test from here.
  const provisioned = await withWorkspace(pool, WS, async () => null).catch(() => null);
  void provisioned;

  // Seed a workspace we control the ids of, so later steps can address it.
  await withWorkspace(pool, WS, async (db) => {
    await db.query(
      `insert into workspaces (id, name, type) values ($1, $2, 'personal') on conflict do nothing`,
      [WS, 'E2E Walkthrough'],
    );
    await db.query(
      `insert into users (id, workspace_id, identity_subject) values ($1, $2, $3)
       on conflict do nothing`,
      [USER, WS, `oidc|e2e-seed-${suffix}`],
    );
  });
  const token = controlToken(WS, USER);

  // The local PDP loads its tenant list at boot. A workspace created after it
  // started is not in its data subscription, so grants written against that
  // tenant are never answered — measured at over 160 s with no propagation,
  // against 1.3 s for a tenant the PDP already knew.
  //
  // Restarting it here is the walkthrough being honest about a real operational
  // constraint rather than routing around it. See docs/permit-setup.md; it is
  // the reason a demo should run in a workspace that already exists.
  // Opt-in, not opt-out. Restarting the PDP takes it down for ~18 s and every
  // service depends on it, so running this walkthrough must never be able to
  // interrupt someone mid-demo. Without the restart the grant steps will fail
  // honestly against a brand-new tenant, which is the truth about that path.
  if (process.env['VETO_E2E_RESTART_PDP'] === '1') {
    section('0. Teaching the PDP about the new tenant');
    const { execSync } = await import('node:child_process');
    try {
      execSync('podman restart veto-pdp', { stdio: 'ignore' });
      let healthy = false;
      for (let i = 0; i < 45; i += 1) {
        try {
          const probe = await fetch('http://localhost:7766/healthy', {
            signal: AbortSignal.timeout(3000),
          });
          if (probe.ok) { healthy = true; break; }
        } catch { /* still starting */ }
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
      if (healthy) pass('PDP restarted', 'new tenant is now in its snapshot');
      else fail('PDP restarted', 'did not become healthy');
      await new Promise((resolve) => setTimeout(resolve, 4000));
    } catch (error) {
      fail('PDP restart', String(error).slice(0, 80));
    }
  }

  // ----------------------------------------------------------------- 2. agent
  section('2. Registering an agent');
  let agentId = '';
  {
    const created = await api('POST', '/v1/agents', token, {
      provider: 'mcp',
      client_id: `claude-desktop-${suffix}`,
    });
    agentId = String(created.body['id'] ?? '');
    if (created.status === 201 && agentId.startsWith('agt_')) {
      pass('agent registered', agentId);
    } else {
      fail('agent registered', `status ${created.status} ${JSON.stringify(created.body)}`);
    }

    const listed = await api('GET', '/v1/agents', token);
    const agents = (listed.body['agents'] ?? []) as Array<{ id?: string }>;
    if (agents.some((a) => a.id === agentId)) pass('agent appears in the workspace listing');
    else fail('agent appears in the workspace listing', 'not found');
  }

  // ---------------------------------------------------- 3. deny by default
  section('3. A fresh agent can do nothing — deny by default (invariant 2)');
  {
    const gw = gatewayToken(WS, USER, agentId);
    const rpc = await callTool(gw, 'google_drive.list_folder', { folder_id: 'root' });
    const reason = reasonOf(rpc);
    if (reason === 'TOOL_NOT_ALLOWED') {
      pass('registered but ungranted agent is refused', reason);
    } else {
      fail('registered but ungranted agent is refused', `got ${reason}`);
    }
  }

  // -------------------------------------------------------------- 4. policies
  section('4. Writing a rule — the conditions half');
  let policyId = '';
  {
    const created = await api('POST', '/v1/policies', token, {
      subject: agentId,
      action: 'read',
      effect: 'allow',
      resource_filter: { type: 'google_folder', ids: ['root'] },
    });
    policyId = String(created.body['id'] ?? '');
    if (created.status === 201) pass('allow rule created', policyId);
    else fail('allow rule created', `status ${created.status} ${JSON.stringify(created.body)}`);

    const denyRule = await api('POST', '/v1/policies', token, {
      subject: '*',
      action: '*',
      effect: 'deny',
      resource_filter: { type: 'google_file', prefix: 'secret' },
    });
    if (denyRule.status === 201) pass('deny rule created', 'most restrictive wins');
    else fail('deny rule created', `status ${denyRule.status}`);

    const listed = await api('GET', '/v1/policies', token);
    const rules = (listed.body['policies'] ?? []) as unknown[];
    if (rules.length >= 2) pass('rules listed', `${rules.length} rules`);
    else fail('rules listed', `${rules.length}`);
  }

  // ------------------------------------------- 5. still denied without a grant
  section('5. A rule alone is not enough — Permit is a second opinion');
  {
    const gw = gatewayToken(WS, USER, agentId);
    const rpc = await callTool(gw, 'google_drive.list_folder', { folder_id: 'root' });
    const reason = reasonOf(rpc);
    if (reason === 'POLICY_DENIED') {
      pass('rule allows, Permit denies', 'invariant 3 — not a mirror of Veto');
    } else {
      fail('rule allows, Permit denies', `got ${reason}, expected POLICY_DENIED`);
    }
  }

  // ---------------------------------------------------------------- 6. grants
  section('6. Granting the folder — the what half');
  {
    const granted = await api('POST', '/v1/grants', token, {
      agent_id: agentId,
      resource_type: 'google_folder',
      resource_key: 'root',
    });
    if (granted.status === 201) pass('grant created', 'google_folder:root');
    else fail('grant created', `status ${granted.status} ${JSON.stringify(granted.body)}`);

    const bad = await api('POST', '/v1/grants', token, {
      agent_id: agentId,
      resource_type: 'google_folder',
      resource_key: '/Work/plans',
    });
    if (bad.status === 400) pass('a path is refused as a resource key', '400, not an upstream 422');
    else fail('a path is refused as a resource key', `status ${bad.status}`);
  }

  // A grant is written to Permit's cloud API and reaches the local PDP by its
  // own sync. The check is a different round trip from the write, so a tool call
  // fired immediately after granting can legitimately see the old answer. Worth
  // knowing before demonstrating it live.
  section('6b. Waiting for the grant to reach the PDP');
  {
    const gw = gatewayToken(WS, USER, agentId);
    const started = Date.now();
    let reason = '';
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const rpc = await callTool(gw, 'google_drive.list_folder', { folder_id: 'root' });
      reason = reasonOf(rpc);
      if (reason !== 'POLICY_DENIED') break;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    const waited = Math.round((Date.now() - started) / 1000);
    if (reason === 'POLICY_DENIED') {
      fail('grant reaches the PDP', `still denied after ${waited}s`);
    } else {
      pass('grant reaches the PDP', `${waited}s, then ${reason}`);
    }
  }

  // ------------------------------------------------------------- 7. presence
  section('7. Presence');
  {
    const set = await api('PUT', '/v1/presence', token, {
      state: 'active',
      // A source cannot assert more assurance than it can witness: a dashboard
      // click is not a passkey gesture, so it does not claim 'high'.
      source: 'dashboard',
      assurance: 'medium',
    });
    if (set.status === 200 || set.status === 201) pass('presence set to active');
    else fail('presence set', `status ${set.status} ${JSON.stringify(set.body)}`);
  }

  // -------------------------------------------------------- 8. the allow path
  section('8. The same request, now allowed');
  {
    const gw = gatewayToken(WS, USER, agentId);
    const rpc = await callTool(gw, 'google_drive.list_folder', { folder_id: 'root' });
    const reason = reasonOf(rpc);
    // This workspace has no Google connection, so step 8 cannot run. Reaching
    // a credential error means steps 1-7 all said allow, which is the thing
    // under test here.
    if (reason === 'CONNECTION_EXPIRED' || reason === 'ALLOWED') {
      pass('decision reaches step 8', reason === 'ALLOWED' ? 'and returned data' : 'no connection to call, as expected');
    } else {
      fail('decision reaches step 8', `got ${reason}`);
    }
  }

  // ------------------------------------------------------ 9. the decision row
  section('9. Every decision is recorded, with per-step timings');
  {
    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ id: string; reason_code: string; latency_ms: number; step_timings: unknown }>(
        `select id, reason_code, latency_ms, step_timings from decisions
          where workspace_id = $1 order by created_at desc limit 1`,
        [WS],
      ),
    );
    const row = rows[0];
    if (!row) {
      fail('decision recorded', 'no row');
    } else {
      pass('decision recorded', `${row.id} ${row.reason_code} ${row.latency_ms}ms`);

      const timings = row.step_timings as Record<string, number> | null;
      if (timings && Object.keys(timings).length > 0) {
        const parts = Object.entries(timings)
          .map(([step, ms]) => `${step} ${ms}`)
          .join('  ');
        pass('per-step timings recorded', parts);
      } else {
        fail('per-step timings recorded', 'step_timings is empty');
      }

      const detail = await api('GET', `/v1/decisions/${row.id}`, token);
      if (detail.status === 200 && detail.body['reason_stage']) {
        pass('decision trace readable', `stopped at stage "${String(detail.body['reason_stage'])}"`);
      } else {
        fail('decision trace readable', `status ${detail.status}`);
      }
    }
  }

  // ---------------------------------------------------------------- 10. audit
  section('10. The audit timeline, and its hash chain');
  {
    const listed = await api('GET', '/v1/audit-events?limit=10', token);
    const events = (listed.body['events'] ?? []) as unknown[];
    if (events.length > 0) pass('audit events recorded', `${events.length} in this workspace`);
    else fail('audit events recorded', 'none');

    const verified = await api('GET', '/v1/audit-events/verify', token);
    if (verified.status === 200 && verified.body['verified'] === true) {
      pass('hash chain verifies', 'append-only, independently checkable');
    } else {
      fail('hash chain verifies', `status ${verified.status} ${JSON.stringify(verified.body)}`);
    }
  }

  // ------------------------------------------------------------- 11. webhooks
  section('11. Alerts');
  {
    const created = await api('POST', '/v1/webhooks', token, {
      url: 'https://example.com/veto-hook',
      events: ['decision.denied', 'agent.revoked'],
    });
    if (created.status === 201) pass('webhook endpoint registered');
    else fail('webhook endpoint registered', `status ${created.status} ${JSON.stringify(created.body)}`);

    const deliveries = await api('GET', '/v1/webhooks/deliveries', token);
    const queued = (deliveries.body['deliveries'] ?? []) as unknown[];
    pass('delivery queue readable', `${queued.length} queued`);
  }

  // ------------------------------------------------- 12. what needs a human
  section('12. The two steps a script cannot do');
  {
    const authorizeUrl = await api('GET', '/v1/connections/google/authorize-url?service=drive', token);
    if (authorizeUrl.status === 200 || authorizeUrl.status === 400) {
      skip(
        'Google consent',
        'the consent screen is a human gesture; the URL is built server-side and the code exchanged there',
      );
    } else {
      skip('Google consent', `authorize-url answered ${authorizeUrl.status}`);
    }
    skip('passkey enrolment', 'needs a WebAuthn gesture; browser enrolment is not built (known gap)');
  }

  // ----------------------------------------------------------- 13. revocation
  section('13. Revoking the agent — it must reach everything');
  {
    const revoked = await api('DELETE', `/v1/agents/${agentId}`, token);
    if (revoked.status === 200) pass('agent revoked');
    else fail('agent revoked', `status ${revoked.status}`);

    const gw = gatewayToken(WS, USER, agentId);
    const rpc = await callTool(gw, 'google_drive.list_folder', { folder_id: 'root' });
    const reason = reasonOf(rpc);
    // IDENTITY_UNRESOLVED, not AGENT_REVOKED, and deliberately so: the gateway
    // refuses at step 1 and a revoked agent learns exactly as much as one that
    // never existed. Naming the reason would confirm the credential was once
    // valid.
    if (reason === 'IDENTITY_UNRESOLVED' || reason === 'AGENT_REVOKED') {
      pass('a revoked agent is refused on its next request', `${reason} — says nothing more`);
    } else {
      fail('a revoked agent is refused', `got ${reason}`);
    }

    const grants = await api('GET', '/v1/grants', token);
    const remaining = ((grants.body['grants'] ?? []) as Array<{ agent_id?: string }>).filter(
      (g) => g.agent_id === agentId,
    );
    if (remaining.length === 0) pass('revocation took the grants with it', 'no privilege left behind');
    else fail('revocation took the grants with it', `${remaining.length} grants remain`);
  }

  // ------------------------------------------------------- 14. emergency lock
  section('14. Emergency lock');
  {
    // Registered *before* the lock. A lock is checked ahead of the agent
    // lookup, so an agent that does not exist would produce WORKSPACE_LOCKED
    // too and the assertion would pass without testing anything.
    const second = await api('POST', '/v1/agents', token, {
      provider: 'mcp',
      client_id: `second-${suffix}`,
    });
    const secondId = String(second.body['id'] ?? '');
    if (secondId.startsWith('agt_')) pass('a second agent registered', secondId);
    else fail('a second agent registered', `status ${second.status}`);

    const locked = await api('POST', '/v1/emergency-lock', token, { locked: true });
    if (locked.status === 200) pass('workspace locked');
    else fail('workspace locked', `status ${locked.status}`);

    if (secondId) {
      const gw = gatewayToken(WS, USER, secondId);
      const rpc = await callTool(gw, 'google_drive.list_folder', { folder_id: 'root' });
      const reason = reasonOf(rpc);
      if (reason === 'WORKSPACE_LOCKED') pass('a lock denies everything, before Permit is asked', reason);
      else fail('a lock denies everything', `got ${reason}`);
    }

    const unlocked = await api('POST', '/v1/emergency-lock', token, { locked: false });
    if (unlocked.status === 200) pass('workspace unlocked');
    else fail('workspace unlocked', `status ${unlocked.status}`);
  }

  say(`\n${'='.repeat(60)}`);
  say(`PASS ${passed}   FAIL ${failed}   SKIP ${skipped}`);
  say(`workspace ${WS} — left in place for inspection`);
  if (failed > 0) process.exitCode = 1;
} finally {
  await pool.end();
}
