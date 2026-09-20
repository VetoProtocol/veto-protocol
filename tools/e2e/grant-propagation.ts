/**
 * How long does a new grant take to reach the PDP?
 *
 * A grant is written to Permit's Cloud API. The check is answered by the PDP.
 * With the hosted PDP those are the same service; with a local one they are
 * not, and the container learns about the grant by its own sync. If that takes
 * long enough to notice, "grant it and try again" stops being a demo and starts
 * being an apology.
 */
import { loadRepoEnv, createPool, withWorkspace } from '@veto/db';
import { mintCapability } from '@veto/tokens';
import { randomBytes } from 'node:crypto';

loadRepoEnv();
const API = 'http://127.0.0.1:4000';
const GW = 'http://127.0.0.1:4100/mcp';
const KEY = process.env['VETO_CAPABILITY_SECRET'] ?? '';
const s = randomBytes(5).toString('hex');
const WS = `ws_gp${s}`;
const USER = `usr_gp${s}`;
const say = (l: string) => process.stdout.write(`${l}\n`);

const control = mintCapability(KEY, {
  aud: 'veto-control-plane', workspaceId: WS, humanId: USER, agentId: null,
  action: 'control-plane', resource: 'agents', ttlMs: 15 * 60 * 1000,
});

const pool = createPool(process.env['DATABASE_URL']);
try {
  await withWorkspace(pool, WS, async (db) => {
    await db.query(`insert into workspaces (id,name,type) values ($1,$1,'personal') on conflict do nothing`, [WS]);
    await db.query(`insert into users (id,workspace_id,identity_subject) values ($1,$2,$3) on conflict do nothing`,
      [USER, WS, `oidc|gp-${s}`]);
    await db.query(`insert into presence (workspace_id,user_id,state,source) values ($1,$2,'active','gp')
                    on conflict do nothing`, [WS, USER]);
  });

  const post = async (path: string, payload: unknown) => {
    const r = await fetch(API + path, {
      method: 'POST',
      headers: { authorization: `Bearer ${control}`, 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return { status: r.status, body: (await r.json()) as Record<string, unknown> };
  };

  const agent = await post('/v1/agents', { provider: 'mcp', client_id: `gp-${s}` });
  const agentId = String(agent.body['id']);
  say(`agent ${agentId}`);

  await post('/v1/policies', {
    subject: agentId, action: 'read', effect: 'allow',
    resource_filter: { type: 'google_folder', ids: ['root'] },
  });
  say('rule written');

  const gw = mintCapability(KEY, {
    aud: 'veto-gateway', workspaceId: WS, humanId: USER, agentId,
    action: 'mcp', resource: 'mcp', ttlMs: 15 * 60 * 1000,
  });

  const ask = async (): Promise<string> => {
    const r = await fetch(GW, {
      method: 'POST',
      headers: { authorization: `Bearer ${gw}`, 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: { name: 'google_drive.list_folder', arguments: { folder_id: 'root' } } }),
    });
    const body = (await r.json()) as Record<string, unknown>;
    const err = body['error'] as { data?: { reason_code?: string } } | undefined;
    return err?.data?.reason_code ?? 'ALLOWED';
  };

  say(`before grant: ${await ask()}`);

  const granted = await post('/v1/grants', {
    agent_id: agentId, resource_type: 'google_folder', resource_key: 'root',
  });
  const grantedAt = Date.now();
  say(`grant written: status ${granted.status}`);

  const grantedWs = WS;
  say(`workspace ${grantedWs}`);
  for (let i = 0; i < 90; i += 1) {
    const reason = await ask();
    const elapsed = ((Date.now() - grantedAt) / 1000).toFixed(1);
    if (reason !== 'POLICY_DENIED') {
      say(`FLIPPED after ${elapsed}s -> ${reason}`);
      break;
    }
    if (i % 10 === 0) say(`  ${elapsed}s still POLICY_DENIED`);
    await new Promise((r) => setTimeout(r, 2000));
  }
} finally {
  await pool.end();
}
