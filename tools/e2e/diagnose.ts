/** Is the grant actually in Permit, and in which tenant? */
import { loadRepoEnv } from '@veto/db';
import { mintCapability } from '@veto/tokens';
loadRepoEnv();
const say = (l: string) => process.stdout.write(`${l}\n`);
const KEY = process.env['VETO_CAPABILITY_SECRET'] ?? '';

const check = async (ws: string, user: string, label: string) => {
  const t = mintCapability(KEY, { aud: 'veto-control-plane', workspaceId: ws, humanId: user,
    agentId: null, action: 'control-plane', resource: 'agents', ttlMs: 300_000 });
  const r = await fetch('http://127.0.0.1:4000/v1/grants', { headers: { authorization: `Bearer ${t}` } });
  const b = (await r.json()) as Record<string, unknown>;
  say(`${label} (${ws}): status ${r.status} -> ${JSON.stringify(b).slice(0, 300)}`);
};

await check('ws_8okUBbecrOy3lIlw', 'usr_Vy98CGmrjKSoleT_', 'WORKING workspace');
await check(process.argv[2] ?? '', process.argv[3] ?? '', 'NEW workspace');
