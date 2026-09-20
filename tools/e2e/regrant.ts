/**
 * Re-create a workspace's grants under workspace-scoped instance keys.
 *
 * One-off migration. Instance keys used to be unscoped, so every grant written
 * before that change addresses a resource instance the checker no longer looks
 * for. Re-granting writes them at the new key; the old instances are left in
 * place because deleting an instance would take any `parent` edges with it.
 */
import { loadRepoEnv } from '@veto/db';
import { mintCapability } from '@veto/tokens';
loadRepoEnv();

const WS = process.argv[2] ?? '';
const USER = process.argv[3] ?? '';
const AGENT = process.argv[4] ?? '';
const say = (l: string) => process.stdout.write(`${l}\n`);

const token = mintCapability(process.env['VETO_CAPABILITY_SECRET'] ?? '', {
  aud: 'veto-control-plane', workspaceId: WS, humanId: USER, agentId: null,
  action: 'control-plane', resource: 'agents', ttlMs: 900_000,
});

const post = async (path: string, payload: unknown) => {
  const r = await fetch(`http://127.0.0.1:4000${path}`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(1_800_000),
  });
  return { status: r.status, body: await r.text() };
};

for (const key of ['root', '1a2B3c-_9zYxQwErTy']) {
  const r = await post('/v1/grants', {
    agent_id: AGENT, resource_type: 'google_folder', resource_key: key,
  });
  say(`grant ${key}: ${r.status}`);
}

say('re-syncing the folder hierarchy (this walks Drive, give it a minute)...');
const sync = await post('/v1/grants/sync', { folder_id: 'root' });
say(`sync: ${sync.status} ${sync.body.slice(0, 120)}`);
