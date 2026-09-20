/**
 * Run a folder sync against a workspace from the command line.
 *
 * The Connections screen has a button for this, and the button is what a
 * customer uses. This exists for the case the button cannot cover: running the
 * sync against a workspace nobody is signed into, or retrying it enough times
 * to tell a transient upstream failure apart from a grant that is genuinely
 * gone. It earned its place doing exactly that — a sync that failed three times
 * with EXCHANGE_FAILED and succeeded on the fourth with no change but time.
 *
 * Operator tooling. It mints its own control-plane credential from the repo
 * `.env`, so it only runs on a machine that already holds the signing key.
 *
 *   node --experimental-strip-types tools/e2e/try-sync.ts <workspaceId> <userId>
 */

import { loadRepoEnv } from '@veto/db';
import { mintCapability } from '@veto/tokens';
loadRepoEnv();
const [ws, user] = process.argv.slice(2);
const t = mintCapability(process.env['VETO_CAPABILITY_SECRET'] ?? '', {
  aud: 'veto-control-plane', workspaceId: ws ?? '', humanId: user ?? '', agentId: null,
  action: 'control-plane', resource: 'agents', ttlMs: 900_000 });
const r = await fetch('http://127.0.0.1:4000/v1/grants/sync', {
  method: 'POST',
  headers: { authorization: `Bearer ${t}`, 'content-type': 'application/json' },
  body: JSON.stringify({ folder_id: 'root' }),
  signal: AbortSignal.timeout(900_000),
});
process.stdout.write(`${r.status} ${(await r.text()).slice(0, 200)}\n`);
