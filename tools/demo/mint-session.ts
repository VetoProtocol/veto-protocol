/**
 * Mint a dashboard session cookie, for local demo recording only.
 *
 * This is throwaway tooling, not part of the product. It exists because a
 * headless browser cannot complete an OIDC round trip against a real provider,
 * and a demo recording should exercise the dashboard's screens rather than
 * Google's consent page.
 *
 * It mirrors `apps/dashboard/src/lib/session.ts` and `lib/credential.ts`
 * instead of importing them, because both are marked `server-only` and throw
 * outside a Next request. The duplication is deliberate and is the reason this
 * file does not live beside them: nothing in the product should be able to
 * reach a session minted here.
 *
 * It holds no power the operator does not already have — it reads the same
 * `.env` the dashboard reads. Run it on a machine you own, never in CI.
 */

import { createHmac } from 'node:crypto';
import { loadRepoEnv } from '@veto/db';
import { mintCapability } from '@veto/tokens';

loadRepoEnv();

const workspaceId = process.argv[2];
const userId = process.argv[3];
if (!workspaceId || !userId) {
  process.stderr.write('usage: mint-session.ts <workspaceId> <userId>\n');
  process.exit(2);
}

const capabilitySecret = (process.env['VETO_CAPABILITY_SECRET'] ?? '').trim();
const sessionSecret = (process.env['DASHBOARD_SESSION_SECRET'] ?? '').trim();
if (capabilitySecret.length < 32 || sessionSecret.length < 32) {
  process.stderr.write('both secrets must be at least 32 characters\n');
  process.exit(2);
}

/** Ten minutes, matching SESSION_TTL_MS. The demo has to finish inside it. */
const TTL_MS = 10 * 60 * 1000;

const credential = mintCapability(capabilitySecret, {
  aud: 'veto-control-plane',
  workspaceId,
  humanId: userId,
  agentId: null,
  action: 'control-plane',
  resource: 'agents',
  ttlMs: TTL_MS,
});

const body = Buffer.from(
  JSON.stringify({ ws: workspaceId, usr: userId, cred: credential, exp: Date.now() + TTL_MS }),
  'utf8',
).toString('base64url');

const mac = createHmac('sha256', Buffer.from(sessionSecret, 'utf8'))
  .update(body)
  .digest('base64url');

process.stdout.write(`${body}.${mac}`);
