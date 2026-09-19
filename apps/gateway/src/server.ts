/**
 * Gateway entry point.
 *
 * Configuration is read once and a missing value refuses to boot. An
 * enforcement point that starts misconfigured and denies everything at runtime
 * is indistinguishable from one that is working correctly, which is the worst
 * possible failure to debug.
 */

import Redis from 'ioredis';
import { createPool, loadRepoEnv } from '@veto/db';
import { createPermitPolicyDecisions, permitConfigFromEnv } from '@veto/permit';
import {
  createDriveReader,
  createGmailReader,
  createGoogleExchange,
  type GoogleOAuthConfig,
} from '@veto/connections';
import { createLocalKeyWrapper } from '@veto/vault';
import { createGateway } from './app.ts';

loadRepoEnv();

function required(name: string): string {
  const value = (process.env[name] ?? '').trim();
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

const pool = createPool(required('DATABASE_URL'));
const redis = new Redis(required('REDIS_URL'));
const policy = createPermitPolicyDecisions(permitConfigFromEnv());

/**
 * Step 8, or nothing.
 *
 * Without Google configured there is no way to carry an allow out, and the
 * gateway says so per call rather than pretending. Half-configured is the state
 * worth refusing loudly: a decision that says allow and then silently returns
 * nothing is the hardest kind of bug to find.
 */
const googleId = (process.env['GOOGLE_CLIENT_ID'] ?? '').trim();
const google: GoogleOAuthConfig | null =
  googleId === ''
    ? null
    : {
        clientId: googleId,
        clientSecret: required('GOOGLE_CLIENT_SECRET'),
        redirectUri: required('GOOGLE_REDIRECT_URI'),
      };

const execute =
  google === null
    ? null
    : {
        wrapper: createLocalKeyWrapper(required('VAULT_MASTER_KEY')),
        exchange: createGoogleExchange(google),
        drive: createDriveReader(),
        gmail: createGmailReader(),
      };

const app = createGateway({
  pool,
  redis,
  policy,
  execute,
  capabilitySecret: required('VETO_CAPABILITY_SECRET'),
  publicUrl: process.env['GATEWAY_PUBLIC_URL'] ?? 'http://localhost:4100',
  authorizationServer: process.env['GATEWAY_AUTH_SERVER'] ?? 'http://localhost:3000',
  logger: true,
});

await app.listen({
  port: Number(process.env['GATEWAY_PORT'] ?? 4100),
  host: process.env['GATEWAY_HOST'] ?? '127.0.0.1',
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    void (async () => {
      await app.close();
      await policy.close();
      redis.disconnect();
      await pool.end();
    })();
  });
}
