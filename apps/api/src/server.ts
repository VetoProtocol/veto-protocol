/**
 * Control-plane server entry point.
 *
 * This exists now and did not before for one reason: there is a real
 * authenticator. `createApp` has always refused to start without one, and until
 * capability tokens existed the only thing that could have been passed was a
 * stub — so there was nothing safe to bind to a port.
 *
 * Configuration is read once, up front, and a missing value is a boot failure
 * rather than a per-request denial. An outage that looks like "nobody is signed
 * in" is far harder to diagnose than one that refuses to start.
 */

import { createPool, loadRepoEnv } from '@veto/db';
import { createPermitPolicyFacts, permitConfigFromEnv } from '@veto/permit';
import Redis from 'ioredis';
import { createApp } from './app.ts';
import { capabilityAuthenticator } from './capability-auth.ts';

// The repo-root .env, with anything already in the environment winning over it.
loadRepoEnv();

function required(name: string): string {
  const value = (process.env[name] ?? '').trim();
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

const pool = createPool(required('DATABASE_URL'));
const redis = new Redis(required('REDIS_URL'));
const policy = createPermitPolicyFacts(permitConfigFromEnv());

const app = createApp({
  pool,
  redis,
  policy,
  authenticate: capabilityAuthenticator(required('VETO_CAPABILITY_SECRET')),
  logger: true,
});

const port = Number(process.env['API_PORT'] ?? 4000);
const host = process.env['API_HOST'] ?? '127.0.0.1';

// Loopback by default. Binding 0.0.0.0 is a deployment decision that should be
// made explicitly by whoever knows what is in front of the process.
await app.listen({ port, host });

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
