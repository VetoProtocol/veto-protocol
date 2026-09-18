/**
 * Gateway entry point.
 *
 * Configuration is read once and a missing value refuses to boot. An
 * enforcement point that starts misconfigured and denies everything at runtime
 * is indistinguishable from one that is working correctly, which is the worst
 * possible failure to debug.
 */

import { createPool, loadRepoEnv } from '@veto/db';
import { createGateway } from './app.ts';

loadRepoEnv();

function required(name: string): string {
  const value = (process.env[name] ?? '').trim();
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

const pool = createPool(required('DATABASE_URL'));

const app = createGateway({
  pool,
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
      await pool.end();
    })();
  });
}
