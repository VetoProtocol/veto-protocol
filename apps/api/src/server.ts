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
import { createLocalKeyWrapper } from '@veto/vault';
import { createGoogleExchange, type GoogleOAuthConfig } from '@veto/connections';
import type { WebAuthnConfig } from '@veto/passkeys';
import { createPermitPolicyDecisions, createPermitPolicyFacts, permitConfigFromEnv } from '@veto/permit';
import Redis from 'ioredis';
import { createApp } from './app.ts';
import { capabilityAuthenticator } from './capability-auth.ts';
import {
  bootable,
  formatReport,
  googleTokenProbe,
  pdpProbe,
  postgresProbe,
  redisProbe,
  runProbes,
} from '@veto/health';

// The repo-root .env, with anything already in the environment winning over it.
loadRepoEnv();

function required(name: string): string {
  const value = (process.env[name] ?? '').trim();
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

const pool = createPool(required('DATABASE_URL'));
const redis = new Redis(required('REDIS_URL'));
const permitConfig = permitConfigFromEnv();
const policy = createPermitPolicyFacts(permitConfig);
const decisions = createPermitPolicyDecisions(permitConfig);
const wrapper = createLocalKeyWrapper(required('VAULT_MASTER_KEY'));

// Google is optional: the server runs without it and the connect route refuses,
// rather than starting in a state where connecting half-works.
const googleId = (process.env['GOOGLE_CLIENT_ID'] ?? '').trim();
const google: GoogleOAuthConfig | null =
  googleId === ''
    ? null
    : {
        clientId: googleId,
        clientSecret: required('GOOGLE_CLIENT_SECRET'),
        redirectUri: required('GOOGLE_REDIRECT_URI'),
      };

// Origin and RP id are configuration, never derived from a request: a caller
// that could name its own origin could satisfy the ceremony from a site it
// controls.
const rpID = (process.env['WEBAUTHN_RP_ID'] ?? '').trim();
const webauthn: WebAuthnConfig | null =
  rpID === ''
    ? null
    : {
        rpID,
        rpName: process.env['WEBAUTHN_RP_NAME'] ?? 'Veto Protocol',
        origins: (process.env['WEBAUTHN_ORIGINS'] ?? '')
          .split(',')
          .map((o) => o.trim())
          .filter(Boolean),
      };

if (webauthn !== null && webauthn.origins.length === 0) {
  throw new Error('WEBAUTHN_ORIGINS must list at least one exact origin');
}

const app = createApp({
  pool,
  redis,
  policy,
  decisions,
  wrapper,
  google,
  webauthn,
  exchange: google === null ? null : createGoogleExchange(google),
  authenticate: capabilityAuthenticator(required('VETO_CAPABILITY_SECRET')),
  logger: true,
});

const port = Number(process.env['API_PORT'] ?? 4000);
const host = process.env['API_HOST'] ?? '127.0.0.1';

// Loopback by default. Binding 0.0.0.0 is a deployment decision that should be
// made explicitly by whoever knows what is in front of the process.
// What this process can and cannot reach, before it accepts a request.
//
// An unreachable dependency does not announce itself — it arrives later wearing
// a disguise. A black-holed IPv6 route to Google reads as CONNECTION_EXPIRED,
// "the connected account could not be used", which sounds like a revoked
// credential; a Permit account over its tenant quota reads as
// POLICY_UNAVAILABLE. Both cost an afternoon to trace. This turns them into one
// line each.
//
// Only Postgres is fatal. Invariant 1 is fail closed at request time, not
// refuse to boot: a service that cannot reach Permit denies every protected
// request, which is correct, while one that will not start cannot be restarted
// into a recovering system.
const health = await runProbes([
  postgresProbe((sql) => pool.query(sql)),
  redisProbe(() => redis.ping()),
  pdpProbe(permitConfigFromEnv().pdpUrl),
  googleTokenProbe(),
]);
for (const line of formatReport(health)) {
  const failed = line.includes('FAIL');
  app.log[failed ? 'error' : 'info'](line);
}
if (!bootable(health)) {
  app.log.error('health  a required dependency is unreachable; refusing to start');
  process.exit(1);
}

await app.listen({ port, host });

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    void (async () => {
      await app.close();
      await policy.close();
      await decisions.close();
      redis.disconnect();
      await pool.end();
    })();
  });
}
