/**
 * Gateway entry point.
 *
 * Configuration is read once and a missing value refuses to boot. An
 * enforcement point that starts misconfigured and denies everything at runtime
 * is indistinguishable from one that is working correctly, which is the worst
 * possible failure to debug.
 */

import { readFileSync } from 'node:fs';
import Redis from 'ioredis';
import { createPool, loadRepoEnv } from '@veto/db';
import { createPermitPolicyDecisions, permitConfigFromEnv } from '@veto/permit';
import {
  createCalendarReader,
  createDriveReader,
  createGitHubExchange,
  createGmailReader,
  createGoogleExchange,
  createIssueReader,
  createRepoReader,
  type GitHubAppConfig,
  type GoogleOAuthConfig,
} from '@veto/connections';
import { createLocalKeyWrapper } from '@veto/vault';
import { createGateway } from './app.ts';
import {
  bootable,
  formatReport,
  googleTokenProbe,
  pdpProbe,
  postgresProbe,
  redisProbe,
  runProbes,
} from '@veto/health';

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

// GitHub, on the same terms as Google: absent means every GitHub tool refuses
// rather than half-works. The private key is read from a path because a PEM is
// multi-line and a mangled one fails at JWT signing, on the first real call.
//
// This is the enforcement point, so it needs the App config too — the control
// plane holding it is not enough. Wiring it there and not here is exactly how
// a tool ends up listed, authorised by policy, and then refused at step 8 with
// "GitHub is not configured on this server".
const githubAppId = (process.env['GITHUB_APP_ID'] ?? '').trim();
const github: GitHubAppConfig | null =
  githubAppId === ''
    ? null
    : {
        appId: githubAppId,
        appSlug: required('GITHUB_APP_SLUG'),
        privateKeyPem: readFileSync(required('GITHUB_PRIVATE_KEY_PATH'), 'utf8'),
      };

const execute =
  google === null
    ? null
    : {
        wrapper: createLocalKeyWrapper(required('VAULT_MASTER_KEY')),
        exchange: createGoogleExchange(google),
        drive: createDriveReader(),
        gmail: createGmailReader(),
        calendar: createCalendarReader(),
        ...(github === null
          ? {}
          : {
              githubExchange: createGitHubExchange(github),
              repos: createRepoReader(),
              issues: createIssueReader(),
            }),
      };

// Where the dashboard lives, for the link on an approval alert.
//
// The same variable the dashboard builds its own public origin from, so the
// two cannot drift into pointing at different hosts. Configuration, never a
// request value: an origin a caller could name is an origin a caller could put
// in an alert somebody is about to click. Empty means alerts carry no link.
const dashboardUrl = (process.env['DASHBOARD_PUBLIC_URL'] ?? '').trim() || null;

const app = createGateway({
  pool,
  dashboardUrl,
  redis,
  policy,
  execute,
  capabilitySecret: required('VETO_CAPABILITY_SECRET'),
  publicUrl: process.env['GATEWAY_PUBLIC_URL'] ?? 'http://localhost:4100',
  authorizationServer: process.env['GATEWAY_AUTH_SERVER'] ?? 'http://localhost:3000',
  logger: true,
});

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
