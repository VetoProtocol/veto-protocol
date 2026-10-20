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

import { readFileSync } from 'node:fs';
import { createPool, loadRepoEnv } from '@veto/db';
import { createLocalKeyWrapper } from '@veto/vault';
import {
  createGitHubExchange,
  createGoogleExchange,
  type GitHubAppConfig,
  type GitHubUserAuthConfig,
  type GoogleOAuthConfig,
  type MicrosoftOAuthConfig,
  type SlackAppConfig,
} from '@veto/connections';
import type { WebAuthnConfig } from '@veto/passkeys';
import { createPermitPolicyDecisions, createPermitPolicyFacts, permitConfigFromEnv } from '@veto/permit';
import Redis from 'ioredis';
import { createApp } from './app.ts';
import { capabilityAuthenticator } from './capability-auth.ts';
import { startScheduler } from '@veto/webhooks';
import { checkDestination } from '@veto/decisions';
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

// GitHub is optional on the same terms as Google. The private key is read from
// a file rather than an environment variable: a PEM is multi-line, and the
// shapes that survive `.env` round-tripping are the ones that invite someone to
// paste it with the newlines mangled.
const githubAppId = (process.env['GITHUB_APP_ID'] ?? '').trim();
const github: GitHubAppConfig | null =
  githubAppId === ''
    ? null
    : {
        appId: githubAppId,
        appSlug: required('GITHUB_APP_SLUG'),
        privateKeyPem: readFileSync(required('GITHUB_PRIVATE_KEY_PATH'), 'utf8'),
      };

// The App's *user*-authorization credentials, needed only to prove that the
// person finishing an install actually controls the installation they claim.
//
// Separate from the App config because the gateway must never hold this: it
// mints installation tokens and takes no part in the install round trip, and a
// secret that only one process needs should only reach one process.
//
// Absent means new GitHub connections cannot be made — the install route
// refuses to start rather than taking the caller's word for an installation id.
// Connections already on file keep working, because minting a token for one
// needs the private key and nothing here.
const githubClientId = (process.env['GITHUB_CLIENT_ID'] ?? '').trim();
const githubUserAuth: GitHubUserAuthConfig | null =
  githubClientId === ''
    ? null
    : { clientId: githubClientId, clientSecret: required('GITHUB_CLIENT_SECRET') };

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

// Where the dashboard lives, for the link on an approval alert.
//
// The same variable the dashboard builds its own public origin from, so the
// two cannot drift into pointing at different hosts. Configuration, never a
// request value: an origin a caller could name is an origin a caller could put
// in an alert somebody is about to click. Empty means alerts carry no link.
const dashboardUrl = (process.env['DASHBOARD_PUBLIC_URL'] ?? '').trim() || null;

// Slack. Token rotation must be on for the app, or the install is refused —
// see docs/slack-setup.md. Empty client id disables Slack entirely, and every
// Slack route then refuses rather than half-working.
const slackClientId = (process.env['SLACK_CLIENT_ID'] ?? '').trim();
const slack: SlackAppConfig | null =
  slackClientId === ''
    ? null
    : {
        clientId: slackClientId,
        clientSecret: required('SLACK_CLIENT_SECRET'),
        redirectUri: required('SLACK_REDIRECT_URI'),
      };

// Microsoft 365. Empty client id disables it entirely, and every Microsoft
// route then refuses rather than half-working. See docs/microsoft-setup.md,
// which also states the gap this provider cannot close: there is no way to
// revoke a single refresh token, so revocation here is local only.
const microsoftClientId = (process.env['MICROSOFT_CLIENT_ID'] ?? '').trim();
const microsoft: MicrosoftOAuthConfig | null =
  microsoftClientId === ''
    ? null
    : {
        clientId: microsoftClientId,
        clientSecret: required('MICROSOFT_CLIENT_SECRET'),
        redirectUri: required('MICROSOFT_REDIRECT_URI'),
      };


const app = createApp({
  pool,
  slack,
  microsoft,
  dashboardUrl,
  redis,
  policy,
  decisions,
  wrapper,
  google,
  github,
  githubUserAuth,
  webauthn,
  exchange: google === null ? null : createGoogleExchange(google),
  githubExchange: github === null ? null : createGitHubExchange(github),
  authenticate: capabilityAuthenticator(required('VETO_CAPABILITY_SECRET')),
  // The same key, used the other way round: the authenticator verifies tokens
  // this process receives, and the §8 token endpoint signs the ones it issues.
  capabilitySecret: required('VETO_CAPABILITY_SECRET'),
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

/**
 * Deliver webhooks on a schedule (§5.4).
 *
 * `/alerts` has always had a "deliver now" button, which was honest about there
 * being no cron rather than draining silently when somebody loaded a page. This
 * is the cron.
 *
 * Every instance runs one. `drainDeliveries` claims rows `for update skip
 * locked`, so two of them split the queue instead of both sending the same
 * event — no leader election, and a receiver that would survive a duplicate
 * anyway does not get one.
 *
 * `WEBHOOK_SCHEDULER=off` stops it, for a deployment that would rather drive
 * delivery from outside.
 */
const scheduler =
  (process.env['WEBHOOK_SCHEDULER'] ?? 'on').trim() === 'off'
    ? null
    : startScheduler({
        pool,
        wrapper,
        // Same adapter the drain route uses: `checkDestination` answers `why`
        // and the worker wants `reason`, and the shapes stay apart so the
        // worker does not depend on the pipeline's type.
        checkDestination: async (url) => {
          const verdict = await checkDestination(url);
          return verdict.ok ? { ok: true } : { ok: false, reason: verdict.why };
        },
        log: app.log,
      });

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    // Stop ticking before the process goes, so a drain in flight is not left
    // holding claimed rows until their lock expires.
    scheduler?.stop();
  });
}

if (scheduler) app.log.info('webhook scheduler started');

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
