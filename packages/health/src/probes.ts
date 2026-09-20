/**
 * The probes every service shares.
 *
 * Each one answers "can this be reached", never "is this credential valid".
 * Validating a key means using a real secret on a path whose entire output is a
 * log line, and invariant 5 does not make an exception for diagnostics.
 */

import type { Probe } from './probe.ts';

/**
 * Reachability, not authorization.
 *
 * Any HTTP answer at all means the host is there and TLS completed, which is
 * the question. A 401 or 404 from an endpoint we deliberately did not
 * authenticate to is a pass — treating it as a failure would report a healthy
 * dependency as broken.
 */
async function reachable(url: string): Promise<void> {
  const response = await fetch(url, {
    method: 'GET',
    redirect: 'manual',
    signal: AbortSignal.timeout(7000),
  });
  // Read nothing. The body is irrelevant and may be large.
  void response.status;
}

/**
 * Postgres. The one dependency worth refusing to boot without.
 *
 * Without it there is no identity to resolve and no audit event to write, so a
 * process that starts anyway serves nothing but 500s while looking healthy —
 * the harder outage to diagnose.
 */
export const postgresProbe = (query: (sql: string) => Promise<unknown>): Probe => ({
  name: 'postgres',
  required: true,
  check: () => query('select 1'),
});

/** Redis. Nonces, challenges, rate counters — degraded, not dead, without it. */
export const redisProbe = (ping: () => Promise<unknown>): Probe => ({
  name: 'redis',
  check: ping,
});

/**
 * The PDP.
 *
 * A local PDP answers `/healthy`; the hosted one does not have that path and
 * answers something else, which is still proof it is reachable.
 */
export const pdpProbe = (pdpUrl: string): Probe => ({
  name: 'permit-pdp',
  check: () => reachable(new URL('/healthy', pdpUrl).href),
});

/**
 * Google's token endpoint.
 *
 * The exact address every Drive, Gmail and Calendar call depends on, and the
 * one that failed silently behind a black-holed IPv6 route — surfacing as
 * `CONNECTION_EXPIRED`, which reads as a revoked credential and is not one.
 * This probe is the reason that costs a log line instead of an afternoon.
 */
export const googleTokenProbe = (): Probe => ({
  name: 'google-oauth',
  check: () => reachable('https://oauth2.googleapis.com/'),
});

/** The OIDC provider the dashboard signs people in against. */
export const oidcProbe = (issuer: string): Probe => ({
  name: 'oidc-issuer',
  check: () => reachable(new URL('/.well-known/openid-configuration', issuer).href),
});
