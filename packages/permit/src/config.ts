/**
 * Permit client configuration, read from the environment.
 *
 * The API key is a server-side secret (§3.2: Permit keys stay server-side) and
 * never leaves this package. It is not logged, not echoed in errors, and not
 * carried on the config object beyond what the client needs.
 *
 * A missing key throws at construction rather than degrading. An adapter that
 * started without credentials would fail every call at request time, which is
 * still a denial — but a denial that looks like an outage and would be waited
 * out rather than fixed. Refusing to construct turns it into a boot failure.
 */

export interface PermitConfig {
  readonly token: string;
  readonly pdpUrl: string;
  readonly apiUrl: string | undefined;
  /** Per-request ceiling. §11 budgets P95 < 200 ms for the whole authorization path. */
  readonly timeoutMs: number;
  /**
   * Route fact writes through the PDP so it acknowledges them before the call
   * resolves.
   *
   * **Only a local PDP can do this.** The endpoint is `/v2/facts/...`, which the
   * PDP container serves and the hosted cloud PDP answers with 404. So this is
   * false whenever the PDP is Permit's cloud, and the consequence is real: a
   * write returns as soon as the Cloud API accepts it, which is *before* any
   * PDP is guaranteed to see it.
   *
   * That gap matters for removal. §11 wants revocation effective within five
   * seconds, and without the proxy nothing here can prove the PDP has caught
   * up — the gateway's own agent-status check is what actually enforces it
   * (see revocation.ts, step 1). Running a local PDP in deployment closes the
   * gap and is the reason to do it.
   */
  readonly proxyFactsViaPdp: boolean;

  /** How long a proxied fact write waits for the PDP. Ignored when not proxying. */
  readonly factsSyncTimeoutMs: number;
}

const DEFAULT_PDP_URL = 'https://cloudpdp.api.permit.io';

export class PermitConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PermitConfigError';
  }
}

export function permitConfigFromEnv(env: NodeJS.ProcessEnv = process.env): PermitConfig {
  const token = (env['PERMIT_API_KEY'] ?? '').trim();
  if (!token) {
    throw new PermitConfigError(
      'PERMIT_API_KEY is not set (checked the environment and the repo-root .env). ' +
        'Refusing to start an adapter that cannot reach Permit.',
    );
  }

  const apiUrl = (env['PERMIT_API_URL'] ?? '').trim();
  const pdpUrl = (env['PERMIT_PDP_URL'] ?? '').trim() || DEFAULT_PDP_URL;

  return {
    token,
    pdpUrl,
    apiUrl: apiUrl || undefined,
    timeoutMs: positiveInt(env['PERMIT_TIMEOUT_MS'], 5_000),
    proxyFactsViaPdp: boolFlag(env['PERMIT_PROXY_FACTS_VIA_PDP'], !isHostedPdp(pdpUrl)),
    factsSyncTimeoutMs: positiveInt(env['PERMIT_FACTS_SYNC_TIMEOUT_MS'], 10_000),
  };
}

/**
 * Is this Permit's hosted PDP rather than a container we run?
 *
 * Matched on host, not on a substring of the whole URL, so a local PDP reached
 * through a path containing the word "permit" is not misclassified. An unparsable
 * URL counts as hosted: the fact proxy is the capability that might not exist,
 * and assuming it is absent fails toward the configuration that works.
 */
export function isHostedPdp(pdpUrl: string): boolean {
  try {
    const host = new URL(pdpUrl).hostname.toLowerCase();
    return host === 'permit.io' || host.endsWith('.permit.io');
  } catch {
    return true;
  }
}

function boolFlag(raw: string | undefined, fallback: boolean): boolean {
  if (raw === undefined || raw.trim() === '') return fallback;
  const value = raw.trim().toLowerCase();
  if (value === 'true' || value === '1') return true;
  if (value === 'false' || value === '0') return false;
  throw new PermitConfigError(`Expected true or false, got ${JSON.stringify(raw)}`);
}

function positiveInt(raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw.trim() === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new PermitConfigError(`Expected a positive integer, got ${JSON.stringify(raw)}`);
  }
  return value;
}
