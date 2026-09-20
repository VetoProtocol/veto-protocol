/**
 * What a service can and cannot reach, said out loud at boot.
 *
 * ## Why this exists
 *
 * A dependency that is unreachable does not announce itself. It arrives later,
 * disguised: an IPv6 route to Google that black-holes reads as
 * `CONNECTION_EXPIRED` — "the connected account could not be used" — which
 * sounds like a revoked credential and is nothing of the kind. A Permit account
 * over its tenant quota reads as `POLICY_UNAVAILABLE`. Both took a working
 * afternoon to trace, because the first honest signal appeared several layers
 * away from the cause.
 *
 * A probe at startup converts that into one line in the log.
 *
 * ## Why a failed probe usually does not stop the service
 *
 * Invariant 1 is fail *closed*, not refuse to boot. A gateway that cannot reach
 * Permit denies every protected request, which is correct; a gateway that
 * refuses to start cannot be restarted into a recovering system, and takes the
 * dashboard's error pages down with it. So an unreachable dependency is loud
 * and not fatal.
 *
 * `required` is reserved for the ones where the service has nothing to offer at
 * all — Postgres, without which there is no identity to resolve and no audit to
 * write. That failure is worth refusing to start for, because a process that
 * serves only 500s while looking healthy is the harder outage.
 *
 * ## What a probe may not do
 *
 * Reach into a credential. A probe answers "can this address be reached", never
 * "is this key valid" — checking the latter means using a real secret on a path
 * whose whole output is a log line (invariant 5). The probes here connect and
 * nothing more.
 */

export interface Probe {
  /** Short, lowercase, stable. It becomes a column in the log. */
  readonly name: string;
  /**
   * True only when the service has nothing to offer without it. A required
   * probe that fails stops the boot; everything else is reported and survived.
   */
  readonly required?: boolean;
  check(): Promise<unknown>;
}

export interface ProbeResult {
  readonly name: string;
  readonly required: boolean;
  readonly ok: boolean;
  readonly ms: number;
  /** Why it failed, trimmed. Absent when it did not. */
  readonly detail?: string;
}

/** Long enough for a slow TLS handshake, short enough not to delay a restart. */
export const PROBE_TIMEOUT_MS = 8000;

const round = (ms: number): number => Math.round(ms * 10) / 10;

/**
 * A short reason, from whatever the failure turned out to be.
 *
 * Node nests the useful part: a connect failure arrives as `TypeError: fetch
 * failed` with the code two levels down in `cause`. Reporting the outer message
 * alone is how "fetch failed" ends up in a log with nothing to act on.
 */
function reasonOf(error: unknown): string {
  const seen = new Set<unknown>();
  let current: unknown = error;
  const codes: string[] = [];

  while (current !== null && current !== undefined && !seen.has(current)) {
    seen.add(current);
    const candidate = current as { code?: unknown; message?: unknown; cause?: unknown };
    if (typeof candidate.code === 'string') codes.push(candidate.code);
    current = candidate.cause;
  }

  const message = error instanceof Error ? error.message : String(error);
  const code = codes.at(-1);
  return (code === undefined ? message : `${message} (${code})`).slice(0, 120);
}

/** Run one probe, and never let it hang the boot. */
async function runOne(probe: Probe): Promise<ProbeResult> {
  const required = probe.required === true;
  const started = process.hrtime.bigint();

  const elapsed = (): number => round(Number(process.hrtime.bigint() - started) / 1e6);

  try {
    await Promise.race([
      probe.check(),
      new Promise((_resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error(`timed out after ${PROBE_TIMEOUT_MS}ms`)),
          PROBE_TIMEOUT_MS,
        );
        // A probe that finished is not a reason to hold the process open.
        timer.unref?.();
      }),
    ]);
    return { name: probe.name, required, ok: true, ms: elapsed() };
  } catch (error) {
    return {
      name: probe.name,
      required,
      ok: false,
      ms: elapsed(),
      detail: reasonOf(error),
    };
  }
}

/**
 * Run every probe at once and report all of them.
 *
 * Concurrent and never short-circuiting: the first failure is rarely the
 * interesting one, and "Postgres is down" is a different morning from
 * "everything is down".
 */
export async function runProbes(probes: readonly Probe[]): Promise<readonly ProbeResult[]> {
  return Promise.all(probes.map(runOne));
}

/** One aligned line per dependency. Fixed width so a scan finds the failure. */
export function formatReport(results: readonly ProbeResult[]): readonly string[] {
  const width = Math.max(4, ...results.map((r) => r.name.length));
  return results.map((result) => {
    const name = result.name.padEnd(width);
    const status = result.ok ? 'ok  ' : 'FAIL';
    const timing = `${result.ms}ms`.padStart(8);
    const detail = result.detail === undefined ? '' : `  ${result.detail}`;
    return `health  ${name}  ${status}${timing}${detail}`;
  });
}

/** True when every probe marked `required` succeeded. */
export const bootable = (results: readonly ProbeResult[]): boolean =>
  results.every((result) => result.ok || !result.required);
