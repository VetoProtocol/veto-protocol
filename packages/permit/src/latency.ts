/**
 * Hosted-PDP latency spike.
 *
 * This is a **measurement tool, not a pipeline component**. It is the only
 * place in the repo that calls `permit.check`, and that call is deliberately
 * not exposed through `PolicyFacts`: the runtime check belongs to the gateway
 * in stage 2, and CLAUDE.md's build order says not to build ahead of it. What
 * this answers is the §16 question that has been open since phase 0 — whether a
 * hosted PDP fits the §11 budget — because there is no container runtime on
 * this machine and a local PDP was never an option here.
 *
 * ## Reading the result
 *
 * §11 budgets **P95 < 200 ms for the whole authorization path**, excluding
 * human approval and the upstream call. The PDP round trip is step 5 of nine.
 * Steps 1–4 and 6 do their own database and Redis work, so the PDP cannot have
 * the whole budget; `budgetMs` defaults to half of it and is the number to
 * argue about, not 200.
 *
 * The measurement is of a *cold-ish network path* from wherever this runs to
 * Permit's cloud. It says nothing about production topology, and a result that
 * passes here can still fail from a different region. Treat a pass as "not
 * disqualifying" rather than "fits".
 */

import { Permit } from 'permitio';
import type { PermitConfig } from './config.ts';

export interface LatencyProbe {
  /** Principal key, e.g. `agent:agt_x`. */
  readonly user: string;
  readonly action: string;
  readonly resourceType: string;
  readonly resourceKey: string;
  readonly tenant: string;
}

export interface LatencyOptions {
  readonly warmup?: number;
  readonly samples?: number;
  /** The slice of the §11 budget allotted to the PDP round trip. */
  readonly budgetMs?: number;
}

export interface LatencyReport {
  readonly samples: number;
  readonly failures: number;
  readonly minMs: number;
  readonly p50Ms: number;
  readonly p95Ms: number;
  readonly p99Ms: number;
  readonly maxMs: number;
  readonly budgetMs: number;
  readonly withinBudget: boolean;
}

export async function measureCheckLatency(
  config: PermitConfig,
  probe: LatencyProbe,
  options: LatencyOptions = {},
): Promise<LatencyReport> {
  const warmup = options.warmup ?? 5;
  const samples = options.samples ?? 50;
  const budgetMs = options.budgetMs ?? 100;

  const permit = new Permit({
    token: config.token,
    pdp: config.pdpUrl,
    ...(config.apiUrl === undefined ? {} : { apiUrl: config.apiUrl }),
    timeout: config.timeoutMs,
    throwOnError: true,
    // `json: false` is not a typo. permitio 2.7.6 inverts this flag:
    //   prettyPrint: config.log.json ? { levelFirst: true } : false
    // and pino 8 throws on any truthy prettyPrint. So `json: true` crashes the
    // constructor, and `json: false` gives plain pino output — which is JSON,
    // because that is pino's default. The value that reads wrong is the one
    // that produces structured logs.
    log: { level: 'error', label: 'permit-latency', json: false },
  });

  const resource = {
    type: probe.resourceType,
    key: probe.resourceKey,
    tenant: probe.tenant,
  };

  // The answer is irrelevant — a deny round trips the same as an allow. What is
  // being timed is the path, so failures are counted rather than thrown: an
  // outage mid-run should not discard the samples already collected.
  const once = async (): Promise<number | null> => {
    const started = process.hrtime.bigint();
    try {
      await permit.check(probe.user, probe.action, resource);
    } catch {
      return null;
    }
    return Number(process.hrtime.bigint() - started) / 1e6;
  };

  for (let i = 0; i < warmup; i += 1) await once();

  const timings: number[] = [];
  let failures = 0;
  for (let i = 0; i < samples; i += 1) {
    const ms = await once();
    if (ms === null) failures += 1;
    else timings.push(ms);
  }

  if (timings.length === 0) {
    throw new Error(`Every one of ${samples} checks failed; no latency to report`);
  }

  timings.sort((a, b) => a - b);
  const p95Ms = percentile(timings, 95);

  return {
    samples: timings.length,
    failures,
    minMs: round(timings[0] ?? 0),
    p50Ms: round(percentile(timings, 50)),
    p95Ms: round(p95Ms),
    p99Ms: round(percentile(timings, 99)),
    maxMs: round(timings[timings.length - 1] ?? 0),
    budgetMs,
    withinBudget: p95Ms < budgetMs,
  };
}

/**
 * Nearest-rank percentile.
 *
 * Deliberately not interpolating. Interpolation invents a value between two
 * measurements, and for a latency budget the honest answer is an observation
 * that actually happened.
 */
export function percentile(sorted: readonly number[], p: number): number {
  if (sorted.length === 0) return 0;
  const rank = Math.ceil((p / 100) * sorted.length);
  const index = Math.min(Math.max(rank, 1), sorted.length) - 1;
  return sorted[index] ?? 0;
}

const round = (ms: number): number => Math.round(ms * 100) / 100;
