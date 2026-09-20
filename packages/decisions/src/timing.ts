/**
 * Where a decision spent its time (§11).
 *
 * The §11 budget is 200 ms P95 for authorization overhead. `latency_ms` has
 * always recorded whether a decision met it; nothing recorded *why* it did not,
 * so a slow decision looked identical whether Permit was slow, the presence
 * lookup was slow, or the audit write was.
 *
 * ## Why this holds numbers and nothing else
 *
 * A timing map travels into the decision row, into logs, and into whatever
 * tracing backend is attached — three places invariant 5 governs. The type
 * makes the rule structural rather than remembered: `StepTimings` maps a step
 * name to a number, and there is no field an argument, a resource id or a tool
 * response could be put in. Same control as `AuditEventInput`, for the same
 * reason.
 *
 * ## Why the pipeline does not import a tracing library
 *
 * Measuring and reporting are different jobs. The pipeline measures and returns
 * plain data; the gateway turns that data into spans. `@veto/decisions` stays
 * free of a tracing dependency, and a test can assert on timings without
 * standing up an exporter.
 */

/** §3.3's nine steps, by the name each is known by in the trace screen. */
export const STEP_NAMES = [
  'identity',
  'normalize',
  'session',
  'precheck',
  'policy',
  'risk',
  'emit',
  'upstream',
  'audit',
] as const;

export type StepName = (typeof STEP_NAMES)[number];

/**
 * Milliseconds per step. Sparse on purpose: a decision that stopped at step 5
 * has nothing truthful to say about steps 6 to 9, and recording a zero would
 * claim it ran and took no time.
 */
export type StepTimings = Partial<Record<StepName, number>>;

export interface StepClock {
  /**
   * Time one step. The step is recorded whether or not `fn` throws.
   *
   * **Additive.** A pipeline step is not one function call — step 4 reads
   * policies, then labels, then a volume counter — and wrapping the whole block
   * in a closure would change what its `return deny(...)` statements return.
   * So each awaited call is timed on its own and the step accumulates. What
   * lands in the map is the time that step spent waiting, which is the number
   * worth having; the synchronous logic between the calls is microseconds.
   */
  time<T>(step: StepName, fn: () => T | Promise<T>): Promise<T>;
  /** Add a duration measured elsewhere, in milliseconds. Additive, as `time` is. */
  record(step: StepName, ms: number): void;
  /** What has been measured so far. A fresh object, so callers cannot mutate it. */
  read(): StepTimings;
}

/** Two decimal places. Sub-microsecond precision is noise in a 200 ms budget. */
const round = (ms: number): number => Math.round(ms * 100) / 100;

export function createStepClock(): StepClock {
  const timings: StepTimings = {};

  const add = (step: StepName, ms: number): void => {
    timings[step] = round((timings[step] ?? 0) + ms);
  };

  return {
    async time(step, fn) {
      const started = process.hrtime.bigint();
      try {
        return await fn();
      } finally {
        // In `finally`, so a step that threw is still reported. A step that
        // failed is exactly the one worth having a duration for.
        add(step, Number(process.hrtime.bigint() - started) / 1e6);
      }
    },

    record(step, ms) {
      add(step, ms);
    },

    read() {
      return { ...timings };
    },
  };
}
