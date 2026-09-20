/**
 * Per-step timings (§11).
 *
 * Two properties, and the second matters more than the first:
 *
 *  * A step that ran is measured, a step that did not is absent. "Not measured"
 *    and "measured as zero" are different facts and the trace screen has to be
 *    able to tell them apart.
 *  * A timing map carries numbers and nothing else. It travels into the
 *    decision row, into logs and into any tracing backend — three places
 *    invariant 5 governs — so the type is the control, exactly as
 *    `AuditEventInput` is for audit events.
 */

import { describe, expect, it } from 'vitest';
import { createStepClock, STEP_NAMES, type StepName } from '../src/timing.ts';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('the step clock', () => {
  it('measures a step that ran', async () => {
    const clock = createStepClock();
    await clock.time('policy', () => sleep(20));

    const timings = clock.read();
    expect(timings.policy).toBeGreaterThan(10);
    expect(timings.policy).toBeLessThan(200);
  });

  it('leaves a step that did not run absent, not zero', async () => {
    const clock = createStepClock();
    await clock.time('session', () => sleep(1));

    const timings = clock.read();
    expect(timings).not.toHaveProperty('policy');
    // A decision that stopped at step 3 did not spend zero milliseconds in
    // step 5; it never reached it. Recording a zero would claim otherwise.
    expect(timings.policy).toBeUndefined();
  });

  it('accumulates a step made of several calls', async () => {
    const clock = createStepClock();
    // Step 4 reads policies, then labels, then a volume counter. Its duration
    // is the sum, not the last one.
    await clock.time('precheck', () => sleep(15));
    await clock.time('precheck', () => sleep(15));

    expect(clock.read().precheck).toBeGreaterThan(25);
  });

  it('records a step that threw', async () => {
    const clock = createStepClock();
    await expect(
      clock.time('policy', async () => {
        await sleep(10);
        throw new Error('Permit is unreachable');
      }),
    ).rejects.toThrow('unreachable');

    // A step that failed is exactly the one worth having a duration for — a
    // five-second timeout is invisible if only successes are measured.
    expect(clock.read().policy).toBeGreaterThan(5);
  });

  it('hands back a copy, so a caller cannot rewrite history', async () => {
    const clock = createStepClock();
    await clock.time('risk', () => sleep(1));

    const first = clock.read();
    (first as Record<string, number>)['risk'] = 9999;
    expect(clock.read().risk).not.toBe(9999);
  });
});

describe('what a timing map cannot carry', () => {
  it('holds only the nine step names', async () => {
    const clock = createStepClock();
    for (const step of STEP_NAMES) await clock.time(step, () => sleep(0));

    // Any key that is not a step name would be a field somebody could put a
    // file name or an argument in. There is no such key.
    expect(Object.keys(clock.read()).sort()).toEqual([...STEP_NAMES].sort());
  });

  it('holds only numbers', async () => {
    const clock = createStepClock();
    await clock.time('policy', () => sleep(2));
    await clock.time('audit', () => sleep(2));

    for (const value of Object.values(clock.read())) {
      expect(typeof value).toBe('number');
      expect(Number.isFinite(value)).toBe(true);
    }
  });

  it('survives JSON round-tripping unchanged, because that is how it is stored', async () => {
    const clock = createStepClock();
    await clock.time('precheck', () => sleep(3));

    const stored = JSON.parse(JSON.stringify(clock.read())) as Record<string, unknown>;
    expect(stored).toEqual(clock.read());
  });

  it('names exactly the nine steps of §3.3, in order', () => {
    const expected: StepName[] = [
      'identity',
      'normalize',
      'session',
      'precheck',
      'policy',
      'risk',
      'emit',
      'upstream',
      'audit',
    ];
    expect([...STEP_NAMES]).toEqual(expected);
  });
});
