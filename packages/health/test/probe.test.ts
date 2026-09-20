/**
 * Startup probes.
 *
 * The properties that matter are about *reporting*, not about the network:
 *
 *  * A failure is reported with a reason somebody can act on. "fetch failed"
 *    with the useful code buried two levels down in `cause` is how an afternoon
 *    gets spent on a dead IPv6 route.
 *  * A probe cannot hang the boot. A dependency that accepts a connection and
 *    then says nothing is exactly the case a naive check waits forever on.
 *  * Only a `required` failure stops the service. Invariant 1 is fail closed at
 *    request time, not refuse to start — a gateway that will not boot cannot be
 *    restarted into a recovering system.
 */

import { describe, expect, it } from 'vitest';
import {
  bootable,
  formatReport,
  runProbes,
  PROBE_TIMEOUT_MS,
  type Probe,
} from '../src/probe.ts';

const ok = (name: string, required = false): Probe => ({
  name,
  required,
  check: async () => undefined,
});

const broken = (name: string, error: unknown, required = false): Probe => ({
  name,
  required,
  check: async () => {
    throw error;
  },
});

describe('running probes', () => {
  it('reports every probe, not just the first failure', async () => {
    const results = await runProbes([
      broken('postgres', new Error('down')),
      broken('redis', new Error('down')),
      ok('permit-pdp'),
    ]);

    // "Postgres is down" is a different morning from "everything is down".
    expect(results).toHaveLength(3);
    expect(results.filter((r) => !r.ok)).toHaveLength(2);
  });

  it('measures how long each took', async () => {
    const results = await runProbes([
      { name: 'slow', check: () => new Promise((resolve) => setTimeout(resolve, 30)) },
    ]);
    expect(results[0]?.ms).toBeGreaterThan(10);
  });

  it('does not hang on a probe that never settles', async () => {
    const started = Date.now();
    const results = await runProbes([{ name: 'silent', check: () => new Promise(() => {}) }]);

    expect(results[0]?.ok).toBe(false);
    expect(results[0]?.detail).toContain('timed out');
    // A dependency that accepts a connection and then says nothing must not
    // hold the process open.
    expect(Date.now() - started).toBeLessThan(PROBE_TIMEOUT_MS + 3000);
  }, 20_000);
});

describe('the reason a probe gives', () => {
  it('digs the code out of a nested cause', async () => {
    // Node's shape for a connect failure: the useful part is two levels down.
    const outer = new TypeError('fetch failed');
    (outer as { cause?: unknown }).cause = Object.assign(new Error('connect'), {
      code: 'ETIMEDOUT',
    });

    const [result] = await runProbes([broken('google-oauth', outer)]);
    expect(result?.detail).toContain('ETIMEDOUT');
  });

  it('falls back to the message when there is no code', async () => {
    const [result] = await runProbes([broken('permit-pdp', new Error('nope'))]);
    expect(result?.detail).toContain('nope');
  });

  it('survives something thrown that is not an Error', async () => {
    const [result] = await runProbes([broken('odd', 'just a string')]);
    expect(result?.ok).toBe(false);
    expect(result?.detail).toContain('just a string');
  });

  it('trims a long reason rather than filling the log with it', async () => {
    const [result] = await runProbes([broken('verbose', new Error('x'.repeat(500)))]);
    expect((result?.detail ?? '').length).toBeLessThanOrEqual(120);
  });
});

describe('whether the service should start', () => {
  it('starts when everything passes', async () => {
    expect(bootable(await runProbes([ok('postgres', true), ok('redis')]))).toBe(true);
  });

  it('starts when an optional dependency is unreachable', async () => {
    // A gateway that cannot reach Permit denies every request, which is
    // correct. One that refuses to boot cannot be restarted into a recovering
    // system.
    const results = await runProbes([ok('postgres', true), broken('permit-pdp', new Error('x'))]);
    expect(bootable(results)).toBe(true);
  });

  it('refuses when a required dependency is unreachable', async () => {
    const results = await runProbes([broken('postgres', new Error('x'), true), ok('redis')]);
    expect(bootable(results)).toBe(false);
  });
});

describe('the report', () => {
  it('gives one line per dependency', async () => {
    const lines = formatReport(await runProbes([ok('postgres', true), ok('redis')]));
    expect(lines).toHaveLength(2);
  });

  it('aligns the names so a scan finds the failure', async () => {
    const lines = formatReport(
      await runProbes([ok('redis'), broken('google-oauth', new Error('x'))]),
    );
    const columns = lines.map((line) => line.indexOf('ok  ') + line.indexOf('FAIL') + 1);
    // Both status words start at the same offset, whatever the name's length.
    expect(new Set(columns).size).toBe(1);
  });

  it('says FAIL in a way that greps', async () => {
    const [line] = formatReport(await runProbes([broken('postgres', new Error('down'), true)]));
    expect(line).toContain('FAIL');
    expect(line).toContain('postgres');
    expect(line).toContain('down');
  });

  it('carries no secret, only a name and a duration', async () => {
    const lines = formatReport(await runProbes([ok('postgres', true), ok('google-oauth')]));
    // A probe answers "can this be reached", never "is this key valid", so
    // there is nothing here for a credential to leak through (invariant 5).
    for (const line of lines) {
      // Name, status, duration. Nothing else is in the line, so there is
      // nothing for a credential to ride out on.
      expect(line).toMatch(/^health\s+[a-z-]+\s+ok\s+[\d.]+ms$/);
    }
  });
});
