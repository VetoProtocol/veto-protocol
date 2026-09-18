import { describe, expect, it } from 'vitest';
import { percentile } from '../src/latency.ts';

describe('percentile', () => {
  const sorted = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];

  it('returns an observation, never an interpolated value', () => {
    // Nearest-rank: every result must be a number that was actually measured.
    for (const p of [1, 25, 50, 75, 95, 99, 100]) {
      expect(sorted).toContain(percentile(sorted, p));
    }
  });

  it('places p50 and p95 at the documented ranks', () => {
    expect(percentile(sorted, 50)).toBe(50);
    expect(percentile(sorted, 95)).toBe(100);
    expect(percentile(sorted, 100)).toBe(100);
  });

  it('does not read past either end', () => {
    expect(percentile([], 95)).toBe(0);
    expect(percentile([42], 95)).toBe(42);
    expect(percentile(sorted, 0)).toBe(10);
  });
});
