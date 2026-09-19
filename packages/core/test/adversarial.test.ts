/**
 * Keeps the adversarial registry honest.
 *
 * A checklist in a document drifts: a scenario gets dropped, or the test behind
 * a ticked row is deleted, and nothing breaks so nobody notices. These
 * assertions make each of those a build failure.
 */

import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  ADVERSARIAL_SCENARIOS,
  MANDATORY_SCENARIO_COUNT,
  pendingScenarios,
} from '../src/adversarial.ts';
import { PIPELINE_STAGES } from '../src/reason-codes.ts';

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const spec = readFileSync(path.join(repoRoot, 'veto-protocol-spec.md'), 'utf8');
const threatModel = readFileSync(path.join(repoRoot, 'docs', 'threat-model.md'), 'utf8');

describe('adversarial scenario registry', () => {
  it('covers every mandatory §12.1 scenario', () => {
    const mandatory = ADVERSARIAL_SCENARIOS.filter((s) => s.source === 'spec §12.1');
    expect(mandatory).toHaveLength(MANDATORY_SCENARIO_COUNT);
  });

  it('matches the number of bullets the spec actually lists under §12.1', () => {
    // Read from the spec rather than trusting the constant, so an amended spec
    // fails here instead of being silently under-covered.
    const section = spec.slice(
      spec.indexOf('### 12.1 Mandatory adversarial scenarios'),
      spec.indexOf('## 13 Delivery roadmap'),
    );
    const bullets = section.split('\n').filter((line) => line.startsWith('- ')).length;

    expect(bullets).toBe(MANDATORY_SCENARIO_COUNT);
  });

  it('gives every scenario a unique id', () => {
    const ids = ADVERSARIAL_SCENARIOS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('names a threat that exists in the threat model', () => {
    for (const scenario of ADVERSARIAL_SCENARIOS) {
      expect(threatModel, `${scenario.id} -> ${scenario.threat}`).toContain(
        `| ${scenario.threat} |`,
      );
    }
  });

  it('names a real pipeline stage', () => {
    for (const scenario of ADVERSARIAL_SCENARIOS) {
      expect(PIPELINE_STAGES, scenario.id).toContain(scenario.stage);
    }
  });

  it('points implemented scenarios at a test file that exists', () => {
    // The row and the file go together. Deleting the test now breaks the build
    // rather than leaving a ticked box behind.
    for (const scenario of ADVERSARIAL_SCENARIOS.filter((s) => s.status === 'implemented')) {
      expect(scenario.test, `${scenario.id} is implemented but names no test`).toBeTruthy();
      expect(
        existsSync(path.join(repoRoot, scenario.test ?? '')),
        `${scenario.id} names a missing file: ${scenario.test}`,
      ).toBe(true);
    }
  });

  it('does not let a pending scenario claim a test', () => {
    for (const scenario of pendingScenarios()) {
      expect(scenario.test, `${scenario.id} is pending but names ${scenario.test}`).toBeNull();
    }
  });

  it('says what each test must assert, at length enough to be useful', () => {
    // Several of these are easy to write so they can never fail. The guidance is
    // the antidote, so it is not allowed to degrade into a one-liner.
    for (const scenario of ADVERSARIAL_SCENARIOS) {
      expect(scenario.asserts.length, scenario.id).toBeGreaterThan(80);
    }
  });

  it('reports what is still owed', () => {
    // All twelve are implemented. Kept as an assertion rather than deleted:
    // adding a scenario without a test should fail here, not pass quietly.
    expect(pendingScenarios().map((s) => s.id)).toEqual([]);
  });
});
