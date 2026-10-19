/**
 * Every starter rule must match a tool that exists.
 *
 * A policy rule names an action and a resource type. If neither matches any
 * real tool the rule is inert: it never fires, nothing is allowed by it, and
 * the workspace keeps denying — which is indistinguishable from having applied
 * no template at all. That is precisely the confusion templates exist to
 * remove, so shipping an inert one would be worse than shipping none.
 *
 * The trap is concrete rather than hypothetical: `google_drive.list_folder`
 * has action `read`, not `list`, and `POLICY_ACTIONS` contains `list`. A
 * template written from the tool's *name* rather than its definition would be
 * dead on arrival and would look like a policy bug.
 *
 * This is the third hand-kept list in this repo to get a drift test, after the
 * tool catalogue and the resource-kind labels. Each one went wrong the same
 * way: two places had to agree, and nothing made them.
 */

import { describe, expect, it } from 'vitest';
import { POLICY_TEMPLATES, POLICY_ACTIONS } from '@veto/decisions';
import { TOOLS } from '../src/tools.ts';

/** `action|resourceType` for every tool the gateway actually serves. */
const REAL = new Set(TOOLS.map((t) => `${t.action}|${t.resourceType}`));

/** Resource types any tool names, whatever the action. */
const REAL_TYPES = new Set(TOOLS.map((t) => t.resourceType));

describe('starter rules match real tools', () => {
  it('names an action and type some tool actually uses', () => {
    const inert: string[] = [];

    for (const template of POLICY_TEMPLATES) {
      for (const rule of template.rules) {
        // `write` is the deliberate exception: no write tool exists, and the
        // `no-writes` template says so in its own summary. A deny for an
        // action nothing performs is a statement that stays true when one
        // arrives — the one case where matching no tool today is the point.
        if (rule.action === 'write' && rule.effect === 'deny') continue;

        const key = `${rule.action}|${rule.resourceFilter.type ?? ''}`;
        if (!REAL.has(key)) inert.push(`${template.id}: ${key}`);
      }
    }

    expect(inert, 'a starter rule that matches no tool would deny silently').toEqual([]);
  });

  it('names only resource types that exist', () => {
    const unknown = POLICY_TEMPLATES.flatMap((template) =>
      template.rules
        .map((rule) => rule.resourceFilter.type ?? '')
        .filter((type) => !REAL_TYPES.has(type))
        .map((type) => `${template.id}: ${type}`),
    );

    expect(unknown).toEqual([]);
  });

  it('names only actions the policy engine knows', () => {
    for (const template of POLICY_TEMPLATES) {
      for (const rule of template.rules) {
        expect(POLICY_ACTIONS, `${template.id}`).toContain(rule.action);
      }
    }
  });

  it('covers every read tool the gateway serves', () => {
    // The other direction. A tool nothing can allow is a tool that is listed,
    // called, and always refused — the same dead end from the other side.
    const covered = new Set(
      POLICY_TEMPLATES.flatMap((t) =>
        t.rules
          .filter((r) => r.effect === 'allow')
          .map((r) => `${r.action}|${r.resourceFilter.type ?? ''}`),
      ),
    );

    const uncovered = [...REAL].filter((key) => !covered.has(key));

    expect(uncovered, 'every tool should be reachable by some starter rule').toEqual([]);
  });
});
