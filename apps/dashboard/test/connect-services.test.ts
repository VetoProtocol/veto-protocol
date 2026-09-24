/**
 * The connect route's service list must match the one the API accepts.
 *
 * `/connections/google/start` checks the `service` query parameter against a
 * closed set before asking the control plane for a consent URL. That set is a
 * hand-kept copy of `GOOGLE_SERVICES`: the guard that owns the real list,
 * `isGoogleService`, cannot be imported by the dashboard because
 * `@veto/connections` re-exports relative `.ts` files and the Next build runs
 * with `allowImportingTsExtensions` off.
 *
 * The copy drifted. `calendar` was missing, and the route's fallback was Drive,
 * so pressing "connect Calendar" opened a Google screen for **Drive** and
 * stored a Drive grant. Nothing failed: the user asked for one thing, approved
 * what they were shown, and got another. In a continuous-consent product that
 * is a wrong `allow`, which §1 calls a security incident rather than a bug.
 *
 * Both lists are read from source rather than imported. The dashboard has no
 * dependency on `@veto/connections` and should not gain one: the moment it is
 * on the package graph somebody imports it from app code and the Next build
 * breaks on a `.ts` specifier. Reading the file keeps the two comparable
 * without making them linkable.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const here = path.dirname(fileURLToPath(import.meta.url));
const route = path.join(here, '..', 'src/app/connections/google/start/route.ts');
const source_of_truth = path.join(here, '../../..', 'packages/connections/src/google.ts');

/** The real list, read from the package that owns it. */
function apiServices(): string[] {
  const source = readFileSync(source_of_truth, 'utf8');
  const match = /export const GOOGLE_SERVICES = \{([^}]*)\}/.exec(source);
  if (!match?.[1]) throw new Error('could not find GOOGLE_SERVICES in @veto/connections');
  return [...match[1].matchAll(/^\s*([a-z]+):/gm)].map((m) => m[1] as string).sort();
}

/** The literal set the route actually checks against, read from its source. */
function declaredServices(): string[] {
  const source = readFileSync(route, 'utf8');
  const match = /GOOGLE_SERVICES:\s*ReadonlySet<string>\s*=\s*new Set\(\[([^\]]*)\]\)/.exec(source);
  if (!match?.[1]) throw new Error('could not find the service set in the start route');
  return [...match[1].matchAll(/'([^']+)'/g)].map((m) => m[1] as string).sort();
}

describe('the connect route’s service allowlist', () => {
  it('finds both lists, so this test cannot silently pass on nothing', () => {
    expect(declaredServices().length).toBeGreaterThan(0);
    expect(apiServices().length).toBeGreaterThan(0);
  });

  it('lists exactly the services the API accepts', () => {
    expect(declaredServices()).toEqual(apiServices());
  });

  it('includes calendar — the one that drifted', () => {
    expect(declaredServices()).toContain('calendar');
  });

  it('refuses an unknown service instead of substituting one', () => {
    const source = readFileSync(route, 'utf8');
    // A fallback here is what turned "connect Calendar" into a Drive grant.
    expect(source).toMatch(/if \(!GOOGLE_SERVICES\.has\(asked\)\) return back\(/);
    expect(source).not.toMatch(/asked === 'gmail' \? 'gmail' : 'drive'/);
  });
});
