/**
 * Construction tests for the real adapter — no network, no key required.
 *
 * These exist because the live tests cannot run without an account, which left
 * the adapter's constructor completely unexercised on every machine and in CI.
 * The first time it ran it threw inside the Permit SDK's logger setup, before a
 * single request was made. A test that needs credentials to catch a crash that
 * happens before credentials are used is a test in the wrong place.
 */

import { describe, expect, it } from 'vitest';
import type { PermitConfig } from '../src/config.ts';
import { createPermitPolicyFacts } from '../src/permit-facts.ts';

const config: PermitConfig = {
  token: 'permit_key_placeholder',
  pdpUrl: 'https://cloudpdp.api.permit.io',
  apiUrl: undefined,
  timeoutMs: 5_000,
  proxyFactsViaPdp: false,
  factsSyncTimeoutMs: 10_000,
};

describe('createPermitPolicyFacts', () => {
  it('constructs without contacting anything', () => {
    // permitio 2.7.6 passes `prettyPrint` to pino when log.json is true, and
    // pino 8 throws on any truthy prettyPrint. The flag is inverted relative to
    // its name, so this assertion is what pins the working value in place.
    expect(() => createPermitPolicyFacts(config)).not.toThrow();
  });

  it('exposes the port and nothing resembling a decision', () => {
    const adapter = createPermitPolicyFacts(config);

    // Same guard as the fake: a `check`-shaped method appearing here would mean
    // the runtime decision had migrated out of the gateway (invariant 3, 8).
    // Writing facts, and nothing that answers a question. `grantResource` is a
    // write — it states that a relationship exists — and the decision that
    // reads it lives behind PolicyDecisions, in the gateway.
    expect(Object.keys(adapter).sort()).toEqual([
      'close',
      'factsFor',
      'grantResource',
      'listGrants',
      'removeAgent',
      'revokeResource',
      'syncAgent',
    ]);
  });

  it('accepts a local PDP url unchanged', () => {
    expect(() =>
      createPermitPolicyFacts({ ...config, pdpUrl: 'http://localhost:7766' }),
    ).not.toThrow();
  });
});
