/**
 * Contract test against the real Permit API.
 *
 * Skipped unless PERMIT_API_KEY is set, so CI and every machine without an
 * account stays green. That makes it the one test here that is *not* proof by
 * default — the fake proves the port's shape, and only this proves the adapter
 * actually speaks to Permit. Run it before trusting the adapter:
 *
 *   pnpm --filter @veto/permit test
 *
 * The key is read from the repo-root .env, with a shell-set value taking
 * precedence over it.
 *
 * It writes to whichever Permit environment the key points at. Point it at
 * development, never at production (§16: separate environments, separate keys).
 */

import { Permit } from 'permitio';
import { afterAll, describe, expect, it } from 'vitest';
import { loadRepoEnv } from '../src/env.ts';
import { permitConfigFromEnv } from '../src/config.ts';
import { createPermitPolicyFacts, type PermitPolicyFacts } from '../src/permit-facts.ts';
import { delegatorFact } from '../src/model.ts';

loadRepoEnv();

const hasKey = (process.env['PERMIT_API_KEY'] ?? '').trim() !== '';
const suffix = Math.random().toString(36).slice(2, 10);
const WS = `ws_live${suffix}`;
const AGENT = `agt_live${suffix}`;
const OWNER = `usr_live${suffix}`;

let policy: PermitPolicyFacts | undefined;
/** Set once the tenant exists, so a skipped or failed-early run deletes nothing. */
let created = false;

/**
 * Delete the tenant this run created.
 *
 * `syncAgent` calls `ensureTenant`, so every run of this file leaves a tenant
 * behind. Ninety-one of them accumulated and exhausted the account's quota,
 * which surfaced as a 500 from Permit's tenants API and a `POLICY_UNAVAILABLE`
 * on agent registration — a failure with no visible connection to its cause,
 * days after the test runs that caused it.
 *
 * Done with the SDK directly rather than through `PolicyFacts`. The port
 * deliberately has no way to delete a tenant: that is a destructive capability
 * the product has no reason to hold, and adding one so a test can tidy up would
 * put it within reach of a route handler.
 *
 * Failures here are reported and not thrown. A tenant that outlives its run is
 * a mess to clean up later; a green suite reported as red because the cleanup
 * raced is a worse one.
 */
afterAll(async () => {
  await policy?.close();

  if (!hasKey || !created) return;

  try {
    const config = permitConfigFromEnv();
    const permit = new Permit({
      token: config.token,
      pdp: config.pdpUrl,
      throwOnError: true,
      log: { level: 'error', label: 'permit-live-cleanup', json: false },
    });
    await permit.api.tenants.delete(WS);
  } catch (error) {
    console.warn(`live test left tenant ${WS} behind: ${String(error).slice(0, 120)}`);
  }
});

describe.skipIf(!hasKey)('PermitPolicyFacts against the live API', () => {
  it('records the delegator relationship on sync', async () => {
    policy = createPermitPolicyFacts(permitConfigFromEnv());

    await policy.syncAgent({ workspaceId: WS, agentId: AGENT, ownerUserId: OWNER });
    created = true;

    expect(await policy.factsFor(WS)).toContain(delegatorFact(AGENT, OWNER));
  }, 60_000);

  it('leaves nothing behind on remove', async () => {
    policy ??= createPermitPolicyFacts(permitConfigFromEnv());

    await policy.removeAgent(WS, AGENT);

    const facts = await policy.factsFor(WS);
    expect(facts).not.toContain(delegatorFact(AGENT, OWNER));
    expect(facts.filter((f) => f.includes(AGENT))).toEqual([]);
  }, 60_000);

  it('is idempotent: removing twice is not an error', async () => {
    policy ??= createPermitPolicyFacts(permitConfigFromEnv());
    await expect(policy.removeAgent(WS, AGENT)).resolves.toBeUndefined();
  }, 60_000);
});

describe('PermitPolicyFacts without credentials', () => {
  it('refuses to construct a config with no key', () => {
    expect(() => permitConfigFromEnv({ PERMIT_API_KEY: '' })).toThrow(/not set/);
  });
});
