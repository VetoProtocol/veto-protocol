/**
 * Delete a Permit tenant created by a test run.
 *
 * Every script here that exercises a fresh workspace causes `ensureTenant` to
 * create a Permit tenant, and Permit counts them against the account. Ninety-one
 * accumulated before anybody noticed, and the failure — a 500 from the tenants
 * API, surfacing as `POLICY_UNAVAILABLE` on agent registration — pointed nowhere
 * near the test runs that caused it.
 *
 * Deliberately not part of `PolicyFacts`. The port has no way to delete a tenant
 * because the product has no reason to hold that capability; adding one so a
 * script can tidy up would put it within reach of a route handler.
 *
 * Never throws. A tenant that outlives its run is a mess; a test reported as
 * failed because its cleanup raced is a worse one.
 */
import { Permit } from 'permitio';
import { permitConfigFromEnv } from '@veto/permit';

export async function deletePermitTenant(workspaceId: string): Promise<void> {
  try {
    const config = permitConfigFromEnv();
    const permit = new Permit({
      token: config.token,
      pdp: config.pdpUrl,
      throwOnError: true,
      log: { level: 'error', label: 'cleanup', json: false },
    });
    await permit.api.tenants.delete(workspaceId);
    process.stdout.write(`cleaned up Permit tenant ${workspaceId}\n`);
  } catch (error) {
    console.warn(`left Permit tenant ${workspaceId} behind: ${String(error).slice(0, 120)}`);
  }
}
