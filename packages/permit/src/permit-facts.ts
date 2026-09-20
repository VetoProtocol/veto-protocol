/**
 * The real Permit adapter for control-plane facts (spec §4.4).
 *
 * Implements the same `PolicyFacts` port as the fake, so nothing upstream
 * changes when this replaces it. It writes facts; it answers no authorization
 * questions. `permit.check` belongs to the gateway in stage 2 and is
 * deliberately absent here — see the port's contract note.
 *
 * ## Every failure is an outage
 *
 * A fact operation has no "no". It succeeds, or it does not, and the caller's
 * response is the same either way: refuse the registration. So every thrown
 * error maps to PolicyUnavailableError, including a 4xx that really means "your
 * tenant does not exist" — a configuration fault, not a network one.
 *
 * That mislabels the cause and gets the effect right, which is the trade this
 * codebase makes everywhere (invariant 1). The cause is not lost: the original
 * error is attached as `cause` for the operator, while the caller sees a
 * denial. What must never happen is a fact operation reporting success it did
 * not achieve.
 *
 * ## Writes wait for the PDP, when the PDP can be waited on
 *
 * `proxyFactsViaPdp` with `factsSyncTimeoutPolicy: 'fail'` makes syncAgent
 * resolve only once the PDP can answer questions about the agent. Without it
 * the Cloud API acks a write the PDP has not necessarily replicated, and a
 * check moments later could miss it. For a grant that is a false deny —
 * annoying. For a removal it is the §11 five-second revocation window.
 *
 * **The hosted PDP cannot do this.** The proxy endpoint is `/v2/facts/...`,
 * served by the PDP container and answered with 404 by cloudpdp.api.permit.io,
 * so the config derives the flag from the PDP URL and the guarantee is simply
 * absent on hosted. What still holds the line is that revocation flips the
 * agent's status in Postgres first and the gateway checks that status on every
 * request (revocation.ts, step 1) — Permit catching up late cannot re-grant
 * anything. Running a local PDP in deployment closes the gap properly.
 */

import { Permit } from 'permitio';
import type { PermitConfig } from './config.ts';
import {
  AGENT_RESOURCE,
  FOLDER_RESOURCE,
  HUMAN_RESOURCE,
  RELATION_DELEGATOR,
  RELATION_PARENT,
  agentInstanceKey,
  agentUserKey,
  delegatorFact,
  humanInstanceKey,
  humanUserKey,
  resourceInstanceKey,
  scopedInstanceKey,
  unscopeInstanceKey,
  roleFact,
  ROLE_READER,
  tenantKey,
} from './model.ts';
import {
  PolicyUnavailableError,
  type AgentFact,
  type PolicyFacts,
  type ResourceGrant,
} from './port.ts';

/**
 * How hard to try before declaring a grant failed.
 *
 * Four attempts across three seconds. Long enough for a freshly created
 * resource instance to become visible in a new tenant, short enough that a
 * genuinely broken grant is reported while somebody is still looking at the
 * screen that asked for it.
 */
const GRANT_ATTEMPTS = 4;
const GRANT_RETRY_MS = 1000;

/** `agent|agt_x` back to `agt_x`, or null when the key is some other principal. */
const agentIdOf = (userKey: string): string | null =>
  userKey.startsWith('agent|') ? userKey.slice('agent|'.length) : null;

export interface PermitPolicyFacts extends PolicyFacts {
  /** Release the underlying HTTP agent. */
  close(): Promise<void>;
}

export function createPermitPolicyFacts(config: PermitConfig): PermitPolicyFacts {
  const permit = new Permit({
    token: config.token,
    pdp: config.pdpUrl,
    ...(config.apiUrl === undefined ? {} : { apiUrl: config.apiUrl }),
    timeout: config.timeoutMs,
    // Surface transport failures instead of returning a default. A silent
    // default is the one outcome that would let an outage look like an answer.
    throwOnError: true,
    // Only meaningful against a local PDP; see PermitConfig.proxyFactsViaPdp.
    // Against the hosted PDP these are left off entirely rather than sent and
    // ignored, so the request does not carry a wait header nothing honours.
    proxyFactsViaPdp: config.proxyFactsViaPdp,
    ...(config.proxyFactsViaPdp
      ? { factsSyncTimeout: config.factsSyncTimeoutMs, factsSyncTimeoutPolicy: 'fail' as const }
      : {}),
    // `json: false` is not a typo. permitio 2.7.6 inverts this flag:
    //   prettyPrint: config.log.json ? { levelFirst: true } : false
    // and pino 8 throws on any truthy prettyPrint. So `json: true` crashes the
    // constructor, and `json: false` gives plain pino output — which is JSON,
    // because that is pino's default. The value that reads wrong is the one
    // that produces structured logs.
    log: { level: 'warn', label: 'permit', json: false },
  });

  /** Run a Permit call, converting any failure into a denial. */
  async function guarded<T>(operation: string, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (error) {
      throw new PolicyUnavailableError(operation, error);
    }
  }

  async function ensureTenant(workspaceId: string): Promise<void> {
    const key = tenantKey(workspaceId);
    try {
      await permit.api.tenants.get(key);
      return;
    } catch {
      // Not found, or unreachable. Creating is idempotent enough to try; if the
      // API is genuinely down the create fails too and the caller gets a denial.
    }
    try {
      await permit.api.tenants.create({ key, name: key });
    } catch (error) {
      if (!isConflict(error)) throw error;
      // A concurrent registration won the race. That is the desired end state.
    }
  }

  return {
    async syncAgent(fact: AgentFact): Promise<void> {
      const { workspaceId, agentId, ownerUserId } = fact;

      await guarded('syncAgent', async () => {
        await ensureTenant(workspaceId);

        // The agent as a principal. No role_assignments: a freshly registered
        // agent is granted nothing, and deny-by-default (invariant 2) is what
        // makes that safe. Grants are attached later, per connection.
        await permit.api.users.sync({
          key: agentUserKey(agentId),
          attributes: { workspace_id: workspaceId, owner_user_id: ownerUserId },
        });

        // The owner, as a principal and as a relation endpoint.
        await permit.api.users.sync({
          key: humanUserKey(ownerUserId),
          attributes: { workspace_id: workspaceId },
        });

        await permit.api.resourceInstances.create({
          resource: HUMAN_RESOURCE,
          key: ownerUserId,
          tenant: tenantKey(workspaceId),
        }).catch(swallowConflict);

        await permit.api.resourceInstances.create({
          resource: AGENT_RESOURCE,
          key: agentId,
          tenant: tenantKey(workspaceId),
        }).catch(swallowConflict);

        // The delegator edge §7.1 reads when deciding who may approve.
        //
        // Direction matters and is easy to get backwards. Permit defines a
        // relation *on the object resource*, naming the other end as
        // subject_resource — the same shape as its "Folder is parent of File"
        // example, where `parent` belongs to File. So `delegator` belongs to
        // veto_agent, and the tuple reads "this agent's delegator is that
        // human": subject is the human, object is the agent.
        await permit.api.relationshipTuples.create({
          subject: humanInstanceKey(ownerUserId),
          relation: RELATION_DELEGATOR,
          object: agentInstanceKey(agentId),
          tenant: tenantKey(workspaceId),
        }).catch(swallowConflict);
      });
    },

    async removeAgent(workspaceId: string, agentId: string): Promise<void> {
      await guarded('removeAgent', async () => {
        const tenant = tenantKey(workspaceId);
        const user = agentUserKey(agentId);

        // Narrowest step first, so a failure part-way through still leaves the
        // agent with less than it had. Unassigning roles is what actually stops
        // access; the later steps remove the residue.
        const assignments = await permit.api.roleAssignments.list({ user, tenant, perPage: 100 });
        for (const assignment of assignments) {
          await permit.api.roleAssignments.unassign({
            user,
            role: assignment.role,
            tenant,
            ...(assignment.resource_instance === undefined
              ? {}
              : { resource_instance: assignment.resource_instance }),
          });
        }

        const tuples = await permit.api.relationshipTuples.list({
          tenant,
          object: agentInstanceKey(agentId),
          perPage: 100,
        });
        for (const tuple of tuples) {
          await permit.api.relationshipTuples.delete({
            subject: tuple.subject,
            relation: tuple.relation,
            object: tuple.object,
          }).catch(swallowNotFound);
        }

        // Finally the principal itself. A deleted user cannot be the subject of
        // a check at all, which is the strongest statement of FR-08 available
        // through this API.
        await permit.api.users.delete(user).catch(swallowNotFound);
      });
    },

    async grantResource(grant): Promise<void> {
      await guarded('grantResource', async () => {
        const tenant = tenantKey(grant.workspaceId);

        await ensureTenant(grant.workspaceId);

        // Drive is not enumerated anywhere, so the first time somebody names a
        // folder is the moment it becomes a thing Permit can hold an opinion
        // about. Creating it here rather than requiring a separate call keeps
        // "grant" a single operation that either happened or did not.
        // Scoped, because Permit makes an instance key unique per environment
        // rather than per tenant. Unscoped, the second workspace to grant
        // `root` collides with the first one's instance. See model.ts.
        const scopedKey = scopedInstanceKey(grant.workspaceId, grant.resourceKey);

        await permit.api.resourceInstances
          .create({
            resource: grant.resourceType,
            key: scopedKey,
            tenant,
          })
          .catch(swallowConflict);

        const user = agentUserKey(grant.agentId);
        const instance = resourceInstanceKey(grant.resourceType, scopedKey);

        // Retried, because the instance created a moment ago is not always
        // queryable yet in a tenant Permit has just seen for the first time,
        // and the assignment fails against a resource that does not exist to
        // it yet. The first grant in a brand-new workspace is exactly that
        // case — the one every new customer hits.
        for (let attempt = 0; attempt < GRANT_ATTEMPTS; attempt += 1) {
          await permit.api.roleAssignments
            .assign({ user, role: ROLE_READER, tenant, resource_instance: instance })
            .catch(swallowConflict);

          // Read it back rather than trusting the write.
          //
          // `swallowConflict` treats 409 as "already assigned", which is right
          // when it is and catastrophic when it is not: a grant that answered
          // 201 while storing nothing tells an operator they have given access
          // they have not given. It fails closed, so it is not a hole — it is
          // worse in a different way, because the system and the person
          // disagree about what is permitted and nothing surfaces it.
          const held = await permit.api.roleAssignments.list({
            user,
            tenant,
            resourceInstance: instance,
            perPage: 10,
          });
          if (held.some((a) => a.role === ROLE_READER)) return;

          await new Promise((resolve) => setTimeout(resolve, GRANT_RETRY_MS));
        }

        // Out of attempts with nothing stored. Raising here turns a silent
        // no-op into a 503 the caller can see and retry.
        throw new Error(`grant not visible after ${GRANT_ATTEMPTS} attempts: ${user} -> ${instance}`);
      });
    },

    async revokeResource(grant): Promise<void> {
      await guarded('revokeResource', async () => {
        await permit.api.roleAssignments
          .unassign({
            user: agentUserKey(grant.agentId),
            role: ROLE_READER,
            tenant: tenantKey(grant.workspaceId),
            resource_instance: resourceInstanceKey(
              grant.resourceType,
              scopedInstanceKey(grant.workspaceId, grant.resourceKey),
            ),
          })
          .catch(swallowNotFound);

        // The instance stays. It is the noun the grant was about, not the
        // grant, and deleting it would take any `parent` edges with it —
        // silently changing grants nobody touched.
      });
    },

    async recordParent(link): Promise<void> {
      await guarded('recordParent', async () => {
        const tenant = tenantKey(link.workspaceId);

        await ensureTenant(link.workspaceId);

        // Both ends, because either may be the first time Permit has heard of
        // it. A tuple whose endpoint does not exist is a 404, not an edge.
        const childKey = scopedInstanceKey(link.workspaceId, link.childKey);
        const parentKey = scopedInstanceKey(link.workspaceId, link.parentKey);

        for (const instance of [
          { resource: link.childType, key: childKey },
          { resource: FOLDER_RESOURCE, key: parentKey },
        ]) {
          await permit.api.resourceInstances
            .create({ ...instance, tenant })
            .catch(swallowConflict);
        }

        // Subject is the container, object is the thing contained — the same
        // direction as the delegator edge, and the direction Permit's own
        // "Folder is parent of File" example uses. Backwards here would make
        // every file a parent of its folder, and a grant on one file would
        // reach the whole folder.
        await permit.api.relationshipTuples
          .create({
            subject: resourceInstanceKey(FOLDER_RESOURCE, parentKey),
            relation: RELATION_PARENT,
            object: resourceInstanceKey(link.childType, childKey),
            tenant,
          })
          .catch(swallowConflict);
      });
    },

    async listGrants(workspaceId: string): Promise<readonly ResourceGrant[]> {
      return guarded('listGrants', async () => {
        const tenant = tenantKey(workspaceId);
        const assignments = await permit.api.roleAssignments.list({
          tenant,
          role: ROLE_READER,
          perPage: 100,
        });

        const grants: ResourceGrant[] = [];
        for (const assignment of assignments) {
          const instance = assignment.resource_instance;
          const agentId = agentIdOf(assignment.user);
          if (instance === undefined || agentId === null) continue;

          // `type:key`, and a Drive id can itself contain a colon, so split
          // once from the left rather than on every colon.
          const at = instance.indexOf(':');
          if (at <= 0) continue;

          // Null means the instance is scoped to a different workspace, which a
          // tenant-filtered listing should never return — but reporting it as
          // this tenant's resource would be exactly the leak the scoping
          // prevents, so it is skipped rather than guessed at.
          const resourceKey = unscopeInstanceKey(workspaceId, instance.slice(at + 1));
          if (resourceKey === null) continue;

          grants.push({
            workspaceId,
            agentId,
            resourceType: instance.slice(0, at),
            resourceKey,
          });
        }

        return grants;
      });
    },

    async factsFor(workspaceId: string): Promise<readonly string[]> {
      return guarded('factsFor', async () => {
        const tenant = tenantKey(workspaceId);
        const facts: string[] = [];

        const tuples = await permit.api.relationshipTuples.list({
          tenant,
          relation: RELATION_DELEGATOR,
          perPage: 100,
        });
        for (const tuple of tuples) {
          const ownerId = instanceKeyOf(tuple.subject, HUMAN_RESOURCE);
          const agentId = instanceKeyOf(tuple.object, AGENT_RESOURCE);
          if (agentId && ownerId) facts.push(delegatorFact(agentId, ownerId));
        }

        const assignments = await permit.api.roleAssignments.list({ tenant, perPage: 100 });
        for (const assignment of assignments) {
          facts.push(roleFact(assignment.user, assignment.role));
        }

        return facts.sort();
      });
    },

    async close(): Promise<void> {
      // The SDK holds an axios instance with a keep-alive pool; nothing to
      // release explicitly today. The method exists so callers can own a
      // lifecycle without changing when that stops being true.
    },
  };
}

/**
 * Key half of a `type:key` instance reference, or null when the type does not
 * match. The type check is not decoration: a tuple whose endpoints are some
 * other resource is not a delegator edge, and rendering it as one would make
 * factsFor report a relationship that does not exist.
 */
function instanceKeyOf(reference: string, expectedResource: string): string | null {
  const separator = reference.indexOf(':');
  if (separator < 0) return null;
  if (reference.slice(0, separator) !== expectedResource) return null;
  const key = reference.slice(separator + 1);
  return key === '' ? null : key;
}

function statusOf(error: unknown): number | undefined {
  const candidate = error as { response?: { status?: number }; status?: number };
  return candidate.response?.status ?? candidate.status;
}

const isConflict = (error: unknown): boolean => statusOf(error) === 409;
const isNotFound = (error: unknown): boolean => statusOf(error) === 404;

function swallowConflict(error: unknown): void {
  if (!isConflict(error)) throw error;
}

function swallowNotFound(error: unknown): void {
  if (!isNotFound(error)) throw error;
}
