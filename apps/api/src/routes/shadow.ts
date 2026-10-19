/**
 * Shadow Agents — what reaches a connected account without passing through us.
 *
 * Veto decides everything that comes through the gateway, and nothing else.
 * An AI tool wired straight into the company Drive is invisible to every other
 * screen in this product, and those screens stay green while it happens. This
 * is the one that looks the other way.
 *
 * ## The failure mode this route is shaped around
 *
 * Reading an inventory needs administrative access a connection may not have.
 * If a reader answered "no apps" when it meant "I was not allowed to look",
 * the screen would say **no shadow agents found** — the most dangerous
 * sentence this product could print, because it is the reassurance somebody
 * would act on and stop checking.
 *
 * So every provider reports either `read` or `unavailable` with a reason, the
 * response carries that distinction intact, and the screen renders them
 * differently. An empty list and an unanswered question are not the same
 * screen.
 *
 * ## A Pro screen, gated before any work
 *
 * Same as `/v1/grants/consent` and `/v1/agents/fingerprints`: 402 first, then
 * nothing. A hidden sidebar link is not a control — anybody can type a URL —
 * and a gate applied after the provider calls have run has already spent them.
 */

import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import {
  reachesProtectedData,
  type AppInventorySource,
  type InventoryResult,
} from '@veto/connections';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';
import { workspacePlan } from '../workspace.ts';

export interface ShadowRoutesDeps {
  readonly pool: Pool;
  /**
   * One per provider we can look into.
   *
   * Empty is the honest default and the current state: no customer has yet
   * granted the administrative access these need, so there is nothing to ask.
   * The screen then says it cannot see rather than that there is nothing to
   * see.
   */
  readonly inventory?: readonly AppInventorySource[] | null;
}

const PROVIDERS = ['google', 'github'] as const;

const RESPONSE = {
  type: 'object',
  properties: {
    providers: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          provider: { type: 'string' },
          /** `read` or `unavailable` — never collapsed into an empty list. */
          state: { type: 'string', enum: ['read', 'unavailable'] },
          reason: { type: 'string', nullable: true },
          apps: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                app_id: { type: 'string' },
                display_name: { type: 'string' },
                scopes: { type: 'array', items: { type: 'string' } },
                is_veto: { type: 'boolean' },
                reaches_protected_data: { type: 'boolean' },
              },
              required: ['app_id', 'display_name', 'scopes', 'is_veto', 'reaches_protected_data'],
            },
          },
        },
        required: ['provider', 'state', 'apps'],
      },
    },
    /**
     * How many apps reach protected data without being Veto.
     *
     * Null rather than zero when any provider could not be read. Zero would be
     * a claim, and a claim made over a question nobody answered.
     */
    shadow_count: { type: 'integer', nullable: true },
  },
  required: ['providers', 'shadow_count'],
} as const;

export function registerShadowRoutes(app: FastifyInstance, deps: ShadowRoutesDeps): void {
  app.get(
    '/v1/shadow',
    {
      schema: { response: { 200: RESPONSE, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA } },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      const plan = await withWorkspace(deps.pool, workspaceId, (db) =>
        workspacePlan(db, workspaceId),
      );
      if (plan !== 'pro') {
        throw new HttpError(
          402,
          'PLAN_REQUIRED',
          'Shadow Agents is part of the Pro plan for this workspace',
        );
      }

      const sources = deps.inventory ?? [];

      const providers = await Promise.all(
        PROVIDERS.map(async (provider) => {
          const source = sources.find((s) => s.provider === provider);

          // No source is `not_configured`, not an empty read. The difference is
          // the entire point of this screen.
          let result: InventoryResult;
          if (!source) {
            result = { kind: 'unavailable', reason: 'not_configured' };
          } else {
            try {
              result = await source.read({ workspaceId, userId });
            } catch (error) {
              // A thrown error is still "could not look". It must never
              // degrade into an empty list that reads as all-clear.
              request.log.warn({ err: error, provider }, 'inventory source failed');
              result = { kind: 'unavailable', reason: 'provider_unavailable' };
            }
          }

          if (result.kind === 'unavailable') {
            return { provider, state: 'unavailable' as const, reason: result.reason, apps: [] };
          }

          return {
            provider,
            state: 'read' as const,
            reason: null,
            apps: result.apps.map((app) => ({
              app_id: app.appId,
              display_name: app.displayName,
              scopes: [...app.scopes],
              is_veto: app.isVeto,
              reaches_protected_data: reachesProtectedData(app),
            })),
          };
        }),
      );

      // Null when anything could not be read. A number here is a statement
      // about the whole estate, and it cannot be made from a partial look.
      const complete = providers.every((p) => p.state === 'read');
      const shadowCount = complete
        ? providers.reduce(
            (total, p) =>
              total + p.apps.filter((a) => !a.is_veto && a.reaches_protected_data).length,
            0,
          )
        : null;

      return { providers, shadow_count: shadowCount };
    },
  );
}
