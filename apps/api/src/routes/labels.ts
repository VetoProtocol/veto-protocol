/**
 * /v1/labels — sensitivity labels (spec §4.2).
 *
 * A label attaches protection to a resource instead of repeating a condition in
 * every rule that can reach it. It **only ever adds a requirement**: a resource
 * no rule allows stays denied whatever it is labelled, and `public` is not
 * permission.
 *
 * Adding one is an ordinary control-plane action. Removing one is too — it
 * takes protection away rather than granting access — and both are audited, so
 * a label that quietly disappears is visible in the timeline.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { newId } from '@veto/core';
import { withWorkspace } from '@veto/db';
import { SENSITIVITY_LEVELS, loadLabels } from '@veto/decisions';
import { writeAuditEvent } from '@veto/identity';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';

const LABEL_SCHEMA = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    resource_type: { type: 'string' },
    pattern: { type: 'string' },
    exact: { type: 'boolean' },
    sensitivity: { type: 'string' },
    note: { type: 'string', nullable: true },
  },
  required: ['id', 'resource_type', 'pattern', 'exact', 'sensitivity'],
} as const;

const PUT_BODY = {
  type: 'object',
  additionalProperties: false,
  required: ['resource_type', 'pattern', 'sensitivity'],
  properties: {
    resource_type: { type: 'string', minLength: 1, maxLength: 60 },
    pattern: { type: 'string', minLength: 1, maxLength: 512 },
    exact: { type: 'boolean' },
    sensitivity: { type: 'string', enum: [...SENSITIVITY_LEVELS] },
    note: { type: 'string', minLength: 1, maxLength: 200 },
  },
} as const;

interface PutBody {
  resource_type: string;
  pattern: string;
  exact?: boolean;
  sensitivity: string;
  note?: string;
}

export function registerLabelRoutes(app: FastifyInstance, deps: { pool: Pool }): void {
  app.get(
    '/v1/labels',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: { labels: { type: 'array', items: LABEL_SCHEMA } },
            required: ['labels'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId } = request.principal;

      const labels = await withWorkspace(deps.pool, workspaceId, (db) =>
        loadLabels(db, workspaceId),
      );

      return {
        labels: labels.map((l) => ({
          id: l.id,
          resource_type: l.resourceType,
          pattern: l.pattern,
          exact: l.exact,
          sensitivity: l.sensitivity,
          note: l.note,
        })),
      };
    },
  );

  app.put(
    '/v1/labels',
    {
      schema: {
        body: PUT_BODY,
        response: { 200: LABEL_SCHEMA, '4xx': ERROR_SCHEMA, '5xx': ERROR_SCHEMA },
      },
    },
    async (request: FastifyRequest<{ Body: PutBody }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;
      const body = request.body;
      const exact = body.exact ?? false;

      const label = await withWorkspace(deps.pool, workspaceId, async (db) => {
        // Upsert on the pattern, so re-labelling a resource changes its level
        // rather than creating a rival label the matcher would have to choose
        // between.
        const { rows } = await db.query<{ id: string; sensitivity: string; note: string | null }>(
          `insert into resource_labels
             (id, workspace_id, resource_type, pattern, exact, sensitivity, note, created_by)
           values ($1,$2,$3,$4,$5,$6,$7,$8)
           on conflict (workspace_id, resource_type, pattern, exact)
             do update set sensitivity = excluded.sensitivity, note = excluded.note
           returning id, sensitivity, note`,
          [
            newId('lbl_'),
            workspaceId,
            body.resource_type,
            body.pattern,
            exact,
            body.sensitivity,
            body.note ?? null,
            userId,
          ],
        );

        const row = rows[0];
        if (!row) throw new Error('label upsert returned no row');

        await writeAuditEvent(db, {
          workspaceId,
          actor: userId,
          eventType: 'label.set',
          // The pattern and the level are classifications, not content.
          resourceRef: `${body.resource_type}:${body.pattern}`,
          outcome: 'lifecycle',
          correlationId: String(request.id),
        });

        return row;
      });

      return {
        id: label.id,
        resource_type: body.resource_type,
        pattern: body.pattern,
        exact,
        sensitivity: label.sensitivity,
        note: label.note,
      };
    },
  );

  app.delete(
    '/v1/labels/:labelId',
    {
      schema: {
        params: {
          type: 'object',
          additionalProperties: false,
          required: ['labelId'],
          properties: { labelId: { type: 'string', pattern: '^lbl_[A-Za-z0-9_-]{1,64}$' } },
        },
        response: {
          200: {
            type: 'object',
            properties: { label_id: { type: 'string' }, removed: { type: 'boolean' } },
            required: ['label_id', 'removed'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Params: { labelId: string } }>) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;
      const { labelId } = request.params;

      const removed = await withWorkspace(deps.pool, workspaceId, async (db) => {
        const { rows } = await db.query<{ resource_type: string; pattern: string }>(
          `delete from resource_labels where workspace_id = $1 and id = $2
           returning resource_type, pattern`,
          [workspaceId, labelId],
        );

        const row = rows[0];
        if (!row) return false;

        // Taking protection away is audited as loudly as adding it. A label
        // that quietly vanished would be the interesting event nobody saw.
        await writeAuditEvent(db, {
          workspaceId,
          actor: userId,
          eventType: 'label.removed',
          resourceRef: `${row.resource_type}:${row.pattern}`,
          outcome: 'lifecycle',
          correlationId: String(request.id),
        });
        return true;
      });

      if (!removed) {
        throw new HttpError(404, 'RESOURCE_OUT_OF_SCOPE', 'No such label in this workspace');
      }

      return { label_id: labelId, removed: true };
    },
  );
}
