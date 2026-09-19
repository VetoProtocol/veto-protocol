/**
 * /v1/passkeys — enrolment (spec §7.1, §15).
 *
 * The registration challenge lives in Redis, keyed by workspace and user, for
 * two minutes, and is deleted the moment it is used. It is never returned in an
 * audit event or a log (invariant 5), and a second registration cannot reuse
 * the first one's challenge.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import { withWorkspace } from '@veto/db';
import {
  CeremonyError,
  DuplicateCredentialError,
  buildRegistrationOptions,
  enrolPasskey,
  listPasskeys,
  verifyRegistration,
  type WebAuthnConfig,
} from '@veto/passkeys';
import { ERROR_SCHEMA, HttpError } from '../errors.ts';
import { requireScope, SCOPE_CONTROL_PLANE } from '../scope.ts';

export interface PasskeyRoutesDeps {
  readonly pool: Pool;
  readonly redis: Redis;
  readonly webauthn: WebAuthnConfig | null;
}

const REG_TTL_SECONDS = 120;
const regKey = (workspaceId: string, userId: string): string =>
  `veto:${workspaceId}:pky-reg:${userId}`;

interface EnrolBody {
  response: Record<string, unknown>;
  label?: string;
}

export function registerPasskeyRoutes(app: FastifyInstance, deps: PasskeyRoutesDeps): void {
  const config = (): WebAuthnConfig => {
    if (!deps.webauthn) {
      throw new HttpError(503, 'IDENTITY_UNRESOLVED', 'Passkeys are not configured on this server');
    }
    return deps.webauthn;
  };

  app.get(
    '/v1/passkeys',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: {
              passkeys: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    label: { type: 'string', nullable: true },
                    created_at: { type: 'string' },
                    last_used_at: { type: 'string', nullable: true },
                  },
                  required: ['id', 'created_at'],
                },
              },
            },
            required: ['passkeys'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      const keys = await withWorkspace(deps.pool, workspaceId, (db) =>
        listPasskeys(db, workspaceId, userId),
      );

      // The credential id and public key are not returned. They are not secret,
      // but nothing needs them and a smaller response is a smaller mistake.
      return {
        passkeys: keys.map((k) => ({
          id: k.id,
          label: k.label,
          created_at: k.createdAt.toISOString(),
          last_used_at: k.lastUsedAt === null ? null : k.lastUsedAt.toISOString(),
        })),
      };
    },
  );

  app.post('/v1/passkeys/options', async (request) => {
    requireScope(request, SCOPE_CONTROL_PLANE);
    const { workspaceId, userId } = request.principal;

    const existing = await withWorkspace(deps.pool, workspaceId, (db) =>
      listPasskeys(db, workspaceId, userId),
    );

    const options = await buildRegistrationOptions(config(), { id: userId, name: userId }, existing);

    // Short-lived and server-side. The browser gets the challenge to sign; the
    // copy that decides whether a response is valid stays here.
    await deps.redis.set(regKey(workspaceId, userId), options.challenge, 'EX', REG_TTL_SECONDS);

    return options;
  });

  app.post(
    '/v1/passkeys',
    {
      schema: {
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['response'],
          properties: {
            response: { type: 'object' },
            label: { type: 'string', minLength: 1, maxLength: 80 },
          },
        },
        response: {
          201: {
            type: 'object',
            properties: { id: { type: 'string' }, label: { type: 'string', nullable: true } },
            required: ['id'],
          },
          '4xx': ERROR_SCHEMA,
          '5xx': ERROR_SCHEMA,
        },
      },
    },
    async (request: FastifyRequest<{ Body: EnrolBody }>, reply) => {
      requireScope(request, SCOPE_CONTROL_PLANE);
      const { workspaceId, userId } = request.principal;

      const key = regKey(workspaceId, userId);
      // Read and delete together: a challenge survives exactly one attempt,
      // successful or not, so a failed ceremony cannot be ground against.
      const challenge = await deps.redis.getdel(key);
      if (challenge === null) {
        throw new HttpError(400, 'APPROVAL_EXPIRED', 'That registration attempt has expired');
      }

      let credential;
      try {
        credential = await verifyRegistration(
          config(),
          request.body.response as never,
          challenge,
        );
      } catch (error) {
        if (error instanceof CeremonyError) {
          throw new HttpError(400, 'ARGUMENT_SCHEMA_INVALID', 'That passkey could not be verified');
        }
        throw error;
      }

      try {
        const passkey = await withWorkspace(deps.pool, workspaceId, (db) =>
          enrolPasskey(db, {
            workspaceId,
            userId,
            credentialId: credential.credentialId,
            publicKey: credential.publicKey,
            signCount: credential.signCount,
            transports: credential.transports,
            label: request.body.label ?? null,
          }),
        );

        return reply.code(201).send({ id: passkey.id, label: passkey.label });
      } catch (error) {
        if (error instanceof DuplicateCredentialError) {
          throw new HttpError(409, 'APPROVAL_REPLAYED', 'That authenticator is already enrolled');
        }
        throw error;
      }
    },
  );
}
