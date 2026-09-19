/**
 * Self-service signup (spec §1.3, §4.2).
 *
 * The persona §1.3 lists first is the individual professional, whose first
 * release is a "self-service dashboard and personal policies". Everything here
 * is about the one line that makes that safe:
 *
 *   * creating **your own new** workspace is fine, and is the product;
 *   * joining **somebody else's** workspace must never be automatic.
 *
 * So most of these tests are about the second: a subject that already belongs
 * somewhere cannot self-provision, and there is no field in the request in
 * which to name a tenant to join.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, createFakePolicyFacts } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let app: FastifyInstance;

const s = suffix();
const EXISTING_WS = `ws_ex${s}`;
const EXISTING_USER = `usr_ex${s}`;
/** Whoever seeds a workspace gets `oidc|<userId>` as their subject. */
const EXISTING_SUBJECT = `oidc|${EXISTING_USER}`;

const newcomer = (tag: string): string => `oidc|newcomer${tag}${s}`;

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  await seed(pool, EXISTING_WS, [EXISTING_USER]);

  app = createApp({
    pool,
    redis,
    policy: createFakePolicyFacts(),
    decisions: createFakePolicyDecisions(),
    wrapper: createLocalKeyWrapper(randomBytes(32).toString('base64')),
    authenticate: headerAuthenticator(),
  });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

/** The sign-in scope, which is what the dashboard holds at this point. */
const signIn = (): Record<string, string> => ({
  ...as('pending', 'pending'),
  'x-test-scope': 'identity-resolve',
});

const provision = (body: unknown, headers = signIn()) =>
  app.inject({ method: 'POST', url: '/v1/auth/provision', headers, payload: body as object });

const resolve = (subject: string) =>
  app.inject({
    method: 'POST',
    url: '/v1/auth/resolve',
    headers: signIn(),
    payload: { subject },
  });

describe('a newcomer creating their own workspace', () => {
  it('gets one, and can then be found by sign-in', async () => {
    const subject = newcomer('a');

    const before = (await resolve(subject)).json() as { identities: unknown[] };
    expect(before.identities).toEqual([]);

    const created = await provision({ subject, workspace_name: 'Ada’s workspace' });
    expect(created.statusCode).toBe(201);

    const body = created.json();
    expect(body.workspace_id).toMatch(/^ws_/);
    expect(body.user_id).toMatch(/^usr_/);

    // The point of the whole feature: the next sign-in finds them.
    const after = (await resolve(subject)).json() as {
      identities: Array<{ workspace_id: string; user_id: string }>;
    };
    expect(after.identities).toEqual([{ workspace_id: body.workspace_id, user_id: body.user_id }]);
  });

  it('is a personal workspace, not an organization', async () => {
    const subject = newcomer('b');
    const body = (await provision({ subject, workspace_name: 'Mine' })).json();

    // Inside the workspace, because `workspaces` is RLS-protected too — keyed
    // on `id` rather than `workspace_id` (migration 0005). Reading it with no
    // tenant set returns nothing, which is the isolation working.
    const { rows } = await withWorkspace(pool, body.workspace_id, (db) =>
      db.query<{ type: string; name: string }>(`select type, name from workspaces where id = $1`, [
        body.workspace_id,
      ]),
    );

    // §4.2: a tenant is an organization *or a personal workspace*. The column
    // has allowed both since migration 0001 and nothing created the second kind
    // until now.
    expect(rows[0]?.type).toBe('personal');
    expect(rows[0]?.name).toBe('Mine');
  });

  it('records the membership in the new workspace’s own audit trail', async () => {
    const subject = newcomer('c');
    const body = (await provision({ subject, workspace_name: 'Audited' })).json();

    const { rows } = await withWorkspace(pool, body.workspace_id, (db) =>
      db.query<{ event_type: string; resource_ref: string }>(
        `select event_type, resource_ref from audit_events where workspace_id = $1`,
        [body.workspace_id],
      ),
    );

    expect(rows[0]?.event_type).toBe('user.invited');
    expect(rows[0]?.resource_ref).toBe(`subject:${subject}`);
  });
});

describe('what signup must never become', () => {
  it('refuses a subject that already belongs to a workspace', async () => {
    // The line this feature exists to hold. Without it, "sign up" is a way to
    // collect a second membership, and the sign-in picker starts offering a
    // workspace nobody let you into.
    const response = await provision({
      subject: EXISTING_SUBJECT,
      workspace_name: 'A second one',
    });

    expect(response.statusCode).toBe(409);
  });

  it('leaves the existing membership exactly as it was', async () => {
    await provision({ subject: EXISTING_SUBJECT, workspace_name: 'Nope' });

    const after = (await resolve(EXISTING_SUBJECT)).json() as {
      identities: Array<{ workspace_id: string }>;
    };
    expect(after.identities).toEqual([{ workspace_id: EXISTING_WS, user_id: EXISTING_USER }]);
  });

  it('has no field in which to name a workspace to join', async () => {
    // `additionalProperties: false`. A caller cannot ask for someone else's
    // tenant because the request cannot express one.
    for (const extra of [
      { workspace_id: EXISTING_WS },
      { user_id: EXISTING_USER },
      { workspace_type: 'organization' },
    ]) {
      const response = await provision({
        subject: newcomer('x'),
        workspace_name: 'Sneaky',
        ...extra,
      });
      expect(response.statusCode, JSON.stringify(extra)).toBe(400);
    }
  });

  it('refuses a session credential — this is a sign-in route', async () => {
    const response = await provision(
      { subject: newcomer('d'), workspace_name: 'X' },
      as('pending', 'pending'),
    );
    expect(response.statusCode).toBe(403);
  });

  it('refuses an empty or oversized workspace name', async () => {
    expect((await provision({ subject: newcomer('e'), workspace_name: '' })).statusCode).toBe(400);
    expect(
      (await provision({ subject: newcomer('f'), workspace_name: 'n'.repeat(121) })).statusCode,
    ).toBe(400);
  });
});

describe('two clicks at once', () => {
  it('produces one workspace, not two', async () => {
    // Uniqueness on `users` is (workspace_id, identity_subject), not the
    // subject alone — so two simultaneous signups would each create their own
    // workspace and both inserts would succeed. The advisory lock in
    // provisionPersonalWorkspace is what stops that, and this is the assertion
    // that would fail without it.
    const subject = newcomer('race');

    const [first, second] = await Promise.all([
      provision({ subject, workspace_name: 'First' }),
      provision({ subject, workspace_name: 'Second' }),
    ]);

    const codes = [first.statusCode, second.statusCode].sort();
    expect(codes).toEqual([201, 409]);

    const after = (await resolve(subject)).json() as { identities: unknown[] };
    expect(after.identities).toHaveLength(1);
  });
});
