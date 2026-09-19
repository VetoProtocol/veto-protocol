/**
 * Stage 3's exit condition (§13): an away-state sensitive action requires the
 * *correct* user to approve it — and correct now means proven.
 *
 * The positive case is the important one. Every refusal below would also pass
 * against a verifier that rejects everything, so a test that a valid assertion
 * actually resolves an approval is what proves the ceremony works.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type Redis from 'ioredis';
import type { FastifyInstance } from 'fastify';
import { withWorkspace } from '@veto/db';
import { createFakePolicyDecisions, createFakePolicyFacts } from '@veto/permit';
import { createLocalKeyWrapper } from '@veto/vault';
import { createVirtualAuthenticator, enrolPasskey } from '@veto/passkeys';
import { createApp } from '../src/app.ts';
import { as, headerAuthenticator, seed, suffix, testPool, testRedis } from './helpers.ts';

let pool: Pool;
let redis: Redis;
let app: FastifyInstance;

const s = suffix();
const WS = `ws_ap${s}`;
const ALICE = `usr_alice${s}`;
const MALLORY = `usr_mal${s}`;
const AGENT = `agt_ap${s}`;

const WEBAUTHN = { rpID: 'localhost', rpName: 'Veto', origins: ['http://localhost:3000'] };
const alicesKey = createVirtualAuthenticator();
const mallorysKey = createVirtualAuthenticator();

let counter = 1;

beforeAll(async () => {
  pool = testPool();
  redis = testRedis();
  await seed(pool, WS, [ALICE, MALLORY]);

  await withWorkspace(pool, WS, async (db) => {
    await db.query(
      `insert into agents (id,workspace_id,provider,client_id,owner_user_id)
       values ($1,$2,'mcp',$3,$4)`,
      [AGENT, WS, `client-${s}`, ALICE],
    );
    await enrolPasskey(db, {
      workspaceId: WS, userId: ALICE,
      credentialId: alicesKey.credentialId, publicKey: alicesKey.publicKey,
      signCount: 0, label: 'Alice laptop',
    });
    await enrolPasskey(db, {
      workspaceId: WS, userId: MALLORY,
      credentialId: mallorysKey.credentialId, publicKey: mallorysKey.publicKey,
      signCount: 0, label: 'Mallory laptop',
    });
  });

  app = createApp({
    pool, redis,
    policy: createFakePolicyFacts(),
    decisions: createFakePolicyDecisions(),
    wrapper: createLocalKeyWrapper(randomBytes(32).toString('base64')),
    webauthn: WEBAUTHN,
    authenticate: headerAuthenticator(),
  });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await pool.end();
  redis.disconnect();
});

/** A pending approval, plus the challenge bytes it is bound to. */
async function openApproval(): Promise<{ id: string; challenge: Buffer }> {
  const decisionId = `dec_${suffix()}${suffix()}`;
  const approvalId = `apr_${suffix()}${suffix()}`;
  const challenge = randomBytes(32);

  await withWorkspace(pool, WS, async (db) => {
    await db.query(
      `insert into decisions (id,workspace_id,request_id,human_id,agent_id,tool,action,
         permit_result,veto_result,reason_code)
       values ($1,$2,$3,$4,$5,'google_drive.read_file','read','allow','challenge','APPROVAL_REQUIRED')`,
      [decisionId, WS, `req_${suffix()}`, ALICE, AGENT],
    );
    await db.query(
      `insert into approvals (id,workspace_id,decision_id,approver_id,action_digest,challenge,expires_at)
       values ($1,$2,$3,$4,$5,$6, now() + interval '5 minutes')`,
      [approvalId, WS, decisionId, ALICE, `sha256:${randomBytes(32).toString('hex')}`, challenge],
    );
  });

  return { id: approvalId, challenge };
}

const sign = (key: typeof alicesKey, challenge: Buffer) =>
  key.assert({
    challenge,
    origin: WEBAUTHN.origins[0] as string,
    rpID: WEBAUTHN.rpID,
    signCount: counter++,
  });

const resolve = (approvalId: string, body: unknown, user = ALICE) =>
  app.inject({
    method: 'POST',
    url: `/v1/approvals/${approvalId}/resolve`,
    headers: as(WS, user),
    payload: body as object,
  });

describe('approving with a passkey', () => {
  it('resolves when the delegator signs the approval’s own challenge', async () => {
    const approval = await openApproval();

    const res = await resolve(approval.id, {
      decision: 'approved',
      assertion: sign(alicesKey, approval.challenge),
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ approval_id: approval.id, status: 'approved' });
  });

  it('marks the user present with high assurance afterwards', async () => {
    const approval = await openApproval();
    await resolve(approval.id, {
      decision: 'approved',
      assertion: sign(alicesKey, approval.challenge),
    });

    const presence = (
      await app.inject({ method: 'GET', url: '/v1/presence', headers: as(WS, ALICE) })
    ).json();

    // A verified assertion is the strongest presence signal there is.
    expect(presence).toMatchObject({ state: 'active', assurance: 'high', source: 'passkey' });
  });
});

describe('what cannot resolve an approval', () => {
  it('no assertion at all', async () => {
    const approval = await openApproval();
    const res = await resolve(approval.id, { decision: 'approved' });
    expect(res.statusCode).toBe(400);
  });

  it('a made-up assertion', async () => {
    const approval = await openApproval();
    const res = await resolve(approval.id, {
      decision: 'approved',
      assertion: { id: 'nonsense', response: {} },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('APPROVER_NOT_DELEGATOR');
  });

  it('a signature over a different approval’s challenge', async () => {
    // §12.1: the grant is bound to one action and one approval. A signature
    // that is valid for something else is not valid here.
    const [a, b] = [await openApproval(), await openApproval()];
    const res = await resolve(a.id, {
      decision: 'approved',
      assertion: sign(alicesKey, b.challenge),
    });
    expect(res.statusCode).toBe(403);
  });

  it('somebody else’s passkey, even a real one from this workspace', async () => {
    // §12.1 approval-link scenario, now with the ceremony in place. Mallory
    // holds a genuinely enrolled credential; it is simply not the delegator's.
    const approval = await openApproval();

    const asMallory = await resolve(
      approval.id,
      { decision: 'approved', assertion: sign(mallorysKey, approval.challenge) },
      MALLORY,
    );
    expect(asMallory.statusCode).toBe(403);

    // And she cannot pass it off as Alice either.
    const impersonating = await resolve(approval.id, {
      decision: 'approved',
      assertion: sign(mallorysKey, approval.challenge),
    });
    expect(impersonating.statusCode).toBe(403);

    // Untouched: a failed attempt must not burn the grant.
    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ status: string }>(`select status from approvals where id=$1`, [approval.id]),
    );
    expect(rows[0]?.status).toBe('pending');
  });

  it('a replayed assertion', async () => {
    const approval = await openApproval();
    const assertion = sign(alicesKey, approval.challenge);

    expect((await resolve(approval.id, { decision: 'approved', assertion })).statusCode).toBe(200);

    // The same signed bytes again. The authenticator counter did not advance,
    // which means a clone or a replay.
    const second = await openApproval();
    const replayed = await resolve(second.id, { decision: 'approved', assertion });
    expect(replayed.statusCode).toBe(403);
  });

  it('a refusal also needs proof', async () => {
    // Otherwise anyone holding the link could deny an approval the real user
    // wanted, which is a denial of service with extra steps.
    const approval = await openApproval();
    expect((await resolve(approval.id, { decision: 'denied' })).statusCode).toBe(400);

    const proper = await resolve(approval.id, {
      decision: 'denied',
      assertion: sign(alicesKey, approval.challenge),
    });
    expect(proper.json()).toEqual({ approval_id: approval.id, status: 'denied' });
  });
});

describe('the challenge endpoint', () => {
  it('gives the approver something to sign', async () => {
    const approval = await openApproval();
    const res = await app.inject({
      method: 'GET',
      url: `/v1/approvals/${approval.id}/challenge`,
      headers: as(WS, ALICE),
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().challenge).toBe(approval.challenge.toString('base64url'));
    expect(res.json().userVerification).toBe('required');
  });

  it('tells nobody else that the approval exists', async () => {
    const approval = await openApproval();
    const mine = await app.inject({
      method: 'GET',
      url: `/v1/approvals/${approval.id}/challenge`,
      headers: as(WS, MALLORY),
    });
    const fictional = await app.inject({
      method: 'GET',
      url: `/v1/approvals/apr_${suffix()}${suffix()}/challenge`,
      headers: as(WS, MALLORY),
    });

    expect(mine.statusCode).toBe(403);
    expect(mine.json()).toEqual(fictional.json());
  });
});
