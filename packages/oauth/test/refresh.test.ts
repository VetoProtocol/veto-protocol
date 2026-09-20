/**
 * Refresh tokens: rotation, and what a second use means.
 *
 * The property this file exists for is the one in RFC 9700: a refresh token
 * presented after it was spent revokes everything descended from the same
 * authorization. An honest client that raced itself pays one re-authorization.
 * A client that was copied pays the same, which is the point — nothing here can
 * tell the two apart, and only one of the two possible mistakes is survivable.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import {
  hashToken,
  issueRefresh,
  registerClient,
  revokeChain,
  rotateRefresh,
  type IssuedRefresh,
} from '../src/index.ts';
import { suffix, testPool } from './helpers.ts';

let pool: Pool;
const s = suffix();
const WS = `ws_oa${s}`;
const USER = `usr_oa${s}`;
const AGENT = `agt_oa${s}`;
let clientId = '';
let otherClientId = '';

const grant = () => ({ workspaceId: WS, userId: USER, agentId: AGENT, clientId });

const issue = (): Promise<IssuedRefresh> =>
  withWorkspace(pool, WS, (db) => issueRefresh(db, grant()));

beforeAll(async () => {
  pool = testPool();
  await withWorkspace(pool, WS, async (db) => {
    await db.query(
      `insert into workspaces (id, name, type) values ($1, $1, 'personal') on conflict do nothing`,
      [WS],
    );
    const client = await registerClient(db, {
      clientName: 'Test client',
      redirectUris: ['http://127.0.0.1:7777/cb'],
    });
    clientId = client.id;
    const other = await registerClient(db, {
      clientName: 'Another client',
      redirectUris: ['http://127.0.0.1:7778/cb'],
    });
    otherClientId = other.id;
  });
});

afterAll(async () => {
  await pool.end();
});

describe('issuing', () => {
  it('returns a token and stores only its hash', async () => {
    const issued = await issue();
    expect(issued.token.length).toBeGreaterThan(20);

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ token_hash: string }>(
        `select token_hash from oauth_refresh_tokens where chain_id = $1`,
        [issued.chainId],
      ),
    );
    // A database read must not yield a working credential.
    expect(rows[0]?.token_hash).toBe(hashToken(issued.token));
    expect(rows.some((r) => r.token_hash === issued.token)).toBe(false);
  });

  it('gives every authorization its own chain', async () => {
    const [first, second] = [await issue(), await issue()];
    expect(first.chainId).not.toBe(second.chainId);
  });
});

describe('rotating', () => {
  it('exchanges a live token for its successor', async () => {
    const first = await issue();
    const result = await withWorkspace(pool, WS, (db) =>
      rotateRefresh(db, first.token, clientId),
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.issued.token).not.toBe(first.token);
    // Same authorization, so same chain.
    expect(result.issued.chainId).toBe(first.chainId);
    expect(result.issued.agentId).toBe(AGENT);
  });

  it('refuses the old token once rotated, and kills the chain', async () => {
    const first = await issue();
    const second = await withWorkspace(pool, WS, (db) =>
      rotateRefresh(db, first.token, clientId),
    );
    expect(second.ok).toBe(true);

    const replay = await withWorkspace(pool, WS, (db) =>
      rotateRefresh(db, first.token, clientId),
    );
    expect(replay.ok).toBe(false);
    if (replay.ok) return;
    expect(replay.reason).toBe('REFRESH_REUSED');

    // The successor dies with it. A copy of the chain is worth nothing after
    // the original owner refreshes once more.
    if (!second.ok) return;
    const after = await withWorkspace(pool, WS, (db) =>
      rotateRefresh(db, second.issued.token, clientId),
    );
    expect(after.ok).toBe(false);
    if (after.ok) return;
    expect(after.reason).toBe('REFRESH_REVOKED');
  });

  it('refuses a token this server never issued', async () => {
    const result = await withWorkspace(pool, WS, (db) =>
      rotateRefresh(db, 'not-a-token-we-minted', clientId),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    // Says no more than "unknown" — not "expired", which would confirm it once
    // existed.
    expect(result.reason).toBe('REFRESH_UNKNOWN');
  });

  it('refuses a token presented by a different client', async () => {
    const first = await issue();
    const result = await withWorkspace(pool, WS, (db) =>
      rotateRefresh(db, first.token, otherClientId),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('CLIENT_MISMATCH');
  });

  it('refuses an expired token', async () => {
    const first = await issue();
    await withWorkspace(pool, WS, (db) =>
      db.query(
        `update oauth_refresh_tokens set expires_at = now() - interval '1 second'
          where token_hash = $1`,
        [hashToken(first.token)],
      ),
    );

    const result = await withWorkspace(pool, WS, (db) =>
      rotateRefresh(db, first.token, clientId),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('REFRESH_EXPIRED');
  });
});

describe('revoking a chain', () => {
  it('kills the live token', async () => {
    const first = await issue();
    await withWorkspace(pool, WS, (db) => revokeChain(db, WS, first.chainId));

    const result = await withWorkspace(pool, WS, (db) =>
      rotateRefresh(db, first.token, clientId),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('REFRESH_REVOKED');
  });

  it('leaves other chains alone', async () => {
    const doomed = await issue();
    const spared = await issue();
    await withWorkspace(pool, WS, (db) => revokeChain(db, WS, doomed.chainId));

    const result = await withWorkspace(pool, WS, (db) =>
      rotateRefresh(db, spared.token, clientId),
    );
    expect(result.ok).toBe(true);
  });
});

describe('one live token per chain', () => {
  it('is enforced by the database, not by hope', async () => {
    const first = await issue();
    // Forging a second active row in the same chain would mean both branches
    // work, which is what single-use is supposed to prevent.
    await expect(
      withWorkspace(pool, WS, (db) =>
        db.query(
          `insert into oauth_refresh_tokens
             (id, workspace_id, user_id, agent_id, client_id, token_hash, chain_id, expires_at)
           values ($1,$2,$3,$4,$5,$6,$7, now() + interval '1 day')`,
          [
            `oar_forged${s}`,
            WS,
            USER,
            AGENT,
            clientId,
            'f'.repeat(64),
            first.chainId,
          ],
        ),
      ),
    ).rejects.toThrow();
  });
});
