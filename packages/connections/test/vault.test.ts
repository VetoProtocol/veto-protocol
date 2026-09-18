/**
 * The vault and broker against a real database.
 *
 * The exit condition for phase 4: a connection is established, stored
 * encrypted, and revocable — and the credential never appears in a log, an
 * audit event, or anything returned to a caller.
 */

import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { createPool, withWorkspace } from '@veto/db';
import { createLocalKeyWrapper, VaultError } from '@veto/vault';
import {
  BrokerError,
  createConnection,
  findConnection,
  listConnections,
  mintUpstreamToken,
  revealRefreshTokenForBroker,
  revokeConnection,
  revokeUpstream,
  type AccessGrant,
  type UpstreamTokenExchange,
} from '../src/index.ts';

const here = path.dirname(fileURLToPath(import.meta.url));
const wrapper = createLocalKeyWrapper(randomBytes(32).toString('base64'));

const REFRESH = '1//0gSuperSecretRefreshTokenValue';
const SCOPES = ['https://www.googleapis.com/auth/drive.readonly'];

let pool: Pool;
const s = Math.random().toString(36).slice(2, 10);
const WS = `ws_c${s}`;
const OTHER_WS = `ws_o${s}`;
// users.id is a global primary key, so each workspace needs its own.
const USERS: Record<string, string> = { [WS]: `usr_c${s}`, [OTHER_WS]: `usr_o${s}` };
const USER = USERS[WS] as string;

/** Records what it was handed, so a test can assert the broker's inputs. */
function fakeExchange(): UpstreamTokenExchange & { seen: string[]; fail: boolean } {
  const state = {
    seen: [] as string[],
    fail: false,
    async refresh(refreshToken: string, scopes: readonly string[]): Promise<AccessGrant> {
      state.seen.push(refreshToken);
      if (state.fail) throw new Error('upstream said no');
      return {
        accessToken: `ya29.fake-${Math.random().toString(36).slice(2)}`,
        expiresAt: new Date(Date.now() + 300_000),
        scopes: [...scopes],
      };
    },
    async revoke(refreshToken: string): Promise<void> {
      state.seen.push(refreshToken);
      if (state.fail) throw new Error('upstream said no');
    },
  };
  return state;
}

beforeAll(async () => {
  const runner = process.env['NODE_ENV'];
  try {
    process.loadEnvFile(path.join(here, '..', '..', '..', '.env'));
  } catch {
    /* present */
  }
  if (runner !== undefined) process.env['NODE_ENV'] = runner;
  pool = createPool(process.env['DATABASE_URL'] ?? '');

  for (const ws of [WS, OTHER_WS]) {
    const c = await pool.connect();
    try {
      await c.query('begin');
      await c.query('select set_config($1,$2,true)', ['veto.workspace_id', ws]);
      await c.query(`insert into workspaces (id,name,type) values ($1,$1,'organization')`, [ws]);
      await c.query(`insert into users (id,workspace_id,identity_subject) values ($1,$2,$3)`, [
        USERS[ws], ws, `oidc|${USERS[ws]}`,
      ]);
      await c.query('commit');
    } finally {
      c.release();
    }
  }
});

afterAll(async () => {
  await pool.end();
});

const connect = (ws = WS, scopes = SCOPES) =>
  withWorkspace(pool, ws, (db) =>
    createConnection(db, wrapper, {
      workspaceId: ws, userId: USERS[ws] as string, provider: 'google', scopes, refreshToken: REFRESH,
    }),
  );

describe('storing a credential', () => {
  it('returns a connection with no token field of any kind', async () => {
    const connection = await connect();

    expect(connection.provider).toBe('google');
    expect(connection.status).toBe('active');
    // The type has no token field; this asserts the runtime shape agrees.
    expect(JSON.stringify(connection)).not.toContain(REFRESH);
    expect(Object.keys(connection).some((k) => /token|secret|credential/i.test(k))).toBe(false);
  });

  it('stores ciphertext, never the token', async () => {
    const connection = await connect();

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ encrypted_refresh_token: Buffer; encryption_key_id: string }>(
        `select encrypted_refresh_token, encryption_key_id from connections where id=$1`,
        [connection.id],
      ),
    );

    expect(rows[0]?.encrypted_refresh_token.includes(Buffer.from(REFRESH, 'utf8'))).toBe(false);
    expect(rows[0]?.encryption_key_id).toBe('local-v1');
  });

  it('keeps the token out of the audit trail', async () => {
    const connection = await connect();

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ resource_ref: string; event_type: string }>(
        `select resource_ref, event_type from audit_events
          where workspace_id=$1 and resource_ref=$2`,
        [WS, `connection:${connection.id}`],
      ),
    );

    expect(rows[0]?.event_type).toBe('connection.created');
    // Invariant 5: a reference, never the credential.
    expect(JSON.stringify(rows)).not.toContain(REFRESH);
  });

  it('will not open one workspace ciphertext in another workspace context', async () => {
    // The row copied into the wrong tenant. RLS would normally stop the read;
    // this proves the crypto stops it too (invariant 4, defence in depth).
    const connection = await connect();

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ encrypted_refresh_token: Buffer; encryption_key_id: string }>(
        `select encrypted_refresh_token, encryption_key_id from connections where id=$1`,
        [connection.id],
      ),
    );

    const stolen = await withWorkspace(pool, OTHER_WS, async (db) => {
      await db.query(
        `insert into connections (id,workspace_id,user_id,provider,scopes,
           encrypted_refresh_token,encryption_key_id,encryption_context)
         values ($1,$2,$3,'google',$4,$5,$6,$7)`,
        [
          connection.id.replace('con_', 'con_x'),
          OTHER_WS, USERS[OTHER_WS], SCOPES,
          rows[0]?.encrypted_refresh_token, rows[0]?.encryption_key_id,
          JSON.stringify({ workspace_id: OTHER_WS, purpose: 'connection.refresh_token', resource_id: 'x' }),
        ],
      );
      return revealRefreshTokenForBroker(db, wrapper, OTHER_WS, connection.id.replace('con_', 'con_x'));
    }).catch((error: unknown) => error);

    expect(stolen).toBeInstanceOf(VaultError);
  });
});

describe('the broker', () => {
  it('returns a short-lived access token and never the refresh token', async () => {
    const connection = await connect();
    const exchange = fakeExchange();

    const grant = await withWorkspace(pool, WS, (db) =>
      mintUpstreamToken(db, wrapper, exchange, {
        workspaceId: WS, connectionId: connection.id, requiredScopes: SCOPES,
      }),
    );

    expect(grant.accessToken).toMatch(/^ya29\./);
    expect(grant.accessToken).not.toBe(REFRESH);
    expect(grant.expiresAt.getTime()).toBeGreaterThan(Date.now());
    // The broker saw the refresh token; the caller did not.
    expect(exchange.seen).toEqual([REFRESH]);
    expect(JSON.stringify(grant)).not.toContain(REFRESH);
  });

  it('refuses a scope the connection does not hold', async () => {
    const connection = await connect();

    await expect(
      withWorkspace(pool, WS, (db) =>
        mintUpstreamToken(db, wrapper, fakeExchange(), {
          workspaceId: WS,
          connectionId: connection.id,
          requiredScopes: ['https://www.googleapis.com/auth/gmail.readonly'],
        }),
      ),
    ).rejects.toMatchObject({ reason: 'SCOPE_NOT_GRANTED' });
  });

  it('refuses a connection id from another workspace', async () => {
    const connection = await connect(OTHER_WS);

    await expect(
      withWorkspace(pool, WS, (db) =>
        mintUpstreamToken(db, wrapper, fakeExchange(), {
          workspaceId: WS, connectionId: connection.id, requiredScopes: SCOPES,
        }),
      ),
    ).rejects.toMatchObject({ reason: 'CONNECTION_UNKNOWN' });
  });

  it('refuses an expired connection — credential expiry is Veto’s check', async () => {
    const connection = await withWorkspace(pool, WS, (db) =>
      createConnection(db, wrapper, {
        workspaceId: WS, userId: USER, provider: 'google', scopes: SCOPES,
        refreshToken: REFRESH, expiresAt: new Date(Date.now() - 1000),
      }),
    );

    await expect(
      withWorkspace(pool, WS, (db) =>
        mintUpstreamToken(db, wrapper, fakeExchange(), {
          workspaceId: WS, connectionId: connection.id, requiredScopes: SCOPES,
        }),
      ),
    ).rejects.toMatchObject({ reason: 'CONNECTION_EXPIRED' });
  });

  it('does not propagate the provider error text', async () => {
    const connection = await connect();
    const exchange = fakeExchange();
    exchange.fail = true;

    const error = await withWorkspace(pool, WS, (db) =>
      mintUpstreamToken(db, wrapper, exchange, {
        workspaceId: WS, connectionId: connection.id, requiredScopes: SCOPES,
      }),
    ).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(BrokerError);
    // Provider errors are written for a console and can echo the request that
    // carried the credential.
    expect(String(error)).not.toContain('upstream said no');
  });
});

describe('revocation', () => {
  it('destroys the ciphertext, not just the status', async () => {
    const connection = await connect();

    const result = await withWorkspace(pool, WS, (db) =>
      revokeConnection(db, WS, connection.id, USER),
    );
    expect(result).toEqual({ revoked: true, alreadyRevoked: false });

    const { rows } = await withWorkspace(pool, WS, (db) =>
      db.query<{ status: string; encrypted_refresh_token: Buffer | null }>(
        `select status, encrypted_refresh_token from connections where id=$1`,
        [connection.id],
      ),
    );

    expect(rows[0]?.status).toBe('revoked');
    // §9.1: delete the local tokens. A revoked row whose token is still
    // recoverable is a revocation that depends on every future reader checking
    // a column.
    expect(rows[0]?.encrypted_refresh_token).toBeNull();
  });

  it('leaves the broker with nothing to mint', async () => {
    const connection = await connect();
    await withWorkspace(pool, WS, (db) => revokeConnection(db, WS, connection.id, USER));

    await expect(
      withWorkspace(pool, WS, (db) =>
        mintUpstreamToken(db, wrapper, fakeExchange(), {
          workspaceId: WS, connectionId: connection.id, requiredScopes: SCOPES,
        }),
      ),
    ).rejects.toMatchObject({ reason: 'CREDENTIAL_REVOKED' });
  });

  it('is idempotent', async () => {
    const connection = await connect();
    await withWorkspace(pool, WS, (db) => revokeConnection(db, WS, connection.id, USER));
    const second = await withWorkspace(pool, WS, (db) =>
      revokeConnection(db, WS, connection.id, USER),
    );
    expect(second).toEqual({ revoked: false, alreadyRevoked: true });
  });

  it('reports a failed provider revocation without throwing', async () => {
    // The local credential is already gone by this point. Throwing would
    // suggest the local revocation did not happen, which is the more dangerous
    // misreading.
    const exchange = fakeExchange();
    exchange.fail = true;
    expect(await revokeUpstream(exchange, REFRESH)).toBe(false);
  });

  it('keeps revoked connections listed, so the history survives', async () => {
    const all = await withWorkspace(pool, WS, (db) => listConnections(db, WS));
    expect(all.some((c) => c.status === 'revoked')).toBe(true);
  });

  it('returns nothing for an unknown connection rather than throwing', async () => {
    expect(await withWorkspace(pool, WS, (db) => findConnection(db, WS, 'con_nope'))).toBeNull();
  });
});
