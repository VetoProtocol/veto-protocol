/**
 * Picking a connection by what it can do, not by when it arrived.
 *
 * Consent is per service (§9.1): Google is asked for one scope at a time and
 * returns exactly that, and the callback stores what came back. So a person who
 * activates Drive, then Gmail, then Calendar ends up with **three** active
 * Google connections holding one scope each — which is correct, and is the
 * shape every lookup has to cope with.
 *
 * `findActiveConnection` did not. It took the newest connection for the
 * provider, so only the service activated last could mint a token and every
 * earlier one began failing as `CONNECTION_EXPIRED` — "the connected account
 * could not be used" — about a credential nobody had touched. Observed live:
 * Drive worked, Calendar was activated, Drive stopped.
 *
 * These are the cases that distinguish the two.
 */

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { withWorkspace } from '@veto/db';
import {
  CALENDAR_READONLY_SCOPE,
  DRIVE_READONLY_SCOPE,
  GMAIL_READONLY_SCOPE,
  findConnectionForScope,
} from '@veto/connections';
import { seed, suffix, testPool } from './helpers.ts';

let pool: Pool;

const s = suffix();
const WS = `ws_cs${s}`;
const ALICE = `usr_alice${s}`;
const BOB = `usr_bob${s}`;

/** One activation: one row, one scope — the way the callback writes them. */
async function activate(user: string, scope: string, id: string): Promise<void> {
  await withWorkspace(pool, WS, (db) =>
    db.query(
      `insert into connections (id, workspace_id, user_id, provider, scopes, status)
       values ($1,$2,$3,'google',$4,'active')`,
      [id, WS, user, [scope]],
    ),
  );
}

beforeAll(async () => {
  pool = testPool();
  await seed(pool, WS, [ALICE, BOB]);
  const r = randomBytes(4).toString('hex');
  // Oldest to newest, the order a person activates them in.
  await activate(ALICE, DRIVE_READONLY_SCOPE, `con_d${r}`);
  await activate(ALICE, GMAIL_READONLY_SCOPE, `con_g${r}`);
  await activate(ALICE, CALENDAR_READONLY_SCOPE, `con_c${r}`);
});

afterAll(async () => {
  await pool.end();
});

const find = (scope: string, user?: string) =>
  withWorkspace(pool, WS, (db) => findConnectionForScope(db, WS, 'google', scope, user));

describe('findConnectionForScope', () => {
  it('finds Drive even though Calendar was activated most recently', async () => {
    const c = await find(DRIVE_READONLY_SCOPE, ALICE);
    expect(c?.scopes).toEqual([DRIVE_READONLY_SCOPE]);
  });

  it('finds Gmail, which is neither the newest nor the oldest', async () => {
    const c = await find(GMAIL_READONLY_SCOPE, ALICE);
    expect(c?.scopes).toEqual([GMAIL_READONLY_SCOPE]);
  });

  it('finds Calendar', async () => {
    const c = await find(CALENDAR_READONLY_SCOPE, ALICE);
    expect(c?.scopes).toEqual([CALENDAR_READONLY_SCOPE]);
  });

  it('returns nothing for a scope no connection holds', async () => {
    expect(await find('https://www.googleapis.com/auth/contacts.readonly', ALICE)).toBeNull();
  });

  it('never hands one person another person’s connection', async () => {
    expect(await find(DRIVE_READONLY_SCOPE, BOB)).toBeNull();
  });

  it('without a user, answers for the workspace — for a folder walk', async () => {
    const c = await find(DRIVE_READONLY_SCOPE);
    expect(c?.scopes).toEqual([DRIVE_READONLY_SCOPE]);
  });

  it('prefers the freshest grant when a service is activated twice', async () => {
    const again = `con_d2${randomBytes(4).toString('hex')}`;
    await activate(ALICE, DRIVE_READONLY_SCOPE, again);
    const c = await find(DRIVE_READONLY_SCOPE, ALICE);
    expect(c?.id).toBe(again);
  });

  it('ignores a revoked connection even when it is the newest', async () => {
    const dead = `con_x${randomBytes(4).toString('hex')}`;
    await activate(BOB, GMAIL_READONLY_SCOPE, dead);
    await withWorkspace(pool, WS, (db) =>
      db.query(`update connections set status = 'revoked' where id = $1`, [dead]),
    );
    expect(await find(GMAIL_READONLY_SCOPE, BOB)).toBeNull();
  });
});
