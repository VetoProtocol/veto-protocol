/**
 * Refresh tokens: issue, rotate, and notice a reuse.
 *
 * ## Why they exist at all
 *
 * The access token this server issues *is* the capability token the gateway
 * already accepts, and `MAX_TTL_MS` caps that at fifteen minutes. Raising the
 * ceiling to suit a long-lived client would weaken every token in the system to
 * fix one of them. So the client refreshes, which means something long-lived
 * has to exist, which means it has to be handled properly.
 *
 * ## Stored as a hash, never as itself
 *
 * A refresh token is a standing credential for one workspace. It is stored as
 * SHA-256 and returned exactly once, at issue — the same rule that stops the
 * vault ever handing back a Google refresh token. A database read must not
 * yield a working credential.
 *
 * SHA-256 and not a password hash on purpose: this is a 256-bit random value we
 * generated, not a human-chosen secret, so there is nothing to brute force and
 * the lookup has to be fast enough to sit on the token endpoint.
 *
 * ## Rotation, and what a second use means
 *
 * Each refresh spends the presented token and issues a new one in the same
 * chain. A token presented after it was spent is either a client that raced
 * itself or a copy somebody else is holding, and there is no way to tell them
 * apart from here.
 *
 * So the whole chain is revoked. That costs an honest client one
 * re-authorization; the alternative costs the customer their account. RFC 9700
 * asks for exactly this, and the asymmetry is why.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { newId } from '@veto/core';
import type { Db } from '@veto/db';

/**
 * Thirty days. Long enough that a client set up once keeps working; short
 * enough that an abandoned laptop stops being a way in within a month.
 */
export const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export interface RefreshGrant {
  readonly workspaceId: string;
  readonly userId: string;
  readonly agentId: string;
  readonly clientId: string;
  readonly chainId: string;
}

export interface IssuedRefresh extends RefreshGrant {
  /** Returned once. Never stored, never recoverable, never logged. */
  readonly token: string;
  readonly expiresAt: Date;
}

export type RefreshFailure =
  | 'REFRESH_UNKNOWN'
  | 'REFRESH_EXPIRED'
  | 'REFRESH_REUSED'
  | 'REFRESH_REVOKED'
  | 'CLIENT_MISMATCH';

export type RefreshResult =
  | { readonly ok: true; readonly issued: IssuedRefresh }
  | { readonly ok: false; readonly reason: RefreshFailure };

/**
 * `{workspaceId}.{secret}` — 256 bits of randomness with its tenant in front.
 *
 * The prefix is a routing hint and nothing more. `oauth_refresh_tokens` has
 * FORCEd row-level security, so a lookup by hash returns nothing unless the
 * transaction already names a workspace — and the workspace is not knowable
 * from a bare random string. Putting it in the token is how the row becomes
 * findable at all.
 *
 * It grants nothing. The hash covers the whole token including the prefix, so a
 * token from one workspace re-presented with another's prefix hashes to
 * something that exists nowhere. Editing it turns a working credential into an
 * unknown one, which is the only thing it can do.
 */
const mintToken = (workspaceId: string): string =>
  `${workspaceId}.${randomBytes(32).toString('base64url')}`;

/** The workspace a token claims, or null when it claims nothing usable. */
export function workspaceOf(token: string): string | null {
  const dot = token.indexOf('.');
  if (dot <= 0) return null;
  const workspaceId = token.slice(0, dot);
  return /^ws_[A-Za-z0-9_-]{1,64}$/.test(workspaceId) ? workspaceId : null;
}

export const hashToken = (token: string): string =>
  createHash('sha256').update(token, 'utf8').digest('hex');

/** Constant-time, because the caller supplies one side of it. */
function sameHash(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

interface Row {
  id: string;
  workspace_id: string;
  user_id: string;
  agent_id: string;
  client_id: string;
  token_hash: string;
  chain_id: string;
  status: string;
  expires_at: Date;
}

/** Write one token. Used both for a fresh chain and for each rotation. */
async function insert(db: Db, grant: RefreshGrant): Promise<IssuedRefresh> {
  const token = mintToken(grant.workspaceId);
  const expiresAt = new Date(Date.now() + REFRESH_TTL_MS);

  await db.query(
    `insert into oauth_refresh_tokens
       (id, workspace_id, user_id, agent_id, client_id, token_hash, chain_id, expires_at)
     values ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      newId('oar_'),
      grant.workspaceId,
      grant.userId,
      grant.agentId,
      grant.clientId,
      hashToken(token),
      grant.chainId,
      expiresAt,
    ],
  );

  return { ...grant, token, expiresAt };
}

/** Start a chain. Called once, when a human approves an authorization. */
export const issueRefresh = (
  db: Db,
  grant: Omit<RefreshGrant, 'chainId'>,
): Promise<IssuedRefresh> => insert(db, { ...grant, chainId: newId('oac_') });

/** Kill every token descended from one authorization. */
export async function revokeChain(db: Db, workspaceId: string, chainId: string): Promise<void> {
  await db.query(
    `update oauth_refresh_tokens set status = 'revoked', used_at = coalesce(used_at, now())
      where workspace_id = $1 and chain_id = $2 and status <> 'revoked'`,
    [workspaceId, chainId],
  );
}

/**
 * Spend a refresh token and issue its successor.
 *
 * Runs inside the caller's transaction, and takes the row `for update`, so two
 * concurrent refreshes cannot both see an active token and both rotate it. That
 * race is not theoretical — it is what a client with a retry loop does on a slow
 * network, and without the lock it would produce a fork where both branches
 * work.
 */
export async function rotateRefresh(
  db: Db,
  presented: string,
  clientId: string,
): Promise<RefreshResult> {
  // The caller has already opened a transaction for the workspace this token
  // names, so row-level security scopes the lookup. A token bearing another
  // tenant's prefix simply is not here, which is the isolation rather than a
  // check on top of it.
  const { rows } = await db.query<Row>(
    `select id, workspace_id, user_id, agent_id, client_id, token_hash, chain_id, status,
            expires_at
       from oauth_refresh_tokens
      where token_hash = $1
      for update`,
    [hashToken(presented)],
  );

  const row = rows[0];
  // Unknown hash. Not "expired", not "revoked" — a token this server never
  // issued, and the answer says no more than that.
  if (!row) return { ok: false, reason: 'REFRESH_UNKNOWN' };
  if (!sameHash(row.token_hash, hashToken(presented))) {
    return { ok: false, reason: 'REFRESH_UNKNOWN' };
  }

  // A rotated token presented again is the case this whole mechanism exists for.
  // Either the client raced itself or somebody else has a copy, and nothing
  // here can tell those apart — so the chain dies.
  if (row.status === 'rotated') {
    await revokeChain(db, row.workspace_id, row.chain_id);
    return { ok: false, reason: 'REFRESH_REUSED' };
  }
  if (row.status === 'revoked') return { ok: false, reason: 'REFRESH_REVOKED' };

  // Checked before expiry, so a stolen token used by the wrong client is
  // reported as the mismatch it is rather than aging into a different answer.
  if (row.client_id !== clientId) return { ok: false, reason: 'CLIENT_MISMATCH' };
  if (row.expires_at.getTime() <= Date.now()) return { ok: false, reason: 'REFRESH_EXPIRED' };

  await db.query(
    `update oauth_refresh_tokens set status = 'rotated', used_at = now() where id = $1`,
    [row.id],
  );

  const issued = await insert(db, {
    workspaceId: row.workspace_id,
    userId: row.user_id,
    agentId: row.agent_id,
    clientId: row.client_id,
    chainId: row.chain_id,
  });

  return { ok: true, issued };
}
