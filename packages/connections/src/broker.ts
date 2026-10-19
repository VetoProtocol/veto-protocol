/**
 * The credential broker (spec §3.2, §3.3 step 8).
 *
 * The only thing allowed to touch a stored refresh token, and the only thing
 * that hands anything to an upstream call. What it returns is a short-lived
 * access token scoped no wider than the action needs — never the refresh token,
 * and never the vault row.
 *
 * ## The checks here are Veto's, not Permit's
 *
 * Connection status and credential expiry are checked here, every time
 * (invariant 3). Permit answers whether a relationship permits an action; it
 * has no idea whether the credential behind that action still works, and asking
 * it would be asking the wrong service a question it cannot answer.
 *
 * ## Narrowest scope
 *
 * A caller states the scopes the action needs. If the connection does not hold
 * them, the request fails rather than falling back to everything the connection
 * has — §9.1 asks for incremental, narrowest-first scopes, and silently
 * upgrading would undo that at the moment it matters.
 */

import type { Db } from '@veto/db';
import type { KeyWrapper } from '@veto/vault';
import { findConnection, revealRefreshTokenForBroker, rotateRefreshToken } from './store.ts';

export interface AccessGrant {
  readonly accessToken: string;
  readonly expiresAt: Date;
  readonly scopes: readonly string[];
  /**
   * A replacement credential, when the provider rotates on every refresh.
   *
   * Optional because most do not: Google's refresh token is stable, and
   * GitHub's durable value is an installation id. Slack with token rotation
   * invalidates the old one as it issues the new, so dropping this does not
   * fail now — it fails on the *next* refresh, hours later, as a connection
   * that expired while nobody was using it.
   *
   * The broker persists it. A provider adapter returns it and never writes.
   */
  readonly rotatedRefreshToken?: string;
}

/**
 * The provider boundary.
 *
 * A port so the broker is testable without the network, and so a second
 * provider does not mean a second broker.
 */
export interface UpstreamTokenExchange {
  /** Trade a refresh token for a short-lived access token. */
  refresh(refreshToken: string, scopes: readonly string[]): Promise<AccessGrant>;
  /** Tell the provider to invalidate the credential (§9.1). */
  revoke(refreshToken: string): Promise<void>;
}

export type BrokerFailure =
  | 'CONNECTION_UNKNOWN'
  | 'CREDENTIAL_REVOKED'
  | 'CONNECTION_EXPIRED'
  | 'SCOPE_NOT_GRANTED'
  | 'EXCHANGE_FAILED';

export class BrokerError extends Error {
  readonly reason: BrokerFailure;

  constructor(reason: BrokerFailure) {
    super(`Credential unavailable: ${reason}`);
    this.name = 'BrokerError';
    this.reason = reason;
  }
}

export interface MintInput {
  readonly workspaceId: string;
  readonly connectionId: string;
  /** Exactly what this one action needs. */
  readonly requiredScopes: readonly string[];
}

export async function mintUpstreamToken(
  db: Db,
  wrapper: KeyWrapper,
  exchange: UpstreamTokenExchange,
  input: MintInput,
): Promise<AccessGrant> {
  const connection = await findConnection(db, input.workspaceId, input.connectionId);

  // Tenant-scoped lookup: a connection id from another workspace is simply not
  // found, and is refused with the same answer as one that never existed.
  if (!connection) throw new BrokerError('CONNECTION_UNKNOWN');
  if (connection.status === 'revoked') throw new BrokerError('CREDENTIAL_REVOKED');
  if (connection.status === 'expired') throw new BrokerError('CONNECTION_EXPIRED');

  if (connection.expiresAt !== null && connection.expiresAt.getTime() <= Date.now()) {
    throw new BrokerError('CONNECTION_EXPIRED');
  }

  const missing = input.requiredScopes.filter((scope) => !connection.scopes.includes(scope));
  if (missing.length > 0) throw new BrokerError('SCOPE_NOT_GRANTED');

  // Serialise refreshes of one connection.
  //
  // Only matters for a provider that rotates: two refreshes in flight together
  // both spend the stored token, the provider honours one, and whichever
  // write lands last may store the loser's — leaving a dead credential on a
  // connection nobody touched. The lock is per connection and held across the
  // provider call, which is a real cost and a smaller one than that failure.
  //
  // It is also why this is outside the §11 budget: step 8 happens after the
  // decision, so a wait here delays an upstream call rather than an answer.
  await db.query(`select 1 from connections where workspace_id = $1 and id = $2 for update`, [
    input.workspaceId,
    input.connectionId,
  ]);

  const refreshToken = await revealRefreshTokenForBroker(
    db,
    wrapper,
    input.workspaceId,
    input.connectionId,
  );
  if (refreshToken === null) throw new BrokerError('CREDENTIAL_REVOKED');

  let grant: AccessGrant;
  try {
    // Ask for what the action needs, not for what the connection holds.
    grant = await exchange.refresh(refreshToken, input.requiredScopes);
  } catch {
    // The provider's error text is not propagated: it is written for a
    // developer reading a console, and it can contain the request that carried
    // the credential.
    throw new BrokerError('EXCHANGE_FAILED');
  }

  // Persisted before the token is handed out, so a caller can never act on a
  // grant whose replacement credential was lost.
  if (grant.rotatedRefreshToken !== undefined && grant.rotatedRefreshToken !== refreshToken) {
    await rotateRefreshToken(db, wrapper, {
      workspaceId: input.workspaceId,
      connectionId: input.connectionId,
      refreshToken: grant.rotatedRefreshToken,
    });
  }

  return grant;
}

/**
 * Revoke at the provider, using the stored credential one last time.
 *
 * Called *after* the local row has been destroyed, so a provider outage leaves
 * the credential already unusable here rather than still live in both places.
 * It therefore takes the token directly — by then there is nothing left to read.
 */
export async function revokeUpstream(
  exchange: UpstreamTokenExchange,
  refreshToken: string,
): Promise<boolean> {
  try {
    await exchange.revoke(refreshToken);
    return true;
  } catch {
    // Reported, never thrown. The local credential is already gone; failing the
    // caller here would suggest the revocation did not happen locally, which is
    // the more dangerous misreading.
    return false;
  }
}
