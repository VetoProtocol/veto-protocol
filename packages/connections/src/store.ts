/**
 * The credential vault (spec §3.2).
 *
 * Stores one thing: a provider refresh token, sealed. Two rules shape every
 * function here.
 *
 * **The refresh token never leaves.** No function in this module returns it,
 * and the public `Connection` type has no field that could carry it. Callers
 * that need upstream access go through the broker, which hands back a
 * short-lived access token instead. §3.2 is explicit that the vault never
 * returns root credentials, and the way to guarantee that is to make it
 * unrepresentable rather than to remember not to.
 *
 * **The encryption context binds the row to its tenant.** Sealing uses
 * `{workspaceId, purpose, connectionId}`, so a row copied into another
 * workspace, or restored from the wrong backup, produces ciphertext that will
 * not open (invariant 4).
 */

import { newId } from '@veto/core';
import type { Db } from '@veto/db';
import { writeAuditEvent } from '@veto/identity';
import { open, seal, type EncryptionContext, type KeyWrapper } from '@veto/vault';

export const REFRESH_TOKEN_PURPOSE = 'connection.refresh_token';

export type ConnectionStatus = 'active' | 'expired' | 'revoked';

/**
 * The public shape of a connection.
 *
 * Deliberately has no token field of any kind. Adding one would be the only way
 * to leak the credential through this module, so the type is the control.
 */
export interface Connection {
  readonly id: string;
  readonly workspaceId: string;
  readonly userId: string;
  readonly provider: string;
  readonly scopes: readonly string[];
  readonly status: ConnectionStatus;
  readonly expiresAt: Date | null;
  readonly createdAt: Date;
}

interface ConnectionRow {
  id: string;
  workspace_id: string;
  user_id: string;
  provider: string;
  scopes: string[];
  status: ConnectionStatus;
  expires_at: Date | null;
  created_at: Date;
}

const toConnection = (row: ConnectionRow): Connection => ({
  id: row.id,
  workspaceId: row.workspace_id,
  userId: row.user_id,
  provider: row.provider,
  scopes: row.scopes,
  status: row.status,
  expiresAt: row.expires_at,
  createdAt: row.created_at,
});

export const contextFor = (workspaceId: string, connectionId: string): EncryptionContext => ({
  workspaceId,
  purpose: REFRESH_TOKEN_PURPOSE,
  resourceId: connectionId,
});

export interface CreateConnectionInput {
  readonly workspaceId: string;
  readonly userId: string;
  readonly provider: string;
  readonly scopes: readonly string[];
  readonly refreshToken: string;
  readonly expiresAt?: Date | null;
  readonly correlationId?: string | null;
}

export async function createConnection(
  db: Db,
  wrapper: KeyWrapper,
  input: CreateConnectionInput,
): Promise<Connection> {
  const id = newId('con_');
  const context = contextFor(input.workspaceId, id);
  const sealed = await seal(wrapper, input.refreshToken, context);

  const { rows } = await db.query<ConnectionRow>(
    `insert into connections
       (id, workspace_id, user_id, provider, scopes,
        encrypted_refresh_token, encryption_key_id, encryption_context, expires_at)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     returning id, workspace_id, user_id, provider, scopes, status, expires_at, created_at`,
    [
      id,
      input.workspaceId,
      input.userId,
      input.provider,
      [...input.scopes],
      sealed.blob,
      sealed.keyId,
      // The context is stored in the clear beside the ciphertext. It is not a
      // secret — it is the label that says what this ciphertext is allowed to
      // be, and key rotation needs to read it.
      JSON.stringify({
        workspace_id: context.workspaceId,
        purpose: context.purpose,
        resource_id: context.resourceId,
      }),
      input.expiresAt ?? null,
    ],
  );

  const row = rows[0];
  if (!row) throw new Error('connection insert returned no row');

  await writeAuditEvent(db, {
    workspaceId: input.workspaceId,
    actor: input.userId,
    eventType: 'connection.created',
    // A reference and the scope names. Never the token (invariant 5).
    resourceRef: `connection:${id}`,
    outcome: 'lifecycle',
    correlationId: input.correlationId ?? null,
  });

  return toConnection(row);
}

export async function findConnection(
  db: Db,
  workspaceId: string,
  connectionId: string,
): Promise<Connection | null> {
  const { rows } = await db.query<ConnectionRow>(
    `select id, workspace_id, user_id, provider, scopes, status, expires_at, created_at
       from connections where workspace_id = $1 and id = $2`,
    [workspaceId, connectionId],
  );
  return rows[0] ? toConnection(rows[0]) : null;
}

export async function listConnections(db: Db, workspaceId: string): Promise<Connection[]> {
  const { rows } = await db.query<ConnectionRow>(
    `select id, workspace_id, user_id, provider, scopes, status, expires_at, created_at
       from connections where workspace_id = $1 order by created_at desc, id`,
    [workspaceId],
  );
  return rows.map(toConnection);
}

/**
 * Read the sealed refresh token.
 *
 * Module-private on purpose: only the broker calls it, and the broker never
 * returns what it gets. Exported because the broker lives in a sibling file,
 * and named so that any other call site reads as obviously wrong in review.
 */
export async function revealRefreshTokenForBroker(
  db: Db,
  wrapper: KeyWrapper,
  workspaceId: string,
  connectionId: string,
): Promise<string | null> {
  const { rows } = await db.query<{
    encrypted_refresh_token: Buffer | null;
    encryption_key_id: string | null;
  }>(
    `select encrypted_refresh_token, encryption_key_id
       from connections where workspace_id = $1 and id = $2`,
    [workspaceId, connectionId],
  );

  const row = rows[0];
  if (!row?.encrypted_refresh_token || !row.encryption_key_id) return null;

  return open(
    wrapper,
    { blob: row.encrypted_refresh_token, keyId: row.encryption_key_id },
    contextFor(workspaceId, connectionId),
  );
}

export interface RevokeConnectionResult {
  readonly revoked: boolean;
  readonly alreadyRevoked: boolean;
}

/**
 * Revoke a connection.
 *
 * The ciphertext is destroyed, not just the status flipped. A revoked
 * connection whose token is still recoverable is a revocation that depends on
 * every future code path remembering to check a column — §9.1 says delete the
 * local tokens, and this deletes them.
 *
 * The provider-side revocation call is the caller's job and happens after this
 * commits, so a failure there leaves the credential already unusable here.
 */
export async function revokeConnection(
  db: Db,
  workspaceId: string,
  connectionId: string,
  actorUserId: string,
): Promise<RevokeConnectionResult> {
  const { rows } = await db.query<{ status: ConnectionStatus }>(
    `select status from connections where workspace_id = $1 and id = $2 for update`,
    [workspaceId, connectionId],
  );

  const existing = rows[0];
  if (!existing) return { revoked: false, alreadyRevoked: false };

  const already = existing.status === 'revoked';

  await db.query(
    `update connections
        set status = 'revoked',
            encrypted_refresh_token = null,
            encryption_key_id = null,
            encryption_context = null
      where workspace_id = $1 and id = $2`,
    [workspaceId, connectionId],
  );

  if (!already) {
    await writeAuditEvent(db, {
      workspaceId,
      actor: actorUserId,
      eventType: 'credential.revoked',
      resourceRef: `connection:${connectionId}`,
      outcome: 'lifecycle',
      correlationId: null,
    });
  }

  return { revoked: !already, alreadyRevoked: already };
}
