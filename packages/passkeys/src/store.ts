/**
 * Enrolled passkeys.
 *
 * Public keys only — a passkey's private half never leaves the user's device,
 * which is the property that makes the whole ceremony worth doing. Nothing here
 * is a secret in the sense the credential vault deals with.
 */

import { newId } from '@veto/core';
import type { Db } from '@veto/db';
import { writeAuditEvent } from '@veto/identity';

export interface Passkey {
  readonly id: string;
  readonly userId: string;
  readonly credentialId: Buffer;
  readonly publicKey: Buffer;
  readonly signCount: number;
  readonly transports: readonly string[];
  readonly label: string | null;
  readonly createdAt: Date;
  readonly lastUsedAt: Date | null;
}

interface PasskeyRow {
  id: string;
  user_id: string;
  credential_id: Buffer;
  public_key: Buffer;
  sign_count: string;
  transports: string[];
  label: string | null;
  created_at: Date;
  last_used_at: Date | null;
}

const toPasskey = (row: PasskeyRow): Passkey => ({
  id: row.id,
  userId: row.user_id,
  credentialId: row.credential_id,
  publicKey: row.public_key,
  // bigint arrives as a string from pg; a counter that silently became NaN
  // would make the clone check pass forever.
  signCount: Number(row.sign_count),
  transports: row.transports,
  label: row.label,
  createdAt: row.created_at,
  lastUsedAt: row.last_used_at,
});

export class DuplicateCredentialError extends Error {
  constructor() {
    super('That authenticator is already enrolled');
    this.name = 'DuplicateCredentialError';
  }
}

export async function listPasskeys(db: Db, workspaceId: string, userId: string): Promise<Passkey[]> {
  const { rows } = await db.query<PasskeyRow>(
    `select id, user_id, credential_id, public_key, sign_count, transports, label,
            created_at, last_used_at
       from passkeys where workspace_id = $1 and user_id = $2
      order by created_at asc`,
    [workspaceId, userId],
  );
  return rows.map(toPasskey);
}

/**
 * Find a credential by its WebAuthn id, within a workspace.
 *
 * Tenant-scoped even though `credential_id` is globally unique: a credential
 * enrolled in another workspace must not satisfy a challenge here, and scoping
 * the lookup means that is structural rather than a comparison somebody could
 * forget (invariant 4).
 */
export async function findByCredentialId(
  db: Db,
  workspaceId: string,
  credentialId: Buffer,
): Promise<Passkey | null> {
  const { rows } = await db.query<PasskeyRow>(
    `select id, user_id, credential_id, public_key, sign_count, transports, label,
            created_at, last_used_at
       from passkeys where workspace_id = $1 and credential_id = $2`,
    [workspaceId, credentialId],
  );
  return rows[0] ? toPasskey(rows[0]) : null;
}

export interface EnrolInput {
  readonly workspaceId: string;
  readonly userId: string;
  readonly credentialId: Buffer;
  readonly publicKey: Buffer;
  readonly signCount: number;
  readonly transports?: readonly string[];
  readonly label?: string | null;
}

export async function enrolPasskey(db: Db, input: EnrolInput): Promise<Passkey> {
  const id = newId('pky_');

  let inserted;
  try {
    inserted = await db.query<PasskeyRow>(
      `insert into passkeys
         (id, workspace_id, user_id, credential_id, public_key, sign_count, transports, label)
       values ($1,$2,$3,$4,$5,$6,$7,$8)
       returning id, user_id, credential_id, public_key, sign_count, transports, label,
                 created_at, last_used_at`,
      [
        id, input.workspaceId, input.userId, input.credentialId, input.publicKey,
        input.signCount, [...(input.transports ?? [])], input.label ?? null,
      ],
    );
  } catch (error) {
    if ((error as { constraint?: string }).constraint === 'passkeys_credential_id_key') {
      // The same authenticator already belongs to an account. Creating a second
      // row would mean two identities whose challenges one device can satisfy.
      throw new DuplicateCredentialError();
    }
    throw error;
  }

  // Marks the user as challengeable. Kept in step here so no code path has to
  // remember to set it.
  await db.query(
    `update users set passkey_enrolled = true where workspace_id = $1 and id = $2`,
    [input.workspaceId, input.userId],
  );

  await writeAuditEvent(db, {
    workspaceId: input.workspaceId,
    actor: input.userId,
    eventType: 'passkey.enrolled',
    // A reference. Never the credential id or the public key.
    resourceRef: `passkey:${id}`,
    outcome: 'lifecycle',
    correlationId: null,
  });

  const row = inserted.rows[0];
  if (!row) throw new Error('passkey insert returned no row');
  return toPasskey(row);
}

/**
 * Record a successful use, and refuse a counter that did not move forward.
 *
 * A WebAuthn authenticator increments its counter on every assertion. A value
 * at or below the stored one means either a cloned credential or a replayed
 * response — both are the same refusal. Authenticators that always report zero
 * (many platform passkeys) are exempt, because for them the counter carries no
 * information and demanding it would lock out the common case.
 */
export async function recordUse(
  db: Db,
  workspaceId: string,
  passkeyId: string,
  newSignCount: number,
): Promise<boolean> {
  const { rows } = await db.query<{ id: string }>(
    `update passkeys
        set sign_count = $3, last_used_at = now()
      where workspace_id = $1 and id = $2
        and ($3 = 0 or $3 > sign_count)
      returning id`,
    [workspaceId, passkeyId, newSignCount],
  );
  return rows.length > 0;
}
