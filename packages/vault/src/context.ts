/**
 * The encryption context — what a ciphertext is allowed to be.
 *
 * Spec §3.4 requires a **separate encryption context per tenant**, and this is
 * where that stops being a slogan. The context is bound into the AEAD as
 * additional authenticated data, so decryption with a different context fails
 * rather than returning the wrong tenant's plaintext.
 *
 * That turns invariant 4 into arithmetic. Copying a row from one workspace to
 * another, restoring a backup into the wrong tenant, or a query that forgot its
 * `workspace_id` all produce ciphertext that will not open. No amount of
 * application-layer carelessness recovers a secret across the boundary.
 *
 * `purpose` is bound too. A refresh token sealed for Google must not be
 * openable by a code path that believes it is handling something else, even
 * inside the right tenant.
 */

export interface EncryptionContext {
  readonly workspaceId: string;
  /** What this secret is for, e.g. 'connection.google.refresh_token'. */
  readonly purpose: string;
  /** The row this belongs to, so one row's ciphertext cannot be swapped into another. */
  readonly resourceId: string;
}

export class EncryptionContextError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EncryptionContextError';
  }
}

/**
 * Canonical bytes for the context.
 *
 * Sorted keys and length-prefixed values. Length prefixes matter more than they
 * look: with plain concatenation, `{workspaceId: 'ws_ab', purpose: 'c'}` and
 * `{workspaceId: 'ws_a', purpose: 'bc'}` would serialise identically, and two
 * different contexts sharing an encoding is exactly the confusion the context
 * exists to prevent.
 */
export function canonicalContext(context: EncryptionContext): Buffer {
  const entries: Array<[string, string]> = [
    ['purpose', context.purpose],
    ['resourceId', context.resourceId],
    ['workspaceId', context.workspaceId],
  ];

  for (const [key, value] of entries) {
    if (typeof value !== 'string' || value === '') {
      throw new EncryptionContextError(`${key} must be a non-empty string`);
    }
    if (value.length > 512) {
      throw new EncryptionContextError(`${key} is too long`);
    }
  }

  const parts: Buffer[] = [];
  for (const [key, value] of entries) {
    const k = Buffer.from(key, 'utf8');
    const v = Buffer.from(value, 'utf8');
    const header = Buffer.alloc(4);
    header.writeUInt16BE(k.length, 0);
    header.writeUInt16BE(v.length, 2);
    parts.push(header, k, v);
  }
  return Buffer.concat(parts);
}

/** The JSON form stored beside the ciphertext, for audit and key rotation. */
export const contextToJson = (context: EncryptionContext): Record<string, string> => ({
  workspace_id: context.workspaceId,
  purpose: context.purpose,
  resource_id: context.resourceId,
});
