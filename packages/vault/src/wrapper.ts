/**
 * The key-wrapping boundary — where a KMS goes.
 *
 * Envelope encryption has two halves: a fresh data key encrypts the secret, and
 * something long-lived encrypts the data key. The second half is what a KMS is
 * for, and it is a port here so that swapping the local implementation for
 * Cloud KMS changes one construction site and nothing else.
 *
 * The local wrapper is for development and self-hosting. It is honest about
 * what it is: the master key sits in the process environment, so anything that
 * can read the environment can unwrap every data key. A KMS moves that boundary
 * to hardware — the difference matters, and pretending otherwise would be the
 * kind of quiet downgrade this codebase is built to avoid (T6).
 */

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';
import { canonicalContext, type EncryptionContext } from './context.ts';

export interface WrappedKey {
  /** Which wrapping key produced this, so rotation can find what to re-wrap. */
  readonly keyId: string;
  readonly bytes: Buffer;
}

export interface KeyWrapper {
  readonly keyId: string;
  wrap(dataKey: Buffer, context: EncryptionContext): Promise<WrappedKey>;
  unwrap(wrapped: WrappedKey, context: EncryptionContext): Promise<Buffer>;
}

export class VaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultError';
  }
}

const IV_BYTES = 12;
const TAG_BYTES = 16;

export function createLocalKeyWrapper(masterKeyBase64: string, keyId = 'local-v1'): KeyWrapper {
  const master = Buffer.from(masterKeyBase64, 'base64');
  // 32 bytes. A shorter master key silently weakens everything derived from it,
  // and there is no signal at use time that it happened.
  if (master.length < 32) {
    throw new VaultError('Master key must be at least 32 bytes (base64-encoded)');
  }

  /**
   * A distinct wrapping key per context.
   *
   * Derived rather than shared, so even a flaw in one context's wrapping does
   * not hand over another tenant's data keys.
   */
  const kekFor = (context: EncryptionContext): Buffer =>
    Buffer.from(hkdfSync('sha256', master, Buffer.from(keyId, 'utf8'), canonicalContext(context), 32));

  return {
    keyId,

    async wrap(dataKey: Buffer, context: EncryptionContext): Promise<WrappedKey> {
      if (dataKey.length !== 32) throw new VaultError('Data key must be 32 bytes');

      const iv = randomBytes(IV_BYTES);
      const cipher = createCipheriv('aes-256-gcm', kekFor(context), iv, { authTagLength: TAG_BYTES });
      // The context authenticates the wrapping as well as the payload, so a
      // wrapped key cannot be moved between tenants even if the derivation were
      // somehow shared.
      cipher.setAAD(canonicalContext(context));
      const sealed = Buffer.concat([cipher.update(dataKey), cipher.final()]);

      return { keyId, bytes: Buffer.concat([iv, cipher.getAuthTag(), sealed]) };
    },

    async unwrap(wrapped: WrappedKey, context: EncryptionContext): Promise<Buffer> {
      if (!constantTimeEquals(wrapped.keyId, keyId)) {
        throw new VaultError(`Unknown wrapping key: ${wrapped.keyId}`);
      }
      if (wrapped.bytes.length <= IV_BYTES + TAG_BYTES) {
        throw new VaultError('Wrapped key is malformed');
      }

      const iv = wrapped.bytes.subarray(0, IV_BYTES);
      const tag = wrapped.bytes.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
      const body = wrapped.bytes.subarray(IV_BYTES + TAG_BYTES);

      const decipher = createDecipheriv('aes-256-gcm', kekFor(context), iv, { authTagLength: TAG_BYTES });
      decipher.setAAD(canonicalContext(context));
      decipher.setAuthTag(tag);

      try {
        return Buffer.concat([decipher.update(body), decipher.final()]);
      } catch {
        // Wrong context, wrong key, or tampered bytes. The caller gets one
        // answer: this did not open. Distinguishing them tells an attacker
        // which half they got right.
        throw new VaultError('Could not unwrap the data key');
      }
    },
  };
}

function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
