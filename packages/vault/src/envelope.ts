/**
 * Envelope encryption for stored secrets (spec §3.4).
 *
 * A fresh 32-byte data key per secret, used once; the data key is wrapped by
 * the KeyWrapper. Fresh per secret because reuse across rows means one
 * compromised key opens everything, and because GCM's nonce budget is a
 * property of the key — a new key per secret makes nonce reuse structurally
 * impossible rather than something to be careful about.
 *
 * The sealed blob is self-describing so it can be stored in one column:
 *
 *     [1]  version
 *     [2]  wrapped data key length (big-endian)
 *     [n]  wrapped data key
 *     [12] iv
 *     [16] auth tag
 *     [..] ciphertext
 *
 * The version byte exists so a format change is detectable rather than
 * misparsed. Nothing reads it yet beyond refusing what it does not recognise.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { canonicalContext, type EncryptionContext } from './context.ts';
import { VaultError, type KeyWrapper } from './wrapper.ts';

const VERSION = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export interface Sealed {
  readonly blob: Buffer;
  readonly keyId: string;
}

export async function seal(
  wrapper: KeyWrapper,
  plaintext: string,
  context: EncryptionContext,
): Promise<Sealed> {
  if (plaintext === '') throw new VaultError('Refusing to seal an empty secret');

  const dataKey = randomBytes(32);
  const iv = randomBytes(IV_BYTES);
  const aad = canonicalContext(context);

  const cipher = createCipheriv('aes-256-gcm', dataKey, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  const wrapped = await wrapper.wrap(dataKey, context);
  // The data key must not outlive its use. This is best effort — V8 may have
  // copied it — but leaving it intact in a long-lived buffer is a choice.
  dataKey.fill(0);

  const header = Buffer.alloc(3);
  header.writeUInt8(VERSION, 0);
  header.writeUInt16BE(wrapped.bytes.length, 1);

  return { blob: Buffer.concat([header, wrapped.bytes, iv, tag, body]), keyId: wrapped.keyId };
}

export async function open(
  wrapper: KeyWrapper,
  sealed: Sealed,
  context: EncryptionContext,
): Promise<string> {
  const blob = sealed.blob;
  if (blob.length < 3) throw new VaultError('Sealed value is malformed');
  if (blob.readUInt8(0) !== VERSION) throw new VaultError('Unknown sealed format version');

  const wrappedLength = blob.readUInt16BE(1);
  const ivStart = 3 + wrappedLength;
  if (blob.length < ivStart + IV_BYTES + TAG_BYTES) {
    throw new VaultError('Sealed value is malformed');
  }

  const wrappedBytes = blob.subarray(3, ivStart);
  const iv = blob.subarray(ivStart, ivStart + IV_BYTES);
  const tag = blob.subarray(ivStart + IV_BYTES, ivStart + IV_BYTES + TAG_BYTES);
  const body = blob.subarray(ivStart + IV_BYTES + TAG_BYTES);

  const dataKey = await wrapper.unwrap({ keyId: sealed.keyId, bytes: wrappedBytes }, context);

  try {
    const decipher = createDecipheriv('aes-256-gcm', dataKey, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(canonicalContext(context));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
  } catch {
    throw new VaultError('Could not open the sealed value');
  } finally {
    dataKey.fill(0);
  }
}
