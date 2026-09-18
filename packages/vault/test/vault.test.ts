/**
 * The property this whole package exists for: a secret sealed for one tenant
 * cannot be opened as another, whatever the application layer does.
 */

import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalContext, EncryptionContextError } from '../src/context.ts';
import { createLocalKeyWrapper, VaultError } from '../src/wrapper.ts';
import { open, seal } from '../src/envelope.ts';

const MASTER = randomBytes(32).toString('base64');
const wrapper = createLocalKeyWrapper(MASTER);

const ctx = (over: Partial<{ workspaceId: string; purpose: string; resourceId: string }> = {}) => ({
  workspaceId: 'ws_a',
  purpose: 'connection.google.refresh_token',
  resourceId: 'con_1',
  ...over,
});

const SECRET = '1//0gRefreshTokenValueThatMustNeverLeak';

describe('sealing and opening', () => {
  it('round trips', async () => {
    const sealed = await seal(wrapper, SECRET, ctx());
    expect(await open(wrapper, sealed, ctx())).toBe(SECRET);
  });

  it('never leaves the plaintext in the blob', async () => {
    const sealed = await seal(wrapper, SECRET, ctx());
    expect(sealed.blob.includes(Buffer.from(SECRET, 'utf8'))).toBe(false);
    expect(sealed.blob.toString('utf8')).not.toContain('Refresh');
  });

  it('produces different bytes each time', async () => {
    // Fresh data key and iv per secret, so identical plaintexts are not
    // identifiable as identical from the ciphertext.
    const a = await seal(wrapper, SECRET, ctx());
    const b = await seal(wrapper, SECRET, ctx());
    expect(a.blob.equals(b.blob)).toBe(false);
  });

  it('refuses to seal nothing', async () => {
    await expect(seal(wrapper, '', ctx())).rejects.toThrow(VaultError);
  });
});

describe('the encryption context is a tenant boundary', () => {
  it('will not open a ciphertext as a different workspace', async () => {
    // The row copied into the wrong tenant. This is invariant 4 enforced by
    // arithmetic rather than by remembering to filter.
    const sealed = await seal(wrapper, SECRET, ctx());
    await expect(open(wrapper, sealed, ctx({ workspaceId: 'ws_b' }))).rejects.toThrow(VaultError);
  });

  it('will not open a ciphertext under a different purpose', async () => {
    const sealed = await seal(wrapper, SECRET, ctx());
    await expect(open(wrapper, sealed, ctx({ purpose: 'something.else' }))).rejects.toThrow(VaultError);
  });

  it('will not open a ciphertext attached to a different row', async () => {
    const sealed = await seal(wrapper, SECRET, ctx());
    await expect(open(wrapper, sealed, ctx({ resourceId: 'con_2' }))).rejects.toThrow(VaultError);
  });

  it('cannot be confused by field boundaries', () => {
    // Without length prefixes these two would serialise identically, and two
    // different contexts sharing an encoding defeats the whole mechanism.
    const a = canonicalContext({ workspaceId: 'ws_ab', purpose: 'c', resourceId: 'r' });
    const b = canonicalContext({ workspaceId: 'ws_a', purpose: 'bc', resourceId: 'r' });
    expect(a.equals(b)).toBe(false);
  });

  it('refuses an empty or oversized context field', () => {
    expect(() => canonicalContext(ctx({ workspaceId: '' }))).toThrow(EncryptionContextError);
    expect(() => canonicalContext(ctx({ purpose: 'x'.repeat(513) }))).toThrow(EncryptionContextError);
  });
});

describe('tampering', () => {
  it('rejects a flipped bit anywhere in the blob', async () => {
    const sealed = await seal(wrapper, SECRET, ctx());

    for (const index of [0, 3, sealed.blob.length - 1, Math.floor(sealed.blob.length / 2)]) {
      const copy = Buffer.from(sealed.blob);
      copy[index] = (copy[index] ?? 0) ^ 0x01;
      await expect(
        open(wrapper, { blob: copy, keyId: sealed.keyId }, ctx()),
        `byte ${index}`,
      ).rejects.toThrow(VaultError);
    }
  });

  it('rejects a truncated blob without reading past the end', async () => {
    const sealed = await seal(wrapper, SECRET, ctx());
    for (const length of [0, 1, 2, 3, 10, sealed.blob.length - 1]) {
      await expect(
        open(wrapper, { blob: sealed.blob.subarray(0, length), keyId: sealed.keyId }, ctx()),
      ).rejects.toThrow(VaultError);
    }
  });

  it('rejects a blob sealed under another master key', async () => {
    const other = createLocalKeyWrapper(randomBytes(32).toString('base64'));
    const sealed = await seal(other, SECRET, ctx());
    await expect(open(wrapper, sealed, ctx())).rejects.toThrow(VaultError);
  });

  it('rejects an unknown wrapping key id', async () => {
    const sealed = await seal(wrapper, SECRET, ctx());
    await expect(open(wrapper, { ...sealed, keyId: 'someone-elses-kms' }, ctx())).rejects.toThrow(
      VaultError,
    );
  });
});

describe('the wrapper itself', () => {
  it('refuses a master key too short to be worth deriving from', () => {
    expect(() => createLocalKeyWrapper(randomBytes(16).toString('base64'))).toThrow(VaultError);
  });

  it('refuses a data key of the wrong size', async () => {
    await expect(wrapper.wrap(randomBytes(16), ctx())).rejects.toThrow(VaultError);
  });
});
