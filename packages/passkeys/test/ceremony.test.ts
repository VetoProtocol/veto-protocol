/**
 * The assertion path, against a virtual authenticator.
 *
 * The positive case earns its keep: it is what distinguishes a verifier that
 * checks signatures from one that rejects everything.
 */

import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { CeremonyError, verifyAssertion } from '../src/ceremony.ts';
import type { Passkey } from '../src/store.ts';
import { createVirtualAuthenticator } from './authenticator.ts';

const CONFIG = { rpID: 'localhost', rpName: 'Veto', origins: ['http://localhost:3000'] };

const authenticator = createVirtualAuthenticator();

const passkey = (over: Partial<Passkey> = {}): Passkey => ({
  id: 'pky_1',
  userId: 'usr_1',
  credentialId: authenticator.credentialId,
  publicKey: authenticator.publicKey,
  signCount: 0,
  transports: [],
  label: null,
  createdAt: new Date(),
  lastUsedAt: null,
  ...over,
});

const challenge = randomBytes(32);

const assertion = (over: Partial<Parameters<typeof authenticator.assert>[0]> = {}) =>
  authenticator.assert({
    challenge,
    origin: CONFIG.origins[0] as string,
    rpID: CONFIG.rpID,
    signCount: 1,
    ...over,
  });

describe('a valid assertion', () => {
  it('verifies, and reports the authenticator counter', async () => {
    const result = await verifyAssertion(CONFIG, assertion() as never, challenge, passkey());
    expect(result.signCount).toBe(1);
  });
});

describe('what must not verify', () => {
  it('a signature over a different challenge', async () => {
    // The whole point of binding the challenge to one approval.
    await expect(
      verifyAssertion(CONFIG, assertion() as never, randomBytes(32), passkey()),
    ).rejects.toThrow(CeremonyError);
  });

  it('a signature from a different origin', async () => {
    await expect(
      verifyAssertion(CONFIG, assertion({ origin: 'https://evil.example' }) as never, challenge, passkey()),
    ).rejects.toThrow(CeremonyError);
  });

  it('a signature for a different relying party', async () => {
    await expect(
      verifyAssertion(CONFIG, assertion({ rpID: 'evil.example' }) as never, challenge, passkey()),
    ).rejects.toThrow(CeremonyError);
  });

  it('a signature verified against somebody else’s public key', async () => {
    const other = createVirtualAuthenticator();
    await expect(
      verifyAssertion(CONFIG, assertion() as never, challenge, passkey({ publicKey: other.publicKey })),
    ).rejects.toThrow(CeremonyError);
  });

  it('an assertion where the user never verified', async () => {
    // userVerification is 'required', not 'preferred'. A step-up a device may
    // silently skip is not a step-up.
    await expect(
      verifyAssertion(CONFIG, assertion({ userVerified: false }) as never, challenge, passkey()),
    ).rejects.toThrow(CeremonyError);
  });

  it('a tampered signature', async () => {
    const forged = assertion() as { response: { signature: string } };
    const bytes = Buffer.from(forged.response.signature, 'base64url');
    bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 0x01;
    forged.response.signature = bytes.toString('base64url');

    await expect(verifyAssertion(CONFIG, forged as never, challenge, passkey())).rejects.toThrow(
      CeremonyError,
    );
  });

  it('a malformed response, without leaking which check failed', async () => {
    const error = await verifyAssertion(CONFIG, {} as never, challenge, passkey()).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(CeremonyError);
    // One message for every failure: the library's own text names the check
    // that failed, which maps the ceremony for anyone probing it.
    expect((error as CeremonyError).reason).toBe('assertion could not be verified');
  });
});
