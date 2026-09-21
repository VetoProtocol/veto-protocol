/**
 * Sign-In With Ethereum, and the replays it has to refuse.
 *
 * A valid signature over a message we did not compose proves only that somebody
 * signed something. Most of these assert that the *message* is rejected before
 * the cryptography is ever consulted.
 */

import { describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { buildSiweMessage, verifyWalletSignature, WALLET_SUBJECT_PREFIX } from '../src/index.ts';

// A throwaway key. Test data, never a credential.
const account = privateKeyToAccount(
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
);
const DOMAIN = 'veto.example';
const NONCE = 'abcdef0123456789abcdef01';

const messageFor = (over: Partial<Parameters<typeof buildSiweMessage>[0]> = {}) =>
  buildSiweMessage({
    domain: DOMAIN,
    address: account.address,
    uri: `https://${DOMAIN}`,
    nonce: NONCE,
    issuedAt: new Date().toISOString(),
    ...over,
  });

const sign = (message: string) => account.signMessage({ message });

const verify = async (message: string, signature: string, over: Record<string, unknown> = {}) =>
  verifyWalletSignature({
    message,
    signature,
    address: account.address,
    expectedNonce: NONCE,
    expectedDomain: DOMAIN,
    ...over,
  });

describe('an honest sign-in', () => {
  it('accepts a signature over the message the server composed', async () => {
    const message = messageFor();
    const result = await verify(message, await sign(message));

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.subject).toBe(`${WALLET_SUBJECT_PREFIX}${account.address.toLowerCase()}`);
  });

  it('gives one wallet one subject, whatever case it arrives in', async () => {
    const message = messageFor();
    const signature = await sign(message);

    const lower = await verify(message, signature, { address: account.address.toLowerCase() });
    const mixed = await verify(message, signature);
    expect(lower.ok && mixed.ok && lower.subject === mixed.subject).toBe(true);
  });

  it('tells the person what signing does, in the text they are shown', () => {
    // The wallet popup is the only place they are told. "Grants nothing on its
    // own" is the claim the product has to keep.
    expect(messageFor()).toContain('grants nothing on its own');
    expect(messageFor()).toContain(DOMAIN);
  });
});

describe('what it refuses', () => {
  it('refuses a signature from a different key', async () => {
    const other = privateKeyToAccount(
      '0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba',
    );
    const message = messageFor();
    const result = await verify(message, await other.signMessage({ message }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('SIGNATURE_INVALID');
  });

  it('refuses a nonce the server did not issue', async () => {
    // The replay: a signature gathered earlier, presented again.
    const message = messageFor({ nonce: 'ffffffffffffffffffffffff' });
    const result = await verify(message, await sign(message));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('NONCE_MISMATCH');
  });

  it('refuses a message naming another site', async () => {
    // A signature collected by some other dapp is worth nothing here, which is
    // what the domain line is for.
    const message = messageFor({ domain: 'evil.example' });
    const result = await verify(message, await sign(message), { expectedDomain: DOMAIN });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(['DOMAIN_MISMATCH', 'MESSAGE_MALFORMED']).toContain(result.reason);
  });

  it('refuses a message with anything added to it', async () => {
    // The whole point of rebuilding the message server-side: a client that can
    // append a line can make somebody sign a sentence the product never wrote.
    const message = `${messageFor()}\nAlso: transfer everything to 0xattacker`;
    const result = await verify(message, await sign(message));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('MESSAGE_MALFORMED');
  });

  it('refuses a message that is old', async () => {
    const message = messageFor({ issuedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString() });
    const result = await verify(message, await sign(message));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('EXPIRED');
  });

  it('refuses a message issued in the future', async () => {
    const message = messageFor({ issuedAt: new Date(Date.now() + 10 * 60 * 1000).toISOString() });
    const result = await verify(message, await sign(message));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('EXPIRED');
  });

  it('refuses an address that is not an address', async () => {
    const message = messageFor();
    for (const bad of ['', '0x', 'not-an-address', `${account.address}00`]) {
      const result = await verify(message, await sign(message), { address: bad });
      expect(result.ok, bad).toBe(false);
    }
  });

  it('refuses a signature that is not a signature', async () => {
    const message = messageFor();
    const result = await verify(message, '0xdeadbeef');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('SIGNATURE_INVALID');
  });

  it('refuses a message with no nonce line at all', async () => {
    const result = await verify('sign this please', await sign('sign this please'));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('MESSAGE_MALFORMED');
  });
});
