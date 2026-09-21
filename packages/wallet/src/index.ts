/**
 * Sign-In With Ethereum (EIP-4361), for the second way into a workspace.
 *
 * ## What a signature proves, and what it does not
 *
 * It proves somebody controls a private key. That is *not* the same claim OIDC
 * makes: an id token says a provider verified an email address and vouches for
 * it. A signature vouches for nothing — there is no issuer, no directory, and
 * nobody to ask.
 *
 * So a wallet identity is a different kind of principal, not a cheaper version
 * of the same one, and the threat model says so. In particular it cannot be
 * recovered: lose the key and the workspace is gone, because there is nobody
 * who could attest that you are the same person.
 *
 * ## One file, no relative imports
 *
 * The dashboard sets `allowImportingTsExtensions: false` and cannot load a
 * package whose index re-exports with `.ts` specifiers. `@veto/tokens` is the
 * same shape for the same reason. Adding a second file here breaks the
 * dashboard build in a way that looks unrelated to the change that caused it.
 */

import { verifyMessage } from 'viem';

/** Namespace for a wallet subject, beside `oidc|` — see the callback route. */
export const WALLET_SUBJECT_PREFIX = 'eth|';

/** How long a nonce is good for. It exists to survive one signing prompt. */
export const NONCE_TTL_MS = 5 * 60 * 1000;

/** Lowercase hex, 20 bytes. Checked before anything is built from it. */
export const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;

export type WalletFailure =
  | 'ADDRESS_MALFORMED'
  | 'NONCE_MISMATCH'
  | 'DOMAIN_MISMATCH'
  | 'MESSAGE_MALFORMED'
  | 'SIGNATURE_INVALID'
  | 'EXPIRED';

export interface SiweFields {
  readonly domain: string;
  readonly address: string;
  readonly uri: string;
  readonly nonce: string;
  readonly issuedAt: string;
}

/**
 * The exact text the wallet is asked to sign.
 *
 * Built here and nowhere else, because the server must reconstruct byte for
 * byte what it expects and compare that against what was signed. A message the
 * *client* composes is a message the client chooses, and "sign this to prove
 * you own the key" becomes "sign whatever I put in front of you".
 *
 * The statement is written for the person reading it in a wallet popup, not for
 * a protocol. That popup is the only place they are told what they are agreeing
 * to.
 */
export function buildSiweMessage(fields: SiweFields): string {
  return [
    `${fields.domain} wants you to sign in with your Ethereum account:`,
    fields.address,
    '',
    'Signing proves you control this wallet. It grants nothing on its own —' +
      ' every action an agent takes is decided separately.',
    '',
    `URI: ${fields.uri}`,
    'Version: 1',
    'Chain ID: 1',
    `Nonce: ${fields.nonce}`,
    `Issued At: ${fields.issuedAt}`,
  ].join('\n');
}

export interface VerifyInput {
  readonly message: string;
  readonly signature: string;
  readonly address: string;
  /** From the server's own cookie, never from the request body. */
  readonly expectedNonce: string;
  readonly expectedDomain: string;
  readonly now?: number;
}

/**
 * Check a signature, and check it is the one we asked for.
 *
 * The signature is the last thing verified, not the first. A valid signature
 * over a message we did not compose proves only that somebody signed
 * something — so the message is reconstructed from the fields we control and
 * compared whole before the cryptography is consulted at all.
 */
export async function verifyWalletSignature(
  input: VerifyInput,
): Promise<{ readonly ok: true; readonly subject: string } | { readonly ok: false; readonly reason: WalletFailure }> {
  if (!ADDRESS_PATTERN.test(input.address)) return { ok: false, reason: 'ADDRESS_MALFORMED' };

  const lines = input.message.split('\n');
  const nonceLine = lines.find((line) => line.startsWith('Nonce: '));
  const issuedLine = lines.find((line) => line.startsWith('Issued At: '));
  if (nonceLine === undefined || issuedLine === undefined) {
    return { ok: false, reason: 'MESSAGE_MALFORMED' };
  }

  // Compared against the cookie, not against the body. A nonce the caller
  // supplies both sides of is not a nonce.
  const nonce = nonceLine.slice('Nonce: '.length);
  if (nonce !== input.expectedNonce) return { ok: false, reason: 'NONCE_MISMATCH' };

  const issuedAt = Date.parse(issuedLine.slice('Issued At: '.length));
  const now = input.now ?? Date.now();
  if (!Number.isFinite(issuedAt) || now - issuedAt > NONCE_TTL_MS || issuedAt - now > 60_000) {
    return { ok: false, reason: 'EXPIRED' };
  }

  if (!input.message.startsWith(`${input.expectedDomain} wants you to sign in`)) {
    // A message naming another site, replayed here. The domain is what stops a
    // signature gathered elsewhere from being worth anything at this one.
    return { ok: false, reason: 'DOMAIN_MISMATCH' };
  }

  // Rebuilt from what the server decided, then compared whole. Anything the
  // caller added, removed or reordered fails here rather than being signed over
  // and accepted.
  // The address as the message spells it, not as the caller spelled it.
  //
  // A wallet signs the checksummed form; a client that posts the lowercase one
  // beside it would fail a whole-message comparison for a reason nobody could
  // read. Both must still name the same account — that is checked next — but
  // the bytes that were signed are what the rebuild has to reproduce.
  const signedAddress = lines[1] ?? '';
  if (signedAddress.toLowerCase() !== input.address.toLowerCase()) {
    return { ok: false, reason: 'ADDRESS_MALFORMED' };
  }

  const expected = buildSiweMessage({
    domain: input.expectedDomain,
    address: signedAddress,
    uri: `https://${input.expectedDomain}`,
    nonce: input.expectedNonce,
    issuedAt: issuedLine.slice('Issued At: '.length),
  });
  if (input.message !== expected) return { ok: false, reason: 'MESSAGE_MALFORMED' };

  let valid = false;
  try {
    valid = await verifyMessage({
      // Recovered against the address the message names, which the check above
      // has already tied to the one the caller claims.
      address: signedAddress as `0x${string}`,
      message: input.message,
      signature: input.signature as `0x${string}`,
    });
  } catch {
    // A malformed signature and a wrong one are the same answer here.
    return { ok: false, reason: 'SIGNATURE_INVALID' };
  }
  if (!valid) return { ok: false, reason: 'SIGNATURE_INVALID' };

  // Lowercased, so one wallet is one subject whatever case the client sent.
  // Lowercased, so one wallet is one subject whatever case it arrived in.
  return { ok: true, subject: `${WALLET_SUBJECT_PREFIX}${signedAddress.toLowerCase()}` };
}
