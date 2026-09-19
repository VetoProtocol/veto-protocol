/**
 * The WebAuthn ceremonies (spec §15, §7.1).
 *
 * Verification is delegated to `@simplewebauthn/server`. Hand-rolling it means
 * parsing COSE keys, checking attestation, and verifying ECDSA and RSA
 * signatures over a concatenation of authenticator data and a client-data hash
 * — and every mistake there fails *open* and silently. A signature that is
 * never really checked looks exactly like one that passes.
 *
 * What this module owns is the part a library cannot decide:
 *
 *  * **Where the challenge comes from.** For an approval it is the bytes
 *    already stored on the approval row, so the signature is over *that*
 *    approval and not a challenge the client chose.
 *  * **User verification is required**, not preferred. "Preferred" means a
 *    device may skip the fingerprint and the ceremony still passes, which
 *    reduces a step-up to proof that a phone was nearby.
 *  * **The origin and RP id are configured**, never derived from the request. A
 *    caller that could name its own origin could satisfy the ceremony from a
 *    site it controls.
 */

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { Passkey } from './store.ts';

export interface WebAuthnConfig {
  /** The registrable domain, e.g. 'localhost' or 'veto.example'. */
  readonly rpID: string;
  readonly rpName: string;
  /** Exact origin(s) a response may come from, e.g. 'http://localhost:3000'. */
  readonly origins: readonly string[];
}

export class CeremonyError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super(`Passkey ceremony failed: ${reason}`);
    this.name = 'CeremonyError';
    this.reason = reason;
  }
}

const toBase64Url = (bytes: Buffer): string => bytes.toString('base64url');

export async function buildRegistrationOptions(
  config: WebAuthnConfig,
  user: { id: string; name: string },
  alreadyEnrolled: readonly Passkey[],
) {
  return generateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    userID: new Uint8Array(Buffer.from(user.id, 'utf8')),
    userName: user.name,
    attestationType: 'none',
    // Offering an authenticator that is already enrolled invites a duplicate
    // the database would refuse anyway; excluding them turns that into a clear
    // message from the browser instead of a failed request.
    excludeCredentials: alreadyEnrolled.map((p) => ({
      id: toBase64Url(p.credentialId),
      transports: [...p.transports],
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      // Required, not preferred: a step-up that a device may silently skip is
      // not a step-up.
      userVerification: 'required',
    },
  });
}

export interface RegisteredCredential {
  readonly credentialId: Buffer;
  readonly publicKey: Buffer;
  readonly signCount: number;
  readonly transports: readonly string[];
}

export async function verifyRegistration(
  config: WebAuthnConfig,
  response: Parameters<typeof verifyRegistrationResponse>[0]['response'],
  expectedChallenge: string,
): Promise<RegisteredCredential> {
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: [...config.origins],
      expectedRPID: config.rpID,
      requireUserVerification: true,
    });
  } catch {
    // The library's message describes which check failed, which is a map of
    // the ceremony for anyone probing it.
    throw new CeremonyError('registration could not be verified');
  }

  if (!verification.verified || !verification.registrationInfo) {
    throw new CeremonyError('registration could not be verified');
  }

  const { credential } = verification.registrationInfo;

  return {
    credentialId: Buffer.from(credential.id, 'base64url'),
    publicKey: Buffer.from(credential.publicKey),
    signCount: credential.counter,
    transports: credential.transports ?? [],
  };
}

export async function buildAuthenticationOptions(
  config: WebAuthnConfig,
  challenge: Buffer,
  allowed: readonly Passkey[],
) {
  return generateAuthenticationOptions({
    rpID: config.rpID,
    // The challenge is not generated here. For an approval it is the value
    // already bound to that approval, so a valid signature proves the user
    // resolved *that* one.
    challenge: new Uint8Array(challenge),
    allowCredentials: allowed.map((p) => ({
      id: toBase64Url(p.credentialId),
      transports: [...p.transports],
    })),
    userVerification: 'required',
  });
}

export interface AssertionResult {
  readonly signCount: number;
}

export async function verifyAssertion(
  config: WebAuthnConfig,
  response: Parameters<typeof verifyAuthenticationResponse>[0]['response'],
  expectedChallenge: Buffer,
  passkey: Passkey,
): Promise<AssertionResult> {
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: toBase64Url(expectedChallenge),
      expectedOrigin: [...config.origins],
      expectedRPID: config.rpID,
      credential: {
        id: toBase64Url(passkey.credentialId),
        publicKey: new Uint8Array(passkey.publicKey),
        counter: passkey.signCount,
        transports: [...passkey.transports] as never,
      },
      requireUserVerification: true,
    });
  } catch {
    throw new CeremonyError('assertion could not be verified');
  }

  if (!verification.verified) throw new CeremonyError('assertion could not be verified');

  return { signCount: verification.authenticationInfo.newCounter };
}

/** The credential id a response claims, for looking it up before verifying. */
export function claimedCredentialId(response: { id?: unknown; rawId?: unknown }): Buffer | null {
  const raw = typeof response.rawId === 'string' ? response.rawId : response.id;
  if (typeof raw !== 'string' || raw === '') return null;
  try {
    const bytes = Buffer.from(raw, 'base64url');
    return bytes.length === 0 ? null : bytes;
  } catch {
    return null;
  }
}
