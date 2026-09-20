/**
 * PKCE (RFC 7636), as RFC 9700 requires it.
 *
 * The authorization code is the one part of the flow that travels through a
 * browser redirect, which is to say through a URL bar, a history file and
 * whatever else is watching. PKCE binds the code to the client that asked for
 * it: without the verifier, an intercepted code is worth nothing.
 *
 * ## S256 only
 *
 * The RFC defines `plain`, where the challenge *is* the verifier. A server that
 * accepts it accepts a flow with no protection at all, and an attacker who can
 * choose the method chooses that one. Offering it and hoping clients pick S256
 * is not a defence — so `plain` is refused here, by name, with a reason.
 */

import { createHash, timingSafeEqual } from 'node:crypto';

/** The only method this server accepts. */
export const PKCE_METHOD = 'S256';

/**
 * RFC 7636 §4.1: 43–128 characters from an unreserved alphabet.
 *
 * Enforced rather than assumed. A short verifier is a guessable one, and the
 * lower bound is the entire security argument for the exchange.
 */
export const VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;

/** base64url of a SHA-256, so 43 characters with no padding. */
export const CHALLENGE_PATTERN = /^[A-Za-z0-9\-_]{43}$/;

export type PkceFailure =
  | 'CHALLENGE_MALFORMED'
  | 'METHOD_UNSUPPORTED'
  | 'VERIFIER_MALFORMED'
  | 'VERIFIER_MISMATCH';

/** Derive the challenge a verifier should produce. */
export const challengeFor = (verifier: string): string =>
  createHash('sha256').update(verifier, 'ascii').digest('base64url');

/**
 * Check a challenge is one this server will accept, before storing it.
 *
 * Done at `/authorize` rather than at `/token`, so a client that got it wrong
 * learns immediately instead of after a human has approved something.
 */
export function checkChallenge(
  challenge: string,
  method: string | undefined,
): PkceFailure | null {
  // Absent means `plain` per the RFC, which is the case being refused — so an
  // omitted method is refused as firmly as an explicit one.
  if (method !== PKCE_METHOD) return 'METHOD_UNSUPPORTED';
  if (!CHALLENGE_PATTERN.test(challenge)) return 'CHALLENGE_MALFORMED';
  return null;
}

/**
 * Check a verifier against the stored challenge.
 *
 * Constant time. The comparison is between two public-ish values, so a timing
 * leak here is not the crisis it would be on a secret — but a verifier is
 * attacker-supplied and compared repeatedly, and there is no reason to hand
 * anybody a free oracle.
 */
export function checkVerifier(verifier: string, challenge: string): PkceFailure | null {
  if (!VERIFIER_PATTERN.test(verifier)) return 'VERIFIER_MALFORMED';

  const derived = Buffer.from(challengeFor(verifier), 'utf8');
  const expected = Buffer.from(challenge, 'utf8');

  // timingSafeEqual throws on a length mismatch, which would itself be a signal.
  if (derived.length !== expected.length) return 'VERIFIER_MISMATCH';
  return timingSafeEqual(derived, expected) ? null : 'VERIFIER_MISMATCH';
}
