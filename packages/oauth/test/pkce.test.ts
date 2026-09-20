/**
 * PKCE, and the downgrade it exists to prevent.
 *
 * The authorization code is the one value that travels through a browser
 * redirect — a URL bar, a history file, a referer header. PKCE is what makes an
 * intercepted code worthless. Every assertion here is about refusing something,
 * because that is the entire job.
 */

import { describe, expect, it } from 'vitest';
import { challengeFor, checkChallenge, checkVerifier, PKCE_METHOD } from '../src/pkce.ts';

/** A verifier of the shape RFC 7636 §4.1 asks for. */
const VERIFIER = 'a'.repeat(43);

describe('the challenge a client registers', () => {
  it('accepts S256 with a well-formed challenge', () => {
    expect(checkChallenge(challengeFor(VERIFIER), PKCE_METHOD)).toBeNull();
  });

  it('refuses the plain method by name', () => {
    // `plain` makes the challenge equal the verifier, which is no protection at
    // all. A server that accepts it accepts whatever an attacker chooses.
    expect(checkChallenge(VERIFIER, 'plain')).toBe('METHOD_UNSUPPORTED');
  });

  it('refuses an omitted method, because the RFC default is plain', () => {
    expect(checkChallenge(challengeFor(VERIFIER), undefined)).toBe('METHOD_UNSUPPORTED');
  });

  it('refuses a method it has never heard of', () => {
    expect(checkChallenge(challengeFor(VERIFIER), 'S512')).toBe('METHOD_UNSUPPORTED');
  });

  it('refuses a challenge that is not a base64url SHA-256', () => {
    for (const bad of ['', 'short', `${'a'.repeat(43)}=`, 'a'.repeat(44), 'has spaces in it']) {
      expect(checkChallenge(bad, PKCE_METHOD), bad).toBe('CHALLENGE_MALFORMED');
    }
  });
});

describe('the verifier presented at exchange', () => {
  it('accepts the one that produced the challenge', () => {
    expect(checkVerifier(VERIFIER, challengeFor(VERIFIER))).toBeNull();
  });

  it('refuses a different verifier', () => {
    // The intercepted-code case: an attacker has the code and not the verifier.
    expect(checkVerifier('b'.repeat(43), challengeFor(VERIFIER))).toBe('VERIFIER_MISMATCH');
  });

  it('refuses a verifier shorter than the RFC allows', () => {
    // 42 characters. The lower bound is the whole security argument.
    const short = 'a'.repeat(42);
    expect(checkVerifier(short, challengeFor(short))).toBe('VERIFIER_MALFORMED');
  });

  it('refuses a verifier longer than the RFC allows', () => {
    const long = 'a'.repeat(129);
    expect(checkVerifier(long, challengeFor(long))).toBe('VERIFIER_MALFORMED');
  });

  it('refuses characters outside the unreserved alphabet', () => {
    for (const bad of [`${'a'.repeat(42)}/`, `${'a'.repeat(42)}+`, `${'a'.repeat(42)} `]) {
      expect(checkVerifier(bad, challengeFor(bad)), bad).toBe('VERIFIER_MALFORMED');
    }
  });

  it('refuses the challenge presented as its own verifier', () => {
    // What a `plain` downgrade would look like arriving at the exchange.
    const challenge = challengeFor(VERIFIER);
    expect(checkVerifier(challenge, challenge)).not.toBeNull();
  });

  it('does not throw when the stored challenge is the wrong length', () => {
    // timingSafeEqual raises on a length mismatch; a raise here would be a 500
    // where a denial belongs.
    expect(() => checkVerifier(VERIFIER, 'too-short')).not.toThrow();
    expect(checkVerifier(VERIFIER, 'too-short')).toBe('VERIFIER_MISMATCH');
  });
});
