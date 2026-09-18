import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  CapabilityError,
  MAX_TTL_MS,
  mintCapability,
  verifyCapability,
  type CapabilityClaims,
} from '../src/index.ts';

const SECRET = 'k'.repeat(40);
const OTHER = 'j'.repeat(40);
const AUD = 'veto-control-plane';

const mint = (over: Partial<Parameters<typeof mintCapability>[1]> = {}) =>
  mintCapability(SECRET, {
    aud: AUD,
    workspaceId: 'ws_a',
    humanId: 'usr_alice',
    action: 'control-plane',
    resource: 'agents',
    ttlMs: 60_000,
    ...over,
  });

const claimsOf = (token: string): CapabilityClaims =>
  JSON.parse(Buffer.from(token.slice(0, token.indexOf('.')), 'base64url').toString('utf8'));

/** Sign arbitrary claims, to forge tokens a well-behaved minter would refuse. */
function sign(claims: CapabilityClaims, secret: string): string {
  const body = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  return `${body}.${createHmac('sha256', Buffer.from(secret, 'utf8')).update(body).digest('base64url')}`;
}

describe('capability tokens', () => {
  it('round trips', () => {
    const claims = verifyCapability(SECRET, mint(), { audience: AUD });
    expect(claims).toMatchObject({ workspaceId: 'ws_a', humanId: 'usr_alice', agentId: null });
  });

  it('gives every token a distinct nonce', () => {
    expect(claimsOf(mint()).nonce).not.toBe(claimsOf(mint()).nonce);
  });

  it('rejects a token signed with another key', () => {
    expect(verifyCapability(OTHER, mint(), { audience: AUD })).toBeNull();
  });

  it('rejects an edited workspace with the original signature', () => {
    // The attack the signed region exists to stop.
    const token = mint();
    const [body, sig] = token.split('.');
    const claims = { ...claimsOf(token), workspaceId: 'ws_victim' };
    const forged = `${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${sig}`;

    expect(body).toBeDefined();
    expect(verifyCapability(SECRET, forged, { audience: AUD })).toBeNull();
  });

  it('rejects a token minted for another audience', () => {
    // A valid signature proves the holder of the key made it, not that it was
    // meant for this service.
    const other = mint({ aud: 'veto-gateway' });
    expect(verifyCapability(SECRET, other, { audience: AUD })).toBeNull();
    expect(verifyCapability(SECRET, other, { audience: 'veto-gateway' })).not.toBeNull();
  });

  it('rejects an expired token', () => {
    const token = mint({ ttlMs: 1_000, now: 0 });
    expect(verifyCapability(SECRET, token, { audience: AUD, now: 500 })).not.toBeNull();
    expect(verifyCapability(SECRET, token, { audience: AUD, now: 60_000 })).toBeNull();
  });

  it('rejects a token issued in the future beyond the leeway', () => {
    const token = mint({ now: 1_000_000 });
    expect(verifyCapability(SECRET, token, { audience: AUD, now: 0 })).toBeNull();
  });

  it('refuses to mint beyond the lifetime ceiling', () => {
    expect(() => mint({ ttlMs: MAX_TTL_MS + 1 })).toThrow(CapabilityError);
    expect(() => mint({ ttlMs: 0 })).toThrow(CapabilityError);
    expect(() => mint({ ttlMs: -1 })).toThrow(CapabilityError);
  });

  it('rejects a correctly signed token that claims a longer life than allowed', () => {
    // Anyone holding the key could hand-roll this; the ceiling is enforced on
    // the way in as well as on the way out.
    const long = sign(
      { ...claimsOf(mint()), issuedAt: 0, expiresAt: MAX_TTL_MS * 4 },
      SECRET,
    );
    expect(verifyCapability(SECRET, long, { audience: AUD, now: 1_000 })).toBeNull();
  });

  it('carries an agent id when one is acting', () => {
    const token = mint({ agentId: 'agt_1' });
    expect(verifyCapability(SECRET, token, { audience: AUD })?.agentId).toBe('agt_1');
  });

  it('rejects malformed input without throwing', () => {
    for (const raw of ['', '.', 'x', 'a.b', 'YQ.', '.YQ', 'not base64url!.sig']) {
      expect(() => verifyCapability(SECRET, raw, { audience: AUD })).not.toThrow();
      expect(verifyCapability(SECRET, raw, { audience: AUD })).toBeNull();
    }
  });

  it('refuses a key too short to sign with', () => {
    expect(() => mintCapability('short', { aud: AUD, workspaceId: 'ws_a', humanId: 'u', action: 'a', resource: 'r', ttlMs: 1000 })).toThrow(/at least 32/);
    expect(() => verifyCapability('short', mint(), { audience: AUD })).toThrow(/at least 32/);
  });

  it('rejects a token with claims missing', () => {
    expect(verifyCapability(SECRET, sign({ aud: AUD } as CapabilityClaims, SECRET), { audience: AUD })).toBeNull();
  });
});
