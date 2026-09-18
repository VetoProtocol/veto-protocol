/**
 * The sign-in flow cookie.
 *
 * It carries the PKCE verifier, state and nonce across the redirect to the
 * provider and back. If a caller could forge one, they could supply a state
 * that matches a callback they crafted — which is the CSRF case §12.1 requires
 * a test for.
 */

import { beforeAll, describe, expect, it } from 'vitest';

const SECRET = 'f'.repeat(48);

let sealFlow: typeof import('../src/lib/flow-cookie.ts').sealFlow;
let openFlow: typeof import('../src/lib/flow-cookie.ts').openFlow;

beforeAll(async () => {
  process.env['DASHBOARD_SESSION_SECRET'] = SECRET;
  const mod = await import('../src/lib/flow-cookie.ts');
  sealFlow = mod.sealFlow;
  openFlow = mod.openFlow;
});

const flow = () => ({
  verifier: 'v'.repeat(43),
  state: 'state-abc',
  nonce: 'nonce-abc',
  expiresAt: Date.now() + 60_000,
});

describe('flow cookie', () => {
  it('round trips', () => {
    const f = flow();
    expect(openFlow(sealFlow(f))).toEqual(f);
  });

  it('rejects a substituted state with the original signature', () => {
    const f = flow();
    const [, mac] = sealFlow(f).split('.');
    const forged = `${Buffer.from(JSON.stringify({ ...f, state: 'attacker-state' })).toString('base64url')}.${mac}`;

    expect(openFlow(forged)).toBeNull();
  });

  it('rejects an unsigned cookie', () => {
    const body = Buffer.from(JSON.stringify(flow())).toString('base64url');
    expect(openFlow(`${body}.`)).toBeNull();
    expect(openFlow(body)).toBeNull();
  });

  it('expires', () => {
    const stale = sealFlow({ ...flow(), expiresAt: Date.now() - 1 });
    expect(openFlow(stale)).toBeNull();
  });

  it('rejects malformed input without throwing', () => {
    for (const raw of ['', '.', 'a.b', 'x']) {
      expect(() => openFlow(raw)).not.toThrow();
      expect(openFlow(raw)).toBeNull();
    }
  });
});
