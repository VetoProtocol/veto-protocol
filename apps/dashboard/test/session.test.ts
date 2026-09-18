/**
 * Session cookie tests.
 *
 * The cookie decides which workspace the dashboard reads. A forged one is a
 * tenant selector handed to the attacker, so every way of tampering with it
 * gets its own case here.
 */

import { beforeAll, describe, expect, it } from 'vitest';

const SECRET = 'a'.repeat(48);
const OTHER_SECRET = 'b'.repeat(48);

let signSession: typeof import('../src/lib/session.ts').signSession;
let verifySession: typeof import('../src/lib/session.ts').verifySession;

beforeAll(async () => {
  process.env['DASHBOARD_SESSION_SECRET'] = SECRET;
  // `server-only` throws when imported outside a server context; the module
  // graph is loaded here with that resolved to a no-op by the alias below.
  const mod = await import('../src/lib/session.ts');
  signSession = mod.signSession;
  verifySession = mod.verifySession;
});

const session = {
  workspaceId: 'ws_a',
  userId: 'usr_alice',
  credential: 'cred-abc',
  expiresAt: Date.now() + 60_000,
};

describe('session cookie', () => {
  it('round trips a valid session', () => {
    const verified = verifySession(signSession(session));
    expect(verified).toEqual(session);
  });

  it('rejects a flipped workspace', () => {
    const raw = signSession(session);
    const [body, mac] = raw.split('.');
    const payload = JSON.parse(Buffer.from(body ?? '', 'base64url').toString('utf8'));

    // The attack this whole module exists to stop: edit the tenant, keep the
    // signature, hope nobody checks.
    payload.ws = 'ws_victim';
    const forged = `${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${mac}`;

    expect(verifySession(forged)).toBeNull();
  });

  it('rejects a signature made with a different secret', () => {
    process.env['DASHBOARD_SESSION_SECRET'] = OTHER_SECRET;
    const foreign = signSession(session);
    process.env['DASHBOARD_SESSION_SECRET'] = SECRET;

    expect(verifySession(foreign)).toBeNull();
  });

  it('rejects an expired session even though the signature is good', () => {
    // Expiry is inside the signed region, so this is a valid signature over a
    // payload that is no longer valid. Both checks have to run.
    const expired = signSession({ ...session, expiresAt: Date.now() - 1 });
    expect(verifySession(expired)).toBeNull();
  });

  it('rejects malformed input without throwing', () => {
    for (const raw of ['', '.', 'nodot', 'a.b', '.mac', Buffer.from('{}').toString('base64url')]) {
      expect(() => verifySession(raw)).not.toThrow();
      expect(verifySession(raw)).toBeNull();
    }
  });

  it('refuses a secret too short to be worth signing with', async () => {
    process.env['DASHBOARD_SESSION_SECRET'] = 'short';
    expect(() => signSession(session)).toThrow(/at least 32/);
    process.env['DASHBOARD_SESSION_SECRET'] = SECRET;
  });
});
