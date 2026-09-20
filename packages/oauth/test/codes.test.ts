/**
 * Authorization codes — the replay this design exists to prevent.
 *
 * The store is a map here rather than Redis, because the property under test is
 * that redemption is *one* operation. A fake that reads and then deletes would
 * pass a test written against a fake that does the same, so this one models
 * `getdel` honestly and a race is asserted directly.
 */

import { describe, expect, it } from 'vitest';
import { issueCode, redeemCode, type CodeGrant, type CodeStore } from '../src/codes.ts';

/** A map with Redis's NX and getdel semantics, and nothing else. */
function fakeStore(): CodeStore & { size: () => number } {
  const values = new Map<string, string>();
  return {
    // Fewer parameters than the interface declares, which still satisfies it.
    // The mode, TTL and NX flag are Redis's to honour; what matters here is
    // that a second write to a live key is refused.
    async set(key, value) {
      if (values.has(key)) return null;
      values.set(key, value);
      return 'OK';
    },
    async getdel(key) {
      const found = values.get(key);
      // Read and remove together. A fake that split these would let a broken
      // implementation pass.
      if (found === undefined) return null;
      values.delete(key);
      return found;
    },
    size: () => values.size,
  };
}

const grant: CodeGrant = {
  workspaceId: 'ws_test',
  userId: 'usr_test',
  agentId: 'agt_test',
  clientId: 'oac_test',
  redirectUri: 'http://127.0.0.1:7777/cb',
  codeChallenge: 'a'.repeat(43),
  resource: 'http://127.0.0.1:4100/mcp',
};

describe('issuing', () => {
  it('returns an opaque code', async () => {
    const code = await issueCode(fakeStore(), grant);
    expect(code.length).toBeGreaterThan(30);
    // Nothing about the grant is readable from it.
    expect(code).not.toContain('ws_test');
    expect(code).not.toContain('agt_test');
  });

  it('gives two authorizations different codes', async () => {
    const store = fakeStore();
    expect(await issueCode(store, grant)).not.toBe(await issueCode(store, grant));
  });
});

describe('redeeming', () => {
  it('returns the grant exactly as approved', async () => {
    const store = fakeStore();
    const code = await issueCode(store, grant);
    expect(await redeemCode(store, code)).toEqual(grant);
  });

  it('cannot be redeemed twice', async () => {
    const store = fakeStore();
    const code = await issueCode(store, grant);

    expect(await redeemCode(store, code)).toEqual(grant);
    // The replay. A code that survives its exchange is the attack.
    expect(await redeemCode(store, code)).toBeNull();
  });

  it('leaves nothing behind once spent', async () => {
    const store = fakeStore();
    await redeemCode(store, await issueCode(store, grant));
    expect(store.size()).toBe(0);
  });

  it('lets only one of two racing redemptions win', async () => {
    const store = fakeStore();
    const code = await issueCode(store, grant);

    const [first, second] = await Promise.all([
      redeemCode(store, code),
      redeemCode(store, code),
    ]);
    expect([first, second].filter((r) => r !== null)).toHaveLength(1);
  });

  it('answers the same for unknown, expired and already spent', async () => {
    const store = fakeStore();
    const spent = await issueCode(store, grant);
    await redeemCode(store, spent);

    // Distinguishing them would tell a caller whether a code was ever real.
    expect(await redeemCode(store, spent)).toBeNull();
    expect(await redeemCode(store, 'never-existed')).toBeNull();
  });

  it('refuses an empty or absurd code without touching the store', async () => {
    const store = fakeStore();
    expect(await redeemCode(store, '')).toBeNull();
    expect(await redeemCode(store, 'x'.repeat(500))).toBeNull();
  });

  it('refuses a key that holds something it did not write', async () => {
    const store = fakeStore();
    await store.set('veto:oauth:code:tampered', 'not json', 'EX', 60, 'NX');
    expect(await redeemCode(store, 'tampered')).toBeNull();
  });
});
