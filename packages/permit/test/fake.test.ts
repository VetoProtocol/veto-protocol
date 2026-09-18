import { describe, expect, it } from 'vitest';
import { createFakePolicyFacts, PolicyUnavailableError } from '../src/index.ts';

const fact = { workspaceId: 'ws_a', agentId: 'agt_1', ownerUserId: 'usr_1' };

describe('the Permit fake is a fixture, not an engine', () => {
  it('refuses to load outside NODE_ENV=test', () => {
    const original = process.env['NODE_ENV'];
    process.env['NODE_ENV'] = 'production';
    try {
      expect(() => createFakePolicyFacts()).toThrow(/test-only/);
    } finally {
      process.env['NODE_ENV'] = original;
    }
  });

  it('exposes no way to ask an authorization question', () => {
    const fake = createFakePolicyFacts();
    // If a `check`-shaped method ever appears here, the fake has started
    // becoming a shadow policy engine (CLAUDE.md invariant 3).
    expect(Object.keys(fake).sort()).toEqual(['breakNext', 'factsFor', 'removeAgent', 'syncAgent']);
  });

  it('records and removes agent facts', async () => {
    const fake = createFakePolicyFacts();
    await fake.syncAgent(fact);
    expect(await fake.factsFor('ws_a')).toEqual(['agent:agt_1#owner=usr_1']);

    await fake.removeAgent('ws_a', 'agt_1');
    expect(await fake.factsFor('ws_a')).toEqual([]);
  });

  it('keeps facts separate per workspace', async () => {
    const fake = createFakePolicyFacts();
    await fake.syncAgent(fact);
    expect(await fake.factsFor('ws_other')).toEqual([]);
  });

  it('can simulate an outage so callers can prove they fail closed', async () => {
    const fake = createFakePolicyFacts();
    fake.breakNext('removeAgent');
    await expect(fake.removeAgent('ws_a', 'agt_1')).rejects.toThrow(PolicyUnavailableError);
    // One-shot: the retry succeeds, so a caller's convergence path is testable.
    await expect(fake.removeAgent('ws_a', 'agt_1')).resolves.toBeUndefined();
  });
});
