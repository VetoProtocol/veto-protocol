import { describe, expect, it } from 'vitest';
import {
  AGENT_RESOURCE,
  PERMIT_USER_KEY_PATTERN,
  HUMAN_RESOURCE,
  RELATION_DELEGATOR,
  agentInstanceKey,
  agentUserKey,
  delegatorFact,
  humanInstanceKey,
  humanUserKey,
  tenantKey,
} from '../src/model.ts';

describe('permit key vocabulary (§4.2)', () => {
  it('uses the key shapes the spec fixes', () => {
    expect(agentUserKey('agt_1')).toBe('agent|agt_1');
    expect(humanUserKey('usr_1')).toBe('human|usr_1');
    expect(tenantKey('ws_1')).toBe('ws_1');
    expect(RELATION_DELEGATOR).toBe('delegator');
  });

  it('keeps principal keys and relation-endpoint keys distinct', () => {
    // Confusing the two would point a relationship tuple at something that is
    // not a resource instance, and the tuple would silently describe nothing.
    expect(agentUserKey('agt_1')).not.toBe(agentInstanceKey('agt_1'));
    expect(agentInstanceKey('agt_1')).toBe(`${AGENT_RESOURCE}:agt_1`);
    expect(humanInstanceKey('usr_1')).toBe(`${HUMAN_RESOURCE}:usr_1`);
  });

  it('builds principal keys Permit will accept', () => {
    // Permit validates user keys against ^[A-Za-z0-9|@+\-._]+$ and answers 422
    // otherwise. §4.2 suggests `agent:{id}`; the colon is not in that set, which
    // cost a live round trip to discover. This assertion keeps it discovered.
    for (const key of [agentUserKey('agt_1'), humanUserKey('usr_1')]) {
      expect(key).toMatch(PERMIT_USER_KEY_PATTERN);
    }
    expect('agent:agt_1').not.toMatch(PERMIT_USER_KEY_PATTERN);
  });

  it('renders the delegator fact the identity tests assert on', () => {
    expect(delegatorFact('agt_1', 'usr_1')).toBe('agent:agt_1#owner=usr_1');
  });
});
