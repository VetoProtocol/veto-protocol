import { describe, expect, it } from 'vitest';
import { AgentId, HumanId, InvalidIdError, WorkspaceId } from '../src/ids.ts';

describe('branded ids', () => {
  it('accepts a well-formed id', () => {
    expect(WorkspaceId.parse('ws_abc123')).toBe('ws_abc123');
    expect(AgentId.parse('agt_A-b_9')).toBe('agt_A-b_9');
  });

  it('rejects an id carrying another type\'s prefix', () => {
    // The tenant-isolation bug this guards: passing a human id where an agent id belongs.
    expect(() => AgentId.parse('usr_abc')).toThrow(InvalidIdError);
    expect(() => WorkspaceId.parse('agt_abc')).toThrow(InvalidIdError);
  });

  it.each([
    ['empty body', 'ws_'],
    ['no prefix', 'abc123'],
    ['prefix only, wrong case', 'WS_abc'],
    ['path traversal', 'ws_../../etc/passwd'],
    ['sql-ish', "ws_1' OR '1'='1"],
    ['whitespace', 'ws_ abc'],
    ['overlong', `ws_${'a'.repeat(65)}`],
  ])('rejects %s', (_label, value) => {
    expect(() => WorkspaceId.parse(value)).toThrow(InvalidIdError);
  });

  it.each([null, undefined, 42, {}, [], true])('rejects non-string %s', (value) => {
    expect(() => WorkspaceId.parse(value)).toThrow(InvalidIdError);
  });

  it('exposes a non-throwing guard', () => {
    expect(HumanId.is('usr_ok')).toBe(true);
    expect(HumanId.is('agt_no')).toBe(false);
    expect(HumanId.is(undefined)).toBe(false);
  });
});
