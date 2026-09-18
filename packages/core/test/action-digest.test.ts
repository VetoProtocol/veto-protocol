import { describe, expect, it } from 'vitest';
import {
  actionDigest,
  canonicalize,
  digestsEqual,
  UndigestibleValueError,
  type DigestibleAction,
} from '../src/action-digest.ts';

const base: DigestibleAction = {
  workspace_id: 'ws_1',
  human_id: 'usr_1',
  agent_id: 'agt_1',
  client_id: 'claude-desktop',
  tool: 'google_drive.read_file',
  action: 'read',
  resource: { type: 'google_file', id: '1abc' },
  arguments: { fields: ['name', 'content'] },
  declared_intent: 'Summarize the Robinhood Chain report',
  destination: null,
};

const withArgs = (args: DigestibleAction['arguments']): DigestibleAction => ({ ...base, arguments: args });

describe('canonicalize', () => {
  it('is independent of object key order', () => {
    expect(canonicalize({ a: 1, b: 2 })).toBe(canonicalize({ b: 2, a: 1 }));
  });

  it('is independent of key order at every depth', () => {
    expect(canonicalize({ o: { x: 1, y: 2 }, z: 3 })).toBe(canonicalize({ z: 3, o: { y: 2, x: 1 } }));
  });

  it('treats array order as significant', () => {
    expect(canonicalize(['a', 'b'])).not.toBe(canonicalize(['b', 'a']));
  });

  it('folds -0 to 0', () => {
    expect(canonicalize(-0)).toBe(canonicalize(0));
  });

  it('rejects values that cannot be represented unambiguously', () => {
    expect(() => canonicalize(undefined)).toThrow(UndigestibleValueError);
    expect(() => canonicalize(Number.NaN)).toThrow(UndigestibleValueError);
    expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow(UndigestibleValueError);
    expect(() => canonicalize(10n)).toThrow(UndigestibleValueError);
    expect(() => canonicalize(() => 1)).toThrow(UndigestibleValueError);
    expect(() => canonicalize(Symbol('s'))).toThrow(UndigestibleValueError);
  });

  it('rejects prototype-polluting keys', () => {
    const hostile = JSON.parse('{"__proto__": {"admin": true}}') as unknown;
    expect(() => canonicalize(hostile)).toThrow(/forbidden key/);
  });

  it('rejects circular structures rather than looping', () => {
    const cyclic: Record<string, unknown> = { a: 1 };
    cyclic['self'] = cyclic;
    expect(() => canonicalize(cyclic)).toThrow(/circular/);
  });

  it('rejects class instances and other exotic objects', () => {
    expect(() => canonicalize(new Date())).toThrow(/plain objects/);
    expect(() => canonicalize(new Map())).toThrow(/plain objects/);
  });

  it('names the failing path so a rejection is debuggable', () => {
    expect(() => canonicalize({ outer: { inner: [1, Number.NaN] } })).toThrow(/outer\.inner\[1\]/);
  });
});

describe('actionDigest', () => {
  it('is stable across calls', () => {
    expect(actionDigest(base)).toBe(actionDigest(base));
  });

  it('is pinned to a known value (regression guard against silent format drift)', () => {
    expect(actionDigest(base)).toMatchInlineSnapshot(`"sha256:691fa68fac17f143bf0e7c5443c9a59098cf329033149d01f818d8cfe8bded3b"`);
  });

  it.each([
    ['workspace', { ...base, workspace_id: 'ws_2' }],
    ['human', { ...base, human_id: 'usr_2' }],
    ['agent', { ...base, agent_id: 'agt_2' }],
    ['client', { ...base, client_id: 'other-client' }],
    ['tool', { ...base, tool: 'google_drive.list_folder' }],
    ['action', { ...base, action: 'search' }],
    ['resource id', { ...base, resource: { type: 'google_file', id: '2def' } }],
    ['resource type', { ...base, resource: { type: 'google_folder', id: '1abc' } }],
    ['declared intent', { ...base, declared_intent: 'Exfiltrate tax records' }],
    ['destination', { ...base, destination: 'https://attacker.example' }],
  ] satisfies [string, DigestibleAction][])('changes when the %s changes', (_label, mutated) => {
    expect(actionDigest(mutated)).not.toBe(actionDigest(base));
  });

  it('ignores key order in arguments, so a re-serialized retry still matches', () => {
    const a = withArgs({ fields: ['name'], limit: 1 });
    const b = withArgs({ limit: 1, fields: ['name'] });
    expect(actionDigest(a)).toBe(actionDigest(b));
  });

  // §12.1: "A compromised agent divides a blocked bulk request into many small requests."
  describe('bulk-splitting (§12.1)', () => {
    it('does not let an approval for one file cover a different file', () => {
      const one = { ...base, resource: { type: 'google_file', id: 'file_1' } };
      const two = { ...base, resource: { type: 'google_file', id: 'file_2' } };
      expect(actionDigest(one)).not.toBe(actionDigest(two));
    });

    it('does not let an approval for one file cover a batch containing it', () => {
      const single = withArgs({ ids: ['file_1'] });
      const batch = withArgs({ ids: ['file_1', 'file_2', 'file_3'] });
      expect(actionDigest(single)).not.toBe(actionDigest(batch));
    });

    it('does not let a narrow approval cover an added argument', () => {
      const narrow = withArgs({ fields: ['name'] });
      const widened = withArgs({ fields: ['name'], recursive: true });
      expect(actionDigest(narrow)).not.toBe(actionDigest(widened));
    });
  });

  // Deliberate restrictive choice — see the module header.
  it('treats NFC and NFD spellings as different actions', () => {
    const nfc = withArgs({ name: 'café' });
    const nfd = withArgs({ name: 'café' });
    expect(actionDigest(nfc)).not.toBe(actionDigest(nfd));
  });

  it('refuses to digest an action with unrepresentable arguments instead of coercing', () => {
    expect(() => actionDigest(withArgs({ n: Number.NaN } as never))).toThrow(UndigestibleValueError);
  });
});

describe('digestsEqual', () => {
  it('matches identical digests and rejects different ones', () => {
    const d = actionDigest(base);
    expect(digestsEqual(d, d)).toBe(true);
    expect(digestsEqual(d, actionDigest({ ...base, action: 'search' }))).toBe(false);
  });

  it('rejects a truncated digest', () => {
    const d = actionDigest(base);
    expect(digestsEqual(d, d.slice(0, -1))).toBe(false);
  });
});
