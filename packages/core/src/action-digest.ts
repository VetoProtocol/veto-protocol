/**
 * Action digest — the binding between an approval and the exact action approved.
 *
 * Spec §7.1: "Bind high-risk approval to the exact action digest. A changed
 * argument set requires a new approval." CLAUDE.md invariant 6 says the same.
 * Two §12.1 attacks turn on precisely what this function covers:
 *   - a previously approved action replayed after expiry / with altered arguments
 *   - a blocked bulk request split into many small requests
 *
 * Design decisions, all resolved toward the more restrictive behaviour
 * (CLAUDE.md "When in doubt"):
 *
 *  1. Object keys are sorted; arrays keep their order. Array order is semantic
 *     (`["a","b"]` is not `["b","a"]`), key order is not.
 *  2. No Unicode normalisation. NFC "café" and NFD "café" produce *different*
 *     digests. Normalising would let an approval be reused for a
 *     visually-identical but byte-different argument; not normalising merely
 *     forces a fresh approval. Spurious challenge beats silent reuse.
 *  3. `undefined`, NaN, ±Infinity, BigInt, functions, symbols and `__proto__`
 *     keys are rejected outright rather than coerced. Ambiguity here is what an
 *     attacker mines for collisions.
 *  4. `-0` is folded to `0` — they are numerically equal and JSON cannot
 *     distinguish them anyway.
 *  5. `request_id` and `occurred_at` are excluded. They differ on every retry,
 *     and a digest that changed per-request could never match an approval.
 */

import { createHash } from 'node:crypto';

export class UndigestibleValueError extends Error {
  constructor(reason: string, path: string) {
    super(`Cannot digest value at ${path || '<root>'}: ${reason}`);
    this.name = 'UndigestibleValueError';
  }
}

export type DigestibleValue =
  | string
  | number
  | boolean
  | null
  | readonly DigestibleValue[]
  | { readonly [key: string]: DigestibleValue };

/** The subset of a request that identifies *which action* is being authorized. */
export interface DigestibleAction {
  readonly workspace_id: string;
  readonly human_id: string;
  readonly agent_id: string;
  readonly client_id: string;
  readonly tool: string;
  readonly action: string;
  readonly resource: { readonly type: string; readonly id: string };
  readonly arguments: DigestibleValue;
  /** Agent-supplied and therefore untrusted; included so changing it invalidates the approval. */
  readonly declared_intent: string | null;
  readonly destination: string | null;
}

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Deterministic serialisation. Not JSON.stringify: that silently drops
 * `undefined`, accepts NaN as `null`, and preserves insertion order.
 */
export function canonicalize(value: unknown, path = '', seen = new WeakSet<object>()): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';

    case 'number': {
      if (!Number.isFinite(value)) {
        throw new UndigestibleValueError(`non-finite number (${String(value)})`, path);
      }
      return JSON.stringify(Object.is(value, -0) ? 0 : value);
    }

    case 'string':
      return JSON.stringify(value);

    case 'undefined':
      throw new UndigestibleValueError('undefined is not representable', path);

    case 'bigint':
      throw new UndigestibleValueError('bigint is not representable', path);

    case 'function':
      throw new UndigestibleValueError('function is not representable', path);

    case 'symbol':
      throw new UndigestibleValueError('symbol is not representable', path);
  }

  const obj = value as object;
  if (seen.has(obj)) throw new UndigestibleValueError('circular reference', path);
  seen.add(obj);

  try {
    if (Array.isArray(obj)) {
      const items = obj.map((item, i) => canonicalize(item, `${path}[${i}]`, seen));
      return `[${items.join(',')}]`;
    }

    if (Object.getPrototypeOf(obj) !== Object.prototype && Object.getPrototypeOf(obj) !== null) {
      throw new UndigestibleValueError('only plain objects are representable', path);
    }

    const keys = Object.keys(obj).sort();
    const parts = keys.map((key) => {
      if (FORBIDDEN_KEYS.has(key)) {
        throw new UndigestibleValueError(`forbidden key "${key}"`, path);
      }
      const child = (obj as Record<string, unknown>)[key];
      return `${JSON.stringify(key)}:${canonicalize(child, path ? `${path}.${key}` : key, seen)}`;
    });
    return `{${parts.join(',')}}`;
  } finally {
    seen.delete(obj);
  }
}

/** `sha256:<hex>` over the canonical form of the action. */
export function actionDigest(action: DigestibleAction): string {
  const canonical = canonicalize({
    workspace_id: action.workspace_id,
    human_id: action.human_id,
    agent_id: action.agent_id,
    client_id: action.client_id,
    tool: action.tool,
    action: action.action,
    resource: { type: action.resource.type, id: action.resource.id },
    arguments: action.arguments,
    declared_intent: action.declared_intent,
    destination: action.destination,
  });
  return `sha256:${createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
}

/**
 * Constant-time comparison. Approval checking compares a stored digest against a
 * freshly computed one; a length-or-content early exit leaks position information.
 */
export function digestsEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
