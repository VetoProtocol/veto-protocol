/**
 * Resource instance keys are scoped to their workspace (invariant 4).
 *
 * Permit enforces uniqueness on an instance by `(resource, key, environment)`,
 * not by tenant. Two workspaces cannot both hold an instance called `root` —
 * and `root` is not a Drive id at all, it is Google's alias for the top of
 * *this* account's My Drive, so it is the one key every single workspace uses.
 *
 * The first customer to grant it took it. Every customer after them got a 409
 * that the adapter swallowed as "already granted", a 201 from the API, and no
 * access. This file is the test that would have caught that.
 */

import { describe, expect, it } from 'vitest';
import {
  FOLDER_RESOURCE,
  resourceInstanceKey,
  scopedInstanceKey,
  unscopeInstanceKey,
} from '../src/model.ts';

const WS_A = 'ws_8okUBbecrOy3lIlw';
const WS_B = 'ws_otherTenant00001';

describe('two workspaces naming the same resource', () => {
  it('produce different instance keys', () => {
    // The whole bug in one assertion. `root` is every account's first folder.
    expect(scopedInstanceKey(WS_A, 'root')).not.toBe(scopedInstanceKey(WS_B, 'root'));
  });

  it('produce different instance references', () => {
    const a = resourceInstanceKey(FOLDER_RESOURCE, scopedInstanceKey(WS_A, 'root'));
    const b = resourceInstanceKey(FOLDER_RESOURCE, scopedInstanceKey(WS_B, 'root'));
    expect(a).not.toBe(b);
    expect(a.startsWith(`${FOLDER_RESOURCE}:`)).toBe(true);
  });

  it('collide once unscoped, which is what Permit rejected', () => {
    // Left here as the record of what the old behaviour was.
    expect(resourceInstanceKey(FOLDER_RESOURCE, 'root')).toBe(
      resourceInstanceKey(FOLDER_RESOURCE, 'root'),
    );
  });
});

describe('reading a scoped key back', () => {
  it('returns the original resource key', () => {
    expect(unscopeInstanceKey(WS_A, scopedInstanceKey(WS_A, 'root'))).toBe('root');
  });

  it('round-trips a real Drive id, underscores and hyphens included', () => {
    const driveId = '1GoTzZ-vRzbw9p3xR2kMZs5qZ0PzpEif6z1eyWhpR0ts';
    expect(unscopeInstanceKey(WS_A, scopedInstanceKey(WS_A, driveId))).toBe(driveId);
  });

  it('refuses another workspace’s key rather than guessing', () => {
    // Falling back to the raw string would report B's resource as A's, which is
    // precisely the leak the scoping exists to prevent.
    expect(unscopeInstanceKey(WS_A, scopedInstanceKey(WS_B, 'root'))).toBeNull();
  });

  it('refuses an unscoped key', () => {
    expect(unscopeInstanceKey(WS_A, 'root')).toBeNull();
  });
});

describe('the grammar Permit enforces', () => {
  const PERMIT_INSTANCE_KEY = /^[A-Za-z0-9\-_]+$/;

  it('accepts a scoped Drive id', () => {
    const key = scopedInstanceKey(WS_A, '1GoTzZ-vRzbw9p3xR2kMZs5qZ0PzpEif6z1eyWhpR0ts');
    // A key Permit refuses is a 422 at grant time, so the separator has to live
    // inside the alphabet it allows.
    expect(PERMIT_INSTANCE_KEY.test(key)).toBe(true);
  });

  it('accepts a scoped alias', () => {
    expect(PERMIT_INSTANCE_KEY.test(scopedInstanceKey(WS_A, 'root'))).toBe(true);
  });

  it('accepts a scoped user id, for mailbox and calendar instances', () => {
    expect(PERMIT_INSTANCE_KEY.test(scopedInstanceKey(WS_A, 'usr_Vy98CGmrjKSoleT_'))).toBe(true);
  });
});

describe('the separator', () => {
  it('is not confused by a single underscore inside a workspace id', () => {
    // `ws_a` + `__` + `b_c` must not be read as `ws` + `_` + `a__b_c`.
    const key = scopedInstanceKey('ws_a', 'b_c');
    expect(unscopeInstanceKey('ws_a', key)).toBe('b_c');
    expect(unscopeInstanceKey('ws', key)).toBeNull();
  });
});
