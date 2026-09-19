import { describe, expect, it } from 'vitest';
import {
  DEFAULT_TTL_MS,
  PresenceTransitionError,
  assertTransition,
  effectiveState,
  meetsAssurance,
  type Presence,
} from '../src/state.ts';

const at = (state: Presence['state'], over: Partial<Presence> = {}): Presence => ({
  state,
  assurance: 'medium',
  source: 'dashboard',
  changedAt: new Date(),
  expiresAt: null,
  ...over,
});

describe('transitions', () => {
  it('allows the ordinary moves', () => {
    expect(() => assertTransition('active', { to: 'away', source: 'device_activity', assurance: 'low' })).not.toThrow();
    expect(() => assertTransition('away', { to: 'active', source: 'passkey', assurance: 'high' })).not.toThrow();
  });

  it('lets anything become locked', () => {
    for (const from of ['active', 'away', 'automation', 'locked'] as const) {
      expect(() => assertTransition(from, { to: 'locked', source: 'operator', assurance: 'medium' })).not.toThrow();
    }
  });

  it('will not let background activity clear a lock', () => {
    // §12.1: a lock set during an active session must not lift because a device
    // started sending signals again.
    expect(() =>
      assertTransition('locked', { to: 'active', source: 'device_activity', assurance: 'low' }),
    ).toThrow(PresenceTransitionError);

    expect(() =>
      assertTransition('locked', { to: 'active', source: 'passkey', assurance: 'high' }),
    ).not.toThrow();
  });

  it('will not let a source claim more confidence than it can witness', () => {
    // Otherwise assurance is just a number the caller picks.
    expect(() =>
      assertTransition('away', { to: 'active', source: 'device_activity', assurance: 'high' }),
    ).toThrow(/cannot assert high/);

    expect(() =>
      assertTransition('away', { to: 'active', source: 'dashboard', assurance: 'high' }),
    ).toThrow(PresenceTransitionError);
  });

  it('requires automation to name a window', () => {
    expect(() =>
      assertTransition('active', { to: 'automation', source: 'operator', assurance: 'medium' }),
    ).toThrow(/expiry/);

    expect(() =>
      assertTransition('active', {
        to: 'automation', source: 'operator', assurance: 'medium', ttlMs: DEFAULT_TTL_MS,
      }),
    ).not.toThrow();
  });

  it('will not let automation drift into an interactive state', () => {
    expect(() =>
      assertTransition('automation', { to: 'active', source: 'device_activity', assurance: 'low' }),
    ).toThrow(PresenceTransitionError);
  });

  it('rejects a state that does not exist', () => {
    expect(() =>
      assertTransition('active', { to: 'online' as never, source: 'operator', assurance: 'low' }),
    ).toThrow(/unknown state/);
  });
});

describe('what a record means now', () => {
  it('treats no record as away, never as active', () => {
    // Absence of a signal is not evidence of presence.
    expect(effectiveState(null).state).toBe('away');
  });

  it('decays an expired record downward', () => {
    const stale = at('active', { expiresAt: new Date(Date.now() - 1000), assurance: 'high' });
    const now = effectiveState(stale);

    expect(now.state).toBe('away');
    // Confidence lapses with the state.
    expect(now.assurance).toBe('low');
  });

  it('keeps a lapsed lock locked', () => {
    // A lock that expires on a timer is a lock an attacker only has to outwait.
    const stale = at('locked', { expiresAt: new Date(Date.now() - 1000) });
    expect(effectiveState(stale).state).toBe('locked');
  });

  it('leaves a live record alone', () => {
    const live = at('active', { expiresAt: new Date(Date.now() + 60_000) });
    expect(effectiveState(live)).toEqual(live);
  });
});

describe('assurance', () => {
  it('compares in order', () => {
    expect(meetsAssurance('high', 'medium')).toBe(true);
    expect(meetsAssurance('medium', 'medium')).toBe(true);
    expect(meetsAssurance('low', 'medium')).toBe(false);
  });
});
