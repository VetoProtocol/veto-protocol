/**
 * The webhook signature scheme (spec §5.4).
 *
 * §5.4 asks for four things by name — HMAC signatures, timestamp tolerance,
 * replay protection, event identifiers — and every one of them is a property
 * somebody can implement in a way that passes a happy-path test and protects
 * nothing. So each has its attack here rather than only its success case.
 */

import { describe, expect, it } from 'vitest';
import {
  DEFAULT_TOLERANCE_SECONDS,
  ID_HEADER,
  SIGNATURE_HEADER,
  TIMESTAMP_HEADER,
  signDelivery,
  verifyDelivery,
} from '../src/signature.ts';

const SECRET = 's'.repeat(43);
const OTHER = 'o'.repeat(43);
const EVENT = 'evt_abc123';
const BODY = JSON.stringify({ id: EVENT, type: 'workspace.locked' });

const NOW = 1_789_800_000;

const sign = (over: Partial<{ secret: string; eventId: string; body: string; at: number }> = {}) =>
  signDelivery(over.secret ?? SECRET, {
    eventId: over.eventId ?? EVENT,
    body: over.body ?? BODY,
    timestampSeconds: over.at ?? NOW,
  });

const verify = (
  signed: ReturnType<typeof signDelivery>,
  over: Partial<{ secret: string; body: string; now: number }> = {},
) =>
  verifyDelivery(over.secret ?? SECRET, {
    body: over.body ?? signed.body,
    headers: signed.headers,
    nowSeconds: over.now ?? NOW,
  });

describe('signing', () => {
  it('round trips', () => {
    expect(verify(sign())).toEqual({ ok: true, eventId: EVENT });
  });

  it('carries the event id, the timestamp and a versioned signature', () => {
    const { headers } = sign();
    expect(headers[ID_HEADER]).toBe(EVENT);
    expect(headers[TIMESTAMP_HEADER]).toBe(String(NOW));
    expect(headers[SIGNATURE_HEADER]).toMatch(/^v1=[A-Za-z0-9_-]+$/);
  });
});

describe('what the signature actually covers', () => {
  it('refuses a changed body', () => {
    const signed = sign();
    expect(verify(signed, { body: `${BODY} ` })).toEqual({ ok: false, reason: 'bad-signature' });
  });

  it('refuses a rewritten timestamp', () => {
    // The point of putting the timestamp inside the MAC. Without it, an
    // attacker holding a captured request just updates the header and the
    // tolerance check becomes decorative.
    const signed = sign();
    const headers = { ...signed.headers, [TIMESTAMP_HEADER]: String(NOW + 10) };
    expect(verifyDelivery(SECRET, { body: signed.body, headers, nowSeconds: NOW + 10 })).toEqual({
      ok: false,
      reason: 'bad-signature',
    });
  });

  it('refuses a signature moved onto a different event with the same body', () => {
    // Two denials of the same action by the same agent produce identical
    // bodies. They are still different events, and a signature from one must
    // not validate the other.
    const first = sign({ eventId: 'evt_first0' });
    const headers = { ...first.headers, [ID_HEADER]: 'evt_second' };
    expect(verifyDelivery(SECRET, { body: first.body, headers, nowSeconds: NOW })).toEqual({
      ok: false,
      reason: 'bad-signature',
    });
  });

  it('cannot be shuffled between fields', () => {
    // `('evt_ab', t)` and `('evt_a', ...)` must not sign the same bytes. The id
    // charset excludes the separator, which is what makes this hold.
    const a = sign({ eventId: 'evt_ab' });
    const b = sign({ eventId: 'evt_a' });
    expect(a.headers[SIGNATURE_HEADER]).not.toBe(b.headers[SIGNATURE_HEADER]);
  });

  it('refuses another endpoint’s secret', () => {
    // Per-endpoint secrets: one compromised receiver cannot forge events to
    // another.
    expect(verify(sign(), { secret: OTHER })).toEqual({ ok: false, reason: 'bad-signature' });
  });
});

describe('timestamp tolerance', () => {
  it('accepts inside the window', () => {
    expect(verify(sign(), { now: NOW + DEFAULT_TOLERANCE_SECONDS - 1 }).ok).toBe(true);
  });

  it('refuses a captured request replayed later', () => {
    expect(verify(sign(), { now: NOW + DEFAULT_TOLERANCE_SECONDS + 1 })).toEqual({
      ok: false,
      reason: 'stale',
    });
  });

  it('refuses a timestamp from the future, not only from the past', () => {
    // Checking one direction leaves an attacker a forward window to sign into.
    expect(verify(sign(), { now: NOW - DEFAULT_TOLERANCE_SECONDS - 1 })).toEqual({
      ok: false,
      reason: 'stale',
    });
  });

  it('refuses a timestamp that is not a number', () => {
    for (const bad of ['300abc', ' 300', '0x12c', '3e2', '', '-300']) {
      const signed = sign();
      const headers = { ...signed.headers, [TIMESTAMP_HEADER]: bad };
      expect(verifyDelivery(SECRET, { body: signed.body, headers, nowSeconds: NOW }), bad).toEqual({
        ok: false,
        reason: 'bad-timestamp',
      });
    }
  });
});

describe('what a receiver must not accept', () => {
  it('refuses a missing header rather than skipping the check', () => {
    const signed = sign();
    for (const header of [ID_HEADER, TIMESTAMP_HEADER, SIGNATURE_HEADER]) {
      const headers: Record<string, string | undefined> = { ...signed.headers };
      delete headers[header];
      expect(
        verifyDelivery(SECRET, { body: signed.body, headers, nowSeconds: NOW }),
        header,
      ).toEqual({ ok: false, reason: 'missing-headers' });
    }
  });

  it('refuses an unknown scheme version rather than guessing', () => {
    const signed = sign();
    const raw = signed.headers[SIGNATURE_HEADER] ?? '';
    const headers = { ...signed.headers, [SIGNATURE_HEADER]: raw.replace('v1=', 'v2=') };
    expect(verifyDelivery(SECRET, { body: signed.body, headers, nowSeconds: NOW })).toEqual({
      ok: false,
      reason: 'unknown-version',
    });
  });

  it('refuses a bare signature with no version prefix', () => {
    const signed = sign();
    const raw = (signed.headers[SIGNATURE_HEADER] ?? '').replace('v1=', '');
    const headers = { ...signed.headers, [SIGNATURE_HEADER]: raw };
    expect(verifyDelivery(SECRET, { body: signed.body, headers, nowSeconds: NOW })).toEqual({
      ok: false,
      reason: 'unknown-version',
    });
  });
});

describe('retries', () => {
  it('keeps the event id and moves the timestamp', () => {
    // The contract §5.4's "idempotent consumers" hangs on. A retry two hours
    // later has to pass the tolerance check, so it is re-signed — and it has to
    // be recognisable as the same event, so the id does not move.
    const first = sign({ at: NOW });
    const retry = sign({ at: NOW + 7200 });

    expect(retry.headers[ID_HEADER]).toBe(first.headers[ID_HEADER]);
    expect(retry.headers[SIGNATURE_HEADER]).not.toBe(first.headers[SIGNATURE_HEADER]);
    expect(verify(retry, { now: NOW + 7200 }).ok).toBe(true);
    // And the original is by then too old to be replayed.
    expect(verify(first, { now: NOW + 7200 })).toEqual({ ok: false, reason: 'stale' });
  });
});
