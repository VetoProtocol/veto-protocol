/**
 * Step 6 checks, in isolation (§12.1 SSRF, invariant 10).
 */

import { describe, expect, it } from 'vitest';
import { checkDestination, isBlockedAddress } from '../src/destination.ts';
import { assessRisk, findCredentialShapedArguments } from '../src/risk.ts';
import { request } from './helpers.ts';

const never = async (): Promise<readonly string[]> => {
  throw new Error('resolution should not have been attempted');
};
const resolvesTo = (...addresses: string[]) => async () => addresses;

describe('§12.1 — a request targeting a private or metadata address', () => {
  it('blocks every address range that must never be reachable', () => {
    for (const address of [
      '127.0.0.1', '127.9.9.9', '0.0.0.0',
      '169.254.169.254',            // AWS/GCP/Azure instance metadata
      '10.0.0.5', '172.16.0.1', '172.31.255.254', '192.168.1.1',
      '100.64.0.1',                 // CGNAT
      '192.0.0.192',                // Oracle Cloud metadata
      '224.0.0.1', '255.255.255.255',
      '::1', '::', 'fe80::1', 'fd00::1', 'ff02::1',
      '::ffff:169.254.169.254',     // the metadata address wearing a hat
      'not-an-address',
      // The same addresses with a hex tail instead of a dotted one. Every line
      // here was ALLOWED until the v6 check stopped matching spellings and
      // started decoding bytes — including cloud metadata.
      '::ffff:7f00:1',              // 127.0.0.1
      '::ffff:a9fe:a9fe',           // 169.254.169.254, metadata
      '::ffff:c0a8:1',              // 192.168.0.1
      '::ffff:0a00:1',              // 10.0.0.1
      '::ffff:ac10:1',              // 172.16.0.1
      '::7f00:1',                   // IPv4-compatible loopback
      '::127.0.0.1',
      '64:ff9b::7f00:1',            // NAT64, a translator built to reach IPv4
      '64:ff9b::169.254.169.254',
      // Prefix families written out in full, where a startsWith test could slip.
      'fe80:0000:0000:0000:0000:0000:0000:0001',
      'fc00::1', 'fdff::1', 'ff00::1',
      // Malformed input is refused, never allowed through.
      '::ffff:999.1.1.1', ':::1', '1:2:3:4:5:6:7:8:9',
    ]) {
      expect(isBlockedAddress(address), address).toBe(true);
    }
  });

  it('permits ordinary public addresses', () => {
    for (const address of [
      '8.8.8.8', '1.1.1.1', '142.251.127.84', '2a00:1450:4001:c21::54',
      '2001:4860:4860::8888',
      '2606:4700:4700::1111',
      // Public v4 inside a v6 wrapper is still public. The fix must not block
      // by wrapper shape — only by the address the wrapper carries.
      '::ffff:8.8.8.8', '::ffff:0808:0808',
      // Near neighbours of the blocked prefixes. fe00 is not fe80::/10 and
      // fb00 is not fc00::/7; a sloppy mask would swallow both.
      'fe00::1', 'fb00::1',
    ]) {
      expect(isBlockedAddress(address), address).toBe(false);
    }
  });

  it('refuses a literal metadata URL without any lookup', async () => {
    const verdict = await checkDestination('https://169.254.169.254/latest/meta-data/', never);
    expect(verdict.ok).toBe(false);
  });

  it('refuses a hostname that resolves into a blocked range', async () => {
    // A name check alone proves nothing: evil.example can point at 127.0.0.1.
    const verdict = await checkDestination('https://evil.example/', resolvesTo('127.0.0.1'));
    expect(verdict.ok).toBe(false);
  });

  it('refuses a name with one public and one private address', async () => {
    // The DNS-rebinding shape. Checking only the first answer would pass this.
    const verdict = await checkDestination('https://mixed.example/', resolvesTo('8.8.8.8', '10.0.0.1'));
    expect(verdict.ok).toBe(false);
  });

  it('refuses anything that is not https, and credentials in the URL', async () => {
    for (const url of [
      'http://example.com/',
      'file:///etc/passwd',
      'gopher://example.com/',
      'https://user:pass@example.com/',
    ]) {
      expect((await checkDestination(url, resolvesTo('8.8.8.8'))).ok, url).toBe(false);
    }
  });

  it('refuses a host that will not resolve rather than attempting it', async () => {
    expect((await checkDestination('https://nothing.invalid/', never)).ok).toBe(false);
  });

  it('returns the addresses it checked, so the connect can pin them', async () => {
    // The verdict is only true of the addresses named here. Resolving again at
    // connect time would reopen the rebinding window.
    const verdict = await checkDestination('https://ok.example/', resolvesTo('8.8.8.8'));
    expect(verdict).toEqual({ ok: true, addresses: ['8.8.8.8'] });
  });
});

describe('credentials never arrive through tool arguments (invariant 10)', () => {
  it('spots credential shapes, however deeply nested', () => {
    for (const args of [
      { header: 'Bearer sk_live_abcdefghijklmnop12345' },
      { key: 'sk-ABCDEFGHIJKLMNOPQRST' },
      { token: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWX' },
      { aws: 'AKIAIOSFODNN7EXAMPLE' },
      { pem: '-----BEGIN PRIVATE KEY-----\nMIIE' },
      { jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc' },
      { note: 'password: hunter2hunter2' },
      { nested: { deeper: [{ v: 'refresh_token=1//0abcdefghij' }] } },
    ]) {
      expect(findCredentialShapedArguments(args), JSON.stringify(args)).toBe(true);
    }
  });

  it('leaves ordinary arguments alone', () => {
    expect(findCredentialShapedArguments({ fields: ['name', 'content'], file_id: '1abc' })).toBe(false);
    expect(findCredentialShapedArguments({ note: 'discuss the password policy' })).toBe(false);
  });

  it('survives a cyclic argument object instead of hanging', () => {
    const cyclic: Record<string, unknown> = { a: 1 };
    cyclic['self'] = cyclic;
    expect(findCredentialShapedArguments(cyclic)).toBe(false);
  });
});

describe('assessRisk', () => {
  const input = (over: Record<string, unknown> = {}) =>
    request({ workspaceId: 'ws_x', humanId: 'usr_x', agentId: 'agt_x', ...over });

  it('denies a credential-shaped argument', async () => {
    const finding = await assessRisk(
      input({ arguments: { q: 'Bearer sk_live_abcdefghijklmnop12345' } }),
      { requireIntent: false },
    );
    expect(finding?.result).toBe('deny');
    expect(finding?.reasonCode).toBe('SENSITIVE_ARGUMENT_BLOCKED');
  });

  it('challenges rather than denying when a required intent is missing', async () => {
    // Intent can raise a challenge. It can never authorise one (FR-11).
    const finding = await assessRisk(input({ declaredIntent: null }), { requireIntent: true });
    expect(finding?.result).toBe('challenge');
    expect(finding?.reasonCode).toBe('INTENT_MISMATCH');
  });

  it('passes a clean request', async () => {
    expect(await assessRisk(input(), { requireIntent: true })).toBeNull();
  });

  it('does not leak why a destination was refused', async () => {
    const finding = await assessRisk(
      input({ destination: 'https://169.254.169.254/' }),
      { requireIntent: false },
    );
    expect(finding?.result).toBe('deny');
    // Telling a prober which ranges are blocked maps the network for them.
    expect(finding?.message).not.toMatch(/169|private|loopback|link-local/i);
  });
});
