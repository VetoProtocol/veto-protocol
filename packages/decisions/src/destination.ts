/**
 * Destination checks — SSRF and the cloud metadata service (§12.1, T12).
 *
 * The scenario this exists for: a compromised agent asks the gateway to send
 * something to `http://169.254.169.254/latest/meta-data/iam/...` and walks off
 * with the instance's cloud credentials. The gateway sits inside the network
 * perimeter, so it is a far better SSRF victim than the agent is.
 *
 * ## What this can and cannot prove
 *
 * A name check alone is not enough: `evil.example` can resolve to 127.0.0.1,
 * and can resolve differently on the second lookup than the first — DNS
 * rebinding. So this resolves the name and checks every address it gets back,
 * and **the connect in phase 5 must pin the address that was checked** rather
 * than resolving again. That is recorded here because the check looks complete
 * and is not: a passing result means "these addresses were safe a moment ago".
 *
 * Failure is denial. A name that will not resolve is refused rather than
 * attempted (invariant 1).
 */

import { isIP } from 'node:net';
import { lookup } from 'node:dns/promises';

export type DestinationVerdict =
  | { readonly ok: true; readonly addresses: readonly string[] }
  | { readonly ok: false; readonly why: string };

/** Ranges that must never be reachable from a tool argument. */
function isBlockedV4(address: string): boolean {
  const parts = address.split('.').map(Number);
  const [a = 0, b = 0] = parts;
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;

  if (a === 0) return true; // "this network"
  if (a === 10) return true; // RFC1918
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local, incl. 169.254.169.254 metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
  if (a === 192 && b === 168) return true; // RFC1918
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 192 && b === 0) return true; // IETF protocol assignments, incl. 192.0.0.192
  if (a >= 224) return true; // multicast and reserved
  return false;
}

function isBlockedV6(address: string): boolean {
  const lower = address.toLowerCase().replace(/^\[|\]$/g, '');
  if (lower === '::' || lower === '::1') return true; // unspecified, loopback
  if (lower.startsWith('fe80')) return true; // link-local
  if (/^f[cd]/.test(lower)) return true; // unique local
  if (lower.startsWith('ff')) return true; // multicast
  // IPv4-mapped (::ffff:169.254.169.254) is the same address wearing a hat.
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (mapped?.[1]) return isBlockedV4(mapped[1]);
  return false;
}

export const isBlockedAddress = (address: string): boolean => {
  const family = isIP(address);
  if (family === 4) return isBlockedV4(address);
  if (family === 6) return isBlockedV6(address);
  return true; // not an address at all
};

export async function checkDestination(
  destination: string,
  resolve: (host: string) => Promise<readonly string[]> = defaultResolve,
): Promise<DestinationVerdict> {
  let url: URL;
  try {
    url = new URL(destination);
  } catch {
    return { ok: false, why: 'not a URL' };
  }

  // https only. Plaintext can be rewritten in flight, and every other scheme —
  // file:, gopher:, ftp: — is a way to reach something that is not the web.
  if (url.protocol !== 'https:') return { ok: false, why: 'scheme must be https' };
  if (url.username !== '' || url.password !== '') {
    return { ok: false, why: 'credentials in a URL are never accepted' };
  }

  const host = url.hostname.replace(/^\[|\]$/g, '');

  if (isIP(host) !== 0) {
    return isBlockedAddress(host)
      ? { ok: false, why: 'address is private, loopback, or link-local' }
      : { ok: true, addresses: [host] };
  }

  let addresses: readonly string[];
  try {
    addresses = await resolve(host);
  } catch {
    return { ok: false, why: 'host does not resolve' };
  }

  if (addresses.length === 0) return { ok: false, why: 'host does not resolve' };

  // Every address, not the first: a name with one public and one private
  // address is a rebinding attack with extra steps.
  for (const address of addresses) {
    if (isBlockedAddress(address)) {
      return { ok: false, why: 'host resolves to a private, loopback, or link-local address' };
    }
  }

  return { ok: true, addresses };
}

async function defaultResolve(host: string): Promise<readonly string[]> {
  const records = await lookup(host, { all: true });
  return records.map((r) => r.address);
}
