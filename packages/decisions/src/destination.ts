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

/**
 * An IPv6 address as its sixteen bytes, or null if it will not parse.
 *
 * Classifying IPv6 by the *text* is what went wrong here. `::ffff:127.0.0.1`
 * was recognised and `::ffff:7f00:1` was not, although they are the same
 * address — one written with a dotted tail and one without. A blocklist that
 * matches spellings can always be spelled around, so this decodes once and
 * every rule below reads bytes.
 *
 * Returns null rather than throwing. The one caller treats null as blocked,
 * which is the direction an unparseable address should fail.
 */
function expandV6(address: string): readonly number[] | null {
  const text = address.toLowerCase().replace(/^\[|\]$/g, '');
  if (text.includes('%')) return null; // zone index: not an address we route to

  const halves = text.split('::');
  if (halves.length > 2) return null;

  const toWords = (part: string): number[] | null => {
    if (part === '') return [];
    const words: number[] = [];
    const groups = part.split(':');

    for (const [index, group] of groups.entries()) {
      // A dotted tail is only legal as the final group, and stands for the low
      // thirty-two bits: `::ffff:127.0.0.1` and `::ffff:7f00:1` are one address.
      if (group.includes('.')) {
        if (index !== groups.length - 1) return null;
        const octets = group.split('.').map(Number);
        if (octets.length !== 4) return null;
        if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
        words.push(((octets[0] ?? 0) << 8) | (octets[1] ?? 0));
        words.push(((octets[2] ?? 0) << 8) | (octets[3] ?? 0));
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
      words.push(Number.parseInt(group, 16));
    }
    return words;
  };

  const head = toWords(halves[0] ?? '');
  const tail = halves.length === 2 ? toWords(halves[1] ?? '') : [];
  if (head === null || tail === null) return null;

  let words: number[];
  if (halves.length === 2) {
    const gap = 8 - head.length - tail.length;
    if (gap < 1) return null; // `::` must stand for at least one zero group
    words = [...head, ...Array<number>(gap).fill(0), ...tail];
  } else {
    words = head;
  }
  if (words.length !== 8) return null;

  const bytes: number[] = [];
  for (const word of words) {
    if (!Number.isInteger(word) || word < 0 || word > 0xffff) return null;
    bytes.push((word >> 8) & 0xff, word & 0xff);
  }
  return bytes;
}

const allZero = (bytes: readonly number[], upTo: number): boolean =>
  bytes.slice(0, upTo).every((b) => b === 0);

/** The low thirty-two bits read as an IPv4 address. */
const trailingV4 = (bytes: readonly number[]): string =>
  `${bytes[12] ?? 0}.${bytes[13] ?? 0}.${bytes[14] ?? 0}.${bytes[15] ?? 0}`;

function isBlockedV6(address: string): boolean {
  const bytes = expandV6(address);
  if (bytes === null) return true; // unparseable is refused, not allowed

  const first = bytes[0] ?? 0;
  const second = bytes[1] ?? 0;

  // Every form that carries an IPv4 address inside it gets the IPv4 rules,
  // because reaching 127.0.0.1 is reaching 127.0.0.1 however it is written.
  //
  //   ::ffff:0:0/96   IPv4-mapped, the common one
  //   ::/96           IPv4-compatible (deprecated, still routed by some stacks),
  //                   which also covers :: and ::1
  //   64:ff9b::/96    NAT64, a translator whose whole job is to reach IPv4
  if (allZero(bytes, 10) && bytes[10] === 0xff && bytes[11] === 0xff) {
    return isBlockedV4(trailingV4(bytes));
  }
  if (allZero(bytes, 12)) return true;
  if (first === 0x00 && second === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b) {
    return isBlockedV4(trailingV4(bytes));
  }

  if (first === 0xfe && (second & 0xc0) === 0x80) return true; // fe80::/10 link-local
  if ((first & 0xfe) === 0xfc) return true; // fc00::/7 unique local
  if (first === 0xff) return true; // ff00::/8 multicast

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
