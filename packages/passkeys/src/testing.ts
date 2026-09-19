/**
 * A virtual authenticator, for tests only.
 *
 * Shipped from `src` rather than `test` so other packages can import it — an
 * end-to-end approval test needs a real signature, and cross-package test
 * imports break `rootDir`. Guarded the same way the other fakes are: it refuses
 * to load outside NODE_ENV=test, so it can never be part of a running server.
 *
 * Exists so there is a *positive* case. Without one, a verifier that rejects
 * everything — including valid signatures — passes every negative test there
 * is, and "nothing gets through" is indistinguishable from "nothing works".
 *
 * It implements the smallest real thing: an ES256 key pair, a COSE-encoded
 * public key, and an assertion signed the way WebAuthn specifies — over
 * `authenticatorData || SHA-256(clientDataJSON)`.
 */

import { createHash, createSign, generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto';

/** CBOR for the five-entry ES256 COSE key. Only this shape is needed. */
function coseEs256(x: Buffer, y: Buffer): Buffer {
  const bytes32 = (b: Buffer) => Buffer.concat([Buffer.from([0x58, 0x20]), b]);
  return Buffer.concat([
    Buffer.from([0xa5]), //        map(5)
    Buffer.from([0x01, 0x02]), //  1 (kty)  : 2   (EC2)
    Buffer.from([0x03, 0x26]), //  3 (alg)  : -7  (ES256)
    Buffer.from([0x20, 0x01]), // -1 (crv)  : 1   (P-256)
    Buffer.from([0x21]),
    bytes32(x), //                 -2 (x)
    Buffer.from([0x22]),
    bytes32(y), //                 -3 (y)
  ]);
}

export interface VirtualAuthenticator {
  readonly credentialId: Buffer;
  readonly publicKey: Buffer;
  assert(options: {
    challenge: Buffer;
    origin: string;
    rpID: string;
    signCount: number;
    /** Leave user verification unset, to prove `required` is enforced. */
    userVerified?: boolean;
  }): Record<string, unknown>;
}

export function createVirtualAuthenticator(): VirtualAuthenticator {
  if (process.env['NODE_ENV'] !== 'test') {
    throw new Error('createVirtualAuthenticator() is test-only and must never run outside NODE_ENV=test');
  }

  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

  // Uncompressed point: 0x04 || X(32) || Y(32).
  const raw = publicKey.export({ format: 'der', type: 'spki' });
  const point = raw.subarray(raw.length - 65);
  const x = point.subarray(1, 33);
  const y = point.subarray(33, 65);

  const credentialId = randomBytes(32);

  return {
    credentialId,
    publicKey: coseEs256(x, y),

    assert({ challenge, origin, rpID, signCount, userVerified = true }) {
      const clientData = Buffer.from(
        JSON.stringify({
          type: 'webauthn.get',
          challenge: challenge.toString('base64url'),
          origin,
          crossOrigin: false,
        }),
        'utf8',
      );

      // UP (0x01) always; UV (0x04) only when the user actually verified.
      const flags = userVerified ? 0x05 : 0x01;
      const counter = Buffer.alloc(4);
      counter.writeUInt32BE(signCount, 0);

      const authData = Buffer.concat([
        createHash('sha256').update(rpID, 'utf8').digest(),
        Buffer.from([flags]),
        counter,
      ]);

      const signature = sign(privateKey, authData, clientData);

      return {
        id: credentialId.toString('base64url'),
        rawId: credentialId.toString('base64url'),
        type: 'public-key',
        clientExtensionResults: {},
        response: {
          authenticatorData: authData.toString('base64url'),
          clientDataJSON: clientData.toString('base64url'),
          signature: signature.toString('base64url'),
          userHandle: null,
        },
      };
    },
  };
}

function sign(privateKey: KeyObject, authData: Buffer, clientData: Buffer): Buffer {
  const payload = Buffer.concat([authData, createHash('sha256').update(clientData).digest()]);
  return createSign('sha256').update(payload).sign(privateKey);
}
