/**
 * Redirect URIs, and the open redirect that comes from loosening one comparison.
 *
 * A redirect URI is where an authorization code gets delivered. Every published
 * open-redirect in an otherwise correct authorization server traces back to a
 * server that compared these with something other than equality.
 */

import { describe, expect, it } from 'vitest';
import {
  redirectUriAllowed,
  redirectUriMatches,
  validateRegistration,
  type OAuthClient,
} from '../src/clients.ts';

const client: OAuthClient = {
  id: 'oac_test',
  clientName: 'Test client',
  redirectUris: ['http://127.0.0.1:7777/callback', 'https://app.example.com/cb'],
};

describe('where a code may be delivered', () => {
  it('allows https anywhere', () => {
    expect(redirectUriAllowed('https://app.example.com/cb')).toBe(true);
  });

  it('allows loopback over plain http, which is how native clients work', () => {
    expect(redirectUriAllowed('http://127.0.0.1:7777/callback')).toBe(true);
    expect(redirectUriAllowed('http://[::1]:7777/callback')).toBe(true);
  });

  it('refuses cleartext to anywhere but this machine', () => {
    // A code in transit over http to a remote host is a code somebody else also
    // has.
    expect(redirectUriAllowed('http://app.example.com/cb')).toBe(false);
    expect(redirectUriAllowed('http://169.254.169.254/cb')).toBe(false);
  });

  it('allows localhost by name, because real clients use it', () => {
    // This was refused, on the reasoning that name resolution is one more thing
    // between the browser and the intended listener. RFC 8252 §7.3 says the IP
    // literal is *preferred*, not required — and `mcp-remote`, the standard
    // shim every stdio-only MCP client uses, registers
    // `http://localhost:PORT/oauth/callback`. The hardening refused every
    // conforming client and bought little: an attacker who controls the user's
    // name resolution already has more than an authorization code, and the code
    // is worthless without the PKCE verifier that never leaves the client.
    expect(redirectUriAllowed('http://localhost:5769/oauth/callback')).toBe(true);
  });

  it('is not fooled by a host that merely starts with localhost', () => {
    // `localhost.evil.test` is somebody else's domain.
    expect(redirectUriAllowed('http://localhost.evil.test/cb')).toBe(false);
    expect(redirectUriAllowed('http://localhosts/cb')).toBe(false);
    expect(redirectUriAllowed('http://notlocalhost/cb')).toBe(false);
  });

  it('allows a private-use scheme, which never leaves the device', () => {
    expect(redirectUriAllowed('com.example.app:/oauth')).toBe(true);
  });

  it('refuses a fragment', () => {
    // Never part of a redirect URI, and a classic way to smuggle one target
    // inside another.
    expect(redirectUriAllowed('https://app.example.com/cb#@evil.example')).toBe(false);
  });

  it('refuses something absurdly long', () => {
    expect(redirectUriAllowed(`https://app.example.com/${'a'.repeat(3000)}`)).toBe(false);
  });
});

describe('matching a request against what was registered', () => {
  it('accepts the exact string', () => {
    expect(redirectUriMatches(client, 'https://app.example.com/cb')).toBe(true);
  });

  it('refuses a longer path under the same origin', () => {
    // Prefix matching is the specific mistake. `/cb/../evil` is under `/cb`.
    expect(redirectUriMatches(client, 'https://app.example.com/cb/evil')).toBe(false);
  });

  it('refuses an added query parameter', () => {
    expect(redirectUriMatches(client, 'https://app.example.com/cb?next=//evil.example')).toBe(
      false,
    );
  });

  it('refuses a different port on the loopback address', () => {
    // Another process on the same machine is still another process.
    expect(redirectUriMatches(client, 'http://127.0.0.1:7778/callback')).toBe(false);
  });

  it('refuses a lookalike host', () => {
    expect(redirectUriMatches(client, 'https://app.example.com.evil.test/cb')).toBe(false);
  });

  it('refuses a trailing slash the client did not register', () => {
    expect(redirectUriMatches(client, 'https://app.example.com/cb/')).toBe(false);
  });
});

describe('what may be registered', () => {
  it('accepts a normal registration', () => {
    expect(validateRegistration('Claude Desktop', ['http://127.0.0.1:7777/cb'])).toBeNull();
  });

  it('refuses a registration with no redirect URI', () => {
    expect(validateRegistration('Claude Desktop', [])).toBe('REDIRECT_URIS_MISSING');
  });

  it('refuses a registration where any URI is disallowed', () => {
    // One bad entry poisons the registration; a client cannot smuggle a
    // cleartext target in alongside a good one.
    expect(
      validateRegistration('Claude Desktop', [
        'https://app.example.com/cb',
        'http://evil.example/cb',
      ]),
    ).toBe('REDIRECT_URI_INVALID');
  });

  it('refuses an empty name', () => {
    expect(validateRegistration('   ', ['https://app.example.com/cb'])).toBe('NAME_INVALID');
  });

  it('refuses a name that can rewrite how the screen reads', () => {
    // The consent screen shows this name to a person who is deciding. React
    // escapes it, so there is no XSS — but a right-to-left override reverses
    // the text that follows it, and a person reading "Veto Admin ⁧settings"
    // has been told something the string does not say.
    //
    // Rejected rather than stripped: silently changing what a client asked to
    // be called would show one name here and another in its own UI.
    const bidi = ['\u202E', '\u202A', '\u2066', '\u200F', '\u200E'];
    for (const mark of bidi) {
      expect(
        validateRegistration(`Veto Admin${mark} gnitteS`, ['https://app.example.com/cb']),
        JSON.stringify(mark),
      ).toBe('NAME_INVALID');
    }
  });

  it('refuses invisible characters', () => {
    // A zero-width space splits a word that reads as one, so two different
    // clients can present the same name to a person.
    for (const mark of ['\u200B', '\u200D', '\uFEFF']) {
      expect(
        validateRegistration(`Veto${mark} Admin`, ['https://app.example.com/cb']),
        JSON.stringify(mark),
      ).toBe('NAME_INVALID');
    }
  });

  it('refuses newlines and control characters', () => {
    // A name is one line on one screen. Anything that can add a second line is
    // a name that can add a sentence the product did not write.
    for (const mark of ['\n', '\r', '\t', '\u0000', '\u001B']) {
      expect(
        validateRegistration(`Claude${mark}verified`, ['https://app.example.com/cb']),
        JSON.stringify(mark),
      ).toBe('NAME_INVALID');
    }
  });

  it('still accepts ordinary names, including non-Latin ones', () => {
    // The rule is about characters that change how text is *read*, not about
    // which language it is in.
    for (const name of ['Claude Desktop', 'Cursor 2.0', 'クロード', 'Zürich Client']) {
      expect(validateRegistration(name, ['https://app.example.com/cb']), name).toBeNull();
    }
  });

  it('accepts a name that is a lie, because the consent screen owns that problem', () => {
    // A client calling itself "Veto Admin" is phishing. Nothing here can tell,
    // and pretending otherwise would put the check in the wrong place — the
    // consent screen has to be written so the name is not what convinces.
    expect(validateRegistration('Veto Admin', ['https://app.example.com/cb'])).toBeNull();
  });
});
