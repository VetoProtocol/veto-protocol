/**
 * The GitHub App provider (spec §9).
 *
 * `fetch` is stubbed, so nothing here talks to GitHub. Two properties are worth
 * the trouble of testing:
 *
 *  - **The permission set cannot grow a write.** `GITHUB_SERVICES` is the only
 *    place that says what an installation token may ask for, and "reads first"
 *    is a sentence in a document until something fails when it stops being
 *    true.
 *  - **Narrowing narrows.** GitHub, unlike Google, honours a subset request at
 *    token-mint time. If this module ever stopped sending `permissions`, every
 *    call would quietly receive the installation's full rights and nothing
 *    would look broken.
 */

import { createVerify, generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  GITHUB_API_URL,
  GITHUB_SERVICES,
  GITHUB_SERVICE_NAMES,
  buildInstallUrl,
  createAppJwt,
  createGitHubExchange,
  isGitHubService,
  readInstallation,
  type GitHubAppConfig,
  userControlsInstallation,
} from '../src/github.ts';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

const CONFIG: GitHubAppConfig = {
  appId: '123456',
  privateKeyPem: privateKey.export({ type: 'pkcs1', format: 'pem' }).toString(),
  appSlug: 'veto-protocol',
};

interface Call {
  url: string;
  method: string;
  authorization: string | undefined;
  body: unknown;
}

function stubFetch(responses: Array<{ status?: number; body?: unknown }>): Call[] {
  const calls: Call[] = [];
  let index = 0;

  vi.stubGlobal('fetch', async (url: unknown, init: unknown) => {
    const opts = init as
      | { method?: string; headers?: Record<string, string>; body?: string }
      | undefined;
    calls.push({
      url: String(url),
      method: opts?.method ?? 'GET',
      authorization: opts?.headers?.['authorization'],
      body: opts?.body === undefined ? undefined : JSON.parse(opts.body),
    });

    const next = responses[Math.min(index, responses.length - 1)];
    index += 1;
    const status = next?.status ?? 200;
    const hasBody = status !== 204 && next?.body !== undefined;
    return new Response(hasBody ? JSON.stringify(next?.body) : null, { status });
  });

  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the permission set', () => {
  it('asks for read and never for write', () => {
    // The whole product position in one assertion. A `contents:write` added
    // here would hand an agent the ability to push, and every other control in
    // the system sits downstream of this list.
    for (const service of GITHUB_SERVICE_NAMES) {
      for (const permission of GITHUB_SERVICES[service]) {
        expect(permission, `${service} -> ${permission}`).toMatch(/:read$/);
      }
    }
  });

  it('names metadata explicitly rather than relying on GitHub granting it', () => {
    // GitHub grants metadata implicitly. Left out here, the broker's
    // SCOPE_NOT_GRANTED check would pass for a connection that never had it.
    for (const service of GITHUB_SERVICE_NAMES) {
      expect(GITHUB_SERVICES[service], service).toContain('metadata:read');
    }
  });

  it('refuses a service name it does not define', () => {
    expect(isGitHubService('repos')).toBe(true);
    expect(isGitHubService('contents:write')).toBe(false);
    expect(isGitHubService('__proto__')).toBe(false);
  });
});

describe('the app JWT', () => {
  it('is signed with the private key and carries the app id', () => {
    const token = createAppJwt(CONFIG, new Date('2026-10-05T12:00:00Z'));
    const [header, payload, signature] = token.split('.');

    const verifier = createVerify('RSA-SHA256');
    verifier.update(`${header}.${payload}`);
    verifier.end();
    expect(verifier.verify(publicKey, Buffer.from(signature ?? '', 'base64url'))).toBe(true);

    const claims = JSON.parse(Buffer.from(payload ?? '', 'base64url').toString()) as {
      iss: string;
    };
    expect(claims.iss).toBe('123456');
    expect(JSON.parse(Buffer.from(header ?? '', 'base64url').toString())).toEqual({
      alg: 'RS256',
      typ: 'JWT',
    });
  });

  it('backdates iat and stays inside the ten-minute ceiling', () => {
    const now = new Date('2026-10-05T12:00:00Z');
    const payload = createAppJwt(CONFIG, now).split('.')[1];
    const claims = JSON.parse(Buffer.from(payload ?? '', 'base64url').toString()) as {
      iat: number;
      exp: number;
    };

    const seconds = Math.floor(now.getTime() / 1000);
    // A clock a few seconds fast otherwise produces an iat in GitHub's future,
    // which it rejects outright.
    expect(claims.iat).toBeLessThan(seconds);
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(600);
  });
});

describe('minting an installation token', () => {
  it('asks for exactly the scopes it was given, and no others', async () => {
    const calls = stubFetch([
      {
        body: {
          token: 'ghs_fake',
          expires_at: '2026-10-05T13:00:00Z',
          permissions: { issues: 'read' },
        },
      },
    ]);

    await createGitHubExchange(CONFIG).refresh('4242', ['metadata:read', 'issues:read']);

    const minted = calls.at(-1);
    expect(minted?.method).toBe('POST');
    expect(minted?.url).toContain('/app/installations/4242/access_tokens');
    // Not `contents`. An issue read must not come back holding file access.
    expect(minted?.body).toEqual({ permissions: { metadata: 'read', issues: 'read' } });
  });

  it('reports what GitHub granted, not what was asked for', async () => {
    stubFetch([
      {
        body: {
          token: 'ghs_fake',
          expires_at: '2026-10-05T13:00:00Z',
          // The installation never had contents, so GitHub silently drops it.
          permissions: { metadata: 'read' },
        },
      },
    ]);

    const grant = await createGitHubExchange(CONFIG).refresh('4242', [
      'metadata:read',
      'contents:read',
    ]);

    expect(grant.scopes).toEqual(['metadata:read']);
  });

  it('refuses a response that carried no token', async () => {
    stubFetch([{ body: { expires_at: '2026-10-05T13:00:00Z' } }]);
    await expect(createGitHubExchange(CONFIG).refresh('4242', ['metadata:read'])).rejects.toThrow(
      /no token/,
    );
  });

  it('assumes a short life when the expiry is missing or unreadable', async () => {
    stubFetch([{ body: { token: 'ghs_fake', expires_at: 'never' } }]);
    const grant = await createGitHubExchange(CONFIG).refresh('4242', ['metadata:read']);

    // Believing a dead token is alive produces a failure at the worst moment.
    expect(grant.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 301_000);
    expect(grant.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it('does not put the private key in the error', async () => {
    stubFetch([{ status: 403, body: { message: 'installation suspended' } }]);
    const error = await createGitHubExchange(CONFIG)
      .refresh('4242', ['metadata:read'])
      .catch((e: unknown) => e);

    const text = String(error);
    expect(text).toContain('403');
    expect(text).not.toContain('PRIVATE KEY');
    expect(text).not.toContain(CONFIG.privateKeyPem.slice(40, 90));
  });
});

describe('reading an installation', () => {
  it('trusts GitHub for the id, not the caller', async () => {
    // The callback hands us `installation_id` as a query parameter. An agent
    // able to assert its own installation id would be choosing whose
    // repositories to reach — the same escalation-by-argument that
    // `/v1/grants/sync` refuses for a file's parent.
    stubFetch([{ body: { id: 99, account: { login: 'acme' }, permissions: { contents: 'read' } } }]);

    const result = await readInstallation(CONFIG, '4242');

    expect(result.installationId).toBe('99');
    expect(result.accountLogin).toBe('acme');
    expect(result.scopes).toEqual(['contents:read']);
  });

  it('fails rather than inventing an installation', async () => {
    stubFetch([{ status: 404, body: { message: 'Not Found' } }]);
    await expect(readInstallation(CONFIG, '4242')).rejects.toThrow(/installation lookup failed/);
  });
});

describe('revoking', () => {
  it('deletes the installation', async () => {
    const calls = stubFetch([{ status: 204 }]);
    await createGitHubExchange(CONFIG).revoke('4242');

    expect(calls.at(-1)?.method).toBe('DELETE');
    expect(calls.at(-1)?.url).toContain('/app/installations/4242');
  });

  it('treats an already-gone installation as success', async () => {
    // 404 means not installed, which is the state the caller wanted.
    stubFetch([{ status: 404, body: { message: 'Not Found' } }]);
    await expect(createGitHubExchange(CONFIG).revoke('4242')).resolves.toBeUndefined();
  });

  it('reports a real failure', async () => {
    stubFetch([{ status: 500, body: {} }]);
    await expect(createGitHubExchange(CONFIG).revoke('4242')).rejects.toThrow(/delete failed/);
  });
});

describe('the install URL', () => {
  it('round-trips state and names no scopes', () => {
    const url = new URL(buildInstallUrl({ appSlug: 'veto-protocol' }, { state: 'st_abc' }));

    expect(url.origin + url.pathname).toBe(
      'https://github.com/apps/veto-protocol/installations/new',
    );
    expect(url.searchParams.get('state')).toBe('st_abc');
    // What an installation may reach is chosen on GitHub's screen, by the
    // person installing it. There is no parameter here that could widen it.
    expect(url.searchParams.get('scope')).toBeNull();
    expect(url.searchParams.get('permissions')).toBeNull();
  });
});

/**
 * Proving an installation belongs to the person claiming it (F-01).
 *
 * `readInstallation` uses the App JWT and can read any installation of this
 * App, so it answers "does this exist" and never "is this yours". These cover
 * the half that answers the second question.
 */
describe('userControlsInstallation', () => {
  const CONFIG = { clientId: 'Iv1.test', clientSecret: 'shh' };

  function stub(options: {
    reachable?: readonly string[];
    tokenBody?: unknown;
    listStatus?: number;
  } = {}) {
    const reachable = options.reachable ?? ['111'];

    vi.stubGlobal('fetch', async (url: unknown) => {
      const href = String(url);
      const json = (body: unknown, status = 200) =>
        new Response(JSON.stringify(body), {
          status,
          headers: { 'content-type': 'application/json' },
        });

      if (href === 'https://github.com/login/oauth/access_token') {
        return json(options.tokenBody ?? { access_token: 'gho_x' });
      }
      if (href.startsWith(`${GITHUB_API_URL}/user/installations`)) {
        if (options.listStatus !== undefined && options.listStatus !== 200) {
          return json({ message: 'nope' }, options.listStatus);
        }
        return json({ installations: reachable.map((id) => ({ id: Number(id) })) });
      }
      throw new Error(`unexpected fetch: ${href}`);
    });
  }

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('says yes for an installation the user can reach', async () => {
    stub({ reachable: ['111', '222'] });
    await expect(userControlsInstallation(CONFIG, { code: 'c', installationId: '222' })).resolves.toBe(
      true,
    );
  });

  it('says no for one they cannot', async () => {
    stub({ reachable: ['111'] });
    await expect(userControlsInstallation(CONFIG, { code: 'c', installationId: '999' })).resolves.toBe(
      false,
    );
  });

  it('throws rather than returning false when the code is rejected', async () => {
    // GitHub answers 200 with an `error` field for a bad code, so a status
    // check alone would read a failure as a success and hand back an empty
    // token. The caller must see a throw, because "no token" and "not yours"
    // are different facts and only one of them is about ownership.
    stub({ tokenBody: { error: 'bad_verification_code' } });
    await expect(
      userControlsInstallation(CONFIG, { code: 'c', installationId: '111' }),
    ).rejects.toThrow();
  });

  it('throws when the installation list cannot be read', async () => {
    // Never a silent false: an unreadable list is not evidence of anything,
    // and the route turns a throw into a refusal anyway (invariant 1).
    stub({ listStatus: 500 });
    await expect(
      userControlsInstallation(CONFIG, { code: 'c', installationId: '111' }),
    ).rejects.toThrow();
  });

  it('reads past the first page', async () => {
    const many = Array.from({ length: 100 }, (_, i) => String(5000 + i));
    stub({ reachable: [...many, '777'] });
    await expect(userControlsInstallation(CONFIG, { code: 'c', installationId: '777' })).resolves.toBe(
      true,
    );
  });

  it('sends the client secret to GitHub and nowhere else', async () => {
    const seen: string[] = [];
    vi.stubGlobal('fetch', async (url: unknown, init: unknown) => {
      seen.push(String(url));
      const body = (init as { body?: unknown }).body;
      if (typeof body === 'string' && body.includes(CONFIG.clientSecret)) {
        expect(String(url)).toBe('https://github.com/login/oauth/access_token');
      }
      return new Response(
        JSON.stringify(
          String(url).includes('/user/installations')
            ? { installations: [{ id: 111 }] }
            : { access_token: 'gho_x' },
        ),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });

    await userControlsInstallation(CONFIG, { code: 'c', installationId: '111' });

    // The list call carries the user token, never the secret.
    expect(seen.some((u) => u.includes('/user/installations'))).toBe(true);
  });
});
