/**
 * The Gmail reader (spec §9.1).
 *
 * `fetch` is stubbed, so nothing here talks to Google. What is under test is
 * the shape of the requests this module builds — because step 8 must forward
 * exactly what was authorised and nothing wider, and the difference between a
 * metadata read and a content read is a query parameter nobody sees.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { createGmailReader, GmailError } from '../src/gmail.ts';

const reader = createGmailReader();
const TOKEN = 'ya29.fake-access-token';

interface Call {
  url: string;
  authorization: string | undefined;
}

/** Answers each request in order and records what was asked for. */
function stubFetch(responses: Array<{ status?: number; body?: unknown }>): Call[] {
  const calls: Call[] = [];
  let index = 0;

  vi.stubGlobal('fetch', async (url: unknown, init: unknown) => {
    const headers = (init as { headers?: Record<string, string> } | undefined)?.headers;
    calls.push({ url: String(url), authorization: headers?.['authorization'] });

    const next = responses[Math.min(index, responses.length - 1)];
    index += 1;
    const status = next?.status ?? 200;
    return new Response(status === 200 ? JSON.stringify(next?.body ?? {}) : null, { status });
  });

  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

const base64url = (value: string): string => Buffer.from(value, 'utf8').toString('base64url');

const message = (id: string, text?: string) => ({
  id,
  threadId: `t-${id}`,
  snippet: 'a preview',
  payload: {
    headers: [
      { name: 'From', value: 'sender@example.com' },
      { name: 'Subject', value: 'Quarterly plan' },
      { name: 'Date', value: 'Fri, 19 Sep 2026 09:00:00 +0000' },
      { name: 'Bcc', value: 'hidden@example.com' },
    ],
    ...(text === undefined ? {} : { mimeType: 'text/plain', body: { data: base64url(text) } }),
  },
});

describe('searching', () => {
  it('returns headers and never a body', async () => {
    const calls = stubFetch([
      { body: { messages: [{ id: 'm1' }, { id: 'm2' }] } },
      { body: message('m1') },
      { body: message('m2') },
    ]);

    const found = await reader.searchMessages(TOKEN, 'from:sender@example.com', 10);

    expect(found.map((m) => m.id)).toEqual(['m1', 'm2']);
    expect(found[0]).toMatchObject({ from: 'sender@example.com', subject: 'Quarterly plan' });
    // `GmailSummary` has no body field. The type is the control, the same way
    // `Connection` has no token field.
    expect(Object.keys(found[0] ?? {})).not.toContain('body');

    // `format=metadata` cannot return a body even if something later asks for
    // one, so the promise the tool's description makes is enforced upstream.
    expect(calls[1]?.url).toContain('format=metadata');
    expect(calls[1]?.url).not.toContain('format=full');
  });

  it('asks only for the headers it will use', async () => {
    const calls = stubFetch([{ body: { messages: [{ id: 'm1' }] } }, { body: message('m1') }]);
    await reader.searchMessages(TOKEN, 'x', 5);

    for (const header of ['From', 'Subject', 'Date']) {
      expect(calls[1]?.url, header).toContain(`metadataHeaders=${header}`);
    }
    // Bcc arrives in the fixture and is dropped rather than forwarded. §11 data
    // minimisation: what is not needed is not carried.
    expect(calls[1]?.url).not.toContain('Bcc');
  });

  it('clamps the page size, even past what the schema allows', async () => {
    const calls = stubFetch([{ body: { messages: [] } }]);
    await reader.searchMessages(TOKEN, 'x', 9999);

    // The decision authorised a bounded read. Step 8 must not widen it.
    expect(calls[0]?.url).toContain('maxResults=50');
  });

  it('returns fewer than asked rather than failing when one message vanishes', async () => {
    // A message can be deleted between the list and the fetch. That is not an
    // outage and must not be reported as one.
    const calls = stubFetch([
      { body: { messages: [{ id: 'm1' }, { id: 'gone' }] } },
      { body: message('m1') },
      { status: 404 },
    ]);

    const found = await reader.searchMessages(TOKEN, 'x', 10);
    expect(found.map((m) => m.id)).toEqual(['m1']);
    expect(calls).toHaveLength(3);
  });

  it('carries the token as a bearer header and never in the URL', async () => {
    const calls = stubFetch([{ body: { messages: [] } }]);
    await reader.searchMessages(TOKEN, 'x', 1);

    expect(calls[0]?.authorization).toBe(`Bearer ${TOKEN}`);
    expect(calls[0]?.url).not.toContain(TOKEN);
  });

  it('fails loudly when the list itself is refused', async () => {
    stubFetch([{ status: 403 }]);
    await expect(reader.searchMessages(TOKEN, 'x', 1)).rejects.toThrow(GmailError);
  });
});

describe('reading one message', () => {
  it('returns no body unless the body was approved', async () => {
    const calls = stubFetch([{ body: message('m1', 'secret contents') }]);

    const read = await reader.readMessage(TOKEN, 'm1', ['from', 'subject']);

    expect(read.body).toBeNull();
    // And the request could not have returned one: metadata format has no body.
    expect(calls[0]?.url).toContain('format=metadata');
  });

  it('returns the body when it was approved', async () => {
    const calls = stubFetch([{ body: message('m1', 'secret contents') }]);

    const read = await reader.readMessage(TOKEN, 'm1', ['subject', 'body']);

    expect(read.body).toBe('secret contents');
    expect(calls[0]?.url).toContain('format=full');
  });

  it('refuses a message that is not the one authorised', async () => {
    // A redirect, an alias, a server bug — whatever the cause, an answer about
    // a different message is not the approved resource. Drive makes the same
    // check for files.
    stubFetch([{ body: message('somethingElse', 'x') }]);
    await expect(reader.readMessage(TOKEN, 'm1', ['body'])).rejects.toThrow(GmailError);
  });

  it('finds text nested inside a multipart message', async () => {
    stubFetch([
      {
        body: {
          id: 'm1',
          payload: {
            mimeType: 'multipart/mixed',
            parts: [
              { mimeType: 'application/pdf', body: { data: base64url('%PDF') } },
              {
                mimeType: 'multipart/alternative',
                parts: [{ mimeType: 'text/plain', body: { data: base64url('the real text') } }],
              },
            ],
          },
        },
      },
    ]);

    expect((await reader.readMessage(TOKEN, 'm1', ['body'])).body).toBe('the real text');
  });

  it('gives up on a maliciously deep message instead of walking it forever', async () => {
    // Attacker-shaped structure. An unbounded walk here is a denial of service
    // against the one process holding a live credential.
    let deep: Record<string, unknown> = {
      mimeType: 'text/plain',
      body: { data: base64url('buried') },
    };
    for (let i = 0; i < 40; i += 1) deep = { mimeType: 'multipart/mixed', parts: [deep] };

    stubFetch([{ body: { id: 'm1', payload: deep } }]);
    expect((await reader.readMessage(TOKEN, 'm1', ['body'])).body).toBeNull();
  });

  it('returns null for a message with no text at all', async () => {
    stubFetch([{ body: { id: 'm1', payload: { mimeType: 'image/png', body: { data: 'x' } } } }]);
    // Null, not an empty string: "there was nothing" and "it was blank" are
    // different answers.
    expect((await reader.readMessage(TOKEN, 'm1', ['body'])).body).toBeNull();
  });

  it('turns an upstream refusal into a typed error carrying the status', async () => {
    stubFetch([{ status: 401 }]);
    await expect(reader.readMessage(TOKEN, 'm1', [])).rejects.toMatchObject({ status: 401 });
  });
});

describe('what this module cannot do', () => {
  it('has no send function', () => {
    // §9.1 keeps sending out of the MVP. Not a rule to remember — there is no
    // method to call, and the scope requested cannot send either.
    expect(Object.keys(reader).sort()).toEqual(['readMessage', 'searchMessages']);
  });
});
