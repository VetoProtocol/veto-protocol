/**
 * Reading Slack conversations.
 *
 * `fetch` is stubbed, so nothing here talks to Slack. The properties that
 * matter are the ones that keep a channel history from becoming a workspace
 * export: bounds that hold whatever a caller asks for, and a refusal that
 * names its cause.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createChannelReader,
  MAX_CHANNELS,
  MAX_MESSAGES,
  SlackError,
} from '../src/channels.ts';

function stub(body: unknown, status = 200) {
  const seen: string[] = [];
  vi.stubGlobal('fetch', async (url: unknown) => {
    seen.push(String(url));
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  });
  return seen;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

const reader = createChannelReader();

describe('listing channels', () => {
  it('returns names and ids, and whether the bot can actually read each one', async () => {
    stub({
      ok: true,
      channels: [
        { id: 'C001', name: 'general', is_private: false, is_member: true },
        { id: 'C002', name: 'secret', is_private: true, is_member: false },
      ],
    });

    const channels = await reader.listChannels('xoxb-token', 25);

    expect(channels).toEqual([
      { id: 'C001', name: 'general', isPrivate: false, botIsMember: true },
      // Surfaced rather than filtered: a channel the bot is not in is one an
      // operator may want to grant next, and hiding it would make the list
      // look like the whole workspace when it is not.
      { id: 'C002', name: 'secret', isPrivate: true, botIsMember: false },
    ]);
  });

  it('never returns a message', async () => {
    // Listing is a separate permission from reading, and the response shape is
    // what enforces it here.
    stub({ ok: true, channels: [{ id: 'C001', name: 'general', is_member: true }] });

    const channels = await reader.listChannels('xoxb-token', 25);

    expect(JSON.stringify(channels)).not.toContain('text');
  });

  it('caps the page size however much a caller asks for', async () => {
    const seen = stub({ ok: true, channels: [] });
    await reader.listChannels('xoxb-token', 10_000);

    expect(seen[0]).toContain(`limit=${String(MAX_CHANNELS)}`);
  });

  it('asks for both kinds, and lets the scopes decide what comes back', async () => {
    // Requesting private channels without `groups:read` returns none rather
    // than failing, so the request does not have to know which scopes the
    // installation holds.
    const seen = stub({ ok: true, channels: [] });
    await reader.listChannels('xoxb-token', 25);

    expect(seen[0]).toContain('public_channel');
    expect(seen[0]).toContain('private_channel');
  });
});

describe('reading history', () => {
  const window = { oldest: new Date('2026-10-01T00:00:00Z'), latest: new Date('2026-10-02T00:00:00Z') };

  it('returns author ids and never resolves them to names', async () => {
    // A name is personal data this feature does not need (§11).
    stub({
      ok: true,
      messages: [{ ts: '1696118400.000100', user: 'U123', text: 'hello', thread_ts: null }],
    });

    const messages = await reader.readHistory('t', 'C001', window.oldest, window.latest, 25);

    expect(messages[0]?.userId).toBe('U123');
    expect(JSON.stringify(messages)).not.toContain('displayName');
  });

  it('caps the message count however much a caller asks for', async () => {
    const seen = stub({ ok: true, messages: [] });
    await reader.readHistory('t', 'C001', window.oldest, window.latest, 10_000);

    expect(seen[0]).toContain(`limit=${String(MAX_MESSAGES)}`);
  });

  it('sends the window as epoch seconds, not milliseconds', async () => {
    // The real risk is the unit. Slack wants seconds; a millisecond value is
    // a timestamp fifty thousand years out, which Slack answers by returning
    // nothing — an empty history that looks like an empty channel.
    const seen = stub({ ok: true, messages: [] });
    await reader.readHistory('t', 'C001', window.oldest, window.latest, 25);

    const asSeconds = Math.floor(window.oldest.getTime() / 1000);
    expect(seen[0]).toContain(`oldest=${String(asSeconds)}`);
    expect(seen[0]).not.toContain(String(window.oldest.getTime()));
  });

  it('survives a message with no author, which Slack sends for system events', async () => {
    stub({ ok: true, messages: [{ ts: '1.0', text: 'someone joined' }] });

    const messages = await reader.readHistory('t', 'C001', window.oldest, window.latest, 25);

    expect(messages[0]?.userId).toBeNull();
  });
});

describe('failures', () => {
  it('treats ok:false as a failure even though the status is 200', async () => {
    stub({ ok: false, error: 'channel_not_found' });

    await expect(reader.listChannels('t', 25)).rejects.toBeInstanceOf(SlackError);
  });

  it('carries the code, because not_in_channel and channel_not_found differ', async () => {
    // One means the bot was never invited; the other that the id is wrong.
    // An operator needs to tell them apart.
    stub({ ok: false, error: 'not_in_channel' });

    await expect(
      reader.readHistory('t', 'C001', new Date(0), new Date(1), 25),
    ).rejects.toMatchObject({ code: 'not_in_channel' });
  });

  it('reports a transport failure as its own kind of error', async () => {
    stub({}, 500);

    await expect(reader.listChannels('t', 25)).rejects.toMatchObject({ code: 'http_500' });
  });
});
