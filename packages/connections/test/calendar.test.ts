/**
 * The Calendar reader (spec §9.1).
 *
 * `fetch` is stubbed, so nothing here talks to Google. What is under test is the
 * shape of the requests this module builds and what it refuses to carry back —
 * a guest list and an event description are both other people's writing, and
 * neither is needed to answer "what is happening".
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { createCalendarReader, CalendarError } from '../src/calendar.ts';

const reader = createCalendarReader();
const TOKEN = 'ya29.fake-access-token';

interface Call {
  url: string;
  authorization: string | undefined;
}

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

const WINDOW = { timeMin: '2026-10-01T00:00:00Z', timeMax: '2026-10-08T00:00:00Z' };

const event = (id: string, over: Record<string, unknown> = {}) => ({
  id,
  summary: 'Board review',
  description: 'Dial-in details and a long agenda',
  location: 'Room 3',
  start: { dateTime: '2026-10-01T09:00:00Z' },
  end: { dateTime: '2026-10-01T10:00:00Z' },
  organizer: { email: 'chair@example.com' },
  attendees: [{ email: 'a@example.com' }, { email: 'b@example.com' }],
  ...over,
});

describe('listing a window', () => {
  it('returns times and titles, and never descriptions', async () => {
    stubFetch([{ body: { items: [event('e1'), event('e2')] } }]);

    const events = await reader.listEvents(TOKEN, WINDOW, 25);

    expect(events.map((e) => e.id)).toEqual(['e1', 'e2']);
    expect(events[0]).toMatchObject({
      summary: 'Board review',
      start: '2026-10-01T09:00:00Z',
      location: 'Room 3',
    });
    // "What is happening" and "what does it say" are separately authorized
    // questions, the same way a mail search is not a mail read.
    expect(events[0]?.description).toBeNull();
  });

  it('counts guests instead of naming them', async () => {
    stubFetch([{ body: { items: [event('e1')] } }]);
    const events = await reader.listEvents(TOKEN, WINDOW, 25);

    expect(events[0]?.attendeeCount).toBe(2);
    // A guest list is other people's data and is not needed to decide anything
    // (§11). There is no field on CalendarEvent that could carry it.
    expect(JSON.stringify(events)).not.toContain('a@example.com');
  });

  it('asks for the window it was given, and expands recurring events', async () => {
    const calls = stubFetch([{ body: { items: [] } }]);
    await reader.listEvents(TOKEN, WINDOW, 25);

    expect(calls[0]?.url).toContain(`timeMin=${encodeURIComponent(WINDOW.timeMin)}`);
    expect(calls[0]?.url).toContain(`timeMax=${encodeURIComponent(WINDOW.timeMax)}`);
    // Without singleEvents a weekly meeting appears once as a series rather
    // than as the occurrences inside the window, and the window stops meaning
    // what a reader thinks it means.
    expect(calls[0]?.url).toContain('singleEvents=true');
  });

  it('clamps the page size past what the schema allows', async () => {
    const calls = stubFetch([{ body: { items: [] } }]);
    await reader.listEvents(TOKEN, WINDOW, 9999);
    expect(calls[0]?.url).toContain('maxResults=100');
  });

  it('handles an all-day event, which has a date and no time', async () => {
    stubFetch([
      {
        body: {
          items: [event('e1', { start: { date: '2026-10-01' }, end: { date: '2026-10-02' } })],
        },
      },
    ]);
    const events = await reader.listEvents(TOKEN, WINDOW, 5);
    expect(events[0]?.start).toBe('2026-10-01');
  });

  it('carries the token as a bearer header and never in the URL', async () => {
    const calls = stubFetch([{ body: { items: [] } }]);
    await reader.listEvents(TOKEN, WINDOW, 5);

    expect(calls[0]?.authorization).toBe(`Bearer ${TOKEN}`);
    expect(calls[0]?.url).not.toContain(TOKEN);
  });

  it('fails loudly when the listing is refused', async () => {
    stubFetch([{ status: 403 }]);
    await expect(reader.listEvents(TOKEN, WINDOW, 5)).rejects.toThrow(CalendarError);
  });
});

describe('reading one event', () => {
  it('returns no description unless the description was approved', async () => {
    stubFetch([{ body: event('e1') }]);
    expect((await reader.readEvent(TOKEN, 'e1', ['summary'])).description).toBeNull();
  });

  it('returns the description when it was approved', async () => {
    stubFetch([{ body: event('e1') }]);
    const read = await reader.readEvent(TOKEN, 'e1', ['summary', 'description']);
    expect(read.description).toBe('Dial-in details and a long agenda');
  });

  it('refuses an event that is not the one authorised', async () => {
    stubFetch([{ body: event('somethingElse') }]);
    await expect(reader.readEvent(TOKEN, 'e1', [])).rejects.toThrow(CalendarError);
  });

  it('turns an upstream refusal into a typed error carrying the status', async () => {
    stubFetch([{ status: 404 }]);
    await expect(reader.readEvent(TOKEN, 'e1', [])).rejects.toMatchObject({ status: 404 });
  });

  it('only ever asks about the primary calendar', async () => {
    // A Google user can often see colleagues' calendars. There is no calendar
    // argument in this module, so reaching one is not a mistake anybody can
    // make later.
    const calls = stubFetch([{ body: event('e1') }]);
    await reader.readEvent(TOKEN, 'e1', []);
    expect(calls[0]?.url).toContain('/calendars/primary/events');
  });
});

describe('what this module cannot do', () => {
  it('has no create, update or delete', () => {
    // §9.1: Calendar begins read-only; create and update arrive later behind a
    // step-up approval. Not a rule to remember — there is no method to call.
    expect(Object.keys(reader).sort()).toEqual(['listEvents', 'readEvent']);
  });
});
